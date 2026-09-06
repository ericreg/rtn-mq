//! Reusable bearer-code enrollment, serialized by the messaging endpoint owner.
use crate::{
    auth::{self, MAX_CERT, MAX_PERMISSIONS},
    buffer::{Budget, Permit},
    cbor::{Reader, Writer},
    endpoint::owner::Command,
    error::transport,
    message::digest,
    wire, *,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use iroh::{Endpoint, EndpointAddr, endpoint::Connection};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    sync::{mpsc, oneshot},
    time::timeout,
};
pub(crate) const ALPN: &[u8] = b"iroh-mq/join/2";
const PREFIX: &str = "rtn-mq://join/";
pub const MAX_JOIN_LIFETIME: Duration = Duration::from_secs(10 * 365 * 24 * 60 * 60);

/// Permission and registration limits attached to a reusable code.
#[derive(Clone, Debug)]
pub struct JoinOptions {
    pub permissions: Vec<Permission>,
    pub limits: CertificateLimits,
    pub lifetime: Duration,
    pub certificate_lifetime: Duration,
    /// Maximum distinct endpoint identities admitted by this code (1..=256).
    pub max_uses: usize,
}
impl JoinOptions {
    pub fn new(permissions: Vec<Permission>) -> Self {
        Self {
            permissions,
            limits: CertificateLimits::default(),
            lifetime: Duration::from_secs(3600),
            certificate_lifetime: Duration::from_secs(3600),
            max_uses: 256,
        }
    }
    pub(crate) fn validate(&self) -> Result<()> {
        if self.permissions.len() > MAX_PERMISSIONS
            || self.lifetime.as_secs() == 0
            || self.lifetime > MAX_JOIN_LIFETIME
            || self.certificate_lifetime.as_secs() == 0
            || self.certificate_lifetime > MAX_JOIN_LIFETIME
            || !(1..=256).contains(&self.max_uses)
        {
            return Err(Error::Config("invalid join code limits"));
        }
        Ok(())
    }
}

/// A bearer credential. Share its encoding privately with intended peers.
/// Debug omits the secret; encode() explicitly reveals the transferable code.
#[derive(Clone)]
pub struct JoinCode {
    pub(crate) address: EndpointAddr,
    secret: [u8; 32],
}
impl std::fmt::Debug for JoinCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JoinCode")
            .field("host", &self.host_id())
            .finish_non_exhaustive()
    }
}
impl JoinCode {
    pub fn id(&self) -> [u8; 16] {
        // Domain separation keeps the public identifier distinct from the stored secret hash.
        let mut input = b"iroh-mq/join-code-id/v3".to_vec();
        input.extend_from_slice(&self.secret);
        digest(&input)[..16].try_into().unwrap()
    }
    pub fn host_id(&self) -> EndpointId {
        self.address.id
    }
    /// Encode a compact v3 code. Relay hints replace interface addresses when available.
    pub fn encode(&self) -> Result<String> {
        let address = compact_address(&self.address);
        let count = address.ip_addrs().count() + address.relay_urls().count();
        if count == 0 || count > 16 {
            return Err(Error::Protocol("join address count"));
        }
        let mut w = Writer::new();
        w.array(4);
        w.u(3);
        w.bytes(address.id.as_bytes());
        w.array(count);
        for ip in address.ip_addrs() {
            w.array(2);
            match ip {
                SocketAddr::V4(ip) => {
                    w.u(0);
                    let mut bytes = ip.ip().octets().to_vec();
                    bytes.extend_from_slice(&ip.port().to_be_bytes());
                    w.bytes(&bytes);
                }
                SocketAddr::V6(ip) => {
                    w.u(1);
                    let mut bytes = ip.ip().octets().to_vec();
                    bytes.extend_from_slice(&ip.port().to_be_bytes());
                    bytes.extend_from_slice(&ip.flowinfo().to_be_bytes());
                    bytes.extend_from_slice(&ip.scope_id().to_be_bytes());
                    w.bytes(&bytes);
                }
            }
        }
        for relay in address.relay_urls() {
            let url = relay.as_str();
            if url.len() > 1024 {
                return Err(Error::MessageTooLarge);
            }
            w.array(2);
            w.u(2);
            w.text(url);
        }
        w.bytes(&self.secret);
        Ok(format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(w.finish())))
    }
    pub fn decode(code: &str) -> Result<Self> {
        if code.len() > 32768 {
            return Err(Error::MessageTooLarge);
        }
        let encoded = code
            .strip_prefix(PREFIX)
            .ok_or(Error::Protocol("join code prefix"))?;
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| Error::Protocol("join code base64"))?;
        let mut r = Reader::new(&bytes);
        r.array(4)?;
        if r.u()? != 3 {
            return Err(Error::Protocol("join code version"));
        }
        let mut address = EndpointAddr::new(auth::endpoint(r.fixed()?)?);
        for _ in 0..r.list(16)? {
            r.array(2)?;
            address = match r.u()? {
                0 => {
                    let bytes: [u8; 6] = r.fixed()?;
                    let ip = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
                    let port = u16::from_be_bytes(bytes[4..6].try_into().unwrap());
                    address.with_ip_addr(SocketAddr::from((ip, port)))
                }
                1 => {
                    let bytes: [u8; 26] = r.fixed()?;
                    let ip = Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[..16]).unwrap());
                    let port = u16::from_be_bytes(bytes[16..18].try_into().unwrap());
                    let flow = u32::from_be_bytes(bytes[18..22].try_into().unwrap());
                    let scope = u32::from_be_bytes(bytes[22..26].try_into().unwrap());
                    address.with_ip_addr(SocketAddr::V6(SocketAddrV6::new(ip, port, flow, scope)))
                }
                2 => address.with_relay_url(
                    r.text(1024)?
                        .parse()
                        .map_err(|_| Error::Protocol("join relay address"))?,
                ),
                _ => return Err(Error::Protocol("join address type")),
            };
        }
        let secret = r.fixed()?;
        r.end()?;
        let value = Self { address, secret };
        if value.encode()? != code {
            return Err(Error::Protocol("noncanonical join code"));
        }
        Ok(value)
    }
}

// A relay is sufficient to bootstrap Iroh's authenticated path negotiation. Direct-only
// deployments retain all IP hints, without relying on a directory or address lookup service.
fn compact_address(address: &EndpointAddr) -> EndpointAddr {
    if address.relay_urls().next().is_some() {
        address
            .relay_urls()
            .fold(EndpointAddr::new(address.id), |addr, relay| {
                addr.with_relay_url(relay.clone())
            })
    } else {
        address.clone()
    }
}

struct Grant {
    hash: [u8; 32],
    expires: u64,
    options: JoinOptions,
    redeemed: BTreeMap<EndpointId, Certificate>,
    _memory: Option<Permit>,
}
struct Member {
    certificate: Certificate,
    _memory: Option<Permit>,
}
pub(crate) enum Admission {
    Host(Box<Host>),
    Client(EndpointId),
}
pub(crate) struct Host {
    authority: Authority,
    codes: BTreeMap<[u8; 16], Grant>,
    members: BTreeMap<[u8; 16], Member>,
    storage: Option<Arc<dyn HostStorage>>,
}

/// Application-managed storage for the host authority, grants, and membership records.
/// These opaque bytes contain private keys and must be kept confidential. `save` must
/// atomically and durably replace the entire value before returning success. Calls are
/// synchronous and serialized by the endpoint owner, as with file persistence.
pub trait HostStorage: Send + Sync + 'static {
    fn load(&self) -> Result<Option<Vec<u8>>>;
    fn save(&self, bytes: &[u8]) -> Result<()>;
}

/// Generate a new private authority and empty enrollment state without starting a transport.
/// Store these opaque bytes securely and return them from `HostStorage::load` when hosting.
pub fn generate_host_state() -> Vec<u8> {
    Host::new(Authority::generate(), None).encode()
}

#[derive(Clone)]
struct FileHostStorage {
    path: PathBuf,
}

impl FileHostStorage {
    const MAX_BYTES: usize = 4 * 1024 * 1024;

    fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    fn load_file(&self) -> Result<Option<Vec<u8>>> {
        let parent = self.parent();
        if parent.exists() {
            Self::validate_parent(parent)?;
        }
        let metadata = match fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        Self::validate_file(&metadata)?;
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        options.custom_flags(libc::O_NOFOLLOW);
        let file = options.open(&self.path)?;
        Self::validate_file(&file.metadata()?)?;
        let mut bytes = Vec::new();
        use std::io::Read;
        file.take((Self::MAX_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > Self::MAX_BYTES {
            return Err(Error::MessageTooLarge);
        }
        Ok(Some(bytes))
    }

    fn save_file(&self, bytes: &[u8]) -> Result<()> {
        if bytes.len() > Self::MAX_BYTES {
            return Err(Error::MessageTooLarge);
        }
        let parent = self.parent();
        let parent_existed = parent.exists();
        fs::create_dir_all(parent)?;
        #[cfg(unix)]
        if !parent_existed {
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
        Self::validate_parent(parent)?;
        if let Ok(metadata) = fs::symlink_metadata(&self.path) {
            Self::validate_file(&metadata)?;
        }
        let temporary = parent.join(format!(".rtn-mq-state-{:032x}", rand::random::<u128>()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let result = (|| {
            let mut file = options.open(&temporary)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            fs::rename(&temporary, &self.path)?;
            #[cfg(unix)]
            fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600))?;
            fs::File::open(parent)?.sync_all()?;
            Ok::<(), Error>(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }

    fn parent(&self) -> &Path {
        self.path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
    }

    fn validate_parent(metadata_path: &Path) -> Result<()> {
        let metadata = fs::symlink_metadata(metadata_path)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(Error::Config(
                "persistent-state directory must be a real directory",
            ));
        }
        #[cfg(unix)]
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(Error::Config(
                "persistent-state directory must be private (0700)",
            ));
        }
        Ok(())
    }

    fn validate_file(metadata: &fs::Metadata) -> Result<()> {
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(Error::Config(
                "persistent state must be a private regular file",
            ));
        }
        #[cfg(unix)]
        if metadata.nlink() != 1 || metadata.permissions().mode() & 0o077 != 0 {
            return Err(Error::Config(
                "persistent state must be an unlinked private (0600) file",
            ));
        }
        Ok(())
    }
}

impl HostStorage for FileHostStorage {
    fn load(&self) -> Result<Option<Vec<u8>>> {
        self.load_file()
    }

    fn save(&self, bytes: &[u8]) -> Result<()> {
        self.save_file(bytes)
    }
}

impl Host {
    fn new(authority: Authority, storage: Option<Arc<dyn HostStorage>>) -> Self {
        Self {
            authority,
            codes: BTreeMap::new(),
            members: BTreeMap::new(),
            storage,
        }
    }

    fn encode_permission(writer: &mut Writer, permission: &Permission) {
        writer.array(2);
        writer.text(permission.topic.as_str());
        writer.u(u64::from(permission.publish) | (u64::from(permission.subscribe) << 1));
    }

    fn decode_permission(reader: &mut Reader<'_>) -> Result<Permission> {
        reader.array(2)?;
        let topic = Topic::new(reader.text(256)?)?;
        match reader.u()? {
            1 => Permission::publish(topic.as_str()),
            2 => Permission::subscribe(topic.as_str()),
            3 => Permission::both(topic.as_str()),
            _ => Err(Error::Protocol("persistent permission mask")),
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        writer.array(6);
        writer.u(1);
        writer.bytes(&self.authority.secret_bytes());
        writer.bytes(&self.authority.realm_id());
        writer.array(self.codes.len());
        for (id, grant) in &self.codes {
            writer.array(9);
            writer.bytes(id);
            writer.bytes(&grant.hash);
            writer.u(grant.expires);
            writer.u(grant.options.lifetime.as_secs());
            writer.u(grant.options.certificate_lifetime.as_secs());
            writer.u(grant.options.max_uses as u64);
            writer.array(2);
            writer.u(grant.options.limits.max_payload);
            writer.u(grant.options.limits.max_subscriptions);
            writer.array(grant.options.permissions.len());
            for permission in &grant.options.permissions {
                Self::encode_permission(&mut writer, permission);
            }
            writer.array(grant.redeemed.len());
            for (endpoint, certificate) in &grant.redeemed {
                writer.array(2);
                writer.bytes(endpoint.as_bytes());
                writer.bytes(certificate.as_bytes());
            }
        }
        writer.array(self.members.len());
        for member in self.members.values() {
            writer.bytes(member.certificate.as_bytes());
        }
        // Reserved for additive state that can be introduced in a new format version.
        writer.array(0);
        writer.finish()
    }

    fn decode(bytes: &[u8], storage: Arc<dyn HostStorage>) -> Result<Self> {
        if bytes.len() > FileHostStorage::MAX_BYTES {
            return Err(Error::MessageTooLarge);
        }
        let mut reader = Reader::new(bytes);
        reader.array(6)?;
        if reader.u()? != 1 {
            return Err(Error::Protocol("persistent-state version"));
        }
        let authority = Authority::from_parts(reader.fixed()?, reader.fixed()?);
        let trust = authority.trust();
        let code_count = reader.list(256)?;
        let mut codes = BTreeMap::new();
        for _ in 0..code_count {
            reader.array(9)?;
            let id = reader.fixed()?;
            let hash = reader.fixed()?;
            let expires = reader.u()?;
            let lifetime = Duration::from_secs(reader.u()?);
            let certificate_lifetime = Duration::from_secs(reader.u()?);
            let max_uses =
                usize::try_from(reader.u()?).map_err(|_| Error::Protocol("persistent max uses"))?;
            reader.array(2)?;
            let limits = CertificateLimits {
                max_payload: reader.u()?,
                max_subscriptions: reader.u()?,
            };
            let permission_count = reader.list(MAX_PERMISSIONS)?;
            let mut permissions = Vec::with_capacity(permission_count);
            for _ in 0..permission_count {
                permissions.push(Self::decode_permission(&mut reader)?);
            }
            let options = JoinOptions {
                permissions,
                limits,
                lifetime,
                certificate_lifetime,
                max_uses,
            };
            options.validate()?;
            let redeemed_count = reader.list(256)?;
            let mut redeemed = BTreeMap::new();
            for _ in 0..redeemed_count {
                reader.array(2)?;
                let endpoint = auth::endpoint(reader.fixed()?)?;
                let certificate = Certificate::from_bytes(reader.bytes(MAX_CERT)?)?;
                match trust.verify(&certificate, endpoint, auth::now()?) {
                    Ok(()) | Err(Error::CertificateExpired) => {}
                    Err(error) => return Err(error),
                }
                if redeemed.insert(endpoint, certificate).is_some() {
                    return Err(Error::Protocol("duplicate persisted endpoint"));
                }
            }
            if redeemed.len() > options.max_uses
                || codes
                    .insert(
                        id,
                        Grant {
                            hash,
                            expires,
                            options,
                            redeemed,
                            _memory: None,
                        },
                    )
                    .is_some()
            {
                return Err(Error::Protocol("duplicate or overused persisted code"));
            }
        }
        let member_count = reader.list(256)?;
        let mut members = BTreeMap::new();
        let now = auth::now()?;
        for _ in 0..member_count {
            let certificate = Certificate::from_bytes(reader.bytes(MAX_CERT)?)?;
            match trust.verify(&certificate, certificate.endpoint_id(), now) {
                Ok(()) | Err(Error::CertificateExpired) => {
                    if members
                        .insert(
                            certificate.id(),
                            Member {
                                certificate,
                                _memory: None,
                            },
                        )
                        .is_some()
                    {
                        return Err(Error::Protocol("duplicate persisted certificate"));
                    }
                }
                Err(error) => return Err(error),
            }
        }
        if reader.list(0)? != 0 {
            return Err(Error::Protocol("persistent-state reserved fields"));
        }
        reader.end()?;
        let host = Self {
            authority,
            codes,
            members,
            storage: Some(storage),
        };
        crate::cbor::canonical(bytes, &host.encode())?;
        Ok(host)
    }

    fn persist(&self) -> Result<()> {
        if let Some(storage) = &self.storage {
            let bytes = self.encode();
            if bytes.len() > FileHostStorage::MAX_BYTES {
                return Err(Error::MessageTooLarge);
            }
            storage.save(&bytes)?;
        }
        Ok(())
    }

    fn meter(&mut self, budget: &Arc<Budget>) -> Result<()> {
        for grant in self.codes.values_mut() {
            if grant._memory.is_none() {
                grant._memory = Some(
                    budget.reserve(
                        1024 + grant
                            .options
                            .permissions
                            .iter()
                            .map(|permission| permission.topic.as_str().len() + 128)
                            .sum::<usize>(),
                    )?,
                );
            }
        }
        for member in self.members.values_mut() {
            if member._memory.is_none() {
                member._memory = Some(budget.reserve(1024)?);
            }
        }
        Ok(())
    }
}

impl Admission {
    pub fn host(authority: Authority) -> Self {
        Self::Host(Box::new(Host::new(authority, None)))
    }
    pub fn persistent(path: impl AsRef<Path>) -> Result<Self> {
        Self::with_storage(Arc::new(FileHostStorage::new(path)))
    }
    pub fn with_storage(storage: Arc<dyn HostStorage>) -> Result<Self> {
        let host = match storage.load()? {
            Some(bytes) => Host::decode(&bytes, storage)?,
            None => {
                let host = Host::new(Authority::generate(), Some(storage));
                host.persist()?;
                host
            }
        };
        Ok(Self::Host(Box::new(host)))
    }
    pub fn authority(&self) -> Result<&Authority> {
        match self {
            Self::Host(host) => Ok(&host.authority),
            Self::Client(_) => Err(Error::Unauthorized),
        }
    }
    pub fn meter(&mut self, budget: &Arc<Budget>) -> Result<()> {
        if let Self::Host(host) = self {
            host.meter(budget)?;
        }
        Ok(())
    }
    pub fn can_dial(&self, peer: EndpointId) -> bool {
        matches!(self, Self::Client(host) if *host == peer)
    }
    pub fn check(&self, peer: EndpointId, certificate: &Certificate) -> Result<()> {
        let allowed = match self {
            Self::Host(host) => host
                .members
                .get(&certificate.id())
                .is_some_and(|m| m.certificate.endpoint_id() == peer),
            Self::Client(host) => *host == peer,
        };
        if allowed {
            Ok(())
        } else {
            Err(Error::Unauthorized)
        }
    }
    pub fn issue(
        &mut self,
        options: JoinOptions,
        address: EndpointAddr,
        now: u64,
        budget: &Arc<Budget>,
        max_codes: usize,
    ) -> Result<JoinCode> {
        let Self::Host(host) = self else {
            return Err(Error::Unauthorized);
        };
        options.validate()?;
        if host.codes.len() >= max_codes {
            return Err(Error::QueueFull);
        }
        host.authority.issue(
            address.id,
            options.permissions.clone(),
            now,
            now + options.certificate_lifetime.as_secs(),
            options.limits,
        )?;
        let memory = budget.reserve(
            1024 + options
                .permissions
                .iter()
                .map(|p| p.topic.as_str().len() + 128)
                .sum::<usize>(),
        )?;
        let secret: [u8; 32] = rand::random();
        let expires = now + options.lifetime.as_secs();
        let code = JoinCode {
            address: compact_address(&address),
            secret,
        };
        code.encode()?;
        host.codes.insert(
            code.id(),
            Grant {
                hash: digest(&secret),
                expires,
                options,
                redeemed: BTreeMap::new(),
                _memory: Some(memory),
            },
        );
        if let Err(error) = host.persist() {
            host.codes.remove(&code.id());
            return Err(error);
        }
        Ok(code)
    }
    pub fn revoke_code(&mut self, id: [u8; 16]) -> Result<()> {
        let Self::Host(host) = self else {
            return Err(Error::Unauthorized);
        };
        let removed = host.codes.remove(&id);
        if let Err(error) = host.persist() {
            if let Some(grant) = removed {
                host.codes.insert(id, grant);
            }
            return Err(error);
        }
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    pub fn enroll(
        &mut self,
        peer: EndpointId,
        id: [u8; 16],
        secret: [u8; 32],
        now: u64,
        host_expires: u64,
        trust: &Trust,
        budget: &Arc<Budget>,
        max_members: usize,
    ) -> Result<Enrollment> {
        let Self::Host(host) = self else {
            return Err(Error::Unauthorized);
        };
        host.members
            .retain(|_, member| member.certificate.expires_at() > now);
        let grant = host.codes.get(&id).ok_or(Error::Unauthorized)?;
        if grant.expires <= now || grant.hash != digest(&secret) {
            return Err(Error::Unauthorized);
        }
        if let Some(cert) = grant.redeemed.get(&peer) {
            match trust.check(cert, peer, now) {
                Ok(()) if now < cert.expires_at() => {
                    return Ok(Enrollment {
                        trust: host.authority.trust(),
                        expires: grant.expires,
                        certificate: cert.clone(),
                    });
                }
                Ok(()) | Err(Error::CertificateExpired) => {}
                Err(error) => return Err(error),
            }
        } else if grant.redeemed.len() >= grant.options.max_uses {
            return Err(Error::QueueFull);
        }
        if host.members.len() >= max_members {
            return Err(Error::QueueFull);
        }
        let permissions = grant.options.permissions.clone();
        let certificate_lifetime = grant.options.certificate_lifetime;
        let limits = grant.options.limits;
        let grant_expires = grant.expires;
        let memory = budget.reserve(1024)?;
        let cert = host
            .authority
            .issue(
                peer,
                permissions,
                now,
                (now + certificate_lifetime.as_secs()).min(host_expires),
                limits,
            )?
            .metered(budget)?;
        // The owner atomically records admission and the cached reply before returning success.
        host.members.insert(
            cert.id(),
            Member {
                certificate: cert.clone(),
                _memory: Some(memory),
            },
        );
        let previous = host
            .codes
            .get_mut(&id)
            .expect("grant checked above")
            .redeemed
            .insert(peer, cert.clone());
        if let Err(error) = host.persist() {
            host.members.remove(&cert.id());
            let redeemed = &mut host
                .codes
                .get_mut(&id)
                .expect("grant checked above")
                .redeemed;
            match previous {
                Some(previous) => {
                    redeemed.insert(peer, previous);
                }
                None => {
                    redeemed.remove(&peer);
                }
            }
            return Err(error);
        }
        Ok(Enrollment {
            trust: host.authority.trust(),
            expires: grant_expires,
            certificate: cert,
        })
    }
    pub fn prune(&mut self, now: u64) {
        if let Self::Host(host) = self {
            host.codes.retain(|_, g| g.expires > now);
            host.members.retain(|_, m| m.certificate.expires_at() > now);
        }
    }
}

struct Close(Connection);
impl Drop for Close {
    fn drop(&mut self) {
        self.0.close(0u32.into(), b"join completed");
    }
}

/// Metadata supplied only over the connection authenticated by the code's host key.
pub(crate) struct Enrollment {
    pub trust: Trust,
    pub expires: u64,
    pub certificate: Certificate,
}
impl Enrollment {
    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.array(5);
        w.u(2);
        w.bytes(&self.trust.realm_id());
        w.bytes(self.trust.root().as_bytes());
        w.u(self.expires);
        w.bytes(self.certificate.as_bytes());
        w.finish()
    }
    fn decode(bytes: &[u8], peer: EndpointId, expected: Option<&Trust>, now: u64) -> Result<Self> {
        let mut r = Reader::new(bytes);
        r.array(5)?;
        join_version(r.u()?)?;
        let realm = r.fixed()?;
        let root = auth::endpoint(r.fixed()?)?;
        let expires = r.u()?;
        let certificate = Certificate::from_bytes(r.bytes(MAX_CERT)?)?;
        r.end()?;
        let value = Self {
            trust: Trust::new(realm, root),
            expires,
            certificate,
        };
        crate::cbor::canonical(bytes, &value.encode())?;
        // Rejoining must preserve the established authority and realm, including when a
        // restarted host reuses its transport identity. Never replace existing trust here.
        if let Some(trust) = expected
            && (trust.root() != root || trust.realm_id() != realm)
        {
            return Err(Error::Unauthorized);
        }
        if expires <= now {
            return Err(Error::CertificateExpired);
        }
        expected
            .unwrap_or(&value.trust)
            .verify(&value.certificate, peer, now)?;
        Ok(value)
    }
}
fn join_version(version: u64) -> Result<()> {
    if version != 2 {
        return Err(Error::Protocol("join protocol version"));
    }
    Ok(())
}

pub(crate) async fn redeem(
    endpoint: &Endpoint,
    config: &Config,
    code: &JoinCode,
    expected: Option<&Trust>,
) -> Result<Enrollment> {
    timeout(config.handshake_timeout, async {
        let conn = endpoint
            .connect(code.address.clone(), ALPN)
            .await
            .map_err(transport)?;
        let _close = Close(conn.clone());
        // Iroh authenticates this identity during connect, before any secret is sent.
        if conn.remote_id() != code.host_id() {
            return Err(Error::Unauthorized);
        }
        let exchange = async {
            let (mut send, mut recv) = conn.open_bi().await.map_err(transport)?;
            let mut w = Writer::new();
            w.array(3);
            w.u(2);
            w.bytes(&code.id());
            w.bytes(&code.secret);
            wire::write_frame(&mut send, wire::HELLO, &w.finish(), &[]).await?;
            let h = wire::read_header(&mut recv, 0)
                .await?
                .ok_or(Error::PeerUnavailable)?;
            let mut bytes = vec![0; h.metadata];
            recv.read_exact(&mut bytes).await.map_err(transport)?;
            if h.kind == 11 {
                let mut r = Reader::new(&bytes);
                r.array(2)?;
                join_version(r.u()?)?;
                let reason = r.u()?;
                r.end()?;
                let mut expected = Writer::new();
                expected.array(2);
                expected.u(2);
                expected.u(reason);
                crate::cbor::canonical(&bytes, &expected.finish())?;
                return Err(match reason {
                    1 => Error::Unauthorized,
                    2 => Error::QueueFull,
                    _ => Error::Protocol("join rejection reason"),
                });
            }
            if h.kind != wire::READY {
                return Err(Error::Protocol("join response"));
            }
            Enrollment::decode(&bytes, endpoint.id(), expected, auth::now()?)
        }
        .await;
        conn.close(0u32.into(), b"join completed");
        exchange
    })
    .await
    .map_err(|_| Error::Timeout)?
}

pub(crate) async fn serve(conn: Connection, tx: mpsc::Sender<Command>) -> Result<()> {
    let (mut send, mut recv) = conn.accept_bi().await.map_err(transport)?;
    let h = wire::read_header(&mut recv, 0)
        .await?
        .ok_or(Error::PeerUnavailable)?;
    if h.kind != wire::HELLO || h.metadata > 128 {
        return Err(Error::Protocol("join request"));
    }
    let mut bytes = vec![0; h.metadata];
    recv.read_exact(&mut bytes).await.map_err(transport)?;
    let mut r = Reader::new(&bytes);
    r.array(3)?;
    join_version(r.u()?)?;
    let id = r.fixed()?;
    let secret = r.fixed()?;
    r.end()?;
    let mut expected = Writer::new();
    expected.array(3);
    expected.u(2);
    expected.bytes(&id);
    expected.bytes(&secret);
    crate::cbor::canonical(&bytes, &expected.finish())?;
    let (reply, rx) = oneshot::channel();
    tx.send(Command::Enroll {
        peer: conn.remote_id(),
        id,
        secret,
        reply,
    })
    .await
    .map_err(|_| Error::ShuttingDown)?;
    let result = rx.await.map_err(|_| Error::ShuttingDown)?;
    let (kind, bytes) = match result {
        Ok(enrollment) => (wire::READY, enrollment.encode()),
        Err(error) => {
            let mut w = Writer::new();
            w.array(2);
            w.u(2);
            w.u(if error == Error::QueueFull { 2 } else { 1 });
            (11, w.finish())
        }
    };
    wire::write_frame(&mut send, kind, &bytes, &[]).await?;
    send.finish().map_err(transport)?;
    let _ = send.stopped().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    };

    struct TestStorage {
        bytes: Mutex<Vec<u8>>,
        fail: AtomicBool,
    }

    impl HostStorage for TestStorage {
        fn load(&self) -> Result<Option<Vec<u8>>> {
            Ok(Some(self.bytes.lock().unwrap().clone()))
        }

        fn save(&self, bytes: &[u8]) -> Result<()> {
            if self.fail.load(Ordering::Relaxed) {
                return Err(Error::Io("test storage failure".into()));
            }
            *self.bytes.lock().unwrap() = bytes.to_vec();
            Ok(())
        }
    }

    #[test]
    fn application_storage_rolls_back_failed_grants_revocations_and_enrollments() {
        let storage = Arc::new(TestStorage {
            bytes: Mutex::new(generate_host_state()),
            fail: AtomicBool::new(false),
        });
        let mut admission = Admission::with_storage(storage.clone()).unwrap();
        let identity = Identity::generate();
        assert_eq!(
            Identity::from_bytes(&identity.to_bytes()).endpoint_id(),
            identity.endpoint_id()
        );
        let address = EndpointAddr::new(identity.endpoint_id())
            .with_ip_addr("127.0.0.1:42000".parse().unwrap());
        let options = JoinOptions::new(vec![Permission::publish("jobs").unwrap()]);
        let budget = Budget::new(1024 * 1024);
        let now = auth::now().unwrap();
        storage.fail.store(true, Ordering::Relaxed);
        assert!(
            admission
                .issue(options.clone(), address.clone(), now, &budget, 1)
                .is_err()
        );
        storage.fail.store(false, Ordering::Relaxed);
        // A failed issuance must not consume the only grant slot.
        let code = admission.issue(options, address, now, &budget, 1).unwrap();
        let trust = admission.authority().unwrap().trust();
        let peer = Identity::generate().endpoint_id();
        storage.fail.store(true, Ordering::Relaxed);
        assert!(admission.revoke_code(code.id()).is_err());
        for _ in 0..2 {
            // Retrying a failed enrollment must not return an uncommitted cached certificate.
            assert!(matches!(
                admission.enroll(
                    peer,
                    code.id(),
                    code.secret,
                    now,
                    now + 3600,
                    &trust,
                    &budget,
                    1
                ),
                Err(Error::Io(_))
            ));
        }
        storage.fail.store(false, Ordering::Relaxed);
        let enrolled = admission
            .enroll(
                peer,
                code.id(),
                code.secret,
                now,
                now + 3600,
                &trust,
                &budget,
                1,
            )
            .unwrap();
        let resumed = Admission::with_storage(storage.clone()).unwrap();
        assert!(resumed.check(peer, &enrolled.certificate).is_ok());
        storage.fail.store(true, Ordering::Relaxed);
        // Already committed enrollments can still return their durable cached reply.
        assert!(
            admission
                .enroll(
                    peer,
                    code.id(),
                    code.secret,
                    now,
                    now + 3600,
                    &trust,
                    &budget,
                    1
                )
                .is_ok()
        );
    }

    #[test]
    fn application_storage_rejects_invalid_state_without_replacing_it() {
        let storage = Arc::new(TestStorage {
            bytes: Mutex::new(vec![0]),
            fail: AtomicBool::new(false),
        });
        assert!(Admission::with_storage(storage.clone()).is_err());
        assert_eq!(*storage.bytes.lock().unwrap(), vec![0]);
    }

    #[test]
    fn service_credentials_allow_ten_years_but_not_longer() {
        let permissions = vec![Permission::publish("service").unwrap()];
        let mut options = JoinOptions::new(permissions);
        options.lifetime = MAX_JOIN_LIFETIME;
        options.certificate_lifetime = MAX_JOIN_LIFETIME;
        assert!(options.validate().is_ok());
        options.lifetime += Duration::from_secs(1);
        assert!(options.validate().is_err());
    }

    #[test]
    fn independent_join_code_fixture_matches_the_public_encoding() {
        let bytes: Vec<u8> = include_str!("../tests/fixtures/join.hex")
            .trim()
            .as_bytes()
            .chunks_exact(2)
            .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect();
        let encoded = format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(&bytes));
        let fixture = JoinCode::decode(&encoded).unwrap();
        let expected = JoinCode {
            address: EndpointAddr::new(iroh::SecretKey::from_bytes(&[2; 32]).public())
                .with_ip_addr("127.0.0.1:42000".parse().unwrap()),
            secret: [9; 32],
        };
        assert_eq!(expected.encode().unwrap(), encoded);
        // Independently calculated with Python hashlib and the protocol domain string.
        assert_eq!(
            fixture.id(),
            [
                207, 105, 51, 178, 72, 186, 118, 171, 10, 128, 224, 144, 54, 130, 35, 245
            ]
        );
    }
    fn sample(address: EndpointAddr) -> JoinCode {
        JoinCode {
            address,
            secret: [9; 32],
        }
    }

    #[test]
    fn relay_codes_stay_short_regardless_of_interface_count() {
        let host = iroh::SecretKey::from_bytes(&[2; 32]).public();
        let relay = "https://usw1-1.relay.n0.iroh.link./".parse().unwrap();
        let mut address = EndpointAddr::new(host).with_relay_url(relay);
        for ip in [
            "10.0.0.77:63439",
            "67.183.197.72:63439",
            "192.168.193.219:63439",
            "[2601:602:8c01:2b20::c571]:49431",
            "[2601:602:8c01:2b20:be:1463:f747:230b]:49431",
            "[2601:602:8c01:2b20:9ce8:9f58:a0c8:31ea]:49431",
        ] {
            address = address.with_ip_addr(ip.parse().unwrap());
        }
        let code = sample(address);
        let encoded = code.encode().unwrap();
        // Includes URI prefix, pinned host, relay URL, and full 256-bit secret.
        assert_eq!(encoded.len(), 161);
        let decoded = JoinCode::decode(&encoded).unwrap();
        assert_eq!(decoded.address, compact_address(&code.address));
        assert_eq!(decoded.address.ip_addrs().count(), 0);
        assert_eq!(decoded.id(), code.id());
    }

    #[test]
    fn direct_codes_preserve_ipv4_ipv6_ports_and_scopes() {
        let host = iroh::SecretKey::from_bytes(&[2; 32]).public();
        let address = EndpointAddr::new(host).with_ip_addr("192.168.1.20:42000".parse().unwrap());
        let code = sample(address.clone());
        assert_eq!(code.encode().unwrap().len(), 121);
        assert_eq!(
            JoinCode::decode(&code.encode().unwrap()).unwrap().address,
            address
        );
        let address = address
            .with_ip_addr("[2601:602:8c01:2b20::c571]:49431".parse().unwrap())
            .with_ip_addr(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::LOCALHOST,
                1234,
                7,
                9,
            )));
        let code = sample(address.clone());
        assert_eq!(
            JoinCode::decode(&code.encode().unwrap()).unwrap().address,
            address
        );
    }

    #[test]
    fn malformed_routes_and_legacy_codes_are_rejected() {
        let host = iroh::SecretKey::from_bytes(&[2; 32]).public();
        let code = sample(EndpointAddr::new(host));
        let encoded_with_routes = |version, routes: &[u8]| {
            let mut w = Writer::new();
            w.array(4);
            w.u(version);
            w.bytes(host.as_bytes());
            let mut bytes = w.finish();
            bytes.extend_from_slice(routes);
            let mut w = Writer::new();
            w.bytes(&code.secret);
            bytes.extend_from_slice(&w.finish());
            format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes))
        };
        // Empty, unknown type, short IPv4, short IPv6, invalid URL, and indefinite list.
        for routes in [
            &[0x80][..],
            &[0x81, 0x82, 3, 0x40],
            &[0x81, 0x82, 0, 0x41, 0],
            &[0x81, 0x82, 1, 0x41, 0],
            &[0x81, 0x82, 2, 0x61, b'?'],
            &[0x9f, 0xff],
        ] {
            assert!(JoinCode::decode(&encoded_with_routes(3, routes)).is_err());
        }
        let route = [0x81, 0x82, 0, 0x46, 127, 0, 0, 1, 0xa4, 0x10];
        for version in [1, 2, 4] {
            assert!(JoinCode::decode(&encoded_with_routes(version, &route)).is_err());
        }
        let mut duplicate = vec![0x82];
        duplicate.extend_from_slice(&route[1..]);
        duplicate.extend_from_slice(&route[1..]);
        assert!(JoinCode::decode(&encoded_with_routes(3, &duplicate)).is_err());
        let mut too_many = vec![0x91];
        for _ in 0..17 {
            too_many.extend_from_slice(&route[1..]);
        }
        assert!(JoinCode::decode(&encoded_with_routes(3, &too_many)).is_err());
    }

    fn bootstrap_fixture() -> Vec<u8> {
        include_str!("../tests/fixtures/join_bootstrap.hex")
            .trim()
            .as_bytes()
            .chunks_exact(2)
            .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn authenticated_bootstrap_verifies_certificate_and_expiry() {
        let bytes = bootstrap_fixture();
        let peer = iroh::SecretKey::from_bytes(&[2; 32]).public();
        let enrolled = Enrollment::decode(&bytes, peer, None, 110).unwrap();
        assert_eq!(enrolled.encode(), bytes);
        assert_eq!(
            enrolled.trust.root(),
            iroh::SecretKey::from_bytes(&[1; 32]).public()
        );
        assert_eq!(enrolled.trust.realm_id(), [3; 16]);
        assert_eq!(enrolled.expires, 180);
        assert!(matches!(
            Enrollment::decode(&bytes, Identity::generate().endpoint_id(), None, 110),
            Err(Error::Unauthorized)
        ));
        assert!(matches!(
            Enrollment::decode(&bytes, peer, None, 180),
            Err(Error::CertificateExpired)
        ));
        assert!(matches!(
            Enrollment::decode(&bytes, peer, None, 99),
            Err(Error::CertificateExpired)
        ));
        let wrong_root = Enrollment {
            trust: Trust::new([3; 16], Identity::generate().endpoint_id()),
            ..enrolled
        };
        assert!(matches!(
            Enrollment::decode(&wrong_root.encode(), peer, None, 110),
            Err(Error::InvalidSignature)
        ));
        let wrong_realm = Enrollment {
            trust: Trust::new([4; 16], iroh::SecretKey::from_bytes(&[1; 32]).public()),
            ..wrong_root
        };
        assert!(matches!(
            Enrollment::decode(&wrong_realm.encode(), peer, None, 110),
            Err(Error::Unauthorized)
        ));
    }

    #[test]
    fn bootstrap_cannot_replace_existing_trust_or_bypass_revocation() {
        let bytes = bootstrap_fixture();
        let peer = iroh::SecretKey::from_bytes(&[2; 32]).public();
        let enrolled = Enrollment::decode(&bytes, peer, None, 110).unwrap();
        assert!(Enrollment::decode(&bytes, peer, Some(&enrolled.trust), 110).is_ok());
        for expected in [
            Trust::new([4; 16], enrolled.trust.root()),
            Trust::new([3; 16], Identity::generate().endpoint_id()),
        ] {
            assert!(matches!(
                Enrollment::decode(&bytes, peer, Some(&expected), 110),
                Err(Error::Unauthorized)
            ));
        }
        let mut revoked = enrolled.trust;
        revoked.deny_certificate(enrolled.certificate.id()).unwrap();
        assert!(matches!(
            Enrollment::decode(&bytes, peer, Some(&revoked), 110),
            Err(Error::Unauthorized)
        ));
    }

    #[test]
    fn bootstrap_rejects_truncation_legacy_versions_and_noncanonical_cbor() {
        let bytes = bootstrap_fixture();
        let peer = iroh::SecretKey::from_bytes(&[2; 32]).public();
        for end in 0..bytes.len() {
            assert!(Enrollment::decode(&bytes[..end], peer, None, 110).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(Enrollment::decode(&trailing, peer, None, 110).is_err());
        let mut version = bytes.clone();
        version[1] = 1;
        assert!(Enrollment::decode(&version, peer, None, 110).is_err());
        let mut noncanonical = vec![bytes[0], 0x18, 2];
        noncanonical.extend_from_slice(&bytes[2..]);
        assert!(Enrollment::decode(&noncanonical, peer, None, 110).is_err());
        let mut indefinite = bytes.clone();
        indefinite[0] = 0x9f;
        indefinite.push(0xff);
        assert!(Enrollment::decode(&indefinite, peer, None, 110).is_err());
    }

    #[tokio::test]
    async fn codes_are_canonical_bounded_redacted_and_secret_authenticated() {
        let mut settings = Config::new();
        settings.relay_mode = RelayMode::Disabled;
        settings.bind_addr = Some("127.0.0.1:0".parse().unwrap());
        let host = MessagingEndpoint::host(settings.clone(), Identity::generate(), vec![])
            .await
            .unwrap();
        let code = host
            .issue_join_code(JoinOptions::new(vec![]))
            .await
            .unwrap();
        let encoded = code.encode().unwrap();
        assert_eq!(
            JoinCode::decode(&encoded).unwrap().encode().unwrap(),
            encoded
        );
        assert!(!format!("{code:?}").contains(&URL_SAFE_NO_PAD.encode(code.secret)));
        assert!(JoinCode::decode(encoded.strip_prefix(PREFIX).unwrap()).is_err());
        assert!(JoinCode::decode(&format!("{encoded}=")).is_err());
        assert!(JoinCode::decode(&"x".repeat(32769)).is_err());
        let mut raw = URL_SAFE_NO_PAD
            .decode(encoded.strip_prefix(PREFIX).unwrap())
            .unwrap();
        raw.push(0);
        assert!(JoinCode::decode(&format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(raw))).is_err());
        let mut bad_secret = code.clone();
        bad_secret.secret[0] ^= 1;
        assert!(matches!(
            MessagingEndpoint::join(settings.clone(), Identity::generate(), &bad_secret).await,
            Err(Error::Unauthorized)
        ));
        let mut wrong_host = code.clone();
        wrong_host.address.id = Identity::generate().endpoint_id();
        let mut short_timeout = settings.clone();
        short_timeout.handshake_timeout = Duration::from_secs(1);
        assert!(
            MessagingEndpoint::join(short_timeout, Identity::generate(), &wrong_host)
                .await
                .is_err()
        );
        host.shutdown(ShutdownMode::Immediate).await.unwrap();
        assert!(
            MessagingEndpoint::join(settings, Identity::generate(), &code)
                .await
                .is_err()
        );
    }
}
