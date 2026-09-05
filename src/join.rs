//! Reusable bearer-code enrollment, serialized by the messaging endpoint owner.
use crate::{
    auth::{self, MAX_CERT, MAX_PERMISSIONS},
    buffer::{Budget, Permit},
    cbor::{Reader, Writer},
    endpoint::{EndpointConfig, owner::Command},
    error::transport,
    message::digest,
    wire, *,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use iroh::{Endpoint, EndpointAddr, endpoint::Connection};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tokio::{
    sync::{mpsc, oneshot},
    time::timeout,
};
pub(crate) const ALPN: &[u8] = b"iroh-mq/join/1";
const PREFIX: &str = "rtn-mq://join/";

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
            || self.lifetime > Duration::from_secs(86400)
            || self.certificate_lifetime.as_secs() == 0
            || self.certificate_lifetime > Duration::from_secs(86400)
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
    realm: RealmId,
    root: EndpointId,
    pub(crate) address: EndpointAddr,
    id: [u8; 16],
    expires: u64,
    secret: [u8; 32],
}
impl std::fmt::Debug for JoinCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JoinCode")
            .field("host", &self.host_id())
            .field("expires", &self.expires)
            .finish_non_exhaustive()
    }
}
impl JoinCode {
    pub fn id(&self) -> [u8; 16] {
        self.id
    }
    pub fn expires_at(&self) -> u64 {
        self.expires
    }
    pub fn host_id(&self) -> EndpointId {
        self.address.id
    }
    pub fn realm_id(&self) -> RealmId {
        self.realm
    }
    pub fn authority(&self) -> EndpointId {
        self.root
    }
    pub(crate) fn trust(&self) -> Trust {
        Trust::new(self.realm, self.root)
    }
    pub fn encode(&self) -> Result<String> {
        let addresses: Vec<String> = self
            .address
            .ip_addrs()
            .map(|a| format!("ip:{a}"))
            .chain(self.address.relay_urls().map(|a| format!("relay:{a}")))
            .collect();
        if addresses.len() > 16 {
            return Err(Error::MessageTooLarge);
        }
        let mut w = Writer::new();
        w.array(8);
        w.u(1);
        w.bytes(&self.realm);
        w.bytes(self.root.as_bytes());
        w.bytes(self.address.id.as_bytes());
        w.array(addresses.len());
        for address in addresses {
            if address.len() > 1024 {
                return Err(Error::MessageTooLarge);
            }
            w.text(&address);
        }
        w.bytes(&self.id);
        w.u(self.expires);
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
        r.array(8)?;
        auth::version(r.u()?)?;
        let realm = r.fixed()?;
        let root = auth::endpoint(r.fixed()?)?;
        let mut address = EndpointAddr::new(auth::endpoint(r.fixed()?)?);
        for _ in 0..r.list(16)? {
            let a = r.text(1024)?;
            if let Some(ip) = a.strip_prefix("ip:") {
                address = address
                    .with_ip_addr(ip.parse().map_err(|_| Error::Protocol("join IP address"))?);
            } else if let Some(relay) = a.strip_prefix("relay:") {
                address = address.with_relay_url(
                    relay
                        .parse()
                        .map_err(|_| Error::Protocol("join relay address"))?,
                );
            } else {
                return Err(Error::Protocol("join address type"));
            }
        }
        let id = r.fixed()?;
        let expires = r.u()?;
        let secret = r.fixed()?;
        r.end()?;
        let value = Self {
            realm,
            root,
            address,
            id,
            expires,
            secret,
        };
        if value.encode()? != code {
            return Err(Error::Protocol("noncanonical join code"));
        }
        Ok(value)
    }
}

struct Grant {
    hash: [u8; 32],
    expires: u64,
    options: JoinOptions,
    redeemed: BTreeMap<EndpointId, Certificate>,
    _memory: Permit,
}
struct Member {
    certificate: Certificate,
    _memory: Permit,
}
pub(crate) enum Admission {
    Host(Box<Host>),
    Client(EndpointId),
}
pub(crate) struct Host {
    authority: Authority,
    codes: BTreeMap<[u8; 16], Grant>,
    members: BTreeMap<[u8; 16], Member>,
}
impl Admission {
    pub fn host(authority: Authority) -> Self {
        Self::Host(Box::new(Host {
            authority,
            codes: BTreeMap::new(),
            members: BTreeMap::new(),
        }))
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
        let id = rand::random();
        let secret: [u8; 32] = rand::random();
        let expires = now + options.lifetime.as_secs();
        let code = JoinCode {
            realm: host.authority.realm_id(),
            root: host.authority.public_key(),
            address,
            id,
            expires,
            secret,
        };
        code.encode()?;
        host.codes.insert(
            id,
            Grant {
                hash: digest(&secret),
                expires,
                options,
                redeemed: BTreeMap::new(),
                _memory: memory,
            },
        );
        Ok(code)
    }
    pub fn revoke_code(&mut self, id: [u8; 16]) -> Result<()> {
        let Self::Host(host) = self else {
            return Err(Error::Unauthorized);
        };
        host.codes.remove(&id);
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
    ) -> Result<Certificate> {
        let Self::Host(host) = self else {
            return Err(Error::Unauthorized);
        };
        host.members
            .retain(|_, member| member.certificate.expires_at() > now);
        let grant = host.codes.get_mut(&id).ok_or(Error::Unauthorized)?;
        if grant.expires <= now || grant.hash != digest(&secret) {
            return Err(Error::Unauthorized);
        }
        if let Some(cert) = grant.redeemed.get(&peer) {
            match trust.check(cert, peer, now) {
                Ok(()) if now < cert.expires_at() => return Ok(cert.clone()),
                Ok(()) | Err(Error::CertificateExpired) => {}
                Err(error) => return Err(error),
            }
        } else if grant.redeemed.len() >= grant.options.max_uses {
            return Err(Error::QueueFull);
        }
        if host.members.len() >= max_members {
            return Err(Error::QueueFull);
        }
        let memory = budget.reserve(1024)?;
        let cert = host
            .authority
            .issue(
                peer,
                grant.options.permissions.clone(),
                now,
                (now + grant.options.certificate_lifetime.as_secs()).min(host_expires),
                grant.options.limits,
            )?
            .metered(budget)?;
        // The owner atomically records admission and the cached reply before returning success.
        host.members.insert(
            cert.id(),
            Member {
                certificate: cert.clone(),
                _memory: memory,
            },
        );
        grant.redeemed.insert(peer, cert.clone());
        Ok(cert)
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

pub(crate) async fn redeem(
    endpoint: &Endpoint,
    config: &EndpointConfig,
    code: &JoinCode,
) -> Result<Certificate> {
    if code.expires <= auth::now()? {
        return Err(Error::CertificateExpired);
    }
    timeout(config.handshake_timeout, async {
        let conn = endpoint
            .connect(code.address.clone(), ALPN)
            .await
            .map_err(transport)?;
        let _close = Close(conn.clone());
        let exchange = async {
            let (mut send, mut recv) = conn.open_bi().await.map_err(transport)?;
            let mut w = Writer::new();
            w.array(3);
            w.u(1);
            w.bytes(&code.id);
            w.bytes(&code.secret);
            wire::write_frame(&mut send, wire::HELLO, &w.finish(), &[]).await?;
            let h = wire::read_header(&mut recv, 0)
                .await?
                .ok_or(Error::PeerUnavailable)?;
            let mut bytes = vec![0; h.metadata];
            recv.read_exact(&mut bytes).await.map_err(transport)?;
            let mut r = Reader::new(&bytes);
            r.array(2)?;
            auth::version(r.u()?)?;
            if h.kind == 11 {
                let code = r.u()?;
                r.end()?;
                let mut expected = Writer::new();
                expected.array(2);
                expected.u(1);
                expected.u(code);
                crate::cbor::canonical(&bytes, &expected.finish())?;
                return Err(if code == 2 {
                    Error::QueueFull
                } else {
                    Error::Unauthorized
                });
            }
            if h.kind != wire::READY {
                return Err(Error::Protocol("join response"));
            }
            let cert = Certificate::from_bytes(r.bytes(MAX_CERT)?)?;
            r.end()?;
            let mut expected = Writer::new();
            expected.array(2);
            expected.u(1);
            expected.bytes(cert.as_bytes());
            crate::cbor::canonical(&bytes, &expected.finish())?;
            config.trust.verify(&cert, endpoint.id(), auth::now()?)?;
            Ok(cert)
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
    auth::version(r.u()?)?;
    let id = r.fixed()?;
    let secret = r.fixed()?;
    r.end()?;
    let mut expected = Writer::new();
    expected.array(3);
    expected.u(1);
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
    let mut w = Writer::new();
    w.array(2);
    w.u(1);
    let kind = match result {
        Ok(cert) => {
            w.bytes(cert.as_bytes());
            wire::READY
        }
        Err(error) => {
            w.u(if error == Error::QueueFull { 2 } else { 1 });
            11
        }
    };
    wire::write_frame(&mut send, kind, &w.finish(), &[]).await?;
    send.finish().map_err(transport)?;
    let _ = send.stopped().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
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
            realm: [3; 16],
            root: iroh::SecretKey::from_bytes(&[1; 32]).public(),
            address: EndpointAddr::new(iroh::SecretKey::from_bytes(&[2; 32]).public())
                .with_ip_addr("127.0.0.1:42000".parse().unwrap()),
            id: [4; 16],
            expires: 200,
            secret: [9; 32],
        };
        assert_eq!(expected.encode().unwrap(), encoded);
        assert_eq!(fixture.id(), [4; 16]);
        assert_eq!(fixture.expires_at(), 200);
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
        let mut bad_root = code.clone();
        bad_root.root = Identity::generate().endpoint_id();
        assert!(matches!(
            MessagingEndpoint::join(settings.clone(), Identity::generate(), &bad_root).await,
            Err(Error::InvalidSignature)
        ));
        host.shutdown(ShutdownMode::Immediate).await.unwrap();
        assert!(
            MessagingEndpoint::join(settings, Identity::generate(), &code)
                .await
                .is_err()
        );
    }
}
