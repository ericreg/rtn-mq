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
use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
    sync::Arc,
    time::Duration,
};
use tokio::{
    sync::{mpsc, oneshot},
    time::timeout,
};
pub(crate) const ALPN: &[u8] = b"iroh-mq/join/2";
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
    ) -> Result<Enrollment> {
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
        Ok(Enrollment {
            trust: host.authority.trust(),
            expires: grant.expires,
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
