use crate::{
    Error, Identity, Result, Topic,
    cbor::{Reader, Writer, canonical},
};
use iroh::{EndpointId, SecretKey, Signature};
use std::{collections::BTreeSet, sync::Arc};

pub type RealmId = [u8; 16];
pub(crate) const MAX_CERT: usize = 15 * 1024;
pub(crate) const MAX_PERMISSIONS: usize = 256;
const CERT_CONTEXT: &[u8] = b"iroh-mq/certificate/v1";
const REVOCATION_CONTEXT: &[u8] = b"iroh-mq/revocation/v1";
// COSE protected map {1: -8}: EdDSA, restricted by this profile to Ed25519 keys.
const PROTECTED: &[u8] = &[0xa1, 0x01, 0x27];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Permission {
    pub topic: Topic,
    pub publish: bool,
    pub subscribe: bool,
}
impl Permission {
    pub fn publish(topic: impl AsRef<str>) -> Result<Self> {
        Ok(Self {
            topic: Topic::new(topic)?,
            publish: true,
            subscribe: false,
        })
    }
    pub fn subscribe(topic: impl AsRef<str>) -> Result<Self> {
        Ok(Self {
            topic: Topic::new(topic)?,
            publish: false,
            subscribe: true,
        })
    }
    pub fn both(topic: impl AsRef<str>) -> Result<Self> {
        Ok(Self {
            topic: Topic::new(topic)?,
            publish: true,
            subscribe: true,
        })
    }
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CertificateLimits {
    /// Zero means no additional certificate ceiling.
    pub max_payload: u64,
    /// Zero means no additional certificate ceiling.
    pub max_subscriptions: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Claims {
    pub realm: RealmId,
    pub issuer: EndpointId,
    pub id: [u8; 16],
    pub subject: EndpointId,
    pub not_before: u64,
    pub expires: u64,
    pub permissions: Vec<Permission>,
    pub limits: CertificateLimits,
}
impl Claims {
    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.array(9);
        w.u(1);
        w.bytes(&self.realm);
        w.bytes(self.issuer.as_bytes());
        w.bytes(&self.id);
        w.bytes(self.subject.as_bytes());
        w.u(self.not_before);
        w.u(self.expires);
        w.array(self.permissions.len());
        for p in &self.permissions {
            w.array(2);
            w.text(p.topic.as_str());
            w.u(u64::from(p.publish) | (u64::from(p.subscribe) << 1));
        }
        w.array(2);
        w.u(self.limits.max_payload);
        w.u(self.limits.max_subscriptions);
        w.finish()
    }
    fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b);
        r.array(9)?;
        version(r.u()?)?;
        let realm = r.fixed()?;
        let issuer = endpoint(r.fixed()?)?;
        let id = r.fixed()?;
        let subject = endpoint(r.fixed()?)?;
        let not_before = r.u()?;
        let expires = r.u()?;
        let count = r.list(MAX_PERMISSIONS)?;
        let mut permissions = Vec::with_capacity(count);
        for _ in 0..count {
            r.array(2)?;
            let topic = Topic::new(r.text(256)?)?;
            let mask = r.u()?;
            if !(1..=3).contains(&mask) {
                return Err(Error::Protocol("permission mask"));
            }
            permissions.push(Permission {
                topic,
                publish: mask & 1 != 0,
                subscribe: mask & 2 != 0,
            });
        }
        r.array(2)?;
        let limits = CertificateLimits {
            max_payload: r.u()?,
            max_subscriptions: r.u()?,
        };
        r.end()?;
        let c = Self {
            realm,
            issuer,
            id,
            subject,
            not_before,
            expires,
            permissions,
            limits,
        };
        c.validate()?;
        canonical(b, &c.encode())?;
        Ok(c)
    }
    fn validate(&self) -> Result<()> {
        if self.not_before >= self.expires || self.permissions.len() > MAX_PERMISSIONS {
            return Err(Error::Protocol("certificate claims"));
        }
        let mut previous: Option<&Topic> = None;
        for p in &self.permissions {
            if (!p.publish && !p.subscribe) || previous.is_some_and(|v| v >= &p.topic) {
                return Err(Error::Protocol("permissions must be unique and sorted"));
            }
            previous = Some(&p.topic);
        }
        Ok(())
    }
}
#[derive(Debug, Clone)]
pub struct Certificate {
    pub(crate) claims: Arc<Claims>,
    bytes: Arc<[u8]>,
    _memory: Option<Arc<crate::buffer::Permit>>,
}
impl Certificate {
    /// Parses the bounded wire profile. Trust is established by `Trust::verify`, not parsing.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let (payload, _) = parse_cose(b, MAX_CERT)?;
        Ok(Self {
            claims: Arc::new(Claims::decode(payload)?),
            bytes: b.into(),
            _memory: None,
        })
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub(crate) fn metered(mut self, budget: &Arc<crate::buffer::Budget>) -> Result<Self> {
        // Charge the encoded container, parsed claims, permission allocations and their descriptors.
        self._memory = Some(Arc::new(budget.reserve(self.bytes.len() * 4 + 16 * 1024)?));
        Ok(self)
    }
    pub fn endpoint_id(&self) -> EndpointId {
        self.claims.subject
    }
    pub fn id(&self) -> [u8; 16] {
        self.claims.id
    }
    pub fn expires_at(&self) -> u64 {
        self.claims.expires
    }
    pub fn permissions(&self) -> &[Permission] {
        &self.claims.permissions
    }
    pub fn limits(&self) -> CertificateLimits {
        self.claims.limits
    }
    pub(crate) fn allows(&self, topic: &Topic, publish: bool) -> bool {
        self.claims
            .permissions
            .iter()
            .any(|p| &p.topic == topic && if publish { p.publish } else { p.subscribe })
    }
}
/// Offline authority. Its signing key is never used as a messaging/enrollment transport key automatically.
pub struct Authority {
    key: SecretKey,
    realm: RealmId,
}
impl Authority {
    pub fn generate() -> Self {
        Self {
            key: SecretKey::generate(),
            realm: rand::random(),
        }
    }
    pub fn from_identity(identity: Identity, realm: RealmId) -> Self {
        Self {
            key: identity.0,
            realm,
        }
    }
    pub fn realm_id(&self) -> RealmId {
        self.realm
    }
    pub fn public_key(&self) -> EndpointId {
        self.key.public()
    }
    pub fn trust(&self) -> Trust {
        Trust::new(self.realm, self.public_key())
    }
    pub fn issue(
        &self,
        subject: EndpointId,
        mut permissions: Vec<Permission>,
        not_before: u64,
        expires_at: u64,
        limits: CertificateLimits,
    ) -> Result<Certificate> {
        permissions.sort_by(|a, b| a.topic.cmp(&b.topic));
        let c = Claims {
            realm: self.realm,
            issuer: self.public_key(),
            id: rand::random(),
            subject,
            not_before,
            expires: expires_at,
            permissions,
            limits,
        };
        c.validate()?;
        let bytes = sign_cose(&c.encode(), &self.key, CERT_CONTEXT);
        Certificate::from_bytes(&bytes)
    }
    pub fn revocations(
        &self,
        version: u64,
        issued_at: u64,
        expires_at: u64,
        certificate_ids: Vec<[u8; 16]>,
    ) -> Result<RevocationSnapshot> {
        let mut ids = certificate_ids;
        ids.sort();
        ids.dedup();
        if ids.len() > 4096 || issued_at >= expires_at || version == 0 {
            return Err(Error::Config("revocation snapshot"));
        }
        let mut w = Writer::new();
        w.array(6);
        w.u(1);
        w.bytes(&self.realm);
        w.u(version);
        w.u(issued_at);
        w.u(expires_at);
        w.array(ids.len());
        for id in ids {
            w.bytes(&id);
        }
        Ok(RevocationSnapshot(sign_cose(
            &w.finish(),
            &self.key,
            REVOCATION_CONTEXT,
        )))
    }
}
impl Default for Authority {
    fn default() -> Self {
        Self::generate()
    }
}
#[derive(Clone, Debug)]
pub struct RevocationSnapshot(Vec<u8>);
impl RevocationSnapshot {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        parse_cose(bytes, 128 * 1024)?;
        Ok(Self(bytes.to_vec()))
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
#[derive(Clone, Debug)]
pub struct Trust {
    pub(crate) realm: RealmId,
    pub(crate) root: EndpointId,
    revoked: BTreeSet<[u8; 16]>,
    version: u64,
    freshness: Option<u64>,
    /// Allowed certificate clock skew, in seconds. Default: zero.
    pub clock_skew_secs: u64,
}
impl Trust {
    pub fn new(realm: RealmId, root: EndpointId) -> Self {
        Self {
            realm,
            root,
            revoked: BTreeSet::new(),
            version: 0,
            freshness: None,
            clock_skew_secs: 0,
        }
    }
    pub fn realm_id(&self) -> RealmId {
        self.realm
    }
    pub fn root(&self) -> EndpointId {
        self.root
    }
    pub(crate) fn revoked_count(&self) -> usize {
        self.revoked.len()
    }
    pub fn revocation_version(&self) -> u64 {
        self.version
    }
    pub fn deny_certificate(&mut self, id: [u8; 16]) -> Result<()> {
        if self.revoked.len() >= 4096 && !self.revoked.contains(&id) {
            return Err(Error::QueueFull);
        }
        self.revoked.insert(id);
        Ok(())
    }
    /// Monotonic within this Trust instance. Persist the version externally when rollback resistance is required.
    pub fn apply_revocations(&mut self, snapshot: &RevocationSnapshot, now: u64) -> Result<()> {
        let b = verify_cose(&snapshot.0, self.root, REVOCATION_CONTEXT, 128 * 1024)?;
        let mut r = Reader::new(b);
        r.array(6)?;
        version(r.u()?)?;
        if r.fixed::<16>()? != self.realm {
            return Err(Error::Unauthorized);
        }
        let v = r.u()?;
        let issued = r.u()?;
        let expires = r.u()?;
        if v <= self.version || issued > now || now >= expires || issued >= expires {
            return Err(Error::Unauthorized);
        }
        let n = r.list(4096)?;
        let mut ids = BTreeSet::new();
        let mut w = Writer::new();
        w.array(6);
        w.u(1);
        w.bytes(&self.realm);
        w.u(v);
        w.u(issued);
        w.u(expires);
        w.array(n);
        for _ in 0..n {
            let id = r.fixed()?;
            ids.insert(id);
            w.bytes(&id);
        }
        r.end()?;
        canonical(b, &w.finish())?;
        // Revocations are cumulative: a new snapshot cannot undo an accepted denial.
        ids.extend(self.revoked.iter().copied());
        if ids.len() > 4096 {
            return Err(Error::QueueFull);
        }
        self.revoked = ids;
        self.version = v;
        self.freshness = Some(expires);
        Ok(())
    }
    pub fn verify(
        &self,
        certificate: &Certificate,
        authenticated_peer: EndpointId,
        now: u64,
    ) -> Result<()> {
        verify_cose(certificate.as_bytes(), self.root, CERT_CONTEXT, MAX_CERT)?;
        self.check(certificate, authenticated_peer, now)
    }
    pub(crate) fn check(&self, c: &Certificate, peer: EndpointId, now: u64) -> Result<()> {
        if c.claims.realm != self.realm
            || c.claims.issuer != self.root
            || c.claims.subject != peer
            || self.revoked.contains(&c.id())
        {
            return Err(Error::Unauthorized);
        }
        if now.saturating_add(self.clock_skew_secs) < c.claims.not_before
            || now >= c.claims.expires.saturating_add(self.clock_skew_secs)
        {
            return Err(Error::CertificateExpired);
        }
        if self.freshness.is_some_and(|deadline| now >= deadline) {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
}
pub(crate) fn endpoint(b: [u8; 32]) -> Result<EndpointId> {
    EndpointId::from_bytes(&b).map_err(|_| Error::Protocol("invalid endpoint key"))
}
pub(crate) fn version(v: u64) -> Result<()> {
    if v != 1 {
        Err(Error::Protocol("unsupported version"))
    } else {
        Ok(())
    }
}
fn signing_bytes(payload: &[u8], context: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.array(4);
    w.text("Signature1");
    w.bytes(PROTECTED);
    w.bytes(context);
    w.bytes(payload);
    w.finish()
}
fn cose(payload: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.array(4);
    w.bytes(PROTECTED);
    w.empty_map();
    w.bytes(payload);
    w.bytes(signature);
    w.finish()
}
pub(crate) fn sign_cose(payload: &[u8], key: &SecretKey, context: &[u8]) -> Vec<u8> {
    cose(
        payload,
        &key.sign(&signing_bytes(payload, context)).to_bytes(),
    )
}
fn parse_cose(bytes: &[u8], max: usize) -> Result<(&[u8], [u8; 64])> {
    if bytes.len() > max {
        return Err(Error::MessageTooLarge);
    }
    let mut r = Reader::new(bytes);
    r.array(4)?;
    if r.bytes(3)? != PROTECTED {
        return Err(Error::Protocol("unsupported COSE protected headers"));
    }
    r.empty_map()?;
    let payload = r.bytes(max)?;
    let signature = r.fixed()?;
    r.end()?;
    canonical(bytes, &cose(payload, &signature))?;
    Ok((payload, signature))
}
pub(crate) fn verify_cose<'a>(
    bytes: &'a [u8],
    key: EndpointId,
    context: &[u8],
    max: usize,
) -> Result<&'a [u8]> {
    let (payload, signature) = parse_cose(bytes, max)?;
    key.verify(
        &signing_bytes(payload, context),
        &Signature::from_bytes(&signature),
    )
    .map_err(|_| Error::InvalidSignature)?;
    Ok(payload)
}
pub(crate) fn now() -> Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| Error::Clock)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn certificate() -> (Authority, Identity, Certificate) {
        let a = Authority::generate();
        let i = Identity::generate();
        let c = a
            .issue(
                i.endpoint_id(),
                vec![Permission::both("jobs").unwrap()],
                100,
                200,
                CertificateLimits::default(),
            )
            .unwrap();
        (a, i, c)
    }
    #[test]
    fn authorization_rejects_wrong_root_realm_subject_time_and_revocation() {
        let (a, i, c) = certificate();
        let mut t = a.trust();
        t.verify(&c, i.endpoint_id(), 100).unwrap();
        assert_eq!(
            t.verify(&c, i.endpoint_id(), 99),
            Err(Error::CertificateExpired)
        );
        assert_eq!(
            t.verify(&c, i.endpoint_id(), 200),
            Err(Error::CertificateExpired)
        );
        assert_eq!(
            t.verify(&c, Identity::generate().endpoint_id(), 150),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            Trust::new([9; 16], a.public_key()).verify(&c, i.endpoint_id(), 150),
            Err(Error::Unauthorized)
        );
        assert_eq!(
            Authority::generate()
                .trust()
                .verify(&c, i.endpoint_id(), 150),
            Err(Error::InvalidSignature)
        );
        t.deny_certificate(c.id()).unwrap();
        assert_eq!(t.verify(&c, i.endpoint_id(), 150), Err(Error::Unauthorized));
    }
    #[test]
    fn endpoint_cannot_delegate_and_duplicate_permissions_fail() {
        let (a, i, c) = certificate();
        let rogue = Authority::from_identity(i, a.realm_id());
        let subject = Identity::generate();
        let forged = rogue
            .issue(
                subject.endpoint_id(),
                c.permissions().to_vec(),
                100,
                200,
                CertificateLimits::default(),
            )
            .unwrap();
        assert_eq!(
            a.trust().verify(&forged, subject.endpoint_id(), 150),
            Err(Error::InvalidSignature)
        );
        assert!(
            a.issue(
                subject.endpoint_id(),
                vec![
                    Permission::publish("jobs").unwrap(),
                    Permission::subscribe("jobs").unwrap()
                ],
                100,
                200,
                CertificateLimits::default()
            )
            .is_err()
        );
    }
    #[test]
    fn cose_rejects_tampering_truncation_headers_and_noncanonical_forms() {
        let (a, i, c) = certificate();
        for n in 0..c.as_bytes().len() {
            assert!(
                Certificate::from_bytes(&c.as_bytes()[..n]).is_err(),
                "prefix {n}"
            );
        }
        let mut modified = c.as_bytes().to_vec();
        *modified.last_mut().unwrap() ^= 1;
        assert_eq!(
            a.trust().verify(
                &Certificate::from_bytes(&modified).unwrap(),
                i.endpoint_id(),
                150
            ),
            Err(Error::InvalidSignature)
        );
        let (payload, sig) = parse_cose(c.as_bytes(), MAX_CERT).unwrap();
        let mut w = Writer::new();
        w.array(4);
        w.bytes(&[0xa2, 1, 0x27, 1, 0x27]);
        w.empty_map();
        w.bytes(payload);
        w.bytes(&sig);
        assert!(Certificate::from_bytes(&w.finish()).is_err());
        let mut noncanonical = vec![0x98, 4];
        noncanonical.extend_from_slice(&c.as_bytes()[1..]);
        assert!(Certificate::from_bytes(&noncanonical).is_err());
        let mut trailing = c.as_bytes().to_vec();
        trailing.push(0);
        assert!(Certificate::from_bytes(&trailing).is_err());
    }
    #[test]
    fn signed_revocations_are_monotonic_cumulative_and_fresh() {
        let (a, i, c) = certificate();
        let mut t = a.trust();
        let first = a.revocations(1, 100, 160, vec![c.id()]).unwrap();
        t.apply_revocations(&first, 150).unwrap();
        assert_eq!(t.verify(&c, i.endpoint_id(), 150), Err(Error::Unauthorized));
        assert_eq!(t.apply_revocations(&first, 151), Err(Error::Unauthorized));
        t.apply_revocations(&a.revocations(2, 150, 180, vec![]).unwrap(), 155)
            .unwrap();
        assert_eq!(t.verify(&c, i.endpoint_id(), 156), Err(Error::Unauthorized));
        let other = a
            .issue(
                i.endpoint_id(),
                vec![],
                100,
                200,
                CertificateLimits::default(),
            )
            .unwrap();
        assert_eq!(
            t.verify(&other, i.endpoint_id(), 181),
            Err(Error::Unauthorized)
        );
    }
}
