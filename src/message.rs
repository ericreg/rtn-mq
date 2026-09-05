use crate::{
    Error, RealmId, Result,
    auth::{endpoint, sign_cose, verify_cose, version},
    cbor::{Reader, Writer, canonical},
};
use iroh::{EndpointId, SecretKey};
use sha2::{Digest, Sha256};
use std::sync::Arc;
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Topic(String);
impl Topic {
    pub fn new(s: impl AsRef<str>) -> Result<Self> {
        let s = s.as_ref();
        if s.is_empty()
            || s.len() > 256
            || s.split('/').any(str::is_empty)
            || !s
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_./".contains(&b))
        {
            return Err(Error::InvalidTopic);
        }
        Ok(Self(s.into()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl std::fmt::Display for Topic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryMode {
    BestEffort,
    Acknowledged,
}
impl DeliveryMode {
    pub(crate) fn number(self) -> u64 {
        match self {
            Self::BestEffort => 0,
            Self::Acknowledged => 1,
        }
    }
    pub(crate) fn decode(n: u64) -> Result<Self> {
        match n {
            0 => Ok(Self::BestEffort),
            1 => Ok(Self::Acknowledged),
            _ => Err(Error::Protocol("delivery mode")),
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nack {
    Retryable,
    Permanent,
}
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MessageId {
    pub realm_id: RealmId,
    pub publisher_endpoint_id: EndpointId,
    pub publisher_epoch: [u8; 16],
    pub topic: Topic,
    pub sequence: u64,
}
#[derive(Debug, Clone)]
pub(crate) struct Envelope {
    pub id: MessageId,
    pub created: u64,
    pub expires: u64,
    pub format: String,
    pub len: usize,
    pub digest: [u8; 32],
    pub mode: DeliveryMode,
}
impl Envelope {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.array(12);
        w.u(1);
        w.bytes(&self.id.realm_id);
        w.bytes(self.id.publisher_endpoint_id.as_bytes());
        w.bytes(&self.id.publisher_epoch);
        w.text(self.id.topic.as_str());
        w.u(self.id.sequence);
        w.u(self.created);
        w.u(self.expires);
        w.text(&self.format);
        w.u(self.len as u64);
        w.bytes(&self.digest);
        w.u(self.mode.number());
        w.finish()
    }
    pub fn sign(&self, key: &SecretKey) -> Arc<[u8]> {
        sign_cose(&self.encode(), key, b"iroh-mq/message/v1").into()
    }
    pub fn verify(bytes: &[u8], peer: EndpointId) -> Result<Self> {
        let b = verify_cose(bytes, peer, b"iroh-mq/message/v1", 4096)?;
        let mut r = Reader::new(b);
        r.array(12)?;
        version(r.u()?)?;
        let realm_id = r.fixed()?;
        let publisher_endpoint_id = endpoint(r.fixed()?)?;
        let publisher_epoch = r.fixed()?;
        let topic = Topic::new(r.text(256)?)?;
        let sequence = r.u()?;
        let created = r.u()?;
        let expires = r.u()?;
        let format = r.text(256)?.to_owned();
        let len = usize::try_from(r.u()?).map_err(|_| Error::MessageTooLarge)?;
        let digest = r.fixed()?;
        let mode = DeliveryMode::decode(r.u()?)?;
        r.end()?;
        let e = Self {
            id: MessageId {
                realm_id,
                publisher_endpoint_id,
                publisher_epoch,
                topic,
                sequence,
            },
            created,
            expires,
            format,
            len,
            digest,
            mode,
        };
        if publisher_endpoint_id != peer || created >= expires {
            return Err(Error::Unauthorized);
        }
        canonical(b, &e.encode())?;
        Ok(e)
    }
    pub fn payload_matches(&self, payload: &[u8]) -> bool {
        self.len == payload.len() && self.digest == digest(payload)
    }
}
pub(crate) fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_topic_validation() {
        for bad in [
            "", "/jobs", "jobs/", "jobs//a", "jobs/*", "jobs/#", "jobs x", "ümlaut", "jobs\n",
        ] {
            assert_eq!(Topic::new(bad), Err(Error::InvalidTopic));
        }
        assert!(Topic::new("a".repeat(257)).is_err());
        assert_ne!(Topic::new("Jobs").unwrap(), Topic::new("jobs").unwrap());
    }
    #[test]
    fn signed_envelope_binds_identity_metadata_and_payload() {
        let key = SecretKey::generate();
        let e = Envelope {
            id: MessageId {
                realm_id: [1; 16],
                publisher_endpoint_id: key.public(),
                publisher_epoch: [2; 16],
                topic: Topic::new("jobs").unwrap(),
                sequence: 1,
            },
            created: 100,
            expires: 200,
            format: "opaque".into(),
            len: 3,
            digest: digest(b"abc"),
            mode: DeliveryMode::Acknowledged,
        };
        let signed = e.sign(&key);
        let decoded = Envelope::verify(&signed, key.public()).unwrap();
        assert!(decoded.payload_matches(b"abc"));
        assert!(!decoded.payload_matches(b"abd"));
        assert!(Envelope::verify(&signed, SecretKey::generate().public()).is_err());
        for n in 0..signed.len() {
            assert!(Envelope::verify(&signed[..n], key.public()).is_err());
        }
        let mut bad = signed.to_vec();
        let index = bad.len() - 5;
        bad[index] ^= 1;
        assert!(Envelope::verify(&bad, key.public()).is_err());
    }
}
