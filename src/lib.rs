//! Authenticated, bounded, direct messaging. See the crate README for delivery semantics.
mod auth;
mod buffer;
mod cbor;
mod endpoint;
mod enrollment;
mod error;
mod identity;
mod message;
mod queue;
mod wire;

pub use auth::{
    Authority, Certificate, CertificateLimits, Permission, RealmId, RevocationSnapshot, Trust,
};
pub use buffer::{BufferPool, PayloadLease};
pub use endpoint::{
    Config, Delivery, MessagingEndpoint, Metrics, PeerInvite, PublishOptions, Publisher, Receipt,
    RecipientOutcome, ShutdownMode, Subscription, SubscriptionOptions,
};
pub use enrollment::{EnrollmentInvite, EnrollmentService};
pub use error::{Error, Result};
pub use identity::Identity;
pub use iroh::{EndpointAddr, EndpointId, RelayMode};
pub use message::{DeliveryMode, MessageId, Nack, Topic};

#[cfg(test)]
mod fixture_tests {
    use super::*;
    fn hex(s: &str) -> Vec<u8> {
        s.trim()
            .as_bytes()
            .chunks_exact(2)
            .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect()
    }
    #[test]
    fn independently_generated_cose_and_wire_fixtures() {
        let root = iroh::SecretKey::from_bytes(&[1; 32]);
        let subject = iroh::SecretKey::from_bytes(&[2; 32]);
        let cert = hex(include_str!("../tests/fixtures/certificate.hex"));
        let certificate = Certificate::from_bytes(&cert).unwrap();
        Trust::new([3; 16], root.public())
            .verify(&certificate, subject.public(), 110)
            .unwrap();
        let cert_payload = auth::verify_cose(
            &cert,
            root.public(),
            b"iroh-mq/certificate/v1",
            auth::MAX_CERT,
        )
        .unwrap();
        assert_eq!(
            auth::sign_cose(cert_payload, &root, b"iroh-mq/certificate/v1"),
            cert
        );
        let signed = hex(include_str!("../tests/fixtures/message.hex"));
        let envelope = message::Envelope::verify(&signed, subject.public()).unwrap();
        assert!(envelope.payload_matches(b"abc"));
        assert_eq!(envelope.sign(&subject).as_ref(), signed);
        let hello = hex(include_str!("../tests/fixtures/hello.hex"));
        assert_eq!(wire::parse_hello(&hello).unwrap().cert, cert);
        assert_eq!(wire::hello(&cert, [6; 16], 1024, 8, 300), hello);
        let data = hex(include_str!("../tests/fixtures/data.hex"));
        let header = wire::Header::decode(data[..12].try_into().unwrap(), 1024).unwrap();
        let (sub, wire_signature) =
            wire::parse_data(&data[12..12 + header.metadata], [7; 16]).unwrap();
        assert_eq!(sub, [8; 16]);
        assert_eq!(wire_signature, signed);
        assert_eq!(&data[12 + header.metadata..], b"abc");
    }
}
