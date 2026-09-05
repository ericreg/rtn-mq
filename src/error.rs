#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("unauthorized")]
    Unauthorized,
    #[error("certificate expired or not yet valid")]
    CertificateExpired,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("invalid topic")]
    InvalidTopic,
    #[error("no eligible subscribers")]
    NoSubscribers,
    #[error("already subscribed")]
    AlreadySubscribed,
    #[error("queue or memory budget exhausted")]
    QueueFull,
    #[error("message too large")]
    MessageTooLarge,
    #[error("peer unavailable")]
    PeerUnavailable,
    #[error("delivery expired; remote processing may have occurred")]
    DeliveryExpired,
    #[error("operation timed out")]
    Timeout,
    #[error("protocol violation: {0}")]
    Protocol(&'static str),
    #[error("shutting down")]
    ShuttingDown,
    #[error("subscription closed")]
    SubscriptionClosed,
    #[error("invalid configuration: {0}")]
    Config(&'static str),
    #[error("clock anomaly")]
    Clock,
    #[error("I/O: {0}")]
    Io(String),
}
pub type Result<T> = std::result::Result<T, Error>;
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}
impl From<minicbor::decode::Error> for Error {
    fn from(_: minicbor::decode::Error) -> Self {
        Self::Protocol("invalid CBOR")
    }
}
pub(crate) fn transport(e: impl std::fmt::Display) -> Error {
    Error::Io(e.to_string())
}
