pub(crate) mod owner;
pub(crate) mod transport;
use crate::{
    auth,
    buffer::{Budget, Permit},
    wire::Id,
    *,
};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode};
use owner::Command;
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{mpsc, oneshot, watch},
    time::Instant,
};
use tokio_util::sync::CancellationToken;

/// Limits are ceilings, not eagerly allocated capacity. Transport overhead is additional.
#[derive(Clone, Debug)]
pub struct Config {
    pub relay_mode: RelayMode,
    /// Disable direct IP transport, e.g. to require and verify relay operation.
    pub relay_only: bool,
    pub bind_addr: Option<SocketAddr>,
    pub max_payload: usize,
    pub payload_bytes: usize,
    pub metadata_bytes: usize,
    pub max_peers: usize,
    pub max_topics: usize,
    pub ingress_slots: usize,
    pub per_peer_messages: usize,
    pub per_peer_bytes: usize,
    pub subscription_messages: usize,
    pub subscription_bytes: usize,
    pub delivery_window: Duration,
    pub retry_interval: Duration,
    pub handshake_timeout: Duration,
}
impl Config {
    pub fn new() -> Self {
        Self {
            relay_mode: RelayMode::Default,
            relay_only: false,
            bind_addr: None,
            max_payload: 1024 * 1024,
            payload_bytes: 128 * 1024 * 1024,
            metadata_bytes: 32 * 1024 * 1024,
            max_peers: 256,
            max_topics: 256,
            ingress_slots: 1024,
            per_peer_messages: 1024,
            per_peer_bytes: 16 * 1024 * 1024,
            subscription_messages: 1024,
            subscription_bytes: 16 * 1024 * 1024,
            delivery_window: Duration::from_secs(300),
            retry_interval: Duration::from_secs(30),
            handshake_timeout: Duration::from_secs(10),
        }
    }
    fn validate(&self) -> Result<()> {
        if (self.relay_only && matches!(self.relay_mode, RelayMode::Disabled))
            || self.max_payload == 0
            || self.max_payload > 1024 * 1024
            || self.payload_bytes < self.max_payload + crate::buffer::PAYLOAD_OVERHEAD
            || self.metadata_bytes < 256 * 1024
            || self.max_peers == 0
            || self.max_peers > 256
            || self.max_topics == 0
            || self.max_topics > 256
            || self.ingress_slots == 0
            || self.ingress_slots > 65536
            || self.per_peer_messages == 0
            || self.per_peer_messages > 65536
            || self.subscription_messages == 0
            || self.subscription_messages > 65536
            || self.per_peer_bytes < self.max_payload + 16396
            || self.subscription_bytes < self.max_payload + 16396
            || self.delivery_window.as_secs() == 0
            || self.delivery_window > Duration::from_secs(300)
            || self.retry_interval.is_zero()
            || self.handshake_timeout.is_zero()
        {
            return Err(Error::Config("invalid endpoint limits"));
        }
        Ok(())
    }
}
impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
pub(crate) struct EndpointConfig {
    pub settings: Config,
    pub trust: Trust,
}
impl std::ops::Deref for EndpointConfig {
    type Target = Config;
    fn deref(&self) -> &Config {
        &self.settings
    }
}

#[derive(Clone, Debug)]
pub struct SubscriptionOptions {
    pub mode: DeliveryMode,
}
impl SubscriptionOptions {
    pub fn acknowledged() -> Self {
        Self {
            mode: DeliveryMode::Acknowledged,
        }
    }
    pub fn best_effort() -> Self {
        Self {
            mode: DeliveryMode::BestEffort,
        }
    }
}
impl Default for SubscriptionOptions {
    fn default() -> Self {
        Self::acknowledged()
    }
}
#[derive(Clone, Debug)]
pub struct PublishOptions {
    pub mode: DeliveryMode,
    pub lifetime: Duration,
    pub format: String,
}
impl Default for PublishOptions {
    fn default() -> Self {
        Self {
            mode: DeliveryMode::Acknowledged,
            lifetime: Duration::from_secs(300),
            format: "opaque".into(),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecipientOutcome {
    Pending,
    Sent,
    Processed,
    Rejected(Error),
    Failed(Error),
    PermanentNack,
    Cancelled,
}
impl RecipientOutcome {
    fn terminal(&self) -> bool {
        !matches!(self, Self::Pending)
    }
}
pub(crate) struct ReceiptEntry {
    peer: EndpointId,
    rx: watch::Receiver<RecipientOutcome>,
    _memory: Arc<Permit>,
}
pub struct Receipt {
    pub message_id: MessageId,
    entries: Vec<ReceiptEntry>,
    handle: Arc<Handle>,
}
impl Receipt {
    pub fn outcomes(&self) -> Vec<(EndpointId, RecipientOutcome)> {
        self.entries
            .iter()
            .map(|e| (e.peer, e.rx.borrow().clone()))
            .collect()
    }
    /// Wait up to `timeout` for all recipients to reach a terminal outcome.
    /// One timeout covers the entire wait. Timing out does not cancel delivery.
    pub async fn wait_for_processing(
        &mut self,
        timeout: Duration,
    ) -> Result<Vec<(EndpointId, RecipientOutcome)>> {
        tokio::time::timeout(timeout, async {
            for e in &mut self.entries {
                while !e.rx.borrow().terminal() {
                    e.rx.changed().await.map_err(|_| Error::ShuttingDown)?;
                }
            }
            Ok(self.outcomes())
        })
        .await
        .map_err(|_| Error::Timeout)?
    }
    /// Does not retract plaintext or side effects already delivered to an application.
    pub async fn cancel(&self) -> Result<()> {
        self.handle
            .request(|reply| Command::Cancel {
                id: self.message_id.clone(),
                reply,
            })
            .await
    }
}
#[derive(Clone, Copy, Debug)]
pub enum ShutdownMode {
    Immediate,
    /// Allow admitted deliveries up to this duration to finish, then close the endpoint.
    Drain {
        timeout: Duration,
    },
}
#[derive(Default, Debug, Clone)]
pub struct Metrics {
    pub peers: usize,
    pub pending_deliveries: usize,
    pub deduplication_records: usize,
    pub terminal_receipts: usize,
    pub resident_payload_bytes: usize,
    pub metadata_bytes: usize,
    pub peak_payload_bytes: usize,
    pub peak_metadata_bytes: usize,
    pub outstanding_credits: usize,
    pub unfinished_on_shutdown: usize,
    pub admitted: u64,
    pub rejected: u64,
    pub processed: u64,
    pub retried: u64,
    pub expired: u64,
    pub authorization_failures: u64,
}
struct Handle {
    tx: mpsc::Sender<Command>,
    endpoint: Endpoint,
    pool: BufferPool,
    metadata: Arc<Budget>,
    cert: watch::Receiver<Certificate>,
    config: EndpointConfig,
    host: Option<EndpointId>,
    stop: CancellationToken,
    done: watch::Receiver<bool>,
}
impl Drop for Handle {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}
impl Handle {
    async fn request<T>(&self, f: impl FnOnce(oneshot::Sender<Result<T>>) -> Command) -> Result<T> {
        if self.stop.is_cancelled() {
            return Err(Error::ShuttingDown);
        }
        let (tx, rx) = oneshot::channel();
        self.tx.send(f(tx)).await.map_err(|_| Error::ShuttingDown)?;
        rx.await.map_err(|_| Error::ShuttingDown)?
    }
}
#[derive(Clone)]
pub struct MessagingEndpoint {
    handle: Arc<Handle>,
}
impl MessagingEndpoint {
    /// Create a realm and host. Only peers enrolled through this host's join codes are admitted.
    pub async fn host(
        config: Config,
        identity: Identity,
        permissions: Vec<Permission>,
    ) -> Result<Self> {
        Self::host_with_admission(
            config,
            identity,
            permissions,
            crate::join::Admission::host(Authority::generate()),
        )
        .await
    }

    /// Create or resume a host whose authority, join grants, and issued membership records
    /// are atomically persisted in a private application state file.
    pub async fn host_persistent(
        config: Config,
        identity: Identity,
        permissions: Vec<Permission>,
        state_path: impl AsRef<Path>,
    ) -> Result<Self> {
        Self::host_with_admission(
            config,
            identity,
            permissions,
            crate::join::Admission::persistent(state_path)?,
        )
        .await
    }

    async fn host_with_admission(
        config: Config,
        identity: Identity,
        permissions: Vec<Permission>,
        admission: crate::join::Admission,
    ) -> Result<Self> {
        config.validate()?;
        let now = auth::now()?;
        let (certificate, trust) = {
            let authority = admission.authority()?;
            (
                authority.issue(
                    identity.endpoint_id(),
                    permissions,
                    now,
                    now + crate::join::MAX_JOIN_LIFETIME.as_secs(),
                    CertificateLimits::default(),
                )?,
                authority.trust(),
            )
        };
        let config = EndpointConfig {
            settings: config,
            trust,
        };
        let endpoint = transport::bind(&config, &identity).await?;
        Self::start_bound(config, identity, certificate, endpoint, admission, None).await
    }

    /// Enroll with a trusted join code and connect to its host. The identity's private key stays local.
    pub async fn join(config: Config, identity: Identity, code: &JoinCode) -> Result<Self> {
        config.validate()?;
        if identity.endpoint_id() == code.host_id() {
            return Err(Error::Unauthorized);
        }
        let endpoint = transport::bind(&config, &identity).await?;
        let enrollment = match crate::join::redeem(&endpoint, &config, code, None).await {
            Ok(enrollment) => enrollment,
            Err(error) => {
                endpoint.close().await;
                return Err(error);
            }
        };
        let config = EndpointConfig {
            settings: config,
            trust: enrollment.trust,
        };
        let certificate = enrollment.certificate;
        let host = code.host_id();
        let client = Self::start_bound(
            config,
            identity,
            certificate,
            endpoint,
            crate::join::Admission::Client(host),
            Some(host),
        )
        .await?;
        if let Err(error) = client.connect_host(code.address.clone()).await {
            let _ = client.shutdown(ShutdownMode::Immediate).await;
            return Err(error);
        }
        Ok(client)
    }

    async fn start_bound(
        config: EndpointConfig,
        identity: Identity,
        certificate: Certificate,
        endpoint: Endpoint,
        mut admission: crate::join::Admission,
        host: Option<EndpointId>,
    ) -> Result<Self> {
        let pool = BufferPool::new(config.payload_bytes, config.max_payload);
        let metadata = Budget::new(config.metadata_bytes);
        if let Err(error) = admission.meter(&metadata) {
            endpoint.close().await;
            return Err(error);
        }
        let setup = (|| {
            Ok::<_, Error>((
                certificate.metered(&metadata)?,
                metadata.reserve(config.trust.revoked_count() * 96)?,
            ))
        })();
        let (certificate, revocation_memory) = match setup {
            Ok(value) => value,
            Err(error) => {
                endpoint.close().await;
                return Err(error);
            }
        };
        let (cert_updates, cert_rx) = watch::channel(certificate.clone());
        let (tx, rx) = mpsc::channel(config.ingress_slots);
        let stop = CancellationToken::new();
        let (done_tx, done) = watch::channel(false);
        let handle = Arc::new(Handle {
            tx: tx.clone(),
            endpoint: endpoint.clone(),
            pool: pool.clone(),
            metadata: metadata.clone(),
            cert: cert_rx,
            config: config.clone(),
            host,
            stop: stop.clone(),
            done,
        });
        tokio::spawn(async move {
            owner::Owner::new(
                config,
                identity,
                certificate,
                cert_updates,
                revocation_memory,
                endpoint.clone(),
                pool,
                metadata,
                tx,
                rx,
                stop,
                admission,
            )
            .run()
            .await;
            endpoint.close().await;
            let _ = done_tx.send(true);
        });
        Ok(Self { handle })
    }

    /// Create a reusable, expiring join code. Only hosts can issue codes.
    pub async fn issue_join_code(&self, options: JoinOptions) -> Result<JoinCode> {
        options.validate()?;
        self.handle
            .request(|reply| Command::IssueCode { options, reply })
            .await
    }

    /// Stop new enrollment and re-enrollment through a code; existing certificates remain valid.
    pub async fn revoke_join_code(&self, id: [u8; 16]) -> Result<()> {
        self.handle
            .request(|reply| Command::RevokeCode { id, reply })
            .await
    }

    /// Re-enroll and reconnect to the same host using a currently valid code.
    /// Preserves identity, publisher epoch, subscriptions, and retained publications.
    pub async fn rejoin(&self, code: &JoinCode) -> Result<()> {
        if self.handle.host != Some(code.host_id()) {
            return Err(Error::Unauthorized);
        }
        let _memory = self.handle.metadata.reserve(128 * 1024)?;
        let enrollment = crate::join::redeem(
            &self.handle.endpoint,
            &self.handle.config,
            code,
            Some(&self.handle.config.trust),
        )
        .await?;
        let certificate = enrollment.certificate;
        self.handle
            .request(|reply| Command::Renew { certificate, reply })
            .await?;
        self.connect_host(code.address.clone()).await
    }

    /// Current authorization, useful for identifying a certificate to revoke.
    pub fn certificate(&self) -> Certificate {
        self.handle.cert.borrow().clone()
    }

    async fn connect_host(&self, address: EndpointAddr) -> Result<()> {
        self.handle
            .request(|reply| Command::Connect { address, reply })
            .await
    }

    pub fn endpoint_id(&self) -> EndpointId {
        self.handle.endpoint.id()
    }
    pub fn buffers(&self) -> &BufferPool {
        &self.handle.pool
    }
    /// Wait up to `timeout` for a relay connection.
    pub async fn online(&self, timeout: Duration) -> Result<()> {
        tokio::time::timeout(timeout, self.handle.endpoint.online())
            .await
            .map_err(|_| Error::Timeout)?;
        Ok(())
    }
    pub async fn disconnect(&self, peer: EndpointId) -> Result<()> {
        self.handle
            .request(|reply| Command::Disconnect { peer, reply })
            .await
    }
    pub async fn subscribe(
        &self,
        topic: impl AsRef<str>,
        options: SubscriptionOptions,
    ) -> Result<Subscription> {
        let topic = Topic::new(topic)?;
        let state = self
            .handle
            .request(|reply| Command::Subscribe {
                topic: topic.clone(),
                options,
                reply,
            })
            .await?;
        Ok(Subscription {
            topic,
            rx: state.rx,
            ready: state.ready,
            _handle: self.handle.clone(),
        })
    }
    pub fn publisher(&self, topic: impl AsRef<str>) -> Result<Publisher> {
        let topic = Topic::new(topic)?;
        if !self.handle.cert.borrow().allows(&topic, true) {
            return Err(Error::Unauthorized);
        }
        Ok(Publisher {
            topic,
            handle: self.handle.clone(),
        })
    }
    pub async fn deny_certificate(&self, id: Id) -> Result<()> {
        self.handle
            .request(|reply| Command::Deny { id, reply })
            .await
    }
    pub async fn apply_revocations(&self, snapshot: RevocationSnapshot) -> Result<()> {
        self.handle
            .request(|reply| Command::Revoke { snapshot, reply })
            .await
    }
    pub async fn metrics(&self) -> Result<Metrics> {
        self.handle.request(Command::Metrics).await
    }
    pub async fn shutdown(&self, mode: ShutdownMode) -> Result<Metrics> {
        let deadline = match mode {
            ShutdownMode::Immediate => Instant::now(),
            ShutdownMode::Drain { timeout } => Instant::now()
                .checked_add(timeout)
                .ok_or(Error::Config("shutdown timeout is too large"))?,
        };
        let result = self
            .handle
            .request(|reply| Command::Shutdown { deadline, reply })
            .await;
        let mut done = self.handle.done.clone();
        while !*done.borrow() {
            if done.changed().await.is_err() {
                break;
            }
        }
        result
    }
}
#[derive(Clone)]
pub struct Publisher {
    topic: Topic,
    handle: Arc<Handle>,
}
impl Publisher {
    pub async fn publish(&self, payload: PayloadLease, options: PublishOptions) -> Result<Receipt> {
        if !self.handle.pool.owns(&payload) {
            return Err(Error::Config(
                "payload must belong to this endpoint's buffer pool",
            ));
        }
        let memory = self.handle.metadata.reserve(512 + options.format.len())?;
        let draft = self
            .handle
            .request(|reply| Command::Publish {
                topic: self.topic.clone(),
                payload,
                options,
                reply,
                _memory: memory,
            })
            .await?;
        Ok(Receipt {
            message_id: draft.id,
            entries: draft.entries,
            handle: self.handle.clone(),
        })
    }
}
pub struct Subscription {
    topic: Topic,
    rx: crate::queue::Receiver<Delivery>,
    ready: watch::Receiver<BTreeMap<EndpointId, Result<()>>>,
    _handle: Arc<Handle>,
}
impl Subscription {
    pub fn topic(&self) -> &Topic {
        &self.topic
    }
    pub async fn recv(&mut self) -> Result<Option<Delivery>> {
        Ok(self.rx.recv().await)
    }
    /// Wait up to `timeout` for this peer to accept the subscription.
    /// Subscription updates do not restart the timeout.
    pub async fn wait_ready(&mut self, peer: EndpointId, timeout: Duration) -> Result<()> {
        tokio::time::timeout(timeout, async {
            loop {
                if let Some(result) = self.ready.borrow().get(&peer)
                    && *result != Err(Error::PeerUnavailable)
                {
                    return result.clone();
                }
                self.ready
                    .changed()
                    .await
                    .map_err(|_| Error::SubscriptionClosed)?;
            }
        })
        .await
        .map_err(|_| Error::Timeout)?
    }
}
pub struct Delivery {
    pub message_id: MessageId,
    pub format: String,
    payload: Option<PayloadLease>,
    disposition: Arc<AtomicU8>,
    completion: watch::Receiver<Option<Result<()>>>,
    wake: Arc<tokio::sync::Notify>,
}
impl Delivery {
    pub fn payload(&self) -> &[u8] {
        self.payload.as_ref().unwrap().as_bytes()
    }
    pub fn lease(&self) -> PayloadLease {
        self.payload.as_ref().unwrap().clone()
    }
    pub async fn ack(self) -> Result<()> {
        self.complete(1).await
    }
    pub async fn nack(self, reason: Nack) -> Result<()> {
        self.complete(if reason == Nack::Retryable { 2 } else { 3 })
            .await
    }
    async fn complete(mut self, code: u8) -> Result<()> {
        self.disposition.store(code, Ordering::Release);
        self.wake.notify_one();
        self.payload.take();
        loop {
            if let Some(result) = self.completion.borrow().clone() {
                return result;
            }
            self.completion
                .changed()
                .await
                .map_err(|_| Error::ShuttingDown)?;
        }
    }
}
impl Drop for Delivery {
    fn drop(&mut self) {
        self.wake.notify_one();
        let _ = self
            .disposition
            .compare_exchange(0, 2, Ordering::AcqRel, Ordering::Acquire);
    }
}
