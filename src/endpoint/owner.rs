use super::*;
use crate::{
    message::{Envelope, digest},
    wire::{self, Control},
};
use iroh::endpoint::Connection;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::atomic::Ordering,
};
use tokio::{sync::Semaphore, task::JoinSet};

type Key = (EndpointId, Id, MessageId);
type DedupKey = (Id, MessageId);
pub(super) struct SubscriptionState {
    pub rx: crate::queue::Receiver<Delivery>,
    pub ready: watch::Receiver<BTreeMap<EndpointId, Result<()>>>,
}
pub(super) struct ReceiptDraft {
    pub id: MessageId,
    pub entries: Vec<ReceiptEntry>,
}
pub(super) struct Registration {
    pub conn: Connection,
    pub cert: Certificate,
    pub session: Id,
    pub dialer: EndpointId,
    pub nonce: Id,
    pub control: mpsc::Sender<Control>,
    pub cancel: CancellationToken,
    pub max_payload: usize,
    pub max_topics: usize,
    pub window_secs: u64,
}
pub(super) struct ReceiveTicket {
    pub envelope: Envelope,
    pub fingerprint: [u8; 32],
    pub permits: Vec<Permit>,
    pub metadata: Permit,
}
pub(super) struct DataOut {
    pub key: Key,
    pub signed: Arc<[u8]>,
    pub payload: PayloadLease,
    pub _memory: Arc<Permit>,
}
pub(super) enum Command {
    Connect {
        invite: PeerInvite,
        reply: oneshot::Sender<Result<()>>,
    },
    Disconnect {
        peer: EndpointId,
        reply: oneshot::Sender<Result<()>>,
    },
    Subscribe {
        topic: Topic,
        options: SubscriptionOptions,
        reply: oneshot::Sender<Result<SubscriptionState>>,
    },
    Publish {
        topic: Topic,
        payload: PayloadLease,
        options: PublishOptions,
        reply: oneshot::Sender<Result<ReceiptDraft>>,
        _memory: Permit,
    },
    Register {
        registration: Registration,
        accepted: oneshot::Sender<bool>,
        connected: Option<oneshot::Sender<Result<()>>>,
    },
    Remote {
        peer: EndpointId,
        session: Id,
        control: Control,
        _memory: Permit,
    },
    Begin {
        stream: u64,
        peer: EndpointId,
        session: Id,
        sub: Id,
        signed: Vec<u8>,
        len: usize,
        reply: oneshot::Sender<Result<ReceiveTicket>>,
        _memory: Permit,
    },
    Incoming {
        peer: EndpointId,
        session: Id,
        sub: Id,
        ticket: ReceiveTicket,
        payload: PayloadLease,
    },
    Sent {
        key: Key,
        session: Id,
        result: Result<()>,
    },
    End {
        peer: EndpointId,
        session: Id,
    },
    Renew {
        certificate: Certificate,
        reply: oneshot::Sender<Result<()>>,
    },
    Deny {
        id: Id,
        reply: oneshot::Sender<Result<()>>,
    },
    Revoke {
        snapshot: RevocationSnapshot,
        reply: oneshot::Sender<Result<()>>,
    },
    Cancel {
        id: MessageId,
        reply: oneshot::Sender<Result<()>>,
    },
    Metrics(oneshot::Sender<Result<Metrics>>),
    Shutdown {
        deadline: Instant,
        reply: oneshot::Sender<Result<Metrics>>,
    },
}
struct Binding {
    sub: Id,
    mode: DeliveryMode,
    credit: Option<usize>,
    requested: bool,
    writer: crate::queue::Sender<DataOut>,
    cancel: CancellationToken,
}
impl Drop for Binding {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
struct Peer {
    reg: Registration,
    outbound: BTreeMap<Topic, Binding>,
    inbound: BTreeMap<Topic, (Id, u64)>,
    slots: Arc<Budget>,
    bytes: Arc<Budget>,
    _memory: Permit,
}
impl Drop for Peer {
    fn drop(&mut self) {
        self.reg.cancel.cancel();
        self.reg.conn.close(0u32.into(), b"session ended");
    }
}
struct Grant {
    bytes: usize,
    permits: Vec<Permit>,
    metadata: Permit,
}
struct LocalSub {
    id: Id,
    mode: DeliveryMode,
    tx: crate::queue::Sender<Delivery>,
    ready: watch::Sender<BTreeMap<EndpointId, Result<()>>>,
    slots: Arc<Budget>,
    bytes: Arc<Budget>,
    confirmed: BTreeSet<EndpointId>,
    grants: BTreeMap<EndpointId, Grant>,
    demand: BTreeMap<EndpointId, usize>,
}
struct Pending {
    recipient_certificate: Certificate,
    signed: Arc<[u8]>,
    envelope: Envelope,
    payload: PayloadLease,
    outcome: watch::Sender<RecipientOutcome>,
    memory: Arc<Permit>,
    _slot: Permit,
    _bytes: Permit,
    deadline: Instant,
    next: Instant,
    attempts: u32,
    writing: bool,
}
enum DedupState {
    Processing {
        disposition: Arc<AtomicU8>,
        completion: watch::Sender<Option<Result<()>>>,
    },
    Retryable,
    Processed,
    Permanent,
}
struct TerminalReceipt {
    expires: u64,
    _memory: Arc<Permit>,
}
struct Dedup {
    fingerprint: [u8; 32],
    expires: u64,
    state: DedupState,
    _memory: Permit,
}
pub(super) struct Owner {
    config: Config,
    identity: Identity,
    cert: Certificate,
    cert_updates: watch::Sender<Certificate>,
    revocation_memory: Vec<Permit>,
    endpoint: Endpoint,
    pool: BufferPool,
    metadata: Arc<Budget>,
    tx: mpsc::Sender<Command>,
    rx: mpsc::Receiver<Command>,
    stop: CancellationToken,
    peers: BTreeMap<EndpointId, Peer>,
    peer_budgets: BTreeMap<EndpointId, (Arc<Budget>, Arc<Budget>)>,
    subscriptions: BTreeMap<Topic, LocalSub>,
    pending: BTreeMap<Key, Pending>,
    dedup: BTreeMap<DedupKey, Dedup>,
    terminal: BTreeMap<Key, TerminalReceipt>,
    auth_attempts: usize,
    auth_window: Instant,
    sequences: BTreeMap<Topic, u64>,
    epoch: Id,
    tasks: JoinSet<()>,
    quota: Arc<Semaphore>,
    stats: Metrics,
    drain: Option<(Instant, oneshot::Sender<Result<Metrics>>)>,
    credit_cursor: usize,
    clock_start: (u64, Instant),
    clock_failed: bool,
}
impl Owner {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: Config,
        identity: Identity,
        cert: Certificate,
        cert_updates: watch::Sender<Certificate>,
        revocation_memory: Permit,
        endpoint: Endpoint,
        pool: BufferPool,
        metadata: Arc<Budget>,
        tx: mpsc::Sender<Command>,
        rx: mpsc::Receiver<Command>,
        stop: CancellationToken,
    ) -> Self {
        let quota = Arc::new(Semaphore::new(config.max_peers * 2));
        Self {
            config,
            identity,
            cert,
            cert_updates,
            revocation_memory: vec![revocation_memory],
            endpoint,
            pool,
            metadata,
            tx,
            rx,
            stop,
            peers: BTreeMap::new(),
            peer_budgets: BTreeMap::new(),
            subscriptions: BTreeMap::new(),
            pending: BTreeMap::new(),
            dedup: BTreeMap::new(),
            terminal: BTreeMap::new(),
            auth_attempts: 0,
            auth_window: Instant::now(),
            sequences: BTreeMap::new(),
            epoch: rand::random(),
            tasks: JoinSet::new(),
            quota,
            stats: Metrics::default(),
            drain: None,
            credit_cursor: 0,
            clock_start: (auth::now().unwrap_or(0), Instant::now()),
            clock_failed: false,
        }
    }
    pub async fn run(mut self) {
        let mut tick = tokio::time::interval(Duration::from_millis(20));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _=self.stop.cancelled()=>break,
                Some(command)=self.rx.recv()=>self.command(command),
                incoming=self.endpoint.accept(), if self.drain.is_none()=> {
                    if let Some(incoming)=incoming {
                        if self.auth_window.elapsed() >= Duration::from_secs(1) { self.auth_window = Instant::now(); self.auth_attempts = 0; }
                        self.auth_attempts += 1;
                        if self.auth_attempts > self.config.max_peers * 4 { incoming.refuse(); continue; }
                        if let (Ok(quota),Ok(memory))=(self.quota.clone().try_acquire_owned(),self.metadata.reserve(128 * 1024)) {
                            let config=self.config.clone();let cert=self.cert.clone();let tx=self.tx.clone();let stop=self.stop.clone();let meta=self.metadata.clone();
                            self.tasks.spawn(async move { let _quota=quota; let _memory=memory; transport::incoming(incoming,config,cert,tx,stop,meta).await; });
                        } else {incoming.refuse();}
                    }
                },
                _=tick.tick()=>self.maintenance(),
                _=self.pool.budget.wake.notified()=>self.maintenance(),
                Some(_)=self.tasks.join_next(),if !self.tasks.is_empty()=>{},
            }
            self.schedule();
            if let Some((deadline, _)) = &self.drain
                && (self.pending.is_empty() || Instant::now() >= *deadline)
            {
                break;
            }
        }
        self.stop.cancel();
        self.stats.unfinished_on_shutdown = self.pending.len();
        for (_, p) in std::mem::take(&mut self.pending) {
            let _ = p
                .outcome
                .send(RecipientOutcome::Failed(Error::ShuttingDown));
        }
        for (_, d) in std::mem::take(&mut self.dedup) {
            if let DedupState::Processing { completion, .. } = d.state {
                let _ = completion.send(Some(Err(Error::ShuttingDown)));
            }
        }
        self.peers.clear();
        self.subscriptions.clear();
        self.tasks.abort_all();
        while self.tasks.join_next().await.is_some() {}
        if let Some((_, reply)) = self.drain.take() {
            let _ = reply.send(Ok(self.metrics()));
        }
    }
    fn local_valid(&self) -> Result<u64> {
        if self.clock_failed {
            return Err(Error::Clock);
        }
        let now = auth::now()?;
        self.config
            .trust
            .check(&self.cert, self.identity.endpoint_id(), now)?;
        Ok(now)
    }
    fn peer_valid(&self, peer: EndpointId, session: Id) -> Result<&Peer> {
        let now = self.local_valid()?;
        let p = self.peers.get(&peer).ok_or(Error::PeerUnavailable)?;
        if p.reg.session != session {
            return Err(Error::PeerUnavailable);
        }
        self.config.trust.check(&p.reg.cert, peer, now)?;
        Ok(p)
    }
    fn command(&mut self, command: Command) {
        match command {
            Command::Connect { invite, reply } => {
                let valid = self.local_valid().and_then(|_| {
                    if self.drain.is_some() {
                        return Err(Error::ShuttingDown);
                    }
                    if invite.realm_id != self.config.trust.realm
                        || invite.authority != self.config.trust.root
                        || invite.address.id == self.endpoint.id()
                    {
                        return Err(Error::Unauthorized);
                    }
                    Ok(())
                });
                if let Err(e) = valid {
                    let _ = reply.send(Err(e));
                    return;
                }
                if self.peers.contains_key(&invite.address.id) {
                    let _ = reply.send(Ok(()));
                    return;
                }
                let quota = self.quota.clone().try_acquire_owned();
                let memory = self.metadata.reserve(128 * 1024);
                match (quota, memory) {
                    (Ok(quota), Ok(memory)) => {
                        let config = self.config.clone();
                        let cert = self.cert.clone();
                        let tx = self.tx.clone();
                        let endpoint = self.endpoint.clone();
                        let stop = self.stop.clone();
                        let meta = self.metadata.clone();
                        self.tasks.spawn(async move {
                            let _quota = quota;
                            let _memory = memory;
                            transport::connect(
                                endpoint,
                                invite.address,
                                config,
                                cert,
                                tx,
                                stop,
                                meta,
                                reply,
                            )
                            .await;
                        });
                    }
                    _ => {
                        let _ = reply.send(Err(Error::QueueFull));
                    }
                }
            }
            Command::Disconnect { peer, reply } => {
                self.remove_peer(peer);
                let _ = reply.send(Ok(()));
            }
            Command::Subscribe {
                topic,
                options,
                reply,
            } => {
                let result = self.subscribe(topic, options);
                let _ = reply.send(result);
            }
            Command::Publish {
                topic,
                payload,
                options,
                reply,
                ..
            } => {
                let result = self.publish(topic, payload, options);
                let _ = reply.send(result);
            }
            Command::Register {
                registration,
                accepted,
                connected,
            } => {
                let result = self.register(registration);
                if let Some(reply) = connected {
                    let _ = reply.send(result.as_ref().map(|_| ()).map_err(Clone::clone));
                }
                let _ = accepted.send(result.unwrap_or(false));
            }
            Command::Remote {
                peer,
                session,
                control,
                ..
            } => {
                if self
                    .peers
                    .get(&peer)
                    .is_some_and(|p| p.reg.session == session)
                    && (self.peer_valid(peer, session).is_err()
                        || self.control(peer, control).is_err())
                {
                    self.stats.authorization_failures += 1;
                    self.remove_peer(peer);
                }
            }
            Command::Begin {
                stream,
                peer,
                session,
                sub,
                signed,
                len,
                reply,
                ..
            } => {
                let result = self.begin(peer, session, sub, stream, &signed, len);
                let _ = reply.send(result);
            }
            Command::Incoming {
                peer,
                session,
                sub,
                ticket,
                payload,
            } => {
                if self.incoming(peer, session, sub, ticket, payload).is_err() {
                    self.remove_peer(peer);
                }
            }
            Command::Sent {
                key,
                session,
                result,
            } => {
                if self
                    .peers
                    .get(&key.0)
                    .is_some_and(|p| p.reg.session == session)
                    && let Some(p) = self.pending.get_mut(&key)
                {
                    p.writing = false;
                    if p.envelope.mode == DeliveryMode::BestEffort {
                        self.finish(
                            &key,
                            match result {
                                Ok(()) => RecipientOutcome::Sent,
                                Err(e) => RecipientOutcome::Failed(e),
                            },
                        );
                    } else if result == Err(Error::SubscriptionClosed) {
                        self.finish(&key, RecipientOutcome::Failed(Error::SubscriptionClosed));
                    } else if result.is_err() {
                        self.remove_peer(key.0);
                    }
                }
            }
            Command::End { peer, session } => {
                if self
                    .peers
                    .get(&peer)
                    .is_some_and(|p| p.reg.session == session)
                {
                    self.remove_peer(peer);
                }
            }
            Command::Renew { certificate, reply } => {
                let result = (|| {
                    if self.drain.is_some() {
                        return Err(Error::ShuttingDown);
                    }
                    self.config.trust.verify(
                        &certificate,
                        self.identity.endpoint_id(),
                        auth::now()?,
                    )?;
                    let certificate = certificate.metered(&self.metadata)?;
                    self.cert = certificate.clone();
                    self.cert_updates.send_replace(certificate);
                    let peers: Vec<_> = self.peers.keys().copied().collect();
                    for peer in peers {
                        self.remove_peer(peer);
                    }
                    self.subscriptions
                        .retain(|topic, _| self.cert.allows(topic, false));
                    self.maintenance();
                    Ok(())
                })();
                let _ = reply.send(result);
            }
            Command::Deny { id, reply } => {
                let result = (|| {
                    let memory = self.metadata.reserve(96)?;
                    let old = self.config.trust.revoked_count();
                    self.config.trust.deny_certificate(id)?;
                    if self.config.trust.revoked_count() > old {
                        self.revocation_memory.push(memory);
                    }
                    Ok(())
                })();
                self.maintenance();
                let _ = reply.send(result);
            }
            Command::Revoke { snapshot, reply } => {
                let result = (|| {
                    // Reserve temporary parsing/merge state before applying an update.
                    let mut memory = self.metadata.reserve(4096 * 96)?;
                    let old = self.config.trust.revoked_count();
                    self.config
                        .trust
                        .apply_revocations(&snapshot, auth::now()?)?;
                    let added = self.config.trust.revoked_count() - old;
                    memory.shrink_to(added * 96);
                    if added > 0 {
                        self.revocation_memory.push(memory);
                    }
                    Ok(())
                })();
                self.maintenance();
                let _ = reply.send(result);
            }
            Command::Cancel { id, reply } => {
                let keys: Vec<_> = self.pending.keys().filter(|k| k.2 == id).cloned().collect();
                for key in keys {
                    self.finish(&key, RecipientOutcome::Cancelled);
                }
                let _ = reply.send(Ok(()));
            }
            Command::Metrics(reply) => {
                let _ = reply.send(Ok(self.metrics()));
            }
            Command::Shutdown { deadline, reply } => {
                if self.drain.is_some() {
                    let _ = reply.send(Err(Error::ShuttingDown));
                    return;
                }
                self.drain = Some((deadline, reply));
                for p in self.peers.values() {
                    Self::send(p, Control::Goodbye);
                }
            }
        }
    }
    fn send(peer: &Peer, control: Control) {
        if peer.reg.control.try_send(control).is_err() {
            peer.reg.cancel.cancel();
        }
    }
    fn register(&mut self, mut reg: Registration) -> Result<bool> {
        let peer = reg.conn.remote_id();
        let now = self.local_valid()?;
        if self.drain.is_some() {
            return Err(Error::ShuttingDown);
        }
        self.config.trust.verify(&reg.cert, peer, now)?;
        if let Some(existing) = self.peers.get(&peer) {
            if (existing.reg.dialer, existing.reg.nonce) <= (reg.dialer, reg.nonce) {
                return Ok(false);
            }
        } else if self.peers.len() >= self.config.max_peers {
            return Err(Error::QueueFull);
        }
        reg.cert = reg.cert.metered(&self.metadata)?;
        let memory = self.metadata.reserve(reg.cert.as_bytes().len() + 4096)?;
        self.remove_peer(peer);
        for (key, pending) in &mut self.pending {
            if key.0 == peer {
                pending.recipient_certificate = reg.cert.clone();
            }
        }
        let (slots, bytes) = self
            .peer_budgets
            .entry(peer)
            .or_insert_with(|| {
                (
                    Budget::new(self.config.per_peer_messages),
                    Budget::new(self.config.per_peer_bytes),
                )
            })
            .clone();
        let p = Peer {
            reg,
            outbound: BTreeMap::new(),
            inbound: BTreeMap::new(),
            slots,
            bytes,
            _memory: memory,
        };
        for (topic, s) in &self.subscriptions {
            Self::send(
                &p,
                Control::Subscribe {
                    topic: topic.clone(),
                    sub: s.id,
                    mode: s.mode,
                },
            );
        }
        self.peers.insert(peer, p);
        Ok(true)
    }
    fn remove_peer(&mut self, peer: EndpointId) {
        self.peers.remove(&peer);
        for s in self.subscriptions.values_mut() {
            s.confirmed.remove(&peer);
            s.grants.remove(&peer);
            s.demand.remove(&peer);
            s.ready.send_modify(|map| {
                map.remove(&peer);
            });
        }
        let mut fail = Vec::new();
        for (key, p) in &mut self.pending {
            if key.0 == peer {
                p.writing = false;
                p.next = Instant::now();
                if p.envelope.mode == DeliveryMode::BestEffort {
                    fail.push(key.clone());
                }
            }
        }
        for key in fail {
            self.finish(&key, RecipientOutcome::Failed(Error::PeerUnavailable));
        }
    }
    fn subscribe(
        &mut self,
        topic: Topic,
        options: SubscriptionOptions,
    ) -> Result<SubscriptionState> {
        self.local_valid()?;
        if self.drain.is_some() {
            return Err(Error::ShuttingDown);
        }
        if !self.cert.allows(&topic, false) {
            return Err(Error::Unauthorized);
        }
        if self.subscriptions.contains_key(&topic) {
            return Err(Error::AlreadySubscribed);
        }
        let ceiling = self.cert.limits().max_subscriptions;
        if self.subscriptions.len() >= self.config.max_topics
            || (ceiling != 0 && self.subscriptions.len() as u64 >= ceiling)
        {
            return Err(Error::QueueFull);
        }
        let memory = self.metadata.reserve(
            2048 + self.config.max_peers * 128
                + self.config.subscription_messages * std::mem::size_of::<Delivery>(),
        )?;
        let (tx, rx) = crate::queue::channel(self.config.subscription_messages, memory);
        let (ready, ready_rx) = watch::channel(BTreeMap::new());
        let id = rand::random();
        for p in self.peers.values() {
            Self::send(
                p,
                Control::Subscribe {
                    topic: topic.clone(),
                    sub: id,
                    mode: options.mode,
                },
            );
        }
        self.subscriptions.insert(
            topic,
            LocalSub {
                id,
                mode: options.mode,
                tx,
                ready,
                slots: Budget::new(self.config.subscription_messages),
                bytes: Budget::new(self.config.subscription_bytes),
                confirmed: BTreeSet::new(),
                grants: BTreeMap::new(),
                demand: BTreeMap::new(),
            },
        );
        Ok(SubscriptionState {
            rx,
            ready: ready_rx,
        })
    }
    fn control(&mut self, peer: EndpointId, control: Control) -> Result<()> {
        match control {
            Control::Subscribe { topic, sub, mode } => {
                let p = self.peers.get_mut(&peer).ok_or(Error::PeerUnavailable)?;
                let permitted = p.reg.cert.allows(&topic, false)
                    && self.cert.allows(&topic, true)
                    && self.drain.is_none();
                if !permitted {
                    Self::send(
                        p,
                        Control::Suback {
                            topic,
                            sub,
                            code: 1,
                        },
                    );
                    return Ok(());
                }
                if let Some(binding) = p.outbound.get(&topic)
                    && binding.sub == sub
                    && binding.mode == mode
                {
                    Self::send(
                        p,
                        Control::Suback {
                            topic,
                            sub,
                            code: 0,
                        },
                    );
                    return Ok(());
                }
                let ceiling = p.reg.cert.limits().max_subscriptions;
                if !p.outbound.contains_key(&topic)
                    && (p.outbound.len() >= self.config.max_topics
                        || p.outbound.len() >= p.reg.max_topics
                        || (ceiling != 0 && p.outbound.len() as u64 >= ceiling))
                {
                    Self::send(
                        p,
                        Control::Suback {
                            topic,
                            sub,
                            code: 2,
                        },
                    );
                    return Ok(());
                }
                let memory = self.metadata.reserve(2048)?;
                let (writer, rx) = crate::queue::channel(1, memory);
                let cancel = p.reg.cancel.child_token();
                let conn = p.reg.conn.clone();
                let tx = self.tx.clone();
                let session = p.reg.session;
                let child = cancel.clone();
                let timeout = self.config.handshake_timeout;
                self.tasks.spawn(async move {
                    transport::write_data(conn, session, rx, tx, child, timeout).await;
                });
                p.outbound.insert(
                    topic.clone(),
                    Binding {
                        sub,
                        mode,
                        credit: None,
                        requested: false,
                        writer,
                        cancel,
                    },
                );
                Self::send(
                    p,
                    Control::Suback {
                        topic,
                        sub,
                        code: 0,
                    },
                );
            }
            Control::Suback { topic, sub, code } => {
                if let Some(s) = self.subscriptions.get_mut(&topic)
                    && s.id == sub
                {
                    let result = match code {
                        0 => Ok(()),
                        1 => Err(Error::Unauthorized),
                        2 => Err(Error::QueueFull),
                        _ => return Err(Error::Protocol("SUBACK code")),
                    };
                    if result.is_ok() {
                        s.confirmed.insert(peer);
                    }
                    s.ready.send_modify(|map| {
                        map.insert(peer, result);
                    });
                }
            }
            Control::Unsubscribe { topic, sub } => {
                if let Some(p) = self.peers.get_mut(&peer)
                    && p.outbound.get(&topic).is_some_and(|b| b.sub == sub)
                {
                    p.outbound.remove(&topic);
                }
                let keys: Vec<_> = self
                    .pending
                    .keys()
                    .filter(|k| k.0 == peer && k.1 == sub && k.2.topic == topic)
                    .cloned()
                    .collect();
                for k in keys {
                    self.finish(&k, RecipientOutcome::Failed(Error::SubscriptionClosed));
                }
            }
            Control::RequestCredit { topic, sub, bytes } => {
                if bytes > self.config.max_payload + wire::MAX_METADATA + 12 {
                    return Err(Error::Protocol("credit request ceiling"));
                }
                if let Some(s) = self.subscriptions.get_mut(&topic)
                    && s.id == sub
                    && s.confirmed.contains(&peer)
                {
                    if bytes == 0 {
                        s.grants.remove(&peer);
                        s.demand.remove(&peer);
                    } else if !s.grants.contains_key(&peer) {
                        s.demand.insert(peer, bytes);
                    }
                    self.pool.budget.wake.notify_one();
                }
            }
            Control::Credit { topic, sub, bytes } => {
                let p = self.peers.get_mut(&peer).ok_or(Error::PeerUnavailable)?;
                if bytes > p.reg.max_payload + wire::MAX_METADATA + 12 || bytes == 0 {
                    return Err(Error::Protocol("credit byte ceiling"));
                }
                let pending = self
                    .pending
                    .keys()
                    .any(|k| k.0 == peer && k.1 == sub && k.2.topic == topic);
                // Old subscription credits can race with unsubscribe/recreate; never apply them to a new binding.
                if let Some(b) = p.outbound.get_mut(&topic)
                    && b.sub == sub
                {
                    if !b.requested || b.credit.replace(bytes).is_some() {
                        return Err(Error::Protocol("unsolicited or duplicate credit grant"));
                    }
                    b.requested = false;
                    if !pending {
                        b.credit = None;
                        Self::send(
                            p,
                            Control::RequestCredit {
                                topic,
                                sub,
                                bytes: 0,
                            },
                        );
                    }
                }
            }
            Control::Outcome {
                topic,
                sub,
                epoch,
                sequence,
                code,
            } => {
                let id = MessageId {
                    realm_id: self.config.trust.realm,
                    publisher_endpoint_id: self.endpoint.id(),
                    publisher_epoch: epoch,
                    topic,
                    sequence,
                };
                let key = (peer, sub, id);
                if !self.pending.contains_key(&key) && !self.terminal.contains_key(&key) {
                    return Err(Error::Protocol(
                        "acknowledgement for an unaddressed delivery",
                    ));
                }
                if let Some(p) = self.pending.get_mut(&key) {
                    if p.attempts == 0 {
                        return Err(Error::Protocol("ACK before DATA"));
                    }
                    match code {
                        0 => {
                            self.stats.processed += 1;
                            self.finish(&key, RecipientOutcome::Processed);
                        }
                        1 => {
                            p.next = Instant::now() + self.config.retry_interval;
                        }
                        2 => self.finish(&key, RecipientOutcome::PermanentNack),
                        _ => return Err(Error::Protocol("outcome")),
                    }
                }
            }
            Control::Error(_) => return Err(Error::Protocol("remote error")),
            Control::Goodbye => {
                // Stop new fan-out admissions; previously admitted deliveries may drain.
                if let Some(p) = self.peers.get_mut(&peer) {
                    p.reg.window_secs = 0;
                }
            }
        }
        Ok(())
    }
    fn publish(
        &mut self,
        topic: Topic,
        payload: PayloadLease,
        options: PublishOptions,
    ) -> Result<ReceiptDraft> {
        let now = self.local_valid()?;
        if self.drain.is_some() {
            return Err(Error::ShuttingDown);
        }
        if !self.cert.allows(&topic, true) {
            return Err(Error::Unauthorized);
        }
        if payload.len() > self.config.max_payload
            || (self.cert.limits().max_payload != 0
                && payload.len() as u64 > self.cert.limits().max_payload)
        {
            return Err(Error::MessageTooLarge);
        }
        if options.lifetime.as_secs() == 0
            || options.lifetime > self.config.delivery_window
            || options.format.len() > 256
        {
            return Err(Error::Config("publication lifetime or format"));
        }
        let recipients: Vec<_> = self
            .peers
            .iter()
            .filter_map(|(id, p)| {
                let binding = p.outbound.get(&topic)?;
                (binding.mode == options.mode
                    && p.reg.window_secs > 0
                    && self.config.trust.check(&p.reg.cert, *id, now).is_ok())
                .then_some((*id, binding.sub))
            })
            .collect();
        if recipients.is_empty() {
            return Err(Error::NoSubscribers);
        }
        if !self.sequences.contains_key(&topic) && self.sequences.len() >= self.config.max_topics {
            return Err(Error::QueueFull);
        }
        let sequence = self.sequences.entry(topic.clone()).or_insert(0);
        *sequence = sequence
            .checked_add(1)
            .ok_or(Error::Config("sequence exhausted"))?;
        let id = MessageId {
            realm_id: self.config.trust.realm,
            publisher_endpoint_id: self.endpoint.id(),
            publisher_epoch: self.epoch,
            topic,
            sequence: *sequence,
        };
        let envelope = Envelope {
            id: id.clone(),
            created: now,
            expires: now
                .checked_add(options.lifetime.as_secs())
                .ok_or(Error::Clock)?,
            format: options.format,
            len: payload.len(),
            digest: digest(payload.as_bytes()),
            mode: options.mode,
        };
        let signed = envelope.sign(&self.identity.0);
        let charge = payload.len() + signed.len() + 256;
        // Reserve all receipt records before any fan-out admission so a failed API call never hides an admitted recipient.
        let mut reservations = Vec::with_capacity(recipients.len());
        for _ in &recipients {
            reservations.push(Arc::new(self.metadata.reserve(signed.len() + 2048)?));
        }
        let mut entries = Vec::with_capacity(recipients.len());
        for ((peer, sub), memory) in recipients.into_iter().zip(reservations) {
            let p = &self.peers[&peer];
            let (outcome, rx) = watch::channel(RecipientOutcome::Pending);
            let reserve = (|| {
                if payload.len() > p.reg.max_payload
                    || (p.reg.cert.limits().max_payload != 0
                        && payload.len() as u64 > p.reg.cert.limits().max_payload)
                {
                    return Err(Error::MessageTooLarge);
                }
                if options.lifetime.as_secs() > p.reg.window_secs {
                    return Err(Error::Config("delivery window exceeds peer limit"));
                }
                Ok((p.slots.reserve(1)?, p.bytes.reserve(charge)?))
            })();
            match reserve {
                Ok((slot, bytes)) => {
                    self.pending.insert(
                        (peer, sub, id.clone()),
                        Pending {
                            recipient_certificate: p.reg.cert.clone(),
                            signed: signed.clone(),
                            envelope: envelope.clone(),
                            payload: payload.clone(),
                            outcome,
                            memory: memory.clone(),
                            _slot: slot,
                            _bytes: bytes,
                            deadline: Instant::now() + options.lifetime,
                            next: Instant::now(),
                            attempts: 0,
                            writing: false,
                        },
                    );
                    self.stats.admitted += 1;
                }
                Err(error) => {
                    let _ = outcome.send(RecipientOutcome::Rejected(error));
                    self.stats.rejected += 1;
                }
            }
            entries.push(ReceiptEntry {
                peer,
                rx,
                _memory: memory,
            });
        }
        self.schedule();
        Ok(ReceiptDraft { id, entries })
    }
    fn begin(
        &mut self,
        peer: EndpointId,
        session: Id,
        sub: Id,
        stream: u64,
        signed: &[u8],
        len: usize,
    ) -> Result<ReceiveTicket> {
        let p = self.peer_valid(peer, session)?;
        let envelope = Envelope::verify(signed, peer)?;
        let now = auth::now()?;
        if envelope.id.realm_id != self.config.trust.realm
            || !p.reg.cert.allows(&envelope.id.topic, true)
            || !self.cert.allows(&envelope.id.topic, false)
        {
            return Err(Error::Unauthorized);
        }
        if envelope.len != len
            || len > self.config.max_payload
            || (self.cert.limits().max_payload != 0 && len as u64 > self.cert.limits().max_payload)
            || (p.reg.cert.limits().max_payload != 0
                && len as u64 > p.reg.cert.limits().max_payload)
        {
            return Err(Error::MessageTooLarge);
        }
        if envelope.created > now.saturating_add(self.config.trust.clock_skew_secs)
            || envelope.expires - envelope.created > self.config.delivery_window.as_secs()
        {
            return Err(Error::DeliveryExpired);
        }
        let inbound = &mut self
            .peers
            .get_mut(&peer)
            .ok_or(Error::PeerUnavailable)?
            .inbound;
        if inbound
            .get(&envelope.id.topic)
            .is_some_and(|(existing_sub, existing_stream)| {
                *existing_sub == sub && *existing_stream != stream
            })
        {
            return Err(Error::Protocol("multiple streams for a topic binding"));
        }
        if !inbound.contains_key(&envelope.id.topic) && inbound.len() >= self.config.max_topics {
            return Err(Error::QueueFull);
        }
        inbound.insert(envelope.id.topic.clone(), (sub, stream));
        let local = self
            .subscriptions
            .get_mut(&envelope.id.topic)
            .ok_or(Error::SubscriptionClosed)?;
        if local.id != sub || local.mode != envelope.mode || !local.confirmed.contains(&peer) {
            return Err(Error::Unauthorized);
        }
        let grant = local
            .grants
            .remove(&peer)
            .ok_or(Error::Protocol("DATA without credit"))?;
        if len + wire::data(session, sub, signed).len() + 12 > grant.bytes {
            return Err(Error::Protocol("DATA exceeds credit"));
        }
        let fingerprint = digest(signed);
        if self
            .dedup
            .get(&(sub, envelope.id.clone()))
            .is_some_and(|d| d.fingerprint != fingerprint)
        {
            return Err(Error::Protocol("conflicting message identity"));
        }
        let mut metadata = grant.metadata;
        metadata.shrink_to(signed.len() + 2048);
        Ok(ReceiveTicket {
            envelope,
            fingerprint,
            permits: grant.permits,
            metadata,
        })
    }
    fn incoming(
        &mut self,
        peer: EndpointId,
        session: Id,
        sub: Id,
        ticket: ReceiveTicket,
        payload: PayloadLease,
    ) -> Result<()> {
        self.peer_valid(peer, session)?;
        let e = ticket.envelope;
        if !e.payload_matches(payload.as_bytes()) {
            return Err(Error::Protocol("payload digest"));
        }
        if auth::now()? >= e.expires
            || self
                .subscriptions
                .get(&e.id.topic)
                .is_none_or(|local| local.id != sub)
        {
            self.send_outcome(peer, sub, &e.id, 2);
            return Ok(());
        }
        let local = self.subscriptions.get_mut(&e.id.topic).unwrap();
        let key = (sub, e.id.clone());
        if let Some(existing) = self.dedup.get(&key) {
            if existing.fingerprint != ticket.fingerprint {
                return Err(Error::Protocol("conflicting message identity"));
            }
            match existing.state {
                DedupState::Processed => {
                    self.send_outcome(peer, sub, &e.id, 0);
                    return Ok(());
                }
                DedupState::Permanent => {
                    self.send_outcome(peer, sub, &e.id, 2);
                    return Ok(());
                }
                DedupState::Processing { .. } => return Ok(()),
                DedupState::Retryable => {}
            }
        }
        let disposition = Arc::new(AtomicU8::new(0));
        let (completion, rx) = watch::channel(None);
        let delivery = Delivery {
            message_id: e.id.clone(),
            format: e.format,
            payload: Some(payload),
            disposition: disposition.clone(),
            completion: rx,
            wake: self.pool.budget.wake.clone(),
        };
        let state = if local.tx.try_send(delivery).is_ok() {
            DedupState::Processing {
                disposition,
                completion,
            }
        } else {
            self.send_outcome(peer, sub, &e.id, 1);
            DedupState::Retryable
        };
        self.dedup.insert(
            key,
            Dedup {
                fingerprint: ticket.fingerprint,
                expires: e.expires,
                state,
                _memory: ticket.metadata,
            },
        );
        Ok(())
    }
    fn send_outcome(&self, peer: EndpointId, sub: Id, id: &MessageId, code: u64) {
        if let Some(p) = self.peers.get(&peer) {
            Self::send(
                p,
                Control::Outcome {
                    topic: id.topic.clone(),
                    sub,
                    epoch: id.publisher_epoch,
                    sequence: id.sequence,
                    code,
                },
            );
        }
    }
    fn finish(&mut self, key: &Key, outcome: RecipientOutcome) {
        if let Some(p) = self.pending.remove(key) {
            if p.attempts > 0 {
                self.terminal.insert(
                    key.clone(),
                    TerminalReceipt {
                        expires: p
                            .envelope
                            .expires
                            .saturating_add(self.config.handshake_timeout.as_secs().max(1)),
                        _memory: p.memory.clone(),
                    },
                );
            }
            let _ = p.outcome.send(outcome);
        }
    }
    fn schedule(&mut self) {
        let now = Instant::now();
        for (key, pending) in &mut self.pending {
            if pending.writing
                || pending.next > now
                || pending.deadline <= now
                || auth::now().is_ok_and(|t| t >= pending.envelope.expires)
            {
                continue;
            }
            let Some(peer) = self.peers.get_mut(&key.0) else {
                continue;
            };
            let Some(binding) = peer.outbound.get_mut(&key.2.topic) else {
                continue;
            };
            if binding.sub != key.1 || binding.mode != pending.envelope.mode {
                continue;
            }
            let Some(credit) = binding.credit else {
                if !binding.requested {
                    let bytes = wire::data(peer.reg.session, key.1, &pending.signed).len()
                        + 12
                        + pending.payload.len();
                    if peer
                        .reg
                        .control
                        .try_send(Control::RequestCredit {
                            topic: key.2.topic.clone(),
                            sub: key.1,
                            bytes,
                        })
                        .is_ok()
                    {
                        binding.requested = true;
                    } else {
                        peer.reg.cancel.cancel();
                    }
                }
                continue;
            };
            let charge = wire::data(peer.reg.session, key.1, &pending.signed).len()
                + 12
                + pending.payload.len();
            if charge > credit {
                continue;
            }
            let item = DataOut {
                key: key.clone(),
                signed: pending.signed.clone(),
                payload: pending.payload.clone(),
                _memory: pending.memory.clone(),
            };
            if binding.writer.try_send(item).is_ok() {
                binding.credit = None;
                pending.writing = true;
                if pending.attempts > 0 {
                    self.stats.retried += 1;
                }
                pending.attempts = pending.attempts.saturating_add(1);
                let factor = 1u32 << pending.attempts.saturating_sub(1).min(5);
                let jitter = Duration::from_millis(rand::random::<u16>() as u64 % 100);
                pending.next = now + self.config.retry_interval.saturating_mul(factor) + jitter;
            }
        }
    }
    fn grant_credits(&mut self) {
        if self.local_valid().is_err() {
            return;
        }
        let mut candidates = Vec::new();
        for (topic, s) in &self.subscriptions {
            for peer in s.demand.keys() {
                if s.confirmed.contains(peer) && !s.grants.contains_key(peer) {
                    candidates.push((topic.clone(), *peer));
                }
            }
        }
        if candidates.is_empty() {
            return;
        }
        let n = candidates.len();
        candidates.rotate_left(self.credit_cursor % n);
        self.credit_cursor = self.credit_cursor.wrapping_add(1);
        for (topic, peer_id) in candidates {
            let Some(p) = self.peers.get(&peer_id) else {
                continue;
            };
            let s = self.subscriptions.get_mut(&topic).unwrap();
            let max_payload = self.config.max_payload.min(p.reg.max_payload);
            let bytes = max_payload + wire::MAX_METADATA + 12;
            let permits = (|| {
                // Reserve replay tracking before payload memory, so a granted frame
                // cannot fail admission for lack of its deduplication record.
                let metadata = self.metadata.reserve(6144)?;
                Ok::<_, Error>((
                    vec![
                        s.slots.reserve(1)?,
                        s.bytes.reserve(bytes)?,
                        self.metadata.reserve(256)?,
                        self.pool
                            .budget
                            .reserve(max_payload + crate::buffer::PAYLOAD_OVERHEAD)?,
                    ],
                    metadata,
                ))
            })();
            if let Ok((permits, metadata)) = permits {
                s.demand.remove(&peer_id);
                s.grants.insert(
                    peer_id,
                    Grant {
                        bytes,
                        permits,
                        metadata,
                    },
                );
                Self::send(
                    p,
                    Control::Credit {
                        topic,
                        sub: s.id,
                        bytes,
                    },
                );
            }
        }
    }
    fn maintenance(&mut self) {
        let now = match auth::now() {
            Ok(n) => n,
            Err(_) => {
                self.clock_failed = true;
                0
            }
        };
        let expected = self
            .clock_start
            .0
            .saturating_add(self.clock_start.1.elapsed().as_secs());
        if now.abs_diff(expected) > 30 {
            self.clock_failed = true;
        }
        let local_error = self.local_valid().err();
        let stale: Vec<_> = self
            .peers
            .iter()
            .filter_map(|(id, p)| {
                (local_error.is_some()
                    || self.config.trust.check(&p.reg.cert, *id, now).is_err()
                    || p.reg.cancel.is_cancelled()
                    || p.reg.conn.close_reason().is_some())
                .then_some(*id)
            })
            .collect();
        for peer in stale {
            self.remove_peer(peer);
        }
        let closed: Vec<_> = self
            .subscriptions
            .iter()
            .filter_map(|(t, s)| s.tx.is_closed().then_some(t.clone()))
            .collect();
        for topic in closed {
            if let Some(s) = self.subscriptions.remove(&topic) {
                for p in self.peers.values_mut() {
                    p.inbound.remove(&topic);
                    Self::send(
                        p,
                        Control::Unsubscribe {
                            topic: topic.clone(),
                            sub: s.id,
                        },
                    );
                }
            }
        }
        let mut outcomes = Vec::new();
        for ((sub, id), d) in &mut self.dedup {
            if let DedupState::Processing {
                disposition,
                completion,
            } = &d.state
            {
                let code = disposition.load(Ordering::Acquire);
                if local_error.is_some() || now >= d.expires {
                    let _ = completion.send(Some(Err(local_error
                        .clone()
                        .unwrap_or(Error::DeliveryExpired))));
                    d.state = DedupState::Permanent;
                } else if code != 0 {
                    let _ = completion.send(Some(Ok(())));
                    d.state = match code {
                        1 => DedupState::Processed,
                        2 => DedupState::Retryable,
                        _ => DedupState::Permanent,
                    };
                    outcomes.push((
                        id.publisher_endpoint_id,
                        *sub,
                        id.clone(),
                        match code {
                            1 => 0,
                            2 => 1,
                            _ => 2,
                        },
                    ));
                }
            }
        }
        for (peer, sub, id, code) in outcomes {
            self.send_outcome(peer, sub, &id, code);
        }
        self.dedup.retain(|_, d| now < d.expires);
        self.terminal.retain(|_, receipt| now < receipt.expires);
        let finished: Vec<_> = self
            .pending
            .iter()
            .filter_map(|(key, p)| {
                let error = if let Some(e) = &local_error {
                    Some(e.clone())
                } else if !self.cert.allows(&key.2.topic, true) {
                    Some(Error::Unauthorized)
                } else if p.deadline <= Instant::now() || now >= p.envelope.expires {
                    Some(Error::DeliveryExpired)
                } else if let Err(error) =
                    self.config
                        .trust
                        .check(&p.recipient_certificate, key.0, now)
                {
                    Some(error)
                } else if !p.recipient_certificate.allows(&key.2.topic, false) {
                    Some(Error::Unauthorized)
                } else if let Some(peer) = self.peers.get(&key.0) {
                    if !peer.reg.cert.allows(&key.2.topic, false) {
                        Some(Error::Unauthorized)
                    } else if peer
                        .outbound
                        .get(&key.2.topic)
                        .is_some_and(|b| b.sub != key.1 || b.mode != p.envelope.mode)
                    {
                        Some(Error::SubscriptionClosed)
                    } else {
                        None
                    }
                } else {
                    None
                };
                error.map(|e| (key.clone(), e))
            })
            .collect();
        for (key, error) in finished {
            if error == Error::DeliveryExpired {
                self.stats.expired += 1;
            }
            self.finish(&key, RecipientOutcome::Failed(error));
        }
        for (peer_id, peer) in &mut self.peers {
            let mut returns = Vec::new();
            for (topic, binding) in &mut peer.outbound {
                if binding.credit.is_some()
                    && !self
                        .pending
                        .keys()
                        .any(|k| k.0 == *peer_id && k.1 == binding.sub && &k.2.topic == topic)
                {
                    binding.credit = None;
                    returns.push(Control::RequestCredit {
                        topic: topic.clone(),
                        sub: binding.sub,
                        bytes: 0,
                    });
                }
            }
            for control in returns {
                Self::send(peer, control);
            }
        }
        self.peer_budgets
            .retain(|id, _| self.peers.contains_key(id) || self.pending.keys().any(|k| &k.0 == id));
        self.grant_credits();
        self.schedule();
    }
    fn metrics(&self) -> Metrics {
        let mut s = self.stats.clone();
        s.peers = self.peers.len();
        s.pending_deliveries = self.pending.len();
        s.deduplication_records = self.dedup.len();
        s.terminal_receipts = self.terminal.len();
        s.resident_payload_bytes = self.pool.resident_bytes();
        s.metadata_bytes = self.metadata.used();
        s.peak_payload_bytes = self.pool.budget.peak();
        s.peak_metadata_bytes = self.metadata.peak();
        s.outstanding_credits = self.subscriptions.values().map(|s| s.grants.len()).sum();
        s
    }
}
