use super::owner::{Command, DataOut, Registration};
use super::*;
use crate::{
    buffer::Budget,
    error::transport as io_error,
    wire::{self, Control},
};
use iroh::endpoint::{Connection, Incoming, QuicTransportConfig, RecvStream, SendStream, presets};
use tokio::{task::JoinSet, time::timeout};
const ALPN: &[u8] = b"iroh-mq/1";

pub(super) async fn bind(config: &Config, identity: &Identity) -> Result<Endpoint> {
    bind_protocol(config, identity, ALPN).await
}
pub(crate) async fn bind_protocol(
    config: &Config,
    identity: &Identity,
    alpn: &[u8],
) -> Result<Endpoint> {
    let transport = QuicTransportConfig::builder()
        .max_concurrent_bidi_streams(1u32.into())
        .max_concurrent_uni_streams((config.max_topics as u32).into())
        .stream_receive_window((2 * 1024 * 1024u32).into())
        .receive_window((4 * 1024 * 1024u32).into())
        .send_window(4 * 1024 * 1024)
        .datagram_receive_buffer_size(None)
        .datagram_send_buffer_size(0)
        .build();
    let mut builder = if matches!(config.relay_mode, RelayMode::Default) {
        Endpoint::builder(presets::N0)
    } else {
        Endpoint::builder(presets::Minimal)
    };
    builder = builder
        .secret_key(identity.0.clone())
        .alpns(vec![alpn.to_vec(), crate::join::ALPN.to_vec()])
        .relay_mode(config.relay_mode.clone())
        .transport_config(transport);
    if config.relay_only {
        builder = builder.clear_ip_transports();
    }
    if let Some(addr) = config.bind_addr.filter(|_| !config.relay_only) {
        builder = builder.bind_addr(addr).map_err(io_error)?;
    }
    builder.bind().await.map_err(io_error)
}
struct Close(Connection);
impl Drop for Close {
    fn drop(&mut self) {
        self.0.close(0u32.into(), b"messaging session ended");
    }
}
#[allow(clippy::too_many_arguments)]
pub(super) async fn connect(
    endpoint: Endpoint,
    address: EndpointAddr,
    config: EndpointConfig,
    cert: Certificate,
    tx: mpsc::Sender<Command>,
    stop: CancellationToken,
    metadata: Arc<Budget>,
    reply: oneshot::Sender<Result<()>>,
) {
    let connection = tokio::select! {_=stop.cancelled()=>Err(Error::ShuttingDown),r=timeout(config.handshake_timeout,endpoint.connect(address,ALPN))=>r.map_err(|_|Error::Timeout).and_then(|r|r.map_err(io_error))};
    match connection {
        Ok(conn) => run(conn, true, config, cert, tx, stop, metadata, Some(reply)).await,
        Err(e) => {
            let _ = reply.send(Err(e));
        }
    }
}
pub(super) async fn incoming(
    incoming: Incoming,
    config: EndpointConfig,
    cert: Certificate,
    tx: mpsc::Sender<Command>,
    stop: CancellationToken,
    metadata: Arc<Budget>,
) {
    let Ok(accepting) = incoming.accept() else {
        return;
    };
    let connection = tokio::select! {_=stop.cancelled()=>return,r=timeout(config.handshake_timeout,accepting)=>r};
    if let Ok(Ok(conn)) = connection {
        if conn.alpn() == crate::join::ALPN {
            let _close = Close(conn.clone());
            tokio::select! {
                _ = stop.cancelled() => {},
                _ = timeout(config.handshake_timeout, crate::join::serve(conn, tx)) => {},
            }
        } else {
            run(conn, false, config, cert, tx, stop, metadata, None).await;
        }
    }
}
async fn read_small(recv: &mut RecvStream, expected: u8) -> Result<Vec<u8>> {
    let h = wire::read_header(recv, 0)
        .await?
        .ok_or(Error::PeerUnavailable)?;
    if h.kind != expected {
        return Err(Error::Protocol("handshake frame order"));
    }
    let mut bytes = vec![0; h.metadata];
    recv.read_exact(&mut bytes).await.map_err(io_error)?;
    Ok(bytes)
}
struct Handshake {
    send: SendStream,
    recv: RecvStream,
    hello: wire::Hello,
    cert: Certificate,
    session: Id,
    dialer: EndpointId,
    nonce: Id,
}
async fn handshake(
    conn: &Connection,
    dialing: bool,
    config: &EndpointConfig,
    cert: &Certificate,
) -> Result<Handshake> {
    if conn.alpn() != ALPN {
        return Err(Error::Protocol("ALPN"));
    }
    let (mut send, mut recv) = if dialing {
        conn.open_bi().await.map_err(io_error)?
    } else {
        conn.accept_bi().await.map_err(io_error)?
    };
    let nonce: Id = rand::random();
    let local = wire::hello(
        cert.as_bytes(),
        nonce,
        config.max_payload,
        config.max_topics,
        config.delivery_window.as_secs(),
    );
    let remote = if dialing {
        wire::write_frame(&mut send, wire::HELLO, &local, &[]).await?;
        read_small(&mut recv, wire::HELLO).await?
    } else {
        let remote = read_small(&mut recv, wire::HELLO).await?;
        // Validate before returning our certificate to an inbound peer.
        let hello = wire::parse_hello(&remote)?;
        let remote_cert = Certificate::from_bytes(&hello.cert)?;
        config
            .trust
            .verify(&remote_cert, conn.remote_id(), auth::now()?)?;
        wire::write_frame(&mut send, wire::HELLO, &local, &[]).await?;
        remote
    };
    let hello = wire::parse_hello(&remote)?;
    let remote_cert = Certificate::from_bytes(&hello.cert)?;
    config
        .trust
        .verify(&remote_cert, conn.remote_id(), auth::now()?)?;
    wire::write_frame(
        &mut send,
        wire::READY,
        &wire::ready(nonce, hello.nonce),
        &[],
    )
    .await?;
    if read_small(&mut recv, wire::READY).await? != wire::ready(hello.nonce, nonce) {
        return Err(Error::Protocol("READY binding"));
    }
    let (dialer, dial_nonce) = if dialing {
        (cert.endpoint_id(), nonce)
    } else {
        (conn.remote_id(), hello.nonce)
    };
    let mut session = [0; 16];
    conn.export_keying_material(&mut session, b"iroh-mq/session/v1", &config.trust.realm)
        .map_err(|_| Error::Protocol("session exporter"))?;
    Ok(Handshake {
        send,
        recv,
        hello,
        cert: remote_cert,
        session,
        dialer,
        nonce: dial_nonce,
    })
}
#[allow(clippy::too_many_arguments)]
async fn run(
    conn: Connection,
    dialing: bool,
    config: EndpointConfig,
    cert: Certificate,
    tx: mpsc::Sender<Command>,
    stop: CancellationToken,
    metadata: Arc<Budget>,
    mut connected: Option<oneshot::Sender<Result<()>>>,
) {
    let _close = Close(conn.clone());
    let peer = conn.remote_id();
    let result = tokio::select! {_=stop.cancelled()=>Err(Error::ShuttingDown),r=timeout(config.handshake_timeout,handshake(&conn,dialing,&config,&cert))=>r.map_err(|_|Error::Timeout).and_then(|v|v)};
    let h = match result {
        Ok(h) => h,
        Err(e) => {
            if let Some(reply) = connected.take() {
                let _ = reply.send(Err(e));
            }
            return;
        }
    };
    let session = h.session;
    let cancel = stop.child_token();
    let _cancel_guard = cancel.clone().drop_guard();
    let (control, mut control_rx) = mpsc::channel(64);
    let (accepted, rx) = oneshot::channel();
    let registration = Registration {
        conn: conn.clone(),
        cert: h.cert,
        session,
        dialer: h.dialer,
        nonce: h.nonce,
        control,
        cancel: cancel.clone(),
        max_payload: h.hello.max_payload,
        max_topics: h.hello.max_topics,
        window_secs: h.hello.window_secs,
    };
    if tx
        .send(Command::Register {
            registration,
            accepted,
            connected,
        })
        .await
        .is_err()
    {
        return;
    }
    if !rx.await.unwrap_or(false) {
        return;
    }
    let mut children = JoinSet::new();
    let mut send = h.send;
    let write_cancel = cancel.clone();
    let write_timeout = config.handshake_timeout;
    children.spawn(async move {
        let result = async {
            while let Some(c) = control_rx.recv().await {
                let (kind, metadata) = c.encode(session);
                timeout(
                    write_timeout,
                    wire::write_frame(&mut send, kind, &metadata, &[]),
                )
                .await
                .map_err(|_| Error::Timeout)??;
            }
            Ok::<(), Error>(())
        };
        tokio::select! {_=write_cancel.cancelled()=>{},_=result=>{write_cancel.cancel();}}
    });
    let read_cancel = cancel.clone();
    let read_tx = tx.clone();
    let read_meta = metadata.clone();
    let mut recv = h.recv;
    children.spawn(async move {
        let result = async {
            let mut count = 0usize;
            let mut start = Instant::now();
            while let Some(header) = wire::read_header(&mut recv, 0).await? {
                if start.elapsed() >= Duration::from_secs(1) {
                    start = Instant::now();
                    count = 0;
                }
                count += 1;
                if count > 8192 {
                    return Err(Error::Protocol("control rate limit"));
                }
                let memory = read_meta.reserve(header.metadata * 2 + 1024)?;
                let mut bytes = vec![0; header.metadata];
                timeout(write_timeout, recv.read_exact(&mut bytes))
                    .await
                    .map_err(|_| Error::Timeout)?
                    .map_err(io_error)?;
                let control = Control::decode(header.kind, &bytes, session)?;
                read_tx
                    .send(Command::Remote {
                        peer,
                        session,
                        control,
                        _memory: memory,
                    })
                    .await
                    .map_err(|_| Error::ShuttingDown)?;
            }
            Ok::<(), Error>(())
        };
        tokio::select! {_=read_cancel.cancelled()=>{},_=result=>{read_cancel.cancel();}}
    });
    let mut active = 0usize;
    let mut stream_generation = 0u64;
    loop {
        tokio::select! {
            _=cancel.cancelled()=>break,
            _=conn.closed()=>break,
            stream=conn.accept_uni()=>{
                let Ok(stream)=stream else{break;};if active>=config.max_topics {break;}active+=1;stream_generation+=1;let stream_id=stream_generation;
                let tx=tx.clone();let meta=metadata.clone();let stop=cancel.clone();let max=config.max_payload;
                children.spawn(async move {let _=read_data(stream,stream_id,peer,session,max,tx,meta,stop.clone(),write_timeout).await.map_err(|_|stop.cancel());});
            },
            Some(_)=children.join_next()=>{active=active.saturating_sub(1);},
        }
    }
    cancel.cancel();
    children.abort_all();
    while children.join_next().await.is_some() {}
    let _ = tx.send(Command::End { peer, session }).await;
}
#[allow(clippy::too_many_arguments)]
async fn read_data(
    mut recv: RecvStream,
    stream: u64,
    peer: EndpointId,
    session: Id,
    max: usize,
    tx: mpsc::Sender<Command>,
    metadata: Arc<Budget>,
    stop: CancellationToken,
    read_timeout: Duration,
) -> Result<()> {
    let mut binding = None;
    loop {
        let header = tokio::select! {_=stop.cancelled()=>return Ok(()),h=wire::read_header(&mut recv,max)=>h?};
        let Some(header) = header else {
            return Ok(());
        };
        if header.kind != wire::DATA {
            return Err(Error::Protocol("non-DATA on data stream"));
        }
        let memory = metadata.reserve(header.metadata * 2 + 1024)?;
        let mut bytes = vec![0; header.metadata];
        timeout(read_timeout, recv.read_exact(&mut bytes))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(io_error)?;
        let (sub, signed) = wire::parse_data(&bytes, session)?;
        drop(bytes);
        let (reply, rx) = oneshot::channel();
        tx.send(Command::Begin {
            stream,
            peer,
            session,
            sub,
            signed,
            len: header.payload,
            reply,
            _memory: memory,
        })
        .await
        .map_err(|_| Error::ShuttingDown)?;
        let mut ticket = match rx.await.map_err(|_| Error::ShuttingDown)? {
            Ok(ticket) => ticket,
            Err(Error::SubscriptionClosed) => {
                let _ = recv.stop(1u32.into());
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        let this_binding = (sub, ticket.envelope.id.topic.clone());
        if binding.as_ref().is_some_and(|b| b != &this_binding) {
            return Err(Error::Protocol("data stream binding changed"));
        }
        binding = Some(this_binding);
        let mut payload = vec![0; header.payload];
        timeout(read_timeout, recv.read_exact(&mut payload))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(io_error)?;
        let payload = PayloadLease::received(payload, std::mem::take(&mut ticket.permits));
        tx.send(Command::Incoming {
            peer,
            session,
            sub,
            ticket,
            payload,
        })
        .await
        .map_err(|_| Error::ShuttingDown)?;
    }
}
pub(super) async fn write_data(
    conn: Connection,
    session: Id,
    mut rx: crate::queue::Receiver<DataOut>,
    tx: mpsc::Sender<Command>,
    cancel: CancellationToken,
    write_timeout: Duration,
) {
    let run = async {
        let mut send = conn.open_uni().await.map_err(io_error)?;
        while let Some(item) = rx.recv().await {
            let metadata = wire::data(session, item.key.1, &item.signed);
            let mut result = timeout(
                write_timeout,
                wire::write_frame(&mut send, wire::DATA, &metadata, item.payload.as_bytes()),
            )
            .await
            .map_err(|_| Error::Timeout)
            .and_then(|r| r);
            if result.is_err()
                && matches!(timeout(write_timeout, send.stopped()).await, Ok(Ok(Some(code))) if code == 1u32.into())
            {
                result = Err(Error::SubscriptionClosed);
            }
            let failure = result.clone().err();
            tx.send(Command::Sent {
                key: item.key,
                session,
                result,
            })
            .await
            .map_err(|_| Error::ShuttingDown)?;
            if let Some(error) = failure {
                return Err(error);
            }
        }
        let _ = send.finish();
        Ok::<(), Error>(())
    };
    tokio::select! {
        _=cancel.cancelled()=>{},
        result=run=>{ if result.is_err() && result != Err(Error::SubscriptionClosed) {
            conn.close(0u32.into(), b"data writer failed");
            let _ = tx.send(Command::End { peer: conn.remote_id(), session }).await;
        }}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn settings() -> Config {
        let mut c = Config::new();
        c.relay_mode = RelayMode::Disabled;
        c.bind_addr = Some("127.0.0.1:0".parse().unwrap());
        c
    }
    #[tokio::test]
    async fn stolen_joined_certificate_fails_the_real_mutual_handshake() {
        let host = MessagingEndpoint::host(settings(), Identity::generate(), vec![])
            .await
            .unwrap();
        let code = host
            .issue_join_code(JoinOptions::new(vec![]))
            .await
            .unwrap();
        let victim = MessagingEndpoint::join(settings(), Identity::generate(), &code)
            .await
            .unwrap();
        let stolen = victim.certificate();
        victim.shutdown(ShutdownMode::Immediate).await.unwrap();
        let config = EndpointConfig {
            settings: settings(),
            trust: host.handle.config.trust.clone(),
        };
        let thief = bind(&config, &Identity::generate()).await.unwrap();
        let conn = thief.connect(code.address, ALPN).await.unwrap();
        assert!(
            timeout(
                Duration::from_secs(3),
                handshake(&conn, true, &config, &stolen)
            )
            .await
            .unwrap()
            .is_err()
        );
        thief.close().await;
        host.shutdown(ShutdownMode::Immediate).await.unwrap();
    }
    #[tokio::test]
    async fn root_signed_certificate_without_join_registration_is_rejected() {
        let root = Authority::generate();
        let key = Identity::generate();
        let now = auth::now().unwrap();
        let cert = root
            .issue(
                key.endpoint_id(),
                vec![],
                now,
                now + 60,
                CertificateLimits::default(),
            )
            .unwrap();
        let unregistered = Identity::generate();
        let unauthorized = root
            .issue(
                unregistered.endpoint_id(),
                vec![],
                now,
                now + 60,
                CertificateLimits::default(),
            )
            .unwrap();
        let config = EndpointConfig {
            settings: settings(),
            trust: root.trust(),
        };
        let endpoint = bind(&config, &key).await.unwrap();
        let host = MessagingEndpoint::start_bound(
            config.clone(),
            key,
            cert,
            endpoint,
            crate::join::Admission::host(root),
            None,
        )
        .await
        .unwrap();
        let raw = bind(&config, &unregistered).await.unwrap();
        let conn = raw
            .connect(host.handle.endpoint.addr(), ALPN)
            .await
            .unwrap();
        let _ = handshake(&conn, true, &config, &unauthorized).await;
        timeout(Duration::from_secs(3), conn.closed())
            .await
            .unwrap();
        assert_eq!(host.metrics().await.unwrap().peers, 0);
        raw.close().await;
        host.shutdown(ShutdownMode::Immediate).await.unwrap();
    }
    #[tokio::test]
    async fn acknowledgement_for_an_unaddressed_delivery_closes_joined_session() {
        let host = MessagingEndpoint::host(settings(), Identity::generate(), vec![])
            .await
            .unwrap();
        let code = host
            .issue_join_code(JoinOptions::new(vec![]))
            .await
            .unwrap();
        let config = EndpointConfig {
            settings: settings(),
            trust: host.handle.config.trust.clone(),
        };
        let raw = bind(&config, &Identity::generate()).await.unwrap();
        let cert = crate::join::redeem(&raw, &config, &code, Some(&config.trust))
            .await
            .unwrap()
            .certificate;
        // A lost enrollment response can be recovered by the same authenticated key.
        let recovered = crate::join::redeem(&raw, &config, &code, Some(&config.trust))
            .await
            .unwrap()
            .certificate;
        assert_eq!(cert.id(), recovered.id());
        let conn = raw.connect(code.address, ALPN).await.unwrap();
        let mut h = handshake(&conn, true, &config, &cert).await.unwrap();
        let (kind, bytes) = Control::Outcome {
            topic: Topic::new("jobs").unwrap(),
            sub: [1; 16],
            epoch: [2; 16],
            sequence: 1,
            code: 0,
        }
        .encode(h.session);
        wire::write_frame(&mut h.send, kind, &bytes, &[])
            .await
            .unwrap();
        timeout(Duration::from_secs(3), conn.closed())
            .await
            .unwrap();
        raw.close().await;
        host.shutdown(ShutdownMode::Immediate).await.unwrap();
    }
    #[tokio::test]
    async fn members_cannot_connect_to_other_members_without_a_host_join() {
        let host = MessagingEndpoint::host(settings(), Identity::generate(), vec![])
            .await
            .unwrap();
        let code = host
            .issue_join_code(JoinOptions::new(vec![]))
            .await
            .unwrap();
        let b = MessagingEndpoint::join(settings(), Identity::generate(), &code)
            .await
            .unwrap();
        let config = EndpointConfig {
            settings: settings(),
            trust: host.handle.config.trust.clone(),
        };
        let raw = bind(&config, &Identity::generate()).await.unwrap();
        let cert = crate::join::redeem(&raw, &config, &code, Some(&config.trust))
            .await
            .unwrap()
            .certificate;
        let conn = raw.connect(b.handle.endpoint.addr(), ALPN).await.unwrap();
        let _ = handshake(&conn, true, &config, &cert).await;
        timeout(Duration::from_secs(3), conn.closed())
            .await
            .unwrap();
        assert_eq!(b.metrics().await.unwrap().peers, 1);
        raw.close().await;
        b.shutdown(ShutdownMode::Immediate).await.unwrap();
        host.shutdown(ShutdownMode::Immediate).await.unwrap();
    }
}
