//! Single-use enrollment with ESP's serialized grant/consume logic and messaging-specific claims.
use crate::{
    auth::{MAX_CERT, MAX_PERMISSIONS, now, version},
    buffer::{Budget, Permit},
    cbor::{Reader, Writer},
    endpoint::transport::bind_protocol,
    error::transport,
    message::digest,
    wire, *,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tokio::{
    sync::{Semaphore, mpsc, oneshot, watch},
    task::JoinSet,
    time::timeout,
};
use tokio_util::sync::CancellationToken;
const ALPN: &[u8] = b"iroh-mq/enrollment/1";

#[derive(Clone)]
pub struct EnrollmentInvite {
    pub contact: PeerInvite,
    pub expires_at: u64,
    id: [u8; 16],
    secret: [u8; 32],
}
impl std::fmt::Debug for EnrollmentInvite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrollmentInvite")
            .field("contact", &self.contact)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}
impl EnrollmentInvite {
    /// Contains a bearer secret. Deliver through a trusted channel and never log this encoding.
    pub fn encode(&self) -> Result<String> {
        let mut w = Writer::new();
        w.array(5);
        w.u(1);
        w.text(&self.contact.encode()?);
        w.u(self.expires_at);
        w.bytes(&self.id);
        w.bytes(&self.secret);
        Ok(URL_SAFE_NO_PAD.encode(w.finish()))
    }
    pub fn decode(code: &str) -> Result<Self> {
        if code.len() > 32768 {
            return Err(Error::MessageTooLarge);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(code)
            .map_err(|_| Error::Protocol("enrollment invitation"))?;
        let mut r = Reader::new(&bytes);
        r.array(5)?;
        version(r.u()?)?;
        let contact = PeerInvite::decode(r.text(24576)?)?;
        let expires_at = r.u()?;
        let id = r.fixed()?;
        let secret = r.fixed()?;
        r.end()?;
        let invite = Self {
            contact,
            expires_at,
            id,
            secret,
        };
        if invite.encode()? != code {
            return Err(Error::Protocol("noncanonical enrollment invite"));
        }
        Ok(invite)
    }
    /// The caller's configured root must match the invite's root. The inviter cannot replace it.
    pub async fn redeem(&self, identity: &Identity, config: &Config) -> Result<Certificate> {
        if config.trust.realm_id() != self.contact.realm_id
            || config.trust.root() != self.contact.authority
        {
            return Err(Error::Unauthorized);
        }
        if now()? >= self.expires_at {
            return Err(Error::CertificateExpired);
        }
        let endpoint = bind_protocol(config, identity, ALPN).await?;
        let result = timeout(config.handshake_timeout, async {
            let conn = endpoint
                .connect(self.contact.address.clone(), ALPN)
                .await
                .map_err(transport)?;
            let (mut send, mut recv) = conn.open_bi().await.map_err(transport)?;
            let mut w = Writer::new();
            w.array(3);
            w.u(1);
            w.bytes(&self.id);
            w.bytes(&self.secret);
            wire::write_frame(&mut send, wire::HELLO, &w.finish(), &[]).await?;
            let h = wire::read_header(&mut recv, 0)
                .await?
                .ok_or(Error::PeerUnavailable)?;
            if h.kind != wire::READY {
                return Err(Error::Unauthorized);
            }
            let mut bytes = vec![0; h.metadata];
            recv.read_exact(&mut bytes).await.map_err(transport)?;
            let mut r = Reader::new(&bytes);
            r.array(2)?;
            version(r.u()?)?;
            let cert = Certificate::from_bytes(r.bytes(MAX_CERT)?)?;
            r.end()?;
            config.trust.verify(&cert, identity.endpoint_id(), now()?)?;
            conn.close(0u32.into(), b"enrolled");
            Ok(cert)
        })
        .await
        .map_err(|_| Error::Timeout)
        .and_then(|r| r);
        endpoint.close().await;
        result
    }
}
struct Grant {
    hash: [u8; 32],
    expires: u64,
    valid_for: u64,
    permissions: Vec<Permission>,
    limits: CertificateLimits,
    redeemed: Option<(EndpointId, Certificate)>,
    _memory: Permit,
}
enum Command {
    Invite {
        permissions: Vec<Permission>,
        limits: CertificateLimits,
        valid_for: Duration,
        lifetime: Duration,
        reply: oneshot::Sender<Result<EnrollmentInvite>>,
    },
    Redeem {
        peer: EndpointId,
        id: [u8; 16],
        secret: [u8; 32],
        reply: oneshot::Sender<Result<Certificate>>,
    },
}
/// In-memory, bounded enrollment authority. Restart invalidates outstanding invitations.
/// The service's transport key must differ from its root signing key.
pub struct EnrollmentService {
    tx: mpsc::Sender<Command>,
    stop: CancellationToken,
    done: watch::Receiver<bool>,
}
impl Drop for EnrollmentService {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}
impl EnrollmentService {
    pub async fn start(authority: Authority, identity: Identity, config: Config) -> Result<Self> {
        if authority.public_key() == identity.endpoint_id()
            || config.trust.root() != authority.public_key()
            || config.trust.realm_id() != authority.realm_id()
        {
            return Err(Error::Config("enrollment root and transport identity"));
        }
        if config.max_peers == 0
            || config.max_peers > 256
            || config.max_topics == 0
            || config.max_topics > 256
            || config.metadata_bytes < 256 * 1024
            || config.handshake_timeout.is_zero()
        {
            return Err(Error::Config("enrollment limits"));
        }
        let endpoint = bind_protocol(&config, &identity, ALPN).await?;
        // Relay-only contacts must contain usable relay material before issuing invitations.
        if config.relay_only {
            timeout(config.handshake_timeout, endpoint.online())
                .await
                .map_err(|_| Error::Timeout)?;
        }
        let (tx, mut rx) = mpsc::channel(64);
        let actor_tx = tx.clone();
        let stop = CancellationToken::new();
        let cancel = stop.clone();
        let (done_tx, done) = watch::channel(false);
        tokio::spawn(async move {
            let budget = Budget::new(config.metadata_bytes);
            let quota = Arc::new(Semaphore::new(config.max_peers));
            let mut tasks = JoinSet::new();
            let mut grants: BTreeMap<[u8; 16], Grant> = BTreeMap::new();
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            let mut attempts = 0usize;
            loop {
                tokio::select! {
                    _=cancel.cancelled()=>break,
                    _=tick.tick()=>{if let Ok(t)=now(){grants.retain(|_,g|g.expires>t);}attempts=0;},
                    Some(command)=rx.recv()=>match command {
                        Command::Invite {permissions,limits,valid_for,lifetime,reply}=>{
                            let result=(||{
                                let t=now()?;
                                if grants.len()>=config.max_topics{return Err(Error::QueueFull);}
                                if permissions.len()>MAX_PERMISSIONS || lifetime.as_secs()==0 || lifetime.as_secs()>86400 || valid_for.as_secs()==0 || valid_for.as_secs()>86400{return Err(Error::Config("invitation limits"));}
                                // Validate and bound the predetermined grant before storing invitation state.
                                authority.issue(identity.endpoint_id(),permissions.clone(),t,t+valid_for.as_secs(),limits)?;
                                let memory=budget.reserve(MAX_CERT+4096+permissions.iter().map(|p|p.topic.as_str().len()+128).sum::<usize>())?;
                                let id=rand::random();let secret: [u8;32]=rand::random();let expires=t+lifetime.as_secs();
                                grants.insert(id,Grant {hash:digest(&secret),expires,valid_for:valid_for.as_secs(),permissions,limits,redeemed:None,_memory:memory});
                                Ok(EnrollmentInvite {contact:PeerInvite {realm_id:authority.realm_id(),authority:authority.public_key(),address:endpoint.addr()},expires_at:expires,id,secret})
                            })();let _=reply.send(result);
                        },
                        Command::Redeem {peer,id,secret,reply}=>{
                            let result=(||{
                                let t=now()?;let grant=grants.get_mut(&id).ok_or(Error::Unauthorized)?;
                                if grant.expires<=t || grant.hash!=digest(&secret){return Err(Error::Unauthorized);}
                                if let Some((subject,cert))=&grant.redeemed {return if *subject==peer && t<cert.expires_at(){Ok(cert.clone())}else{Err(Error::Unauthorized)};}
                                let cert=authority.issue(peer,grant.permissions.clone(),t,t+grant.valid_for,grant.limits)?;
                                // Single-owner mutation makes consumption and issuance one atomic in-memory transition.
                                grant.redeemed=Some((peer,cert.clone()));Ok(cert)
                            })();let _=reply.send(result);
                        }
                    },
                    incoming=endpoint.accept()=>if let Some(incoming)=incoming {
                        attempts+=1;
                        if attempts>config.max_peers*4 {incoming.refuse();continue;}
                        if let (Ok(quota),Ok(memory))=(quota.clone().try_acquire_owned(),budget.reserve(128 * 1024)) {
                            let tx=actor_tx.clone();let duration=config.handshake_timeout;
                            tasks.spawn(async move {
                                let _quota=quota;let _memory=memory;
                                let _=timeout(duration,async {
                                    let conn=incoming.accept().map_err(transport)?.await.map_err(transport)?;
                                    if conn.alpn()!=ALPN{return Err(Error::Unauthorized);}
                                    let (mut send,mut recv)=conn.accept_bi().await.map_err(transport)?;
                                    let h=wire::read_header(&mut recv,0).await?.ok_or(Error::PeerUnavailable)?;
                                    if h.kind!=wire::HELLO || h.metadata>128{return Err(Error::Protocol("enrollment request"));}
                                    let mut bytes=vec![0;h.metadata];recv.read_exact(&mut bytes).await.map_err(transport)?;
                                    let mut r=Reader::new(&bytes);r.array(3)?;version(r.u()?)?;let id=r.fixed()?;let secret=r.fixed()?;r.end()?;
                                    let mut expected=Writer::new();expected.array(3);expected.u(1);expected.bytes(&id);expected.bytes(&secret);crate::cbor::canonical(&bytes,&expected.finish())?;
                                    let (reply,rx)=oneshot::channel();tx.send(Command::Redeem {peer:conn.remote_id(),id,secret,reply}).await.map_err(|_|Error::ShuttingDown)?;
                                    let result=rx.await.map_err(|_|Error::ShuttingDown)?;let mut w=Writer::new();w.array(2);w.u(1);
                                    let kind=match result {Ok(cert)=>{w.bytes(cert.as_bytes());wire::READY},Err(_)=>{w.u(1);11}};
                                    wire::write_frame(&mut send,kind,&w.finish(),&[]).await?;send.finish().map_err(transport)?;
                                    let _=send.stopped().await;Ok::<(),Error>(())
                                }).await;
                            });
                        }else{incoming.refuse();}
                    },
                    Some(_)=tasks.join_next(),if !tasks.is_empty()=>{},
                }
            }
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
            endpoint.close().await;
            let _ = done_tx.send(true);
        });
        Ok(Self { tx, stop, done })
    }
    pub async fn issue_invite(
        &self,
        permissions: Vec<Permission>,
        limits: CertificateLimits,
        valid_for: Duration,
        lifetime: Duration,
    ) -> Result<EnrollmentInvite> {
        if permissions.len() > MAX_PERMISSIONS {
            return Err(Error::MessageTooLarge);
        }
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Command::Invite {
                permissions,
                limits,
                valid_for,
                lifetime,
                reply,
            })
            .await
            .map_err(|_| Error::ShuttingDown)?;
        rx.await.map_err(|_| Error::ShuttingDown)?
    }
    pub async fn shutdown(mut self) -> Result<()> {
        self.stop.cancel();
        while !*self.done.borrow() {
            self.done.changed().await.map_err(|_| Error::ShuttingDown)?;
        }
        Ok(())
    }
}
