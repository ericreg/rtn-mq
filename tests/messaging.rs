use rtn_mq::*;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::timeout;
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn wait_timeout() -> Duration {
    Duration::from_secs(5)
}
fn config(authority: &Authority) -> Config {
    let mut c = Config::new(authority.trust());
    c.relay_mode = RelayMode::Disabled;
    c.bind_addr = Some("127.0.0.1:0".parse().unwrap());
    c.max_payload = 256;
    c.payload_bytes = 4096;
    c.metadata_bytes = 1024 * 1024;
    c.max_peers = 8;
    c.max_topics = 8;
    c.retry_interval = Duration::from_millis(60);
    c.delivery_window = Duration::from_secs(4);
    c.handshake_timeout = Duration::from_secs(3);
    c
}
async fn start(
    authority: &Authority,
    permissions: Vec<Permission>,
    c: Config,
) -> MessagingEndpoint {
    let identity = Identity::generate();
    let cert = authority
        .issue(
            identity.endpoint_id(),
            permissions,
            now() - 1,
            now() + 60,
            CertificateLimits::default(),
        )
        .unwrap();
    MessagingEndpoint::start(c, identity, cert).await.unwrap()
}
fn options() -> PublishOptions {
    PublishOptions {
        lifetime: Duration::from_secs(3),
        ..Default::default()
    }
}
async fn delivery(s: &mut Subscription) -> Delivery {
    timeout(Duration::from_secs(5), s.recv())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
}
async fn pair() -> (MessagingEndpoint, MessagingEndpoint, Subscription) {
    let authority = Authority::generate();
    let a = start(
        &authority,
        vec![Permission::publish("jobs").unwrap()],
        config(&authority),
    )
    .await;
    let b = start(
        &authority,
        vec![Permission::subscribe("jobs").unwrap()],
        config(&authority),
    )
    .await;
    let mut sub = b
        .subscribe("jobs", SubscriptionOptions::acknowledged())
        .await
        .unwrap();
    a.connect(b.invite()).await.unwrap();
    sub.wait_ready(a.endpoint_id(), wait_timeout())
        .await
        .unwrap();
    (a, b, sub)
}
async fn close(a: &MessagingEndpoint, b: &MessagingEndpoint) {
    a.shutdown(ShutdownMode::Immediate).await.unwrap();
    b.shutdown(ShutdownMode::Immediate).await.unwrap();
}

#[tokio::test]
async fn direct_signed_delivery_and_processing_receipt() {
    let (a, b, mut sub) = pair().await;
    let mut receipt = a
        .publisher("jobs")
        .unwrap()
        .publish(a.buffers().copy_from_slice(b"job").unwrap(), options())
        .await
        .unwrap();
    let d = delivery(&mut sub).await;
    assert_eq!(d.payload(), b"job");
    assert_eq!(receipt.message_id, d.message_id);
    assert_eq!(receipt.outcomes()[0].1, RecipientOutcome::Pending);
    d.ack().await.unwrap();
    assert_eq!(
        receipt.wait_for_processing(wait_timeout()).await.unwrap()[0].1,
        RecipientOutcome::Processed
    );
    close(&a, &b).await;
}
#[tokio::test]
async fn no_subscribers_and_duplicate_local_subscription_are_explicit() {
    let authority = Authority::generate();
    let a = start(
        &authority,
        vec![Permission::both("jobs").unwrap()],
        config(&authority),
    )
    .await;
    assert!(matches!(
        a.publisher("jobs")
            .unwrap()
            .publish(a.buffers().copy_from_slice(b"x").unwrap(), options())
            .await,
        Err(Error::NoSubscribers)
    ));
    let _s = a
        .subscribe("jobs", SubscriptionOptions::default())
        .await
        .unwrap();
    assert!(matches!(
        a.subscribe("jobs", SubscriptionOptions::default()).await,
        Err(Error::AlreadySubscribed)
    ));
    assert!(matches!(a.publisher("Jobs"), Err(Error::Unauthorized)));
    a.shutdown(ShutdownMode::Immediate).await.unwrap();
}
#[tokio::test]
async fn retryable_nack_and_abandonment_keep_message_identity() {
    let (a, b, mut sub) = pair().await;
    let mut r = a
        .publisher("jobs")
        .unwrap()
        .publish(a.buffers().copy_from_slice(b"retry").unwrap(), options())
        .await
        .unwrap();
    let d = delivery(&mut sub).await;
    let id = d.message_id.clone();
    d.nack(Nack::Retryable).await.unwrap();
    let d = delivery(&mut sub).await;
    assert_eq!(d.message_id, id);
    drop(d);
    let d = delivery(&mut sub).await;
    assert_eq!(d.message_id, id);
    d.ack().await.unwrap();
    assert_eq!(
        r.wait_for_processing(wait_timeout()).await.unwrap()[0].1,
        RecipientOutcome::Processed
    );
    assert!(a.metrics().await.unwrap().retried >= 2);
    close(&a, &b).await;
}
#[tokio::test]
async fn permanent_nack_is_terminal() {
    let (a, b, mut sub) = pair().await;
    let mut r = a
        .publisher("jobs")
        .unwrap()
        .publish(a.buffers().copy_from_slice(b"bad").unwrap(), options())
        .await
        .unwrap();
    delivery(&mut sub)
        .await
        .nack(Nack::Permanent)
        .await
        .unwrap();
    assert_eq!(
        r.wait_for_processing(wait_timeout()).await.unwrap()[0].1,
        RecipientOutcome::PermanentNack
    );
    close(&a, &b).await;
}
#[tokio::test]
async fn held_payload_lease_retains_credit_after_ack() {
    let authority = Authority::generate();
    let a = start(
        &authority,
        vec![Permission::publish("jobs").unwrap()],
        config(&authority),
    )
    .await;
    let mut c = config(&authority);
    c.subscription_messages = 1;
    c.payload_bytes = 512;
    let b = start(&authority, vec![Permission::subscribe("jobs").unwrap()], c).await;
    let mut sub = b
        .subscribe("jobs", SubscriptionOptions::default())
        .await
        .unwrap();
    a.connect(b.invite()).await.unwrap();
    sub.wait_ready(a.endpoint_id(), wait_timeout())
        .await
        .unwrap();
    let p = a.publisher("jobs").unwrap();
    let mut first = p
        .publish(a.buffers().copy_from_slice(b"one").unwrap(), options())
        .await
        .unwrap();
    let d = delivery(&mut sub).await;
    let lease = d.lease();
    d.ack().await.unwrap();
    first.wait_for_processing(wait_timeout()).await.unwrap();
    let mut second = p
        .publish(a.buffers().copy_from_slice(b"two").unwrap(), options())
        .await
        .unwrap();
    assert!(
        timeout(Duration::from_millis(150), sub.recv())
            .await
            .is_err()
    );
    assert_eq!(lease.as_bytes(), b"one");
    assert_eq!(b.metrics().await.unwrap().outstanding_credits, 0);
    drop(lease);
    delivery(&mut sub).await.ack().await.unwrap();
    second.wait_for_processing(wait_timeout()).await.unwrap();
    close(&a, &b).await;
}
#[tokio::test]
async fn reconnect_regenerates_lost_ack_without_redelivery() {
    let (a, b, mut sub) = pair().await;
    let mut r = a
        .publisher("jobs")
        .unwrap()
        .publish(a.buffers().copy_from_slice(b"once").unwrap(), options())
        .await
        .unwrap();
    let d = delivery(&mut sub).await;
    a.disconnect(b.endpoint_id()).await.unwrap();
    timeout(Duration::from_secs(2), async {
        while b.metrics().await.unwrap().peers != 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    d.ack().await.unwrap();
    a.connect(b.invite()).await.unwrap();
    sub.wait_ready(a.endpoint_id(), wait_timeout())
        .await
        .unwrap();
    assert_eq!(
        r.wait_for_processing(wait_timeout()).await.unwrap()[0].1,
        RecipientOutcome::Processed
    );
    assert!(
        timeout(Duration::from_millis(150), sub.recv())
            .await
            .is_err()
    );
    close(&a, &b).await;
}
#[tokio::test]
async fn three_peers_and_partial_fanout_admission() {
    let authority = Authority::generate();
    let mut c = config(&authority);
    c.per_peer_messages = 1;
    let a = start(&authority, vec![Permission::publish("jobs").unwrap()], c).await;
    let b = start(
        &authority,
        vec![Permission::subscribe("jobs").unwrap()],
        config(&authority),
    )
    .await;
    let c = start(
        &authority,
        vec![Permission::subscribe("jobs").unwrap()],
        config(&authority),
    )
    .await;
    let mut bs = b
        .subscribe("jobs", SubscriptionOptions::default())
        .await
        .unwrap();
    let mut cs = c
        .subscribe("jobs", SubscriptionOptions::default())
        .await
        .unwrap();
    a.connect(b.invite()).await.unwrap();
    a.connect(c.invite()).await.unwrap();
    bs.wait_ready(a.endpoint_id(), wait_timeout())
        .await
        .unwrap();
    cs.wait_ready(a.endpoint_id(), wait_timeout())
        .await
        .unwrap();
    let p = a.publisher("jobs").unwrap();
    let mut first = p
        .publish(a.buffers().copy_from_slice(b"one").unwrap(), options())
        .await
        .unwrap();
    let held = delivery(&mut bs).await;
    delivery(&mut cs).await.ack().await.unwrap();
    timeout(Duration::from_secs(2), async {
        while !first
            .outcomes()
            .iter()
            .any(|(id, o)| *id == c.endpoint_id() && *o == RecipientOutcome::Processed)
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let mut second = p
        .publish(a.buffers().copy_from_slice(b"two").unwrap(), options())
        .await
        .unwrap();
    assert!(second.outcomes().contains(&(
        b.endpoint_id(),
        RecipientOutcome::Rejected(Error::QueueFull)
    )));
    delivery(&mut cs).await.ack().await.unwrap();
    second.wait_for_processing(wait_timeout()).await.unwrap();
    held.ack().await.unwrap();
    first.wait_for_processing(wait_timeout()).await.unwrap();
    close(&a, &b).await;
    c.shutdown(ShutdownMode::Immediate).await.unwrap();
}
#[tokio::test]
async fn deadline_and_cancellation_are_visible() {
    let (a, b, mut sub) = pair().await;
    let p = a.publisher("jobs").unwrap();
    let mut r = p
        .publish(
            a.buffers().copy_from_slice(b"slow").unwrap(),
            PublishOptions {
                lifetime: Duration::from_secs(2),
                ..options()
            },
        )
        .await
        .unwrap();
    let d = delivery(&mut sub).await;
    assert_eq!(
        r.wait_for_processing(wait_timeout()).await.unwrap()[0].1,
        RecipientOutcome::Failed(Error::DeliveryExpired)
    );
    drop(d);
    let mut r = p
        .publish(a.buffers().copy_from_slice(b"cancel").unwrap(), options())
        .await
        .unwrap();
    r.cancel().await.unwrap();
    assert_eq!(
        r.wait_for_processing(wait_timeout()).await.unwrap()[0].1,
        RecipientOutcome::Cancelled
    );
    close(&a, &b).await;
}
#[tokio::test]
async fn simultaneous_dials_converge_and_best_effort_is_explicit() {
    let authority = Authority::generate();
    let a = start(
        &authority,
        vec![Permission::both("jobs").unwrap()],
        config(&authority),
    )
    .await;
    let b = start(
        &authority,
        vec![Permission::both("jobs").unwrap()],
        config(&authority),
    )
    .await;
    let mut sub = b
        .subscribe("jobs", SubscriptionOptions::best_effort())
        .await
        .unwrap();
    let (ar, br) = tokio::join!(a.connect(b.invite()), b.connect(a.invite()));
    ar.unwrap();
    br.unwrap();
    sub.wait_ready(a.endpoint_id(), wait_timeout())
        .await
        .unwrap();
    let mut r = a
        .publisher("jobs")
        .unwrap()
        .publish(
            a.buffers().copy_from_slice(b"best").unwrap(),
            PublishOptions {
                mode: DeliveryMode::BestEffort,
                ..options()
            },
        )
        .await
        .unwrap();
    let d = delivery(&mut sub).await;
    assert_eq!(
        r.wait_for_processing(wait_timeout()).await.unwrap()[0].1,
        RecipientOutcome::Sent
    );
    d.ack().await.unwrap();
    assert_eq!(a.metrics().await.unwrap().peers, 1);
    assert_eq!(b.metrics().await.unwrap().peers, 1);
    close(&a, &b).await;
}
#[tokio::test]
async fn certificate_expiry_closes_active_session() {
    let authority = Authority::generate();
    let a = start(
        &authority,
        vec![Permission::publish("jobs").unwrap()],
        config(&authority),
    )
    .await;
    let identity = Identity::generate();
    let cert = authority
        .issue(
            identity.endpoint_id(),
            vec![Permission::subscribe("jobs").unwrap()],
            now() - 1,
            now() + 2,
            CertificateLimits::default(),
        )
        .unwrap();
    let b = MessagingEndpoint::start(config(&authority), identity, cert)
        .await
        .unwrap();
    a.connect(b.invite()).await.unwrap();
    timeout(Duration::from_secs(4), async {
        while a.metrics().await.unwrap().peers != 0 {
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    })
    .await
    .unwrap();
    close(&a, &b).await;
}
#[tokio::test]
async fn wrong_root_and_stolen_certificate_are_rejected() {
    let authority = Authority::generate();
    let identity = Identity::generate();
    let cert = authority
        .issue(
            identity.endpoint_id(),
            vec![],
            now() - 1,
            now() + 60,
            CertificateLimits::default(),
        )
        .unwrap();
    assert!(matches!(
        MessagingEndpoint::start(config(&authority), Identity::generate(), cert.clone()).await,
        Err(Error::Unauthorized)
    ));
    let wrong = Authority::generate();
    assert!(matches!(
        MessagingEndpoint::start(config(&wrong), identity, cert).await,
        Err(Error::InvalidSignature)
    ));
}

#[tokio::test]
async fn revocation_fails_pending_delivery_even_while_disconnected() {
    let authority = Authority::generate();
    let a = start(
        &authority,
        vec![Permission::publish("jobs").unwrap()],
        config(&authority),
    )
    .await;
    let key = Identity::generate();
    let cert = authority
        .issue(
            key.endpoint_id(),
            vec![Permission::subscribe("jobs").unwrap()],
            now() - 1,
            now() + 60,
            CertificateLimits::default(),
        )
        .unwrap();
    let id = cert.id();
    let b = MessagingEndpoint::start(config(&authority), key, cert)
        .await
        .unwrap();
    let mut sub = b
        .subscribe("jobs", SubscriptionOptions::default())
        .await
        .unwrap();
    a.connect(b.invite()).await.unwrap();
    sub.wait_ready(a.endpoint_id(), wait_timeout())
        .await
        .unwrap();
    let mut r = a
        .publisher("jobs")
        .unwrap()
        .publish(a.buffers().copy_from_slice(b"pending").unwrap(), options())
        .await
        .unwrap();
    let d = delivery(&mut sub).await;
    a.disconnect(b.endpoint_id()).await.unwrap();
    a.deny_certificate(id).await.unwrap();
    assert_eq!(
        r.wait_for_processing(wait_timeout()).await.unwrap()[0].1,
        RecipientOutcome::Failed(Error::Unauthorized)
    );
    drop(d);
    close(&a, &b).await;
}
#[tokio::test]
async fn reconnect_preserves_outbound_budget() {
    let authority = Authority::generate();
    let mut ac = config(&authority);
    ac.per_peer_messages = 1;
    let a = start(&authority, vec![Permission::publish("jobs").unwrap()], ac).await;
    let b = start(
        &authority,
        vec![Permission::subscribe("jobs").unwrap()],
        config(&authority),
    )
    .await;
    let mut sub = b
        .subscribe("jobs", SubscriptionOptions::default())
        .await
        .unwrap();
    a.connect(b.invite()).await.unwrap();
    sub.wait_ready(a.endpoint_id(), wait_timeout())
        .await
        .unwrap();
    let p = a.publisher("jobs").unwrap();
    let mut first = p
        .publish(a.buffers().copy_from_slice(b"one").unwrap(), options())
        .await
        .unwrap();
    let held = delivery(&mut sub).await;
    a.disconnect(b.endpoint_id()).await.unwrap();
    a.connect(b.invite()).await.unwrap();
    sub.wait_ready(a.endpoint_id(), wait_timeout())
        .await
        .unwrap();
    let second = p
        .publish(a.buffers().copy_from_slice(b"two").unwrap(), options())
        .await
        .unwrap();
    assert_eq!(
        second.outcomes()[0].1,
        RecipientOutcome::Rejected(Error::QueueFull)
    );
    held.ack().await.unwrap();
    first.wait_for_processing(wait_timeout()).await.unwrap();
    close(&a, &b).await;
}
#[tokio::test]
async fn single_use_enrollment_and_same_key_response_recovery() {
    let authority = Authority::generate();
    let c = config(&authority);
    let service = EnrollmentService::start(authority, Identity::generate(), c.clone())
        .await
        .unwrap();
    let invite = service
        .issue_invite(
            vec![Permission::both("jobs").unwrap()],
            CertificateLimits::default(),
            Duration::from_secs(60),
            Duration::from_secs(30),
        )
        .await
        .unwrap();
    let encoded = invite.encode().unwrap();
    let invite = EnrollmentInvite::decode(&encoded).unwrap();
    assert!(!format!("{invite:?}").contains(&encoded));
    let one = Identity::generate();
    let two = Identity::generate();
    let (a, b) = tokio::join!(invite.redeem(&one, &c), invite.redeem(&two, &c));
    assert_ne!(a.is_ok(), b.is_ok());
    let (winner, cert) = if let Ok(cert) = a {
        (one, cert)
    } else {
        (two, b.unwrap())
    };
    assert_eq!(
        invite.redeem(&winner, &c).await.unwrap().as_bytes(),
        cert.as_bytes()
    );
    let other_invite = service
        .issue_invite(
            vec![Permission::both("jobs").unwrap()],
            CertificateLimits::default(),
            Duration::from_secs(60),
            Duration::from_secs(30),
        )
        .await
        .unwrap();
    let other = Identity::generate();
    let other_cert = other_invite.redeem(&other, &c).await.unwrap();
    service.shutdown().await.unwrap();
    let a = MessagingEndpoint::start(c.clone(), winner, cert)
        .await
        .unwrap();
    let b = MessagingEndpoint::start(c, other, other_cert)
        .await
        .unwrap();
    let mut sub = b
        .subscribe("jobs", SubscriptionOptions::default())
        .await
        .unwrap();
    a.connect(b.invite()).await.unwrap();
    sub.wait_ready(a.endpoint_id(), wait_timeout())
        .await
        .unwrap();
    let mut r = a
        .publisher("jobs")
        .unwrap()
        .publish(a.buffers().copy_from_slice(b"enrolled").unwrap(), options())
        .await
        .unwrap();
    delivery(&mut sub).await.ack().await.unwrap();
    r.wait_for_processing(wait_timeout()).await.unwrap();
    close(&a, &b).await;
}
#[tokio::test]
async fn relay_only_delivery_with_two_then_three_peers() {
    use iroh_relay::server::{RelayConfig, Server, ServerConfig};
    let mut server_config = ServerConfig::default();
    server_config.relay = Some(RelayConfig::new(
        "127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap(),
    ));
    let server = Server::spawn(server_config).await.unwrap();
    let url = format!("http://{}", server.http_addr().unwrap())
        .parse()
        .unwrap();
    let authority = Authority::generate();
    let mut c = config(&authority);
    c.relay_mode = RelayMode::custom([url]);
    c.relay_only = true;
    c.handshake_timeout = Duration::from_secs(5);
    let a = start(
        &authority,
        vec![Permission::publish("jobs").unwrap()],
        c.clone(),
    )
    .await;
    let b = start(
        &authority,
        vec![Permission::subscribe("jobs").unwrap()],
        c.clone(),
    )
    .await;
    let third = start(&authority, vec![Permission::subscribe("jobs").unwrap()], c).await;
    let (ar, br, cr) = tokio::join!(
        a.online(wait_timeout()),
        b.online(wait_timeout()),
        third.online(wait_timeout())
    );
    ar.unwrap();
    br.unwrap();
    cr.unwrap();
    assert_eq!(a.invite().address.ip_addrs().count(), 0);
    assert_eq!(b.invite().address.ip_addrs().count(), 0);
    assert_eq!(third.invite().address.ip_addrs().count(), 0);
    let mut bs = b
        .subscribe("jobs", SubscriptionOptions::default())
        .await
        .unwrap();
    let mut cs = third
        .subscribe("jobs", SubscriptionOptions::default())
        .await
        .unwrap();
    a.connect(b.invite()).await.unwrap();
    bs.wait_ready(a.endpoint_id(), wait_timeout())
        .await
        .unwrap();
    let publisher = a.publisher("jobs").unwrap();
    let mut first = publisher
        .publish(
            a.buffers().copy_from_slice(b"two relayed peers").unwrap(),
            options(),
        )
        .await
        .unwrap();
    delivery(&mut bs).await.ack().await.unwrap();
    first.wait_for_processing(wait_timeout()).await.unwrap();
    a.connect(third.invite()).await.unwrap();
    cs.wait_ready(a.endpoint_id(), wait_timeout())
        .await
        .unwrap();
    let mut second = publisher
        .publish(
            a.buffers().copy_from_slice(b"three relayed peers").unwrap(),
            options(),
        )
        .await
        .unwrap();
    delivery(&mut bs).await.ack().await.unwrap();
    delivery(&mut cs).await.ack().await.unwrap();
    assert_eq!(
        second
            .wait_for_processing(wait_timeout())
            .await
            .unwrap()
            .len(),
        2
    );
    close(&a, &b).await;
    third.shutdown(ShutdownMode::Immediate).await.unwrap();
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn renewal_keeps_pending_message_identity_and_subscription() {
    let authority = Authority::generate();
    let identity = Identity::generate();
    let cert = authority
        .issue(
            identity.endpoint_id(),
            vec![Permission::publish("jobs").unwrap()],
            now() - 1,
            now() + 60,
            CertificateLimits::default(),
        )
        .unwrap();
    let a = MessagingEndpoint::start(config(&authority), identity.clone(), cert)
        .await
        .unwrap();
    let b = start(
        &authority,
        vec![Permission::subscribe("jobs").unwrap()],
        config(&authority),
    )
    .await;
    let mut sub = b
        .subscribe("jobs", SubscriptionOptions::default())
        .await
        .unwrap();
    a.connect(b.invite()).await.unwrap();
    sub.wait_ready(a.endpoint_id(), wait_timeout())
        .await
        .unwrap();
    let mut receipt = a
        .publisher("jobs")
        .unwrap()
        .publish(a.buffers().copy_from_slice(b"renew").unwrap(), options())
        .await
        .unwrap();
    let held = delivery(&mut sub).await;
    let id = held.message_id.clone();
    let renewed = authority
        .issue(
            identity.endpoint_id(),
            vec![Permission::publish("jobs").unwrap()],
            now() - 1,
            now() + 120,
            CertificateLimits::default(),
        )
        .unwrap();
    a.renew(renewed).await.unwrap();
    a.connect(b.invite()).await.unwrap();
    sub.wait_ready(a.endpoint_id(), wait_timeout())
        .await
        .unwrap();
    held.ack().await.unwrap();
    assert_eq!(
        receipt.wait_for_processing(wait_timeout()).await.unwrap()[0].1,
        RecipientOutcome::Processed
    );
    assert_eq!(receipt.message_id, id);
    close(&a, &b).await;
}
#[tokio::test]
async fn idle_publishers_do_not_reserve_another_publishers_receive_capacity() {
    let authority = Authority::generate();
    let idle = start(
        &authority,
        vec![Permission::publish("jobs").unwrap()],
        config(&authority),
    )
    .await;
    let active = start(
        &authority,
        vec![Permission::publish("jobs").unwrap()],
        config(&authority),
    )
    .await;
    let mut c = config(&authority);
    c.payload_bytes = 512;
    c.subscription_messages = 1;
    let receiver = start(&authority, vec![Permission::subscribe("jobs").unwrap()], c).await;
    let mut sub = receiver
        .subscribe("jobs", SubscriptionOptions::default())
        .await
        .unwrap();
    idle.connect(receiver.invite()).await.unwrap();
    sub.wait_ready(idle.endpoint_id(), wait_timeout())
        .await
        .unwrap();
    active.connect(receiver.invite()).await.unwrap();
    sub.wait_ready(active.endpoint_id(), wait_timeout())
        .await
        .unwrap();
    assert_eq!(receiver.metrics().await.unwrap().outstanding_credits, 0);
    let mut r = active
        .publisher("jobs")
        .unwrap()
        .publish(
            active.buffers().copy_from_slice(b"active").unwrap(),
            options(),
        )
        .await
        .unwrap();
    delivery(&mut sub).await.ack().await.unwrap();
    r.wait_for_processing(wait_timeout()).await.unwrap();
    close(&idle, &receiver).await;
    active.shutdown(ShutdownMode::Immediate).await.unwrap();
}
#[tokio::test]
async fn shutdown_deadline_reports_unfinished_processing() {
    let (a, b, mut sub) = pair().await;
    let mut r = a
        .publisher("jobs")
        .unwrap()
        .publish(
            a.buffers().copy_from_slice(b"unfinished").unwrap(),
            options(),
        )
        .await
        .unwrap();
    let held = delivery(&mut sub).await;
    let metrics = a
        .shutdown(ShutdownMode::Drain {
            timeout: Duration::from_millis(60),
        })
        .await
        .unwrap();
    assert_eq!(metrics.unfinished_on_shutdown, 1);
    assert_eq!(
        r.wait_for_processing(wait_timeout()).await.unwrap()[0].1,
        RecipientOutcome::Failed(Error::ShuttingDown)
    );
    drop(held);
    b.shutdown(ShutdownMode::Immediate).await.unwrap();
}
#[tokio::test]
async fn unauthorized_remote_subscription_is_rejected_at_readiness() {
    let authority = Authority::generate();
    let a = start(
        &authority,
        vec![Permission::publish("jobs").unwrap()],
        config(&authority),
    )
    .await;
    let b = start(
        &authority,
        vec![Permission::subscribe("private").unwrap()],
        config(&authority),
    )
    .await;
    let mut sub = b
        .subscribe("private", SubscriptionOptions::default())
        .await
        .unwrap();
    a.connect(b.invite()).await.unwrap();
    assert_eq!(
        sub.wait_ready(a.endpoint_id(), wait_timeout()).await,
        Err(Error::Unauthorized)
    );
    close(&a, &b).await;
}

#[tokio::test]
async fn subscription_churn_preserves_other_topic_streams() {
    let authority = Authority::generate();
    let topics: Vec<_> = std::iter::once("stable".to_owned())
        .chain((0..6).map(|i| format!("temporary/{i}")))
        .collect();
    let permissions = topics
        .iter()
        .map(|t| Permission::both(t).unwrap())
        .collect::<Vec<_>>();
    let a = start(&authority, permissions.clone(), config(&authority)).await;
    let mut receiver_config = config(&authority);
    receiver_config.max_topics = 2;
    let b = start(&authority, permissions, receiver_config).await;
    let mut stable = b
        .subscribe("stable", SubscriptionOptions::acknowledged())
        .await
        .unwrap();
    a.connect(b.invite()).await.unwrap();
    stable
        .wait_ready(a.endpoint_id(), wait_timeout())
        .await
        .unwrap();
    for topic in &topics[1..] {
        let mut temporary = b
            .subscribe(topic, SubscriptionOptions::acknowledged())
            .await
            .unwrap();
        temporary
            .wait_ready(a.endpoint_id(), wait_timeout())
            .await
            .unwrap();
        let publisher = a.publisher(topic).unwrap();
        let mut first = publisher
            .publish(a.buffers().copy_from_slice(b"first").unwrap(), options())
            .await
            .unwrap();
        delivery(&mut temporary).await.ack().await.unwrap();
        assert_eq!(
            first.wait_for_processing(wait_timeout()).await.unwrap()[0].1,
            RecipientOutcome::Processed
        );
        let mut racing = publisher
            .publish(
                a.buffers().copy_from_slice(b"racing unsubscribe").unwrap(),
                options(),
            )
            .await
            .unwrap();
        drop(temporary);
        let _ = racing.wait_for_processing(wait_timeout()).await.unwrap();
        // Give the remote owner time to retire the old stream before opening the next binding.
        tokio::time::sleep(Duration::from_millis(40)).await;
        let mut receipt = a
            .publisher("stable")
            .unwrap()
            .publish(
                a.buffers().copy_from_slice(b"still connected").unwrap(),
                options(),
            )
            .await
            .unwrap();
        delivery(&mut stable).await.ack().await.unwrap();
        assert_eq!(
            receipt.wait_for_processing(wait_timeout()).await.unwrap()[0].1,
            RecipientOutcome::Processed
        );
        assert_eq!(a.metrics().await.unwrap().peers, 1);
        assert_eq!(b.metrics().await.unwrap().peers, 1);
    }
    close(&a, &b).await;
}

#[tokio::test]
async fn duration_waits_timeout_without_cancelling_delivery() {
    let (a, b, mut sub) = pair().await;
    // A completed condition succeeds without waiting, even with a zero budget.
    sub.wait_ready(a.endpoint_id(), Duration::ZERO)
        .await
        .unwrap();
    assert_eq!(
        sub.wait_ready(
            Identity::generate().endpoint_id(),
            Duration::from_millis(20)
        )
        .await,
        Err(Error::Timeout)
    );
    // This pair disables relays, so online must return at the caller's timeout.
    assert_eq!(
        a.online(Duration::from_millis(20)).await,
        Err(Error::Timeout)
    );
    let mut receipt = a
        .publisher("jobs")
        .unwrap()
        .publish(
            a.buffers().copy_from_slice(b"still pending").unwrap(),
            options(),
        )
        .await
        .unwrap();
    let held = delivery(&mut sub).await;
    assert_eq!(
        receipt.wait_for_processing(Duration::from_millis(20)).await,
        Err(Error::Timeout)
    );
    assert_eq!(receipt.outcomes()[0].1, RecipientOutcome::Pending);
    held.ack().await.unwrap();
    assert_eq!(
        receipt.wait_for_processing(wait_timeout()).await.unwrap()[0].1,
        RecipientOutcome::Processed
    );
    assert_eq!(
        receipt.wait_for_processing(Duration::ZERO).await.unwrap()[0].1,
        RecipientOutcome::Processed
    );
    close(&a, &b).await;
}

#[tokio::test]
async fn processing_timeout_is_shared_by_all_recipients() {
    let authority = Authority::generate();
    let a = start(
        &authority,
        vec![Permission::publish("jobs").unwrap()],
        config(&authority),
    )
    .await;
    let b = start(
        &authority,
        vec![Permission::subscribe("jobs").unwrap()],
        config(&authority),
    )
    .await;
    let c = start(
        &authority,
        vec![Permission::subscribe("jobs").unwrap()],
        config(&authority),
    )
    .await;
    let mut bs = b
        .subscribe("jobs", SubscriptionOptions::acknowledged())
        .await
        .unwrap();
    let mut cs = c
        .subscribe("jobs", SubscriptionOptions::acknowledged())
        .await
        .unwrap();
    a.connect(b.invite()).await.unwrap();
    a.connect(c.invite()).await.unwrap();
    bs.wait_ready(a.endpoint_id(), wait_timeout())
        .await
        .unwrap();
    cs.wait_ready(a.endpoint_id(), wait_timeout())
        .await
        .unwrap();
    let mut receipt = a
        .publisher("jobs")
        .unwrap()
        .publish(
            a.buffers().copy_from_slice(b"two recipients").unwrap(),
            options(),
        )
        .await
        .unwrap();
    let bd = delivery(&mut bs).await;
    let cd = delivery(&mut cs).await;
    // Receipt entries are in endpoint-ID order. Complete the first entry partway
    // through the wait, then the second after the original budget has elapsed.
    let (first, second) = if receipt.outcomes()[0].0 == b.endpoint_id() {
        (bd, cd)
    } else {
        (cd, bd)
    };
    let acknowledgements = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        first.ack().await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        second.ack().await.unwrap();
    });
    assert_eq!(
        receipt
            .wait_for_processing(Duration::from_millis(300))
            .await,
        Err(Error::Timeout)
    );
    acknowledgements.await.unwrap();
    assert!(
        receipt
            .wait_for_processing(wait_timeout())
            .await
            .unwrap()
            .iter()
            .all(|(_, outcome)| *outcome == RecipientOutcome::Processed)
    );
    close(&a, &b).await;
    c.shutdown(ShutdownMode::Immediate).await.unwrap();
}
