use rtn_mq::*;
use std::time::Duration;
use tokio::time::timeout;
fn wait_timeout() -> Duration {
    Duration::from_secs(5)
}
fn config() -> Config {
    let mut c = Config::new();
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
async fn host(permissions: Vec<Permission>, config: Config) -> MessagingEndpoint {
    MessagingEndpoint::host(config, Identity::generate(), permissions)
        .await
        .unwrap()
}
async fn member(
    host: &MessagingEndpoint,
    permissions: Vec<Permission>,
    config: Config,
) -> MessagingEndpoint {
    let code = host
        .issue_join_code(JoinOptions::new(permissions))
        .await
        .unwrap();
    MessagingEndpoint::join(config, Identity::generate(), &code)
        .await
        .unwrap()
}
async fn reconnect(host: &MessagingEndpoint, client: &MessagingEndpoint) {
    let code = host
        .issue_join_code(JoinOptions::new(
            client.certificate().permissions().to_vec(),
        ))
        .await
        .unwrap();
    client.rejoin(&code).await.unwrap();
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
    let a = host(vec![Permission::publish("jobs").unwrap()], config()).await;
    let b = member(&a, vec![Permission::subscribe("jobs").unwrap()], config()).await;
    let mut sub = b
        .subscribe("jobs", SubscriptionOptions::acknowledged())
        .await
        .unwrap();
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
async fn readiness_requires_both_topics_and_clears_on_disconnect() {
    let server = host(
        vec![
            Permission::publish("responses").unwrap(),
            Permission::subscribe("requests").unwrap(),
        ],
        config(),
    )
    .await;
    let client = member(
        &server,
        vec![
            Permission::publish("requests").unwrap(),
            Permission::subscribe("responses").unwrap(),
        ],
        config(),
    )
    .await;
    assert!(
        !client
            .topics_ready(server.endpoint_id(), "requests", "responses")
            .await
            .unwrap()
    );
    let mut responses = client
        .subscribe("responses", SubscriptionOptions::acknowledged())
        .await
        .unwrap();
    responses
        .wait_ready(server.endpoint_id(), wait_timeout())
        .await
        .unwrap();
    assert!(
        !client
            .topics_ready(server.endpoint_id(), "requests", "responses")
            .await
            .unwrap()
    );
    let mut requests = server
        .subscribe("requests", SubscriptionOptions::acknowledged())
        .await
        .unwrap();
    requests
        .wait_ready(client.endpoint_id(), wait_timeout())
        .await
        .unwrap();
    assert!(
        client
            .topics_ready(server.endpoint_id(), "requests", "responses")
            .await
            .unwrap()
    );
    client.disconnect(server.endpoint_id()).await.unwrap();
    assert!(
        !client
            .topics_ready(server.endpoint_id(), "requests", "responses")
            .await
            .unwrap()
    );
    close(&server, &client).await;
}

#[tokio::test]
async fn persistent_host_recovers_one_use_membership_after_restart() {
    let directory = tempfile::tempdir().unwrap();
    let private = directory.path().join("private");
    let state_path = private.join("host.cbor");
    let host_identity = Identity::generate();
    let gateway_identity = Identity::generate();
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    drop(socket);

    let mut host_config = config();
    host_config.bind_addr = Some(address);
    let host = MessagingEndpoint::host_persistent(
        host_config.clone(),
        host_identity.clone(),
        vec![Permission::publish("responses").unwrap()],
        &state_path,
    )
    .await
    .unwrap();
    let mut options = JoinOptions::new(vec![Permission::subscribe("responses").unwrap()]);
    options.max_uses = 1;
    options.lifetime = Duration::from_secs(60);
    options.certificate_lifetime = Duration::from_secs(60);
    let code = host.issue_join_code(options).await.unwrap();
    let gateway = MessagingEndpoint::join(config(), gateway_identity.clone(), &code)
        .await
        .unwrap();
    assert!(matches!(
        MessagingEndpoint::join(config(), Identity::generate(), &code).await,
        Err(Error::QueueFull)
    ));
    close(&host, &gateway).await;
    drop(host);
    drop(gateway);

    let host = MessagingEndpoint::host_persistent(
        host_config,
        host_identity,
        vec![Permission::publish("responses").unwrap()],
        &state_path,
    )
    .await
    .unwrap();
    let gateway = MessagingEndpoint::join(config(), gateway_identity, &code)
        .await
        .unwrap();
    assert!(matches!(
        MessagingEndpoint::join(config(), Identity::generate(), &code).await,
        Err(Error::QueueFull)
    ));
    close(&host, &gateway).await;
    assert!(std::fs::metadata(state_path).unwrap().len() > 64);
}

#[tokio::test]
async fn burst_publications_do_not_lose_receive_credit_requests() {
    let (publisher, receiver, mut sub) = pair().await;
    let topic = publisher.publisher("jobs").unwrap();
    let mut receipts = Vec::new();
    // Queue messages without waiting for previous processing receipts. DATA and
    // the next credit request travel on different QUIC streams and can race.
    for _ in 0..12 {
        receipts.push(
            topic
                .publish(
                    publisher.buffers().copy_from_slice(b"burst").unwrap(),
                    options(),
                )
                .await
                .unwrap(),
        );
    }
    for _ in 0..receipts.len() {
        delivery(&mut sub).await.ack().await.unwrap();
    }
    for mut receipt in receipts {
        assert_eq!(
            receipt.wait_for_processing(wait_timeout()).await.unwrap()[0].1,
            RecipientOutcome::Processed
        );
    }
    close(&publisher, &receiver).await;
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
    let a = host(vec![Permission::both("jobs").unwrap()], config()).await;
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
    let a = host(vec![Permission::publish("jobs").unwrap()], config()).await;
    let mut c = config();
    c.subscription_messages = 1;
    c.payload_bytes = 512;
    let b = member(&a, vec![Permission::subscribe("jobs").unwrap()], c).await;
    let mut sub = b
        .subscribe("jobs", SubscriptionOptions::default())
        .await
        .unwrap();
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
    reconnect(&a, &b).await;
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
    let mut c = config();
    c.per_peer_messages = 1;
    let a = host(vec![Permission::publish("jobs").unwrap()], c).await;
    let b = member(&a, vec![Permission::subscribe("jobs").unwrap()], config()).await;
    let c = member(&a, vec![Permission::subscribe("jobs").unwrap()], config()).await;
    let mut bs = b
        .subscribe("jobs", SubscriptionOptions::default())
        .await
        .unwrap();
    let mut cs = c
        .subscribe("jobs", SubscriptionOptions::default())
        .await
        .unwrap();
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
async fn concurrent_rejoins_converge_and_best_effort_is_explicit() {
    let a = host(vec![Permission::both("jobs").unwrap()], config()).await;
    let b = member(&a, vec![Permission::both("jobs").unwrap()], config()).await;
    let mut sub = b
        .subscribe("jobs", SubscriptionOptions::best_effort())
        .await
        .unwrap();
    let code = a
        .issue_join_code(JoinOptions::new(vec![Permission::both("jobs").unwrap()]))
        .await
        .unwrap();
    let (ar, br) = tokio::join!(b.rejoin(&code), b.rejoin(&code));
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
async fn reconnect_preserves_outbound_budget() {
    let mut ac = config();
    ac.per_peer_messages = 1;
    let a = host(vec![Permission::publish("jobs").unwrap()], ac).await;
    let b = member(&a, vec![Permission::subscribe("jobs").unwrap()], config()).await;
    let mut sub = b
        .subscribe("jobs", SubscriptionOptions::default())
        .await
        .unwrap();
    reconnect(&a, &b).await;
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
    reconnect(&a, &b).await;
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
    let a = host(vec![Permission::publish("jobs").unwrap()], config()).await;
    let b = member(
        &a,
        vec![Permission::subscribe("private").unwrap()],
        config(),
    )
    .await;
    let mut sub = b
        .subscribe("private", SubscriptionOptions::default())
        .await
        .unwrap();
    assert_eq!(
        sub.wait_ready(a.endpoint_id(), wait_timeout()).await,
        Err(Error::Unauthorized)
    );
    close(&a, &b).await;
}

#[tokio::test]
async fn subscription_churn_preserves_other_topic_streams() {
    let topics: Vec<_> = std::iter::once("stable".to_owned())
        .chain((0..6).map(|i| format!("temporary/{i}")))
        .collect();
    let permissions = topics
        .iter()
        .map(|t| Permission::both(t).unwrap())
        .collect::<Vec<_>>();
    let a = host(permissions.clone(), config()).await;
    let mut receiver_config = config();
    receiver_config.max_topics = 2;
    let b = member(&a, permissions, receiver_config).await;
    let mut stable = b
        .subscribe("stable", SubscriptionOptions::acknowledged())
        .await
        .unwrap();
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
    let a = host(vec![Permission::publish("jobs").unwrap()], config()).await;
    let b = member(&a, vec![Permission::subscribe("jobs").unwrap()], config()).await;
    let c = member(&a, vec![Permission::subscribe("jobs").unwrap()], config()).await;
    let mut bs = b
        .subscribe("jobs", SubscriptionOptions::acknowledged())
        .await
        .unwrap();
    let mut cs = c
        .subscribe("jobs", SubscriptionOptions::acknowledged())
        .await
        .unwrap();
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

#[tokio::test]
async fn reusable_code_admits_concurrent_members_with_a_shared_limit() {
    let a = host(vec![Permission::both("jobs").unwrap()], config()).await;
    let mut opts = JoinOptions::new(vec![Permission::both("jobs").unwrap()]);
    opts.max_uses = 2;
    let code = a.issue_join_code(opts).await.unwrap();
    let code = JoinCode::decode(&code.encode().unwrap()).unwrap();
    let (b, c) = tokio::join!(
        MessagingEndpoint::join(config(), Identity::generate(), &code),
        MessagingEndpoint::join(config(), Identity::generate(), &code),
    );
    let b = b.unwrap();
    let c = c.unwrap();
    assert_ne!(b.certificate().id(), c.certificate().id());
    assert_ne!(b.endpoint_id(), c.endpoint_id());
    let mut ready = a
        .subscribe("jobs", SubscriptionOptions::acknowledged())
        .await
        .unwrap();
    ready
        .wait_ready(b.endpoint_id(), wait_timeout())
        .await
        .unwrap();
    ready
        .wait_ready(c.endpoint_id(), wait_timeout())
        .await
        .unwrap();
    assert_eq!(a.metrics().await.unwrap().peers, 2);
    assert_eq!(b.metrics().await.unwrap().peers, 1);
    assert_eq!(c.metrics().await.unwrap().peers, 1);
    assert!(matches!(
        MessagingEndpoint::join(config(), Identity::generate(), &code).await,
        Err(Error::QueueFull)
    ));
    let cert = b.certificate().id();
    b.rejoin(&code).await.unwrap();
    assert_eq!(cert, b.certificate().id());
    assert!(matches!(
        b.issue_join_code(JoinOptions::new(vec![])).await,
        Err(Error::Unauthorized)
    ));
    close(&a, &b).await;
    c.shutdown(ShutdownMode::Immediate).await.unwrap();
}

#[tokio::test]
async fn revoked_code_blocks_enrollment_but_keeps_admitted_peer_authorized() {
    let a = host(vec![Permission::subscribe("jobs").unwrap()], config()).await;
    let code = a
        .issue_join_code(JoinOptions::new(vec![Permission::publish("jobs").unwrap()]))
        .await
        .unwrap();
    let b = MessagingEndpoint::join(config(), Identity::generate(), &code)
        .await
        .unwrap();
    a.revoke_join_code(code.id()).await.unwrap();
    assert!(matches!(
        MessagingEndpoint::join(config(), Identity::generate(), &code).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(b.rejoin(&code).await, Err(Error::Unauthorized));
    let mut sub = a
        .subscribe("jobs", SubscriptionOptions::acknowledged())
        .await
        .unwrap();
    sub.wait_ready(b.endpoint_id(), wait_timeout())
        .await
        .unwrap();
    let mut receipt = b
        .publisher("jobs")
        .unwrap()
        .publish(
            b.buffers().copy_from_slice(b"still authorized").unwrap(),
            options(),
        )
        .await
        .unwrap();
    delivery(&mut sub).await.ack().await.unwrap();
    assert_eq!(
        receipt.wait_for_processing(wait_timeout()).await.unwrap()[0].1,
        RecipientOutcome::Processed
    );
    close(&a, &b).await;
}

#[tokio::test]
async fn revoked_member_fails_retained_delivery_and_cannot_recover_the_revoked_grant() {
    let a = host(vec![Permission::publish("jobs").unwrap()], config()).await;
    let code = a
        .issue_join_code(JoinOptions::new(vec![
            Permission::subscribe("jobs").unwrap(),
        ]))
        .await
        .unwrap();
    let b = MessagingEndpoint::join(config(), Identity::generate(), &code)
        .await
        .unwrap();
    let mut sub = b
        .subscribe("jobs", SubscriptionOptions::acknowledged())
        .await
        .unwrap();
    sub.wait_ready(a.endpoint_id(), wait_timeout())
        .await
        .unwrap();
    let mut receipt = a
        .publisher("jobs")
        .unwrap()
        .publish(a.buffers().copy_from_slice(b"revoked").unwrap(), options())
        .await
        .unwrap();
    let held = delivery(&mut sub).await;
    a.disconnect(b.endpoint_id()).await.unwrap();
    a.deny_certificate(b.certificate().id()).await.unwrap();
    assert_eq!(
        receipt.wait_for_processing(wait_timeout()).await.unwrap()[0].1,
        RecipientOutcome::Failed(Error::Unauthorized)
    );
    assert_eq!(b.rejoin(&code).await, Err(Error::Unauthorized));
    drop(held);
    close(&a, &b).await;
}

#[tokio::test]
async fn expired_code_and_certificate_have_separate_lifetimes() {
    let a = host(vec![], config()).await;
    let mut opts = JoinOptions::new(vec![]);
    opts.lifetime = Duration::from_secs(1);
    opts.certificate_lifetime = Duration::from_secs(3);
    let code = a.issue_join_code(opts).await.unwrap();
    let b = MessagingEndpoint::join(config(), Identity::generate(), &code)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(matches!(
        MessagingEndpoint::join(config(), Identity::generate(), &code).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(a.metrics().await.unwrap().peers, 1);
    timeout(Duration::from_secs(4), async {
        while a.metrics().await.unwrap().peers != 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    close(&a, &b).await;
}

#[tokio::test]
async fn renewed_grant_preserves_pending_message_and_removed_permissions_are_enforced() {
    let a = host(vec![Permission::both("jobs").unwrap()], config()).await;
    let code = a
        .issue_join_code(JoinOptions::new(vec![Permission::both("jobs").unwrap()]))
        .await
        .unwrap();
    let b = MessagingEndpoint::join(config(), Identity::generate(), &code)
        .await
        .unwrap();
    let mut sub = a
        .subscribe("jobs", SubscriptionOptions::acknowledged())
        .await
        .unwrap();
    sub.wait_ready(b.endpoint_id(), wait_timeout())
        .await
        .unwrap();
    let mut receipt = b
        .publisher("jobs")
        .unwrap()
        .publish(b.buffers().copy_from_slice(b"renew").unwrap(), options())
        .await
        .unwrap();
    let held = delivery(&mut sub).await;
    let id = held.message_id.clone();
    b.disconnect(a.endpoint_id()).await.unwrap();
    let updated = a
        .issue_join_code(JoinOptions::new(vec![Permission::publish("jobs").unwrap()]))
        .await
        .unwrap();
    b.rejoin(&updated).await.unwrap();
    sub.wait_ready(b.endpoint_id(), wait_timeout())
        .await
        .unwrap();
    held.ack().await.unwrap();
    assert_eq!(
        receipt.wait_for_processing(wait_timeout()).await.unwrap()[0].1,
        RecipientOutcome::Processed
    );
    assert_eq!(receipt.message_id, id);
    assert!(matches!(
        b.subscribe("jobs", SubscriptionOptions::default()).await,
        Err(Error::Unauthorized)
    ));
    let stranger = host(vec![], config()).await;
    let unrelated = stranger
        .issue_join_code(JoinOptions::new(vec![]))
        .await
        .unwrap();
    assert_eq!(b.rejoin(&unrelated).await, Err(Error::Unauthorized));
    stranger.shutdown(ShutdownMode::Immediate).await.unwrap();
    close(&a, &b).await;
}

#[tokio::test]
async fn join_limits_are_validated_and_membership_memory_is_bounded() {
    let mut c = config();
    c.max_peers = 1;
    c.max_topics = 1;
    let a = host(vec![], c).await;
    let mut invalid = JoinOptions::new(vec![]);
    invalid.max_uses = 0;
    assert!(matches!(
        a.issue_join_code(invalid).await,
        Err(Error::Config(_))
    ));
    let code = a.issue_join_code(JoinOptions::new(vec![])).await.unwrap();
    assert!(matches!(
        a.issue_join_code(JoinOptions::new(vec![])).await,
        Err(Error::QueueFull)
    ));
    let b = MessagingEndpoint::join(config(), Identity::generate(), &code)
        .await
        .unwrap();
    b.shutdown(ShutdownMode::Immediate).await.unwrap();
    // Disconnecting cannot free the admission record and bypass the membership ceiling.
    assert!(matches!(
        MessagingEndpoint::join(config(), Identity::generate(), &code).await,
        Err(Error::QueueFull)
    ));
    assert!(a.metrics().await.unwrap().metadata_bytes <= config().metadata_bytes);
    a.shutdown(ShutdownMode::Immediate).await.unwrap();
}

#[tokio::test]
async fn relay_only_join_code_connects_two_then_three_peers() {
    use iroh_relay::server::{RelayConfig, Server, ServerConfig};
    let mut relay_config = ServerConfig::default();
    relay_config.relay = Some(RelayConfig::new(
        "127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap(),
    ));
    let relay = Server::spawn(relay_config).await.unwrap();
    let url = format!("http://{}", relay.http_addr().unwrap())
        .parse()
        .unwrap();
    let mut c = config();
    c.relay_only = true;
    c.bind_addr = None;
    c.relay_mode = RelayMode::custom([url]);
    let a = host(vec![Permission::subscribe("jobs").unwrap()], c.clone()).await;
    a.online(wait_timeout()).await.unwrap();
    let code = a
        .issue_join_code(JoinOptions::new(vec![Permission::publish("jobs").unwrap()]))
        .await
        .unwrap();
    let code = JoinCode::decode(&code.encode().unwrap()).unwrap();
    let mut sub = a
        .subscribe("jobs", SubscriptionOptions::acknowledged())
        .await
        .unwrap();
    let b = MessagingEndpoint::join(c.clone(), Identity::generate(), &code)
        .await
        .unwrap();
    let third = MessagingEndpoint::join(c, Identity::generate(), &code)
        .await
        .unwrap();
    for peer in [&b, &third] {
        sub.wait_ready(peer.endpoint_id(), wait_timeout())
            .await
            .unwrap();
        let mut receipt = peer
            .publisher("jobs")
            .unwrap()
            .publish(
                peer.buffers()
                    .copy_from_slice(b"joined over relay")
                    .unwrap(),
                options(),
            )
            .await
            .unwrap();
        delivery(&mut sub).await.ack().await.unwrap();
        assert_eq!(
            receipt.wait_for_processing(wait_timeout()).await.unwrap()[0].1,
            RecipientOutcome::Processed
        );
    }
    close(&a, &b).await;
    third.shutdown(ShutdownMode::Immediate).await.unwrap();
    relay.shutdown().await.unwrap();
}

#[tokio::test]
async fn idle_publishers_do_not_reserve_another_publishers_receive_capacity() {
    let mut c = config();
    c.payload_bytes = 512;
    c.subscription_messages = 1;
    let receiver = host(vec![Permission::subscribe("jobs").unwrap()], c).await;
    let idle = member(
        &receiver,
        vec![Permission::publish("jobs").unwrap()],
        config(),
    )
    .await;
    let active = member(
        &receiver,
        vec![Permission::publish("jobs").unwrap()],
        config(),
    )
    .await;
    let mut sub = receiver
        .subscribe("jobs", SubscriptionOptions::default())
        .await
        .unwrap();
    sub.wait_ready(idle.endpoint_id(), wait_timeout())
        .await
        .unwrap();
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
async fn rejoin_rejects_a_new_realm_even_if_host_reuses_its_transport_key() {
    let identity = Identity::generate();
    let a = MessagingEndpoint::host(config(), identity.clone(), vec![])
        .await
        .unwrap();
    let code = a.issue_join_code(JoinOptions::new(vec![])).await.unwrap();
    let code = JoinCode::decode(&code.encode().unwrap()).unwrap();
    let b = MessagingEndpoint::join(config(), Identity::generate(), &code)
        .await
        .unwrap();
    let previous_certificate = b.certificate();
    a.shutdown(ShutdownMode::Immediate).await.unwrap();
    let restarted = MessagingEndpoint::host(config(), identity, vec![])
        .await
        .unwrap();
    let new_code = restarted
        .issue_join_code(JoinOptions::new(vec![]))
        .await
        .unwrap();
    let new_code = JoinCode::decode(&new_code.encode().unwrap()).unwrap();
    assert_eq!(new_code.host_id(), code.host_id());
    assert_eq!(b.rejoin(&new_code).await, Err(Error::Unauthorized));
    assert_eq!(b.certificate().id(), previous_certificate.id());
    // Explicitly joining anew can accept the restarted host's new authority and realm.
    let fresh = MessagingEndpoint::join(config(), Identity::generate(), &new_code)
        .await
        .unwrap();
    close(&restarted, &fresh).await;
    b.shutdown(ShutdownMode::Immediate).await.unwrap();
}
