//! Local direct-path smoke benchmark; it is not a network capacity claim.
use rtn_mq::*;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::Instant;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let parse = |index: usize, default: usize| -> Result<usize> {
        args.get(index)
            .map(|s| {
                s.parse()
                    .map_err(|_| Error::Config("expected iterations fanout payload_bytes"))
            })
            .unwrap_or(Ok(default))
    };
    let iterations = parse(0, 20)?;
    let fanout = parse(1, 3)?;
    let size = parse(2, 1024)?;
    if iterations == 0 || iterations > 10000 || fanout == 0 || fanout > 100 || size > 1024 * 1024 {
        return Err(Error::Config("benchmark limits"));
    }
    let authority = Authority::generate();
    let mut config = Config::new(authority.trust());
    config.relay_mode = RelayMode::Disabled;
    config.bind_addr = Some("127.0.0.1:0".parse().unwrap());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let key = Identity::generate();
    let cert = authority.issue(
        key.endpoint_id(),
        vec![Permission::publish("bench")?],
        now,
        now + 3600,
        CertificateLimits::default(),
    )?;
    let sender = MessagingEndpoint::start(config.clone(), key, cert).await?;
    let mut receivers = Vec::new();
    let mut workers = Vec::new();
    for _ in 0..fanout {
        let key = Identity::generate();
        let cert = authority.issue(
            key.endpoint_id(),
            vec![Permission::subscribe("bench")?],
            now,
            now + 3600,
            CertificateLimits::default(),
        )?;
        let receiver = MessagingEndpoint::start(config.clone(), key, cert).await?;
        let mut subscription = receiver
            .subscribe("bench", SubscriptionOptions::default())
            .await?;
        sender.connect(receiver.invite()).await?;
        subscription
            .wait_ready(sender.endpoint_id(), Duration::from_secs(10))
            .await?;
        workers.push(tokio::spawn(async move {
            for _ in 0..iterations {
                let delivery = tokio::time::timeout(Duration::from_secs(60), subscription.recv())
                    .await
                    .map_err(|_| Error::Timeout)??
                    .ok_or(Error::SubscriptionClosed)?;
                delivery.ack().await?;
            }
            Ok::<_, Error>(())
        }));
        receivers.push(receiver);
    }
    drop(authority);
    let publisher = sender.publisher("bench")?;
    let mut latencies = Vec::with_capacity(iterations);
    let start = Instant::now();
    for _ in 0..iterations {
        let payload = sender.buffers().from_vec(vec![7; size])?;
        let sent = Instant::now();
        let mut receipt = publisher
            .publish(payload, PublishOptions::default())
            .await?;
        let outcomes = receipt.wait_for_processing(Duration::from_secs(60)).await?;
        if outcomes
            .iter()
            .any(|(_, o)| *o != RecipientOutcome::Processed)
        {
            return Err(Error::Protocol("benchmark delivery failed"));
        }
        latencies.push(sent.elapsed().as_micros());
    }
    let elapsed = start.elapsed();
    latencies.sort_unstable();
    let percentile = |p: usize| latencies[((latencies.len() - 1) * p) / 100];
    let metrics = sender.metrics().await?;
    println!(
        "iterations,fanout,payload_bytes,elapsed_ms,deliveries_per_second,p50_us,p95_us,p99_us,peak_sender_payload_charge,peak_sender_metadata_charge"
    );
    println!(
        "{iterations},{fanout},{size},{:.3},{:.3},{},{},{},{},{}",
        elapsed.as_secs_f64() * 1000.0,
        (iterations * fanout) as f64 / elapsed.as_secs_f64(),
        percentile(50),
        percentile(95),
        percentile(99),
        metrics.peak_payload_bytes,
        metrics.peak_metadata_bytes
    );
    for worker in workers {
        worker.await.map_err(|_| Error::ShuttingDown)??;
    }
    sender.shutdown(ShutdownMode::Immediate).await?;
    for receiver in receivers {
        receiver.shutdown(ShutdownMode::Immediate).await?;
    }
    Ok(())
}
