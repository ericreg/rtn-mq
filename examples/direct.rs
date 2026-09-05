use rtn_mq::*;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
#[tokio::main]
async fn main() -> Result<()> {
    let authority = Authority::generate();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let publisher_key = Identity::generate();
    let subscriber_key = Identity::generate();
    let publisher_cert = authority.issue(
        publisher_key.endpoint_id(),
        vec![Permission::publish("jobs")?],
        now,
        now + 3600,
        CertificateLimits::default(),
    )?;
    let subscriber_cert = authority.issue(
        subscriber_key.endpoint_id(),
        vec![Permission::subscribe("jobs")?],
        now,
        now + 3600,
        CertificateLimits::default(),
    )?;
    let mut config = Config::new(authority.trust());
    config.relay_mode = RelayMode::Disabled;
    config.bind_addr = Some("127.0.0.1:0".parse().unwrap());
    drop(authority); // No authority participates in messaging.
    let sender = MessagingEndpoint::start(config.clone(), publisher_key, publisher_cert).await?;
    let receiver = MessagingEndpoint::start(config, subscriber_key, subscriber_cert).await?;
    let mut subscription = receiver
        .subscribe("jobs", SubscriptionOptions::acknowledged())
        .await?;
    sender.connect(receiver.invite()).await?;
    subscription
        .wait_ready(sender.endpoint_id(), Duration::from_secs(5))
        .await?;
    let mut receipt = sender
        .publisher("jobs")?
        .publish(
            sender.buffers().copy_from_slice(b"hello over Iroh")?,
            PublishOptions::default(),
        )
        .await?;
    if let Some(delivery) = subscription.recv().await? {
        println!("received: {}", String::from_utf8_lossy(delivery.payload()));
        delivery.ack().await?;
    }
    println!(
        "outcomes: {:?}",
        receipt.wait_for_processing(Duration::from_secs(5)).await?
    );
    sender.shutdown(ShutdownMode::Immediate).await?;
    receiver.shutdown(ShutdownMode::Immediate).await?;
    Ok(())
}
