use rtn_mq::*;
use std::time::Duration;
#[tokio::main]
async fn main() -> Result<()> {
    let mut config = Config::new();
    config.relay_mode = RelayMode::Disabled;
    config.bind_addr = Some("127.0.0.1:0".parse().unwrap());
    let sender = MessagingEndpoint::host(
        config.clone(),
        Identity::generate(),
        vec![Permission::publish("jobs")?],
    )
    .await?;
    let code = sender
        .issue_join_code(JoinOptions::new(vec![Permission::subscribe("jobs")?]))
        .await?;
    let receiver = MessagingEndpoint::join(config, Identity::generate(), &code).await?;
    let mut subscription = receiver
        .subscribe("jobs", SubscriptionOptions::acknowledged())
        .await?;
    subscription
        .wait_ready(sender.endpoint_id(), Duration::from_secs(5))
        .await?;
    let mut receipt = sender
        .publisher("jobs")?
        .publish(
            sender
                .buffers()
                .from_vec(minicbor::to_vec("hello over Iroh").unwrap())?,
            PublishOptions {
                format: "text/cbor".into(),
                ..PublishOptions::default()
            },
        )
        .await?;
    if let Some(delivery) = subscription.recv().await? {
        println!(
            "received: {}",
            minicbor::decode::<&str>(delivery.payload())?
        );
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
