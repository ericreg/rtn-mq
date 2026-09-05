//! Run `host` on A, then `join <code> <message>` on any number of other machines.
use rtn_mq::*;
use std::{error::Error as StdError, net::SocketAddr, time::Duration};
use tokio::time::{sleep, timeout};
const TOPIC: &str = "quickstart/messages";
const FORMAT: &str = "quickstart/text-v1+cbor";
const MAX_TEXT: usize = 16 * 1024;
type AppResult<T> = std::result::Result<T, Box<dyn StdError + Send + Sync>>;
const USAGE: &str = "Usage:
  cargo run --locked --example two_computers -- host [--bind IP:PORT]
  cargo run --locked --example two_computers -- join <join-code> <message> [--bind IP:PORT]

Copy the host's join code to each joining computer. No setup files are needed.
The reusable code expires in one hour and admits up to 256 distinct identities.
Default networking uses Iroh relays; --bind selects a direct-only local address.
The host runs until Ctrl+C. Each join command creates a fresh identity.";

#[tokio::main]
async fn main() -> AppResult<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [] => println!("{USAGE}"),
        [help] if help == "--help" || help == "-h" => println!("{USAGE}"),
        [mode, rest @ ..] if mode == "host" => host(bind_arg(rest)?).await?,
        [mode, code, text, rest @ ..] if mode == "join" => {
            join(code, text, bind_arg(rest)?).await?
        }
        _ => return Err(USAGE.into()),
    }
    Ok(())
}
fn bind_arg(args: &[String]) -> AppResult<Option<SocketAddr>> {
    match args {
        [] => Ok(None),
        [flag, address] if flag == "--bind" => Ok(Some(address.parse()?)),
        _ => Err(USAGE.into()),
    }
}
fn config(bind: Option<SocketAddr>) -> Config {
    let mut c = Config::new();
    c.handshake_timeout = Duration::from_secs(30);
    if let Some(address) = bind {
        c.relay_mode = RelayMode::Disabled;
        c.bind_addr = Some(address);
    }
    c
}
fn encode_text(text: &str) -> AppResult<Vec<u8>> {
    if text.len() > MAX_TEXT {
        return Err("message exceeds 16 KiB of UTF-8 text".into());
    }
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(2)?.u8(1)?.str(text)?;
    Ok(encoder.into_writer())
}
fn decode_text(bytes: &[u8]) -> AppResult<&str> {
    let mut decoder = minicbor::Decoder::new(bytes);
    if decoder.array()? != Some(2) || decoder.u8()? != 1 {
        return Err("unsupported message schema".into());
    }
    let text = decoder.str()?;
    if text.len() > MAX_TEXT || decoder.position() != bytes.len() {
        return Err("invalid message length or trailing data".into());
    }
    Ok(text)
}
async fn host(bind: Option<SocketAddr>) -> AppResult<()> {
    let host = MessagingEndpoint::host(
        config(bind),
        Identity::generate(),
        vec![Permission::subscribe(TOPIC)?],
    )
    .await?;
    let result = async {
        let mut subscription = host
            .subscribe(TOPIC, SubscriptionOptions::acknowledged())
            .await?;
        if bind.is_none() {
            println!("Waiting for relay connectivity...");
            host.online(Duration::from_secs(30)).await?;
        }
        let code = host
            .issue_join_code(JoinOptions::new(vec![Permission::publish(TOPIC)?]))
            .await?;
        println!("Join code: {}", code.encode()?);
        println!("Share this code privately. Waiting for messages; press Ctrl+C to stop.");
        loop {
            let delivery = tokio::select! {
                result = tokio::signal::ctrl_c() => { result?; break; },
                result = subscription.recv() => result?.ok_or("subscription closed")?,
            };
            let decoded = if delivery.format == FORMAT {
                decode_text(delivery.payload())
            } else {
                Err("unexpected message format".into())
            };
            match decoded {
                Ok(text) => println!("Received: {text}"),
                Err(error) => {
                    eprintln!("Rejected message: {error}");
                    delivery.nack(Nack::Permanent).await?;
                    continue;
                }
            }
            delivery.ack().await?;
            println!("Acknowledged. Waiting for more messages...");
        }
        Ok::<(), Box<dyn StdError + Send + Sync>>(())
    }
    .await;
    host.shutdown(ShutdownMode::Immediate).await?;
    result
}
async fn join(code: &str, text: &str, bind: Option<SocketAddr>) -> AppResult<()> {
    let payload = encode_text(text)?;
    let code = JoinCode::decode(code.trim())?;
    println!("Joining host...");
    let sender = MessagingEndpoint::join(config(bind), Identity::generate(), &code).await?;
    let result = async {
        println!("Connected. Waiting for the host's subscription...");
        let publisher = sender.publisher(TOPIC)?;
        let payload = sender.buffers().from_vec(payload)?;
        let options = PublishOptions {
            lifetime: Duration::from_secs(30),
            format: FORMAT.into(),
            ..PublishOptions::default()
        };
        // Retry only failed admission; an admitted message is tracked by its receipt.
        let mut receipt = timeout(Duration::from_secs(30), async {
            loop {
                match publisher.publish(payload.clone(), options.clone()).await {
                    Err(Error::NoSubscribers) => sleep(Duration::from_millis(50)).await,
                    result => break result,
                }
            }
        })
        .await
        .map_err(|_| Error::Timeout)??;
        let outcomes = receipt.wait_for_processing(Duration::from_secs(35)).await?;
        if outcomes
            .iter()
            .any(|(id, outcome)| *id == code.host_id() && *outcome == RecipientOutcome::Processed)
        {
            println!("Processed: host acknowledged your message.");
            Ok(())
        } else {
            Err(format!("message was not acknowledged: {outcomes:?}").into())
        }
    }
    .await;
    sender.shutdown(ShutdownMode::Immediate).await?;
    result
}
