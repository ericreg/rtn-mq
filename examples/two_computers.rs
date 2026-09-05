//! One message between separate processes or computers. See USER_GUIDE.md.
use rtn_mq::*;
use std::{
    error::Error as StdError,
    fs::{File, OpenOptions},
    io::{Read, Write},
    net::SocketAddr,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::{Instant, sleep, timeout};

const TOPIC: &str = "quickstart/messages";
const FORMAT: &str = "quickstart/text-v1+cbor";
const MAX_SETUP: u64 = 64 * 1024;
const MAX_TEXT: usize = 16 * 1024;
type AppResult<T> = std::result::Result<T, Box<dyn StdError + Send + Sync>>;

const USAGE: &str = "Usage:
  cargo run --locked --example two_computers -- receive <setup.cbor> [--bind IP:PORT]
  cargo run --locked --example two_computers -- send <setup.cbor> <message> [--bind IP:PORT]

Defaults use Iroh's relays. --bind selects direct-only networking on a local address.
The receiver creates a one-use setup file; copy it privately to the sender.
Each run creates fresh keys and handles one message. Existing setup files are not overwritten.";

#[tokio::main]
async fn main() -> AppResult<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [] => println!("{USAGE}"),
        [help] if help == "--help" || help == "-h" => println!("{USAGE}"),
        [mode, path, rest @ ..] if mode == "receive" => {
            receive(Path::new(path), bind_arg(rest)?).await?;
        }
        [mode, path, text, rest @ ..] if mode == "send" => {
            send(Path::new(path), text, bind_arg(rest)?).await?;
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

fn config(trust: Trust, bind: Option<SocketAddr>) -> Config {
    let mut config = Config::new(trust);
    config.handshake_timeout = Duration::from_secs(30);
    if let Some(bind) = bind {
        config.relay_mode = RelayMode::Disabled;
        config.bind_addr = Some(bind);
    }
    config
}

// This is trusted bootstrap configuration, transferred privately by the user.
// Neither contact information nor an enrollment secret contains a private key.
fn write_setup(path: &Path, enrollment: &EnrollmentInvite, peer: &PeerInvite) -> AppResult<()> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(3)?
        .u8(1)?
        .str(&enrollment.encode()?)?
        .str(&peer.encode()?)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(&encoder.into_writer())?;
    file.sync_all()?;
    Ok(())
}

fn read_setup(path: &Path) -> AppResult<(EnrollmentInvite, PeerInvite)> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_SETUP + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_SETUP {
        return Err("setup file exceeds 64 KiB".into());
    }
    let mut decoder = minicbor::Decoder::new(&bytes);
    if decoder.array()? != Some(3) || decoder.u8()? != 1 {
        return Err("unsupported setup file".into());
    }
    let enrollment = EnrollmentInvite::decode(decoder.str()?)?;
    let peer = PeerInvite::decode(decoder.str()?)?;
    if decoder.position() != bytes.len()
        || enrollment.contact.realm_id != peer.realm_id
        || enrollment.contact.authority != peer.authority
    {
        return Err("inconsistent setup file".into());
    }
    Ok((enrollment, peer))
}

fn encode_text(text: &str) -> AppResult<Vec<u8>> {
    if text.len() > MAX_TEXT {
        return Err("message must be at most 16 KiB of UTF-8 text".into());
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

async fn receive(path: &Path, bind: Option<SocketAddr>) -> AppResult<()> {
    // Refuse to silently replace a still-live invitation from another run.
    match std::fs::symlink_metadata(path) {
        Ok(_) => return Err("setup file already exists; choose a new filename".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let authority = Authority::generate();
    let identity = Identity::generate();
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let certificate = authority.issue(
        identity.endpoint_id(),
        vec![Permission::subscribe(TOPIC)?],
        now,
        now + 3600,
        CertificateLimits::default(),
    )?;
    let messaging_config = config(authority.trust(), bind);
    let receiver =
        MessagingEndpoint::start(messaging_config.clone(), identity, certificate).await?;
    let result = async {
        let mut subscription = receiver
            .subscribe(TOPIC, SubscriptionOptions::acknowledged())
            .await?;
        if bind.is_none() {
            println!("Waiting for relay connectivity...");
            receiver.online(Duration::from_secs(30)).await?;
        }
        // Enrollment uses a different key and port from the messaging endpoint.
        let mut enrollment_config = messaging_config;
        if let Some(mut address) = bind {
            address.set_port(0);
            enrollment_config.bind_addr = Some(address);
        } else {
            // EnrollmentService waits for a usable relay address in this mode.
            enrollment_config.relay_only = true;
        }
        let service =
            EnrollmentService::start(authority, Identity::generate(), enrollment_config).await?;
        let exchange = async {
            let invitation = service
                .issue_invite(
                    vec![Permission::publish(TOPIC)?],
                    CertificateLimits::default(),
                    Duration::from_secs(3600),
                    Duration::from_secs(600),
                )
                .await?;
            write_setup(path, &invitation, &receiver.invite())?;
            println!("Setup file written: {}", path.display());
            println!(
                "Copy this file privately to the sender. Waiting up to 10 minutes for a message..."
            );
            let delivery = timeout(Duration::from_secs(600), subscription.recv())
                .await??
                .ok_or("subscription closed before a message arrived")?;
            let parsed = if delivery.format == FORMAT {
                decode_text(delivery.payload())
            } else {
                Err("unexpected message format".into())
            };
            match parsed {
                Ok(text) => println!("Received: {text}"),
                Err(error) => {
                    delivery.nack(Nack::Permanent).await?;
                    return Err(error);
                }
            }
            delivery.ack().await?;
            println!("Acknowledged. Waiting for the sender to disconnect...");
            // Keep the endpoint alive so the ACK reaches the sender and can be
            // regenerated if necessary. The sender disconnects after Processed.
            timeout(Duration::from_secs(45), async {
                while receiver.metrics().await?.peers != 0 {
                    sleep(Duration::from_millis(100)).await;
                }
                Ok::<(), rtn_mq::Error>(())
            })
            .await??;
            Ok::<(), Box<dyn StdError + Send + Sync>>(())
        }
        .await;
        service.shutdown().await?;
        exchange
    }
    .await;
    receiver.shutdown(ShutdownMode::Immediate).await?;
    result
}

async fn send(path: &Path, text: &str, bind: Option<SocketAddr>) -> AppResult<()> {
    let payload = encode_text(text)?;
    let (enrollment, peer) = read_setup(path)?;
    // The file is the explicit trust bootstrap. Accept only the file obtained
    // from your intended receiver through your authenticated transfer channel.
    let trust = Trust::new(peer.realm_id, peer.authority);
    let config = config(trust, bind);
    let identity = Identity::generate();
    println!("Enrolling this sender...");
    let certificate = enrollment.redeem(&identity, &config).await?;
    let sender = MessagingEndpoint::start(config, identity, certificate).await?;
    let result = async {
        let receiver_id = peer.address.id;
        sender.connect(peer).await?;
        println!("Connected. Waiting for the receiver's subscription...");
        let publisher = sender.publisher(TOPIC)?;
        let payload = sender.buffers().from_vec(payload)?;
        let options = PublishOptions {
            lifetime: Duration::from_secs(30),
            format: FORMAT.into(),
            ..PublishOptions::default()
        };
        let ready_deadline = Instant::now() + Duration::from_secs(30);
        let mut receipt = loop {
            match publisher.publish(payload.clone(), options.clone()).await {
                Ok(receipt) => break receipt,
                Err(Error::NoSubscribers) if Instant::now() < ready_deadline => {
                    sleep(Duration::from_millis(50)).await;
                }
                Err(error) => return Err(error.into()),
            }
        };
        let outcomes = receipt.wait_for_processing(Duration::from_secs(35)).await?;
        if outcomes
            .iter()
            .any(|(id, outcome)| *id == receiver_id && *outcome == RecipientOutcome::Processed)
        {
            println!("Processed: receiver acknowledged your message.");
            Ok(())
        } else {
            Err(format!("message was not acknowledged: {outcomes:?}").into())
        }
    }
    .await;
    sender.shutdown(ShutdownMode::Immediate).await?;
    result
}
