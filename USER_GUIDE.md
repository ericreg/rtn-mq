# Connecting peers with rtn-mq

`rtn-mq` is a Rust library that you embed in your application. Each running peer can accept connections, initiate connections, publish, and subscribe according to its certificate. It uses Iroh for transport and does not require ESP or an ESP daemon.

To exchange messages, provision both peers under the same authority and realm, start their endpoints, share a peer contact code, and call `connect()`. Then establish a subscription before publishing. A transport connection alone does not mean a topic has a ready subscriber.

## Quick start

This walkthrough sends one message between two peers on your computer. A **peer** is an application participating in messaging; in this example, one program starts two peer endpoints to keep setup simple. An **endpoint** is the library object that manages a peer's connections.

You only need basic Rust knowledge to run the example. It creates the keys, permissions, and connections for you.

### 1. Check your tools and open the project

You need Rust 1.96 or newer, including Cargo, Rust's build and package tool. Check your installation:

```sh
rustc --version
cargo --version
```

Open a terminal in the `rtn-mq` project directory—the directory containing `Cargo.toml`, `Cargo.lock`, and the `examples` folder. The first build may need internet access to download dependencies.

### 2. Run the example

```sh
cargo run --locked --example direct
```

Cargo compiles the project and runs [examples/direct.rs](examples/direct.rs). `--locked` uses the dependency versions recorded in `Cargo.lock`, and `--example direct` selects that example program. The first build can take a few minutes.

You need only one terminal. The program starts both endpoints and connects them through `127.0.0.1`, the address for your own computer. This is called a **loopback** connection. No separate server, relay service, or configuration file is needed to run this example.

### 3. Check the result

After the build messages, you should see output like this:

```text
received: hello over Iroh
outcomes: [(PublicKey(...), Processed)]
```

The actual output contains a public key in place of `...`. It identifies the receiving peer and changes each run because this example creates temporary keys.

The first line shows that the receiver read the message. `Processed` means the receiver also called `ack()`, short for **acknowledge**, to tell the sender that its application finished handling the message. The program then closes both endpoints and exits.

### 4. Follow the code

Open [examples/direct.rs](examples/direct.rs). The program performs these steps in order:

1. **Create identities and permissions.** Each peer gets its own private key. A shared **authority** signs a certificate for each peer: one certificate allows sending on `jobs`, and the other allows receiving on `jobs`. A certificate is a signed record of what that peer is allowed to do.
2. **Start the endpoints.** `MessagingEndpoint::start(...)` creates the sender and receiver using their keys and certificates. The `#[tokio::main]` annotation starts the runtime that runs their asynchronous network operations.
3. **Subscribe and connect.** The receiver subscribes to `jobs`. A **topic** is a message category, identified by a string; subscribing asks to receive messages in that category. `sender.connect(receiver.invite()).await?` uses the receiver's contact information to establish the connection.
4. **Wait, then publish.** `subscription.wait_ready(...)` waits until the sender has accepted the subscription. Then `publish(...)` sends the message and returns a **receipt**, which tracks its delivery result. Connecting and becoming ready to receive a topic are separate steps.
5. **Receive and acknowledge.** `subscription.recv().await?` waits for a message. The receiver prints it and calls `delivery.ack().await?`. The sender checks the receipt with `wait_for_processing(...)` before shutting down.

In these calls, `.await` waits for an asynchronous operation to finish while allowing the runtime to run other work. The `?` operator returns an error to the calling function if the operation fails.

Wait methods accept a duration, such as `receipt.wait_for_processing(Duration::from_secs(5)).await?`. This gives that call up to five seconds in total; the library handles the clock internally. `wait_ready(peer_id, Duration::from_secs(5))` and `online(Duration::from_secs(5))` use the same convention. If the wait times out, it returns `Error::Timeout`. A receipt timeout stops waiting but does not cancel the message.

The example acknowledges immediately after printing. In your application, call `ack()` after completing the work the message requested—for example, after successfully saving a record.

### 5. Make a small change

In `examples/direct.rs`, find `b"hello over Iroh"` and replace it with `b"my first message"`. The `b` prefix makes this a byte string, which is the payload type used by this example. Run the same Cargo command again and check that the receiver prints your new message.

The protocol encodes its metadata and signed records with CBOR, a binary data format. The payload API accepts bytes; for structured application messages, encode your data as CBOR and decode it in the receiver. You do not need to change the encoding to try this text-message example.

### Send a message between two computers

The [two-computer example](examples/two_computers.rs) runs one peer on each computer. Call the receiving computer **A** and the sending computer **B**. Both need Rust 1.96 or newer and the same version of this checkout. Run the commands below from the project directory on each computer.

This example creates temporary keys and handles **one message per run**. Computer A also acts as the authority for this demonstration: it gives B a certificate allowing B to send a message. Each computer generates its own private key locally.

The default commands use Iroh's network setup, including relays. A **relay** is a service that helps peers communicate when they cannot reach each other directly. Both computers need network access to the configured services. For computers on the same LAN without relay access, use the LAN commands below.

#### Step A: start the receiver on computer A

```sh
cargo run --locked --example two_computers -- receive peer-setup.cbor
```

The `--` separates Cargo's options from the example program's arguments. `receive` selects the receiver role, and `peer-setup.cbor` is the setup file it will create in the current directory.

Wait until the terminal prints:

```text
Setup file written: peer-setup.cbor
Copy this file privately to the sender. Waiting up to 10 minutes for a message...
```

Leave this terminal running. The receiver has subscribed to `quickstart/messages` and is ready for the sender to connect.

#### Step B: copy the setup file to computer B

The setup file contains the receiver's contact information, the authority's public key and realm (the messaging group's ID), and a one-use enrollment secret. **Copy it privately from A to B using a trusted file-transfer method.** B uses this file to decide which authority and peer to trust; do not accept a replacement from someone else.

For example, if you already have SSH access to B, open another terminal on A in the project directory and run:

```sh
scp peer-setup.cbor YOUR_USER@COMPUTER_B:/absolute/path/to/rtn-mq/peer-setup.cbor
```

Replace `YOUR_USER`, `COMPUTER_B`, and the destination path with your own values. If you do not use SSH, copy the file using another authenticated, private transfer method. There is no private key in this file, but its enrollment secret grants permission to the first sender that redeems it, so do not put it in a public chat or commit it to Git.

The program creates the file with private permissions on Unix. On other platforms, store and transfer it in a location accessible only to the intended user.

#### Step C: send a message from computer B

Once `peer-setup.cbor` is in B's project directory, run:

```sh
cargo run --locked --example two_computers -- send peer-setup.cbor "Hello from computer B"
```

The sender reads the setup file, creates its own key, obtains a certificate, connects to A, and waits for A's subscription before sending. The message is encoded as CBOR using the small schema `[1, text]`, where `1` is the schema version. This example accepts up to 16 KiB of UTF-8 message text.

Computer A should print:

```text
Received: Hello from computer B
Acknowledged. Waiting for the sender to disconnect...
```

Computer B should print:

```text
Enrolling this sender...
Connected. Waiting for the receiver's subscription...
Processed: receiver acknowledged your message.
```

`Processed` confirms that A decoded the message, printed it, and acknowledged it. B then disconnects, and both programs exit. A stays connected until B finishes so that closing A too early does not interrupt the acknowledgement.

#### Run it again

Start a fresh receiver run with a new filename, for example `peer-setup-2.cbor`, then repeat the copy and send steps with that file. The program refuses to overwrite an existing setup file. Each invitation has a 10-minute redemption window; stopping the receiver also invalidates it. Restart from Step A if the receiver exits or the sender fails after redeeming the invitation: a new sender process generates a new identity.

After the run, delete the setup files from both computers when you no longer need them. For long-running applications that preserve identities across restarts, follow [the provisioning section](#1-provision-identities-and-permissions).

#### Option: use a direct connection on the same LAN

If both computers can reach each other on your local network, add `--bind` to disable relays and choose a local address. In this example, A's LAN address is `192.168.1.20` and B's is `192.168.1.21`; replace them with addresses assigned to your own computers.

On A:

```sh
cargo run --locked --example two_computers -- receive lan-setup.cbor --bind 192.168.1.20:42000
```

Copy `lan-setup.cbor` to B as in Step B, then run on B:

```sh
cargo run --locked --example two_computers -- send lan-setup.cbor "Hello over the LAN" --bind 192.168.1.21:0
```

Port `0` asks the operating system to choose a free port. A listens for messages on UDP port `42000` and starts its enrollment service on another automatically selected UDP port, which is included in the setup file. Allow the example application's UDP traffic between the two computers for both enrollment and messaging. Use a fresh filename if you already ran this LAN example.

Do not use `127.0.0.1` for two different computers: each computer interprets that address as itself. To practice the same two-process workflow on a single computer, use two terminals, pass `--bind 127.0.0.1:0` to both commands, and let both read the same setup file; no file transfer is needed.

If the default example times out while waiting for a relay, check network access or use the LAN option. If enrollment fails, check that A is still running and that you copied its current setup file within the 10-minute window. See [Troubleshooting](#troubleshooting) for other errors.

## What each peer needs

| Item | Purpose | How to handle it |
|---|---|---|
| `Identity` | The peer's private key; determines its `EndpointId` | Generate on that peer and keep private. Load the same key on restart. |
| `Certificate` | Authority-signed permission to publish/subscribe on exact topics | Obtain from your authority, bound to this peer's endpoint ID. |
| `Trust` | The realm ID and authority public key this application accepts | Provision through your deployment configuration or another trusted channel. |
| `PeerInvite` | A peer's endpoint ID, realm, authority public key, and address hints | Export from a running messaging endpoint and share with its intended peer. |

The authority's signing key belongs to your provisioning system. Ordinary messaging peers need only its public key. Do not generate a different authority for each peer, and do not reuse an authority key as a messaging endpoint identity.

A peer contact code does **not** issue a certificate or grant permissions. An `EnrollmentInvite`, described below, is a separate kind of invitation that contains a secret and can issue a certificate.

## 1. Provision identities and permissions

Use one of two provisioning paths:

- **Offline provisioning:** send each peer's public endpoint ID to the authority and return its signed certificate.
- **Network enrollment:** give the peer a single-use enrollment invitation so it can obtain a certificate for its own key.

### Offline provisioning

On Unix, create a private directory before saving a key:

```sh
install -d -m 700 ./peer-state
```

Generate the identity once during initial setup. This helper refuses to replace an existing key:

```rust
use rtn_mq::*;
use std::path::Path;

fn create_identity(path: &Path) -> Result<EndpointId> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => return Err(Error::Config("identity already exists")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let identity = Identity::generate();
    identity.save(path)?;
    Ok(identity.endpoint_id())
}
```

Call it with `Path::new("peer-state/identity.key")` on each peer. Give the returned **public** endpoint IDs to the authority; keep each private key on its own machine. `Identity::save`/`load` support Unix private files. On other platforms, supply an `Identity` using an application-managed key store.

On the provisioning system, issue certificates with complementary permissions. This helper takes your existing authority and the two public IDs:

```rust
use rtn_mq::*;
use std::time::{SystemTime, UNIX_EPOCH};

fn issue_pair(
    authority: &Authority,
    publisher_id: EndpointId,
    subscriber_id: EndpointId,
) -> Result<(Certificate, Certificate)> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Clock)?
        .as_secs();
    let publisher = authority.issue(
        publisher_id,
        vec![Permission::publish("jobs")?],
        now,
        now + 3600,
        CertificateLimits::default(),
    )?;
    let subscriber = authority.issue(
        subscriber_id,
        vec![Permission::subscribe("jobs")?],
        now,
        now + 3600,
        CertificateLimits::default(),
    )?;
    Ok((publisher, subscriber))
}
```

Create an authority with `Authority::generate()` for a disposable demonstration. For a persistent deployment, restore its private identity and realm with `Authority::from_identity(identity, realm_id)` rather than generating a new authority at every startup.

Write each certificate's `as_bytes()` to that peer's `peer-state/certificate.cbor`. Distribute `authority.realm_id()` and `authority.public_key()` as trusted application configuration to both peers. The example certificates last one hour; plan to replace them before expiry.

Topics are case-sensitive exact paths: `jobs` and `Jobs` are different, and `jobs/*` is not a wildcard. For two-way messaging on `jobs`, issue `Permission::both("jobs")` to both peers and create a subscription on each.

## 2. Start both endpoints

Add the library to your application's `Cargo.toml`. This example assumes your application and this checkout are sibling directories; adjust the path to your layout:

```toml
[dependencies]
rtn-mq = { path = "../rtn-mq" }
tokio = { version = "=1.53.1", features = ["rt-multi-thread", "macros", "time"] }
```

Run the async helpers in this guide from a Tokio runtime, such as an `async fn main()` annotated with `#[tokio::main]`. These are application building blocks; your application supplies its trusted configuration, file paths, and contact-code exchange.

On each peer, load its own identity and certificate:

```rust
use rtn_mq::*;
use std::path::Path;

async fn start_peer(
    state_dir: &Path,
    realm_id: RealmId,
    authority_public_key: EndpointId,
) -> Result<MessagingEndpoint> {
    let identity = Identity::load(state_dir.join("identity.key"))?;
    let certificate = Certificate::from_bytes(
        &std::fs::read(state_dir.join("certificate.cbor"))?,
    )?;
    let trust = Trust::new(realm_id, authority_public_key);
    MessagingEndpoint::start(Config::new(trust), identity, certificate).await
}
```

The realm and root passed here come from your trusted configuration, not from an unverified contact code. `start()` checks that the certificate matches the identity and trust configuration and is currently valid.

`Config::new` enables the default Iroh relay and address-lookup setup. `start()` binds the endpoint and starts accepting connections; there is no additional `listen()` call. Keep the endpoint and Tokio runtime alive while communicating.

## 3. Export the receiver's contact code

On the receiving application, create the subscription before sharing the contact code. With the default relay configuration, wait for relay connectivity before taking the address snapshot:

```rust
use rtn_mq::*;
use std::time::Duration;

async fn prepare_receiver(
    receiver: &MessagingEndpoint,
) -> Result<(Subscription, String)> {
    let subscription = receiver
        .subscribe("jobs", SubscriptionOptions::acknowledged())
        .await?;
    receiver
        .online(Duration::from_secs(20))
        .await?;
    let contact_code = receiver.invite().encode()?;
    Ok((subscription, contact_code))
}
```

Share `contact_code` through your application's trusted configuration channel, a trusted file transfer, or another authenticated exchange. It carries contact information, not a private key or enrollment secret. Address hints are a snapshot; export a fresh code when addresses change or a peer restarts.

`online()` waits for a relay connection. It does not connect to another messaging peer, confirm topic readiness, or guarantee that address lookup has published the endpoint. Skip this call for a direct-only LAN or loopback configuration with relays disabled.

Keep the returned `Subscription` alive. Dropping it unsubscribes from the topic. There can be only one local subscription handle per topic on an endpoint.

## 4. Connect and send from the publisher

Pass the receiver's contact code to the publishing application. Only one peer needs to dial; the resulting connection supports traffic in either direction, subject to permissions. Simultaneous dials are also supported.

The following helper is for a publisher with one intended receiver. It waits briefly for the receiver's subscription to arrive, then waits for the processing acknowledgement:

```rust
use rtn_mq::*;
use std::time::Duration;
use tokio::time::{Instant, sleep};

async fn connect_and_send(
    sender: &MessagingEndpoint,
    receiver_code: &str,
) -> Result<()> {
    let invite = PeerInvite::decode(receiver_code.trim())?;
    let receiver_id = invite.address.id;
    sender.connect(invite).await?;

    let publisher = sender.publisher("jobs")?;
    let payload = sender.buffers().copy_from_slice(b"hello from another peer")?;
    let ready_deadline = Instant::now() + Duration::from_secs(10);
    let mut receipt = loop {
        match publisher.publish(payload.clone(), PublishOptions::default()).await {
            Ok(receipt) => break receipt,
            Err(Error::NoSubscribers) if Instant::now() < ready_deadline => {
                sleep(Duration::from_millis(50)).await;
            }
            Err(error) => return Err(error),
        }
    };

    let outcomes = receipt
        .wait_for_processing(Duration::from_secs(30))
        .await?;
    for (peer, outcome) in &outcomes {
        println!("{peer}: {outcome:?}");
    }
    if !outcomes.iter().any(|(peer, outcome)| {
        *peer == receiver_id && *outcome == RecipientOutcome::Processed
    }) {
        return Err(Error::Protocol("receiver did not acknowledge processing"));
    }
    Ok(())
}
```

`connect()` checks the contact's root and realm against local trust, authenticates the remote endpoint, and exchanges certificates. A successful return confirms the messaging session. Subscription negotiation can still be in progress, which is why the example retries **only** `NoSubscribers`: that error means nothing was admitted. After a receipt is returned, inspect its outcomes rather than submitting the same application operation again blindly.

Publishing sends to all currently eligible subscribers on that topic; the receiver ID above checks the intended peer's outcome and does not restrict fan-out. In a multi-peer application, coordinate readiness for the intended set before publishing. A newly ready subscriber is not added to an already admitted publication.

### Receive and acknowledge

Run this on the receiving application while the sender waits for its receipt:

```rust
use rtn_mq::*;

async fn receive_jobs(mut subscription: Subscription) -> Result<()> {
    while let Some(delivery) = subscription.recv().await? {
        println!("received: {}", String::from_utf8_lossy(delivery.payload()));
        // Complete your application's work here before acknowledging.
        delivery.ack().await?;
    }
    Ok(())
}
```

`Processed` means the receiver explicitly acknowledged application processing. Dropping an unacknowledged delivery requests a retry; use its `MessageId` for application-level idempotency when side effects must not repeat. A receipt timeout does not prove that the receiver did no work.

### Explicit readiness when the subscriber dials

You can reverse the connection direction: have the publisher export its contact and the subscriber dial it. This lets the subscriber wait explicitly for the publisher to accept its subscription:

```rust
use rtn_mq::*;
use std::time::Duration;

async fn subscribe_to_publisher(
    receiver: &MessagingEndpoint,
    publisher_code: &str,
) -> Result<Subscription> {
    let invite = PeerInvite::decode(publisher_code.trim())?;
    let publisher_id = invite.address.id;
    let mut subscription = receiver
        .subscribe("jobs", SubscriptionOptions::acknowledged())
        .await?;
    receiver.connect(invite).await?;
    subscription
        .wait_ready(publisher_id, Duration::from_secs(10))
        .await?;
    Ok(subscription)
}
```

Once `wait_ready()` succeeds, notify the publishing application through your application startup coordination that it may publish. In the one-process [direct example](examples/direct.rs), the same task performs this sequencing. Call this helper instead of `prepare_receiver()`, since both create the same topic subscription.

## Network choices

Choose the configuration before calling `MessagingEndpoint::start`:

| Use case | Configuration | Contact handling |
|---|---|---|
| Different machines, including NAT | Keep `Config::new(trust)` defaults | Wait for `online()`, then export a fresh invite. |
| One-machine test | `relay_mode = RelayMode::Disabled`; bind `127.0.0.1:0` | Skip `online()`; exchange the bound loopback contact. |
| Direct-only LAN | `relay_mode = RelayMode::Disabled`; bind a reachable local LAN address and UDP port | Skip `online()`; exchange a contact with an address reachable from the other machine. |
| Require relayed traffic | `relay_only = true`; keep relays enabled | Wait for `online()` before exporting the invite. |

For example, in a direct-only LAN deployment:

```rust
use rtn_mq::*;

fn lan_config(trust: Trust, local_addr: std::net::SocketAddr) -> Config {
    let mut config = Config::new(trust);
    config.relay_mode = RelayMode::Disabled;
    config.bind_addr = Some(local_addr);
    config
}
```

Supply an address assigned to that machine, for example `192.168.1.20:42000`, and allow inbound UDP on that port. Each machine uses its own local address. A loopback address such as `127.0.0.1` is usable only on the same machine; it cannot be copied into a contact for another host.

The `relay_only` and `RelayMode::Disabled` settings cannot be combined. With `relay_only`, `bind_addr` is ignored. In direct-only or custom-relay configurations, the default address-lookup preset is not enabled; exchange usable address hints explicitly. The library does not discover topic subscribers across the network or forward messages through other messaging peers.

## Enroll a peer over the network

Enrollment replaces offline certificate delivery. It does not replace the messaging connection steps above.

On the provisioning host, run an `EnrollmentService` using the authority and a separate transport identity. This example requires relay connectivity so invitations include relay contact information:

```rust
use rtn_mq::*;
use std::time::Duration;

async fn offer_enrollment(authority: Authority) -> Result<(EnrollmentService, String)> {
    let mut config = Config::new(authority.trust());
    config.relay_only = true;
    let service = EnrollmentService::start(authority, Identity::generate(), config).await?;
    let invitation = service.issue_invite(
        vec![Permission::subscribe("jobs")?],
        CertificateLimits::default(),
        Duration::from_secs(3600), // Certificate validity after redemption.
        Duration::from_secs(600),  // Invitation redemption window.
    ).await?;
    let secret_code = invitation.encode()?;
    Ok((service, secret_code))
}
```

Keep `service` alive until enrollment finishes. Give `secret_code` privately to one intended peer; it is a bearer secret and should not be logged. Issue a separate invitation for each new peer, choosing its permissions at issuance.

On the enrolling peer, load its own saved identity, then redeem against independently configured trust:

```rust
use rtn_mq::*;

async fn enroll_and_start(
    secret_code: &str,
    identity: Identity,
    trust: Trust,
) -> Result<MessagingEndpoint> {
    let config = Config::new(trust);
    let invitation = EnrollmentInvite::decode(secret_code.trim())?;
    let certificate = invitation.redeem(&identity, &config).await?;
    // Persist certificate.as_bytes() in this peer's state directory for later starts.
    MessagingEndpoint::start(config, identity, certificate).await
}
```

Only one endpoint identity can redeem an invitation. Before invitation expiry, that same identity can retrieve the issued certificate again if the response was lost. Enrollment records are in memory; restarting the service invalidates outstanding invitations. `service.shutdown().await?` stops enrollment without stopping already provisioned messaging peers.

After enrollment, export a **messaging** `endpoint.invite()` and use `connect()` as above. `EnrollmentInvite.contact` addresses the enrollment service and must not be used as a messaging peer contact.

## Reconnect, renew, and shut down

Reconnects are application-controlled. After a disconnect, obtain a current `PeerInvite` if needed and call `endpoint.connect(invite).await?` again. Keep existing subscription handles and wait for their `wait_ready(peer_id, timeout)` to succeed before relying on readiness. The endpoint retains eligible acknowledged publications across a connection loss and resumes retries within their delivery deadlines.

For certificate renewal, obtain a replacement bound to the **same** endpoint identity, save it for future starts, and call `endpoint.renew(certificate).await?`. Renewal closes current sessions so peers can exchange the new authorization on reconnect. Pending message IDs, the publisher epoch, and still-authorized subscription IDs survive renewal in the running endpoint.

Loading the same identity after a process restart preserves its endpoint ID, but queues, subscriptions, receipts, and deduplication state are memory-only. Recreate subscriptions and connections after restart; do not expect pending messages to recover from disk.

To stop one connection, call `endpoint.disconnect(peer_id).await?`. To stop the endpoint, use `ShutdownMode::Immediate` or give admitted work a timeout duration to finish:

```rust
use rtn_mq::*;
use std::time::Duration;

async fn stop_peer(endpoint: &MessagingEndpoint) -> Result<()> {
    let metrics = endpoint.shutdown(ShutdownMode::Drain {
        timeout: Duration::from_secs(10),
    }).await?;
    println!("unfinished deliveries: {}", metrics.unfinished_on_shutdown);
    Ok(())
}
```

Keep receive/ACK tasks running during a drain. When its timeout expires, unfinished deliveries are reported; draining does not persist them.

## Troubleshooting

| Symptom | Check |
|---|---|
| `Unauthorized` during connection | Both peers must trust the same authority and realm, and each certificate must match its endpoint's private key. Check revocation and that the contact points to the intended peer. |
| `Unauthorized` during subscription or publication | The publisher needs publish permission and the subscriber needs subscribe permission for the exact topic. |
| `CertificateExpired` | Check both machines' clocks, certificate validity, and any enrollment invitation expiry. |
| `online()` times out | A configured relay must be reachable. Omit this step for direct-only operation. |
| Connection timeout or I/O error | Confirm the other application is running, use a fresh contact, and check the advertised address and local network access. Loopback contacts do not cross machines. |
| `NoSubscribers` | Wait for subscription negotiation, verify topic/mode agreement, and keep the receiver's subscription handle alive. A connected peer is not automatically a subscriber. |
| `wait_ready()` times out | It needs the publisher's endpoint ID, an active session, and permission for that subscription. |
| `AlreadySubscribed` | Reuse the existing receive handle for that topic instead of creating another. |
| `QueueFull` or receipt rejection | Inspect `metrics()` and per-recipient outcomes; process queued deliveries, release held payload leases, or adjust configured limits. |
| Receipt remains pending | Run the receive task and call `ack()` after processing; also check connection health and memory/credit pressure. |
| `MessageTooLarge` | Check endpoint and certificate limits; inline payloads are capped at 1 MiB. |
| Key file fails to load/save | On Unix, use a private directory and regular private key file; symlinks, hard links, and permissive key modes are rejected. |

See [README.md](README.md) for delivery/resource details and [ARCHITECTURE.md](ARCHITECTURE.md) for the complete protocol and design.
