# Connecting peers with rtn-mq

`rtn-mq` is a Rust library you put inside an application. A **host** starts a messaging group and prints a join code. Other applications use that code to become **peers** of the host. Each peer gets its own identity and permission to send or receive particular messages.

Join codes are the only supported way to establish connections. Each machine generates its private key locally; you share a code, not a key or setup file. This project reuses ideas from ESP but does not depend on ESP.

## Quick start

You need Rust 1.96 or newer, including Cargo, Rust's build and package tool. Check your installation:

```sh
rustc --version
cargo --version
```

Open a terminal in the `rtn-mq` project directory, which contains `Cargo.toml` and `examples`. The first build may take a few minutes and needs internet access to download dependencies.

### Try a message on one computer

```sh
cargo run --locked --example direct
```

Cargo builds and runs [examples/direct.rs](examples/direct.rs). `--locked` uses dependency versions from `Cargo.lock`. The example starts a host, creates a join code, joins a second endpoint, and sends one CBOR-encoded message through loopback, the network connection back to your own computer.

Expected output:

```text
received: hello over Iroh
outcomes: [(PublicKey(...), Processed)]
```

The actual public key identifies the receiving peer and changes each run. `Processed` means the receiver called `ack()`—short for acknowledge—after handling the message. Both endpoints then close.

To try a change, edit the string `"hello over Iroh"` in `examples/direct.rs` and run the command again. The example encodes that string as CBOR, a binary data format.

### Send a message between two computers

Use [examples/two_computers.rs](examples/two_computers.rs). Call the host computer **A** and a joining computer **B**. Both need the same version of this checkout and a working Rust installation. Run each command from its computer's project directory.

#### Step A: start the host

On A:

```sh
cargo run --locked --example two_computers -- host
```

The `--` separates Cargo's options from arguments passed to the example. `host` asks the example to start the receiving application.

After its relay connection is ready, A prints:

```text
Join code: rtn-mq://join/...
Share this code privately. Waiting for messages; press Ctrl+C to stop.
```

The real code is a longer string. Copy the entire string beginning with `rtn-mq://join/`, without the `Join code:` label, and give it privately to the intended joining machines. Anyone holding the code can register with its permissions while it remains valid. An authenticated private chat or your usual trusted configuration channel is sufficient; no file transfer is required.

The compact code is typically about **161 characters with one relay**, or **121 characters with one IPv4 address** in direct-only mode. Extra addresses or longer custom relay URLs increase its length. It contains A's public key, its connection route, and a secret that grants permission to join. Keep the whole code; truncating it makes it unusable. Older version 1 and 2 codes are no longer accepted: update both computers, restart the host, and copy its newly generated code.

Leave A running. It has subscribed to the topic `quickstart/messages`. A **topic** is a string naming a category of messages. Subscribing asks to receive messages in that category.

#### Step B: join and send a message

On B, replace `PASTE_JOIN_CODE_HERE` with A's full code, keeping the quotes:

```sh
cargo run --locked --example two_computers -- join "PASTE_JOIN_CODE_HERE" "Hello from computer B"
```

B generates its own private key and authenticates A using the public key in the code. A checks the secret and supplies the messaging group's ID, its authority public key, the code expiry, and a **certificate**, a signed record allowing it to publish on `quickstart/messages`. B verifies the certificate against the authority supplied by A, then establishes an authenticated messaging session, waits for the host's subscription, and sends its message.

B should print:

```text
Joining host...
Connected. Waiting for the host's subscription...
Processed: host acknowledged your message.
```

A should print:

```text
Received: Hello from computer B
Acknowledged. Waiting for more messages...
```

B exits after receiving the acknowledgement. A keeps running.

#### Step C: add another computer

On C, use **the same join code**:

```sh
cargo run --locked --example two_computers -- join "PASTE_JOIN_CODE_HERE" "Hello from computer C"
```

C gets its own identity and certificate. A receives C's message as well. B and C each connect to A; they do not discover or connect to one another.

The example's code lasts one hour and admits up to 256 distinct identities. Each invocation of `join` creates a fresh identity and uses another registration. A library application can retain an identity and use `rejoin(&code)` without spending another registration on the same still-valid grant.

Press Ctrl+C on A to stop the host. Starting it again creates a new realm (messaging group) and a new code. Old codes no longer work; copy the new code to the joining machines. These examples do not persist identities or membership.

The join code is an enrollment credential. Keep it out of public repositories and shared logs. Passing it on a command line can also leave it in shell history; an application embedding the library can accept it through its own private input flow. No endpoint private key is included in the code.

#### Option: connect directly on the same LAN

Default networking uses Iroh's relays and address lookup. A **relay** helps establish or carry encrypted connections when peers cannot reach one another directly. Both computers need access to the configured services. A relay-backed code carries the relay address instead of every network interface address, keeping it short. The relay is needed for initial contact; Iroh can then negotiate a direct connection. For a LAN without relay access, use the direct-only commands below.

For a direct-only LAN connection, supply each computer's own local address with `--bind`. For example, if A is `192.168.1.20` and B is `192.168.1.21`:

On A:

```sh
cargo run --locked --example two_computers -- host --bind 192.168.1.20:42000
```

Copy A's newly printed code, then on B:

```sh
cargo run --locked --example two_computers -- join "PASTE_JOIN_CODE_HERE" "Hello over the LAN" --bind 192.168.1.21:0
```

Replace those IPs with addresses assigned to your computers. Port `0` asks the operating system to pick a free port. A uses UDP port `42000` for both joining and messaging; allow the application's UDP traffic between the machines. `--bind` disables relays in this example.

`127.0.0.1` always means the computer running the command. To practice in two terminals on a single computer, use `--bind 127.0.0.1:0` for both commands. It cannot connect two different computers.

## Use join codes in your own application

Add this checkout as a dependency, adjusting the path for your directory layout:

```toml
[dependencies]
rtn-mq = { path = "../rtn-mq" }
tokio = { version = "=1.53.1", features = ["rt-multi-thread", "macros", "time"] }
minicbor = { version = "=2.3.0", features = ["std"] }
```

Run async calls inside a Tokio runtime, commonly an `async fn main()` annotated with `#[tokio::main]`. `.await` lets the runtime run other work while an operation waits. `?` returns an error to the calling function if an operation fails.

### Create a host and code

```rust
use rtn_mq::*;
use std::time::Duration;

async fn start_host() -> Result<(MessagingEndpoint, Subscription, String)> {
    let host = MessagingEndpoint::host(
        Config::new(), Identity::generate(), vec![Permission::subscribe("jobs")?],
    ).await?;
    let subscription = host.subscribe("jobs", SubscriptionOptions::acknowledged()).await?;
    host.online(Duration::from_secs(30)).await?;
    let mut options = JoinOptions::new(vec![Permission::publish("jobs")?]);
    options.lifetime = Duration::from_secs(600);
    options.certificate_lifetime = Duration::from_secs(3600);
    options.max_uses = 20;
    let code = host.issue_join_code(options).await?;
    Ok((host, subscription, code.encode()?))
}
```

The host's permission describes its own role. The code's permissions describe the joining peers' role. For two-way messaging on `jobs`, give both sides `Permission::both("jobs")` and create a subscription on each side. Topics are case-sensitive exact names; `jobs/*` is not a wildcard.

`online(Duration)` waits for relay connectivity, not for a peer or subscription. Omit it with relays disabled. Generate the code after the host's address is usable, because it contains a snapshot of that address.

### Join the host

```rust
use rtn_mq::*;

async fn join_host(encoded_code: &str, identity: Identity) -> Result<MessagingEndpoint> {
    let code = JoinCode::decode(encoded_code.trim())?;
    MessagingEndpoint::join(Config::new(), identity, &code).await
}
```

The trusted code pins the host endpoint ID and grants enrollment permission to its holder. The host supplies the realm, authority public key, code expiry, and signed certificate over the authenticated enrollment connection. The client checks the certificate signature, its own identity, the realm, and validity before accepting it. Sharing a code therefore means trusting that host to choose the network authority. `join()` performs enrollment and the messaging handshake before returning; there is no separate address-based `connect()` call. Joining peers cannot issue codes in that realm.

A network connection and a ready subscription are separate conditions. When the subscriber knows the publisher's endpoint ID, call `subscription.wait_ready(publisher_id, Duration::from_secs(5)).await?`. The two-computer example instead waits on the publishing side for `NoSubscribers` to stop occurring before it has admitted a message.

After publication returns a receipt, use `receipt.wait_for_processing(Duration::from_secs(5)).await?` to inspect outcomes. Timeouts cover the whole wait and do not cancel an admitted publication. Call `receipt.cancel().await?` if you explicitly want to stop retained retries.

Run the subscriber's receive loop while publishers are waiting. Decode the CBOR payload, perform the requested work, and then acknowledge. Dropping an unacknowledged delivery requests retry. Use `MessageId` for idempotency if processing has side effects that should not repeat.

## Code policy and revocation

| Setting or operation | Meaning |
|---|---|
| `JoinOptions::permissions` | Exact topics the joining endpoint may publish or subscribe to. |
| `lifetime` | How long the code admits registrations/rejoins: 1 second–10 years. Default one hour. |
| `certificate_lifetime` | Certificate validity after issuance: 1 second–10 years, capped by host certificate expiry. Default one hour. |
| `max_uses` | Distinct identities admitted by this code: 1–256. Default 256. Same-key recovery of a valid grant does not consume another use. |
| `limits` | Optional restrictions on the joining peer's payload size and subscription count. |
| `host.revoke_join_code(code.id())` | Disable future enrollment through that code. Existing certificates and sessions remain valid. |
| `host.deny_certificate(peer.certificate().id())` | Revoke that particular certificate, including existing sessions and retained deliveries. |

A code no longer contains the realm, authority key, or expiry, so it cannot report those values before contacting its host. The old `JoinCode::realm_id()`, `authority()`, and `expires_at()` accessors have been removed. Hosts control expiry through `JoinOptions::lifetime`; clients receive and check it during enrollment.

Limits are checked by the host, including concurrent joins. Code expiry, revocation, and usage counts live on the host; editing the encoded code cannot extend them. `Config::max_topics` also bounds active codes, `max_peers` bounds unexpired issued certificate records, and the metadata budget charges all retained code/membership state. Disconnecting does not free a registration record before its certificate expires.

## Rejoin, lifetime, and shutdown

Keep the same `MessagingEndpoint` and call `peer.rejoin(&code).await?` after a connection loss. The code must currently be valid and target the same host. The host's reply must match the authority and realm accepted during the first join; `rejoin` never replaces them. A new code issued by that host can also authorize a new certificate. Wait for subscription readiness again after reconnecting.

`rejoin` preserves the running endpoint's identity, publisher epoch, retained message IDs, and still-authorized subscriptions. It retrieves a cached valid certificate or renews an expired grant; changing code permissions is enforced when the replacement authorization is installed. Failed enrollment leaves the previous authorization in place. Expiring/revoking a code does not itself revoke previously issued certificates, but a new valid code is required for a subsequent rejoin.

`MessagingEndpoint::host` is memory-only: its root key and realm are generated when it starts, so restarting it invalidates old codes and membership. For a restartable host, use `MessagingEndpoint::host_persistent(config, identity, permissions, state_path)` and reuse an identity loaded with `Identity::load`. It atomically recovers the authority, join grants, redeemed endpoint identities, and membership certificates. The state and identity directories/files must be private on Unix.

Persistent enrollment is not a durable message queue. Subscriptions, queued publications, receipt state, deduplication history, and runtime revocation snapshots still reset with the process. Host and issued-certificate lifetimes can be at most ten years; re-enroll before expiry. Other platforms use application-managed key stores.

To disconnect a session, use `endpoint.disconnect(peer_id).await?`. It does not create a new connection path; reconnect through `rejoin(&code)`.

To stop an endpoint immediately, call `shutdown(ShutdownMode::Immediate)`. To let admitted work finish for a bounded duration:

```rust
use rtn_mq::*;
use std::time::Duration;

async fn stop(endpoint: &MessagingEndpoint) -> Result<()> {
    let metrics = endpoint.shutdown(ShutdownMode::Drain {
        timeout: Duration::from_secs(10),
    }).await?;
    println!("unfinished deliveries: {}", metrics.unfinished_on_shutdown);
    Ok(())
}
```

Keep receive/ACK tasks running while draining. Unfinished work is reported when the timeout expires; it is not saved to disk.

## Troubleshooting

| Symptom | Check |
|---|---|
| Code decoding fails | Paste the entire `rtn-mq://join/…` string, without the label. Old contact codes and setup files are unsupported. |
| `Unauthorized` when joining/rejoining | The code may have expired or been disabled, or the cached certificate may have been revoked. A rejoin must retain the original host, authority, and realm. |
| `QueueFull` during enrollment | The code's registration limit, host certificate-record limit, code-count limit, or metadata budget may be full. |
| `CertificateExpired` | The returned code expiry or certificate validity failed a clock check. Check both machines' clocks and obtain a new code if needed. Host rejection of an expired code is `Unauthorized`. |
| Relay wait or connection times out | Check network access and that the host is still running. On a reachable LAN, try the direct `--bind` option. |
| `Unauthorized` for a topic | Verify the exact topic and both sides' permissions. Being enrolled does not grant every topic. |
| `NoSubscribers` | Wait for subscription readiness; keep the subscription handle alive. Dropping it unsubscribes. |
| Receipt remains pending | Run the receive loop and ACK after processing. Release held payload leases if receive capacity is exhausted. |
| B cannot see C after both join A | Expected: there is no peer discovery, directory, or forwarding. Each is connected only to A. |

The old external-certificate startup, contact invites, separate enrollment service, and direct-address connection APIs have been removed. See [README.md](README.md) for delivery semantics and [ARCHITECTURE.md](ARCHITECTURE.md) for protocol details.
