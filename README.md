# rtn-mq

An embedded Rust publish/subscribe library over Iroh. **Join codes are the only public connection path.** A host creates a realm and issues reusable codes; each joining machine generates its own key, obtains a certificate, and connects to that host. ESP supplied reference logic; ESP is not a dependency or runtime requirement.

Start with [USER_GUIDE.md](USER_GUIDE.md) for the two-computer walkthrough, or run the local example:

```sh
cargo run --locked --example direct
```

On computer A:

```sh
cargo run --locked --example two_computers -- host
```

Share its printed code privately. On B, C, or another computer:

```sh
cargo run --locked --example two_computers -- join "PASTE_JOIN_CODE_HERE" "Hello from another computer"
```

The host keeps receiving until Ctrl+C. The code expires in one hour and admits at most 256 distinct endpoint identities by default. The example creates fresh identities on each run. There are no setup files or separate enrollment processes. The guide includes a direct LAN option.

## Library API

Applications supply a Tokio runtime. `Config::new()` selects Iroh's default networking. For local-only tests, disable relays and bind loopback as in [examples/direct.rs](examples/direct.rs).

```rust
use rtn_mq::*;
use std::time::Duration;

async fn example() -> Result<()> {
    let host = MessagingEndpoint::host(
        Config::new(), Identity::generate(), vec![Permission::subscribe("jobs")?],
    ).await?;
    let mut subscription = host.subscribe("jobs", SubscriptionOptions::acknowledged()).await?;
    host.online(Duration::from_secs(30)).await?;
    let code = host.issue_join_code(JoinOptions::new(vec![Permission::publish("jobs")?])).await?;

    // Transfer code.encode()? privately to the joining application.
    let peer = MessagingEndpoint::join(Config::new(), Identity::generate(), &code).await?;
    subscription.wait_ready(peer.endpoint_id(), Duration::from_secs(5)).await?;
    let payload = peer.buffers().from_vec(minicbor::to_vec("example job").unwrap())?;
    let mut receipt = peer.publisher("jobs")?.publish(payload, PublishOptions::default()).await?;
    if let Some(delivery) = subscription.recv().await? {
        println!("{}", minicbor::decode::<&str>(delivery.payload())?);
        delivery.ack().await?;
    }
    println!("{:?}", receipt.wait_for_processing(Duration::from_secs(5)).await?);
    peer.shutdown(ShutdownMode::Immediate).await?;
    host.shutdown(ShutdownMode::Immediate).await?;
    Ok(())
}
```

`JoinCode::decode` accepts only the versioned `rtn-mq://join/…` encoding. Receiving the code through a trusted channel pins the host identity and grants enrollment permission. After authenticating that host, the client obtains the realm, authority key, code expiry, and its signed certificate from it. Its secret is omitted from `Debug`; calling `encode()` explicitly reveals it.

`JoinOptions` controls permissions, code lifetime, certificate lifetime, restrictive certificate limits, and maximum distinct registrations. Rejoining with the same key and code recovers an existing valid certificate without consuming another use. `rejoin(&code)` requires a currently valid code for the same host and preserves the running endpoint's publisher epoch, pending message IDs, and still-authorized subscriptions.

`host.revoke_join_code(code.id())` blocks future enrollment through that code. Existing certificates remain valid. `deny_certificate(id)` separately rejects an enrolled certificate, including active and retained deliveries. A joining peer cannot issue codes. The host verifies that each connecting certificate was actually registered through its join flow.

Compact v3 codes take 161 characters with the standard relay URL used in the guide, or 121 with one IPv4 address, including the URI prefix. They carry the full host key and 256-bit secret; longer URLs or extra routes increase their length. Relay-backed codes need the relay for initial contact; direct-only configurations retain binary IP hints. Code versions 1 and 2 are unsupported: upgrade both sides and generate fresh codes. Rejoining preserves the authority and realm established at the first join.

This is a breaking API change: raw contact invites, standalone enrollment services, externally provisioned endpoint startup, and direct-address connection methods have been removed. There are no compatibility wrappers. Rejoin uses a join code as well.

## Delivery and resource behavior

- CBOR via `minicbor` is the serialization format; signatures use COSE/CBOR. Applications define and validate their payload schemas over immutable leased bytes.
- Publication snapshots currently connected, authorized subscriptions. Receipts expose per-recipient admission and processing outcomes. `NoSubscribers` means nothing was admitted.
- Acknowledged messages retry within their lifetime. ACK follows application processing; dropped deliveries request retry. Use `MessageId` for idempotent application side effects. Best-effort `Sent` means the transport write completed.
- `wait_ready`, `wait_for_processing`, and `online` accept `Duration`. Each call has one total timeout budget. A receipt timeout does not cancel delivery; `receipt.cancel()` is explicit.
- Payload leases share storage and retain their byte/slot charges until the final clone drops, independently of ACK. Receiver credits reserve payload and deduplication capacity before advertising admission.
- Join codes, cached grants, issued membership records, certificates, queues, and delivery history are bounded and metered. Disconnecting does not discard unexpired membership or pending-delivery charges. Metrics report library charges and high-water marks, not process RSS.
- Shutdown uses `Immediate` or `Drain { timeout: Duration }`. Drain reports unfinished deliveries when its budget expires.

Only host-to-joined-peer connections are supported. There is no peer discovery, membership directory, forwarding, or automatic B-to-C connection. No broker routes messages between joined peers.

Host authority keys, join-code state, certificates, queues, and replay state are in memory. Restarting a host creates a new realm and invalidates its old codes. Host certificates last 24 hours; issued certificates cannot outlive them. Restart/re-enroll for a new host lifetime. Applications may persist endpoint identities with `Identity::save`/`load` on Unix, but this does not persist host membership or message state. Durability and io_uring remain optional future work.

## Validate and measure

```sh
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --all -- --check
uv run --with cbor2 --with cryptography tools/generate_fixtures.py
cargo run --locked --release --example benchmark -- 20 10 1024
```

Tests include concurrent reusable-code admission, limits, code/member revocation, same-key response recovery, forged/stolen/unregistered certificate rejection, relay-only enrollment and delivery, retries, reconnects, memory bounds, and shutdown. The relay test runs a loopback relay and disables direct transports.

The benchmark enrolls each recipient through a join code before timing delivery. [Smoke results](benchmarks/smoke.csv) and their [environment](benchmarks/environment.txt) cover fan-out 1/10/100 and payloads 128 bytes–1 MiB. Regenerate with `python3 tools/run_smoke_benchmarks.py`. These are small loopback smoke measurements, not WAN capacity claims. See [ARCHITECTURE.md](ARCHITECTURE.md) for protocol details and the ESP logic source map.
