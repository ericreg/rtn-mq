# rtn-mq

An embedded Rust publish/subscribe library over Iroh. Peers exchange messages directly, using independently generated endpoint keys, root-signed topic permissions, and signed message envelopes. ESP supplied reference logic; **ESP is not a dependency or runtime requirement**.

The memory-only implementation includes offline provisioning, single-use network enrollment, certificate renewal and revocation, exact-topic subscriptions, per-recipient receipts, ACK/NACK retries, reconnect resumption, bounded queues, metered immutable payloads, and graceful shutdown. Direct and relay-only paths are covered by local integration tests.

## Run

Rust 1.96 or newer is required. Run the two-endpoint example:

```sh
cargo run --locked --example direct
```

It creates an offline authority, provisions independent publisher/subscriber keys, drops the authority, exchanges a signed message over Iroh, and reports its processing acknowledgement.

```sh
cargo test --locked --all-features --all-targets
cargo clippy --locked --all-features --all-targets -- -D warnings
cargo fmt --all -- --check
```

For a runnable sender and receiver on separate computers, follow the [two-computer quick start](USER_GUIDE.md#send-a-message-between-two-computers) using [examples/two_computers.rs](examples/two_computers.rs). It includes one-use enrollment, CBOR message payloads, and an optional direct LAN mode.

The relay test starts its own loopback relay and disables direct IP transport. Tests do not require an ESP daemon or public relay service.

## Use in an application

See [USER_GUIDE.md](USER_GUIDE.md) for peer provisioning, contact exchange, connections across machines, enrollment, and reconnects.

Applications supply a Tokio runtime. See [examples/direct.rs](examples/direct.rs) for the complete setup. After starting and connecting provisioned endpoints:

```rust
use rtn_mq::{MessagingEndpoint, PublishOptions, Result, SubscriptionOptions};
use std::time::Duration;

async fn exchange(sender: &MessagingEndpoint, receiver: &MessagingEndpoint) -> Result<()> {
    let mut subscription = receiver
        .subscribe("jobs", SubscriptionOptions::acknowledged())
        .await?;
    subscription
        .wait_ready(sender.endpoint_id(), Duration::from_secs(5))
        .await?;

    let payload = sender.buffers().from_vec(b"example job".to_vec())?;
    let mut receipt = sender.publisher("jobs")?
        .publish(payload, PublishOptions::default()).await?;
    if let Some(delivery) = subscription.recv().await? {
        // Apply the application's side effect before acknowledging.
        println!("received {} bytes", delivery.payload().len());
        delivery.ack().await?;
    }
    let outcomes = receipt
        .wait_for_processing(Duration::from_secs(5))
        .await?;
    println!("{outcomes:?}");
    Ok(())
}
```

Wait methods (`wait_for_processing`, `wait_ready`, and `online`) accept `Duration` timeouts. Each timeout covers the whole wait; a receipt timeout does not cancel delivery. Graceful shutdown uses `ShutdownMode::Drain { timeout: Duration::from_secs(10) }`.

`Config::new(authority.trust())` enables Iroh's default relay and address-lookup configuration. Provision `PeerInvite` contact material through a trusted channel. `connect()` authenticates the peer; `wait_ready()` confirms a particular peer's acceptance of a subscription. Topics are case-sensitive ASCII paths, with one receive handle per topic per endpoint.

For network enrollment, start `EnrollmentService` with an `Authority`, a **different** transport `Identity`, and matching `Config`. `issue_invite()` fixes the permissions, certificate lifetime, invitation lifetime, and restrictive limits. Deliver the encoded `EnrollmentInvite` privately; its `redeem(&identity, &config)` method checks the pinned authority and returns a certificate bound to that identity. Concurrent redemption can authorize only one endpoint. The same endpoint can retrieve its grant again after a lost response. Invitation state is memory-only; a service restart invalidates outstanding invites.

`Identity::save` and `Identity::load` provide explicit Unix private-key storage. The parent directory must already exist with private permissions. On other platforms, supply a key through `Identity::from_secret_key` and an application-managed key store. No API reads ESP configuration.

`renew(certificate)` replaces local authorization and closes old sessions. Reconnect with `connect(invite)` to exchange the new certificate; retained publications and still-authorized subscription IDs survive. Applications choose reconnect timing and refresh stale contact hints. Signed revocation snapshots enforce increasing versions and freshness in memory; applications needing restart-resistant rollback protection must persist and restore their trust state/version policy externally.

## Delivery and resource behavior

- `publish().await` reports local fan-out admission, not processing success. Every recipient has its own outcome. Full peers can be rejected while healthy peers continue; no eligible recipient returns `NoSubscribers`.
- `Acknowledged` retains and retries admitted deliveries until ACK, permanent NACK, cancellation, authorization failure, or deadline. Lost ACKs regenerate from bounded deduplication state. Dropping a delivery requests retry. Application side effects should use `MessageId` for idempotency.
- `BestEffort` reports `Sent` after the transport write completes. This does not prove remote receipt or processing. Delivery modes are explicitly matched to the subscription.
- Cancelling a publish/receipt wait does not retract an admitted publication. `Receipt::cancel()` is explicit; it cannot undo already-delivered plaintext or application side effects.
- Receivers grant one message slot at a time per topic/peer binding, on demand. Grants reserve bytes against shared subscription and endpoint budgets. A cloned `PayloadLease` retains its reservation after ACK until the final clone drops.
- Buffer charges include allocation capacity and a conservative 256-byte ownership allowance. Incoming grants reserve the negotiated maximum payload plus that allowance. Metadata charges include queue storage, certificates, pending/terminal receipts, and deduplication records. `Metrics` reports charged bytes and high-water marks, not process RSS.
- Deduplication history remains charged through the message lifetime; terminal receipt history adds one handshake-timeout grace period for late acknowledgements. Exhaustion produces explicit backpressure rather than evicting live replay state. There is no durable inbox/outbox, offline history replay, broker, forwarding, wildcard subscription, or exactly-once guarantee.

The endpoint owner serializes mutable routing/delivery state. `rtrb` SPSC rings serve topic writers and subscription receivers; ingress and session events use bounded Tokio MPSC channels. Ring operations are nonblocking; async notifications and the complete network pipeline do not have a blanket lock-free guarantee. This crate forbids its own unsafe Rust.

CBOR is the library's serialization format, implemented with `minicbor`; signed certificates and message envelopes use COSE/CBOR. For structured application payloads, encode CBOR into a buffer lease and decode from `delivery.payload()` or `PayloadLease::as_bytes()`. The payload API exposes bytes, so applications define and validate their own payload schemas.

## Protocol and measurements

The complete architecture, concrete CBOR/COSE profile, resource defaults, ESP source map, and remaining optional extensions are in [ARCHITECTURE.md](ARCHITECTURE.md). Independent Python CBOR/Ed25519 fixtures are checked into `tests/fixtures`; regenerate them with:

```sh
uv run --with cbor2 --with cryptography tools/generate_fixtures.py
```

A configurable local benchmark measures publish-to-processing-ACK latency and delivery throughput:

```sh
# iterations, fan-out, payload bytes
cargo run --locked --release --example benchmark -- 20 10 1024
```

The checked-in [smoke results](benchmarks/smoke.csv) and [environment](benchmarks/environment.txt) cover fan-out of 1, 10, and 100 for payloads from 128 bytes to 1 MiB. Regenerate the matrix with `python3 tools/run_smoke_benchmarks.py`.

The benchmark includes signing, verification, payload hashing, credits, and application ACKs. Its CSV output describes a local direct-path smoke run, not WAN performance or a capacity promise. Durability, io_uring storage, a reusable allocation pool, and broader performance/concurrency-model studies remain extensions beyond this baseline.
