# Iroh Brokerless Messaging
## Architecture and Version 1 Protocol

**Status:** Breaking join-code-only Rust baseline implemented; optional persistent host enrollment is available, while durable message queues remain unimplemented
**Date:** September 4, 2026  
**Implementation language:** Rust  
**Deployment model:** An embedded messaging endpoint in each application

## 1. Design summary

Build a small, brokerless publish/subscribe library on Iroh. Applications connect exclusively through reusable join codes carrying a pinned host identity, bounded connection routes, and bearer secret. The authenticated host supplies realm, authority key, code expiry, and certificate during enrollment. Each endpoint owns its connections, authorization policy, subscriptions, bounded queues, and pending deliveries.

A **host** owns its realm authority and enrolls independently generated peer keys through join codes. The host and each joined peer communicate directly according to their certificates. There is no member-to-member connection, discovery, directory, or forwarding in this baseline. Enrollment and messaging share the host endpoint but use separate ALPNs; its root signing key differs from its transport key.

The public abstraction is deliberately small:

```text
start a host and issue a reusable join code
join its realm and connect to that host
publish to an exact topic
subscribe to an exact topic
receive a message and acknowledge its processing
```

The performance objective is **minimal copying with bounded memory**, not an unconditional end-to-end zero-copy promise. Immutable payloads move through local queues by reference. Single-owner state and bounded single-producer/single-consumer handoffs make selected queue operations lock-free. Iroh retains ownership of its network transport; an optional Linux storage engine can use io_uring later.

| Area | Version 1 decision |
|---|---|
| Network topology | Direct host-to-joined-peer pub/sub; no forwarding or global mesh |
| Roles | Orchestrator, publisher, subscriber; an application may combine roles |
| Identity | Independent endpoint key pairs; orchestrator-signed delegations |
| Message authenticity | Signed message envelopes, verified against the authorized endpoint identity |
| Bootstrap | Reusable join codes only; no externally provisioned startup or address-based connect API |
| Discovery | No application-level global peer or topic discovery |
| Topics | Exact, case-sensitive names scoped to a realm |
| Delivery | Best-effort or acknowledged, bounded retry; duplicates are possible |
| Storage | Memory-only baseline; crash-durable storage is a separate extension |
| Queues | Bounded by both message count and bytes, with endpoint-wide budgets |
| Serialization | CBOR via `minicbor`; COSE/CBOR signatures; application payloads held as immutable bytes |
| Concurrency | Single-owner endpoint state; bounded descriptor handoffs |
| Platform | Portable Iroh runtime baseline; Linux-specific optimizations isolated |

All numerical defaults below are **initial engineering choices**, not measured capacity or performance claims. The implementation, runnable examples, and validation commands are described in [README.md](README.md).

## 2. Goals and deliberate exclusions

### Goals

Support both short-lived workers and long-running applications. Allow deployments containing thousands of applications without requiring every application to connect to every other application. Keep authorization verifiable without contacting the orchestrator for each message.

Make queue capacity, overload behavior, delivery outcomes, and payload lifetime explicit. Provide enough observability to distinguish a slow consumer, an unreachable peer, authorization failure, and local resource exhaustion.

Reuse the existing Iroh-based invitation and connectivity experience, but implement messaging as a native application protocol rather than tunneling it through SSH or a local TCP port.

### Not in the baseline

There is no distributed broker, consensus protocol, globally ordered log, replicated retention, automatic topic-member search, multi-hop forwarding, wildcard matching, distributed consumer group, or exactly-once processing guarantee.

A topic is not a durable log. A disconnected subscriber does not automatically receive messages published while it was absent. Memory-only queues do not survive process failure. Cross-process shared-memory transport and content-addressed large-object transfer are future extensions, not prerequisites.

## 3. Roles and component ownership

### Host and realm authority

`MessagingEndpoint::host` creates a new authority and realm, signs a bounded-lifetime certificate for its independent transport identity, and starts the endpoint owner. `MessagingEndpoint::host_persistent` instead recovers or atomically creates private authority, grant, redemption, and membership state. `issue_join_code` associates permissions, expiry, certificate lifetime, and a distinct-registration limit with a random secret. Only hosts can issue codes.

`MessagingEndpoint::join` generates no remote keys: the caller supplies its own `Identity`. The code pins the initial trusted host. Only after authenticating it does the joining endpoint accept the root and realm supplied in its enrollment response. The joining endpoint redeems the secret against the authenticated host, verifies its certificate, and establishes a messaging session. `rejoin(&code)` repeats this flow against the same host while preserving local delivery state and the previously established root/realm. A response that changes either is rejected. Every establishment/re-establishment originates from a valid join code.

There is no separate public authority/enrollment service or certificate-based endpoint constructor. The internal authority signs only the host identity and code-issued member certificates. Host availability is required to enroll or rejoin. Since every supported link is to the host, losing it interrupts these links; no member-to-member path is created automatically.

### Publisher and subscriber endpoints

Publisher and subscriber are capabilities of the same endpoint implementation, not different server products. One application can publish some topics and subscribe to others. The original connection acceptor is simply another endpoint; it does not become a broker by accepting a connection.

| Component | Responsibility |
|---|---|
| Identity and authorization | Local key, trusted root, delegation validation, permission checks, revocation state |
| Peer sessions | Iroh connections, protocol negotiation, reconnects, authenticated session state |
| Topic registry | Local interests and each connected peer's accepted subscriptions |
| Endpoint owner | Sequence assignment, routing decisions, queue accounting, delivery state |
| Buffer manager | Immutable payload ownership, pooling, live-byte accounting |
| Delivery engine | Per-recipient pending deliveries, ACK/NACK handling, retry deadlines |
| Observability | Metrics, structured errors, lifecycle events |
| Storage interface | Memory implementation now; optional journal implementation later |

```text
       Host A: root authority + messaging endpoint + bounded local queues
                    /                              \
             join code + Iroh                 join code + Iroh
                  /                                  \
          Joined peer B                         Joined peer C
          own key and certificate               own key and certificate

          No B-to-C discovery, connection, or message forwarding
```

Iroh provides authenticated, encrypted QUIC connectivity and may use relays when a direct path is unavailable. Those relays forward encrypted transport traffic; they are not this library's topic router, durable queue, or offline mailbox. Brokerless does not necessarily mean infrastructure-free. [S1]

## 4. Trust, enrollment, and delegated certificates

### 4.1 Independent keys, signed authorization

Each endpoint generates its own private/public key pair. The orchestrator signs a compact certificate binding that public key to a realm and explicit permissions. Private client keys are not derived from the root key and are not sent to the orchestrator.

The root can authorize new identities but cannot regenerate independently generated client private keys. Root compromise still compromises the realm's authorization boundary, even though it does not reveal those existing private keys.

Use a standard signature implementation and a standard signed container, such as **COSE_Sign1 with a fixed Ed25519 profile**. COSE defines the signed structure; this application defines the claims and their authorization meaning. Reject unsupported algorithms, ambiguous encodings, duplicate map keys, and unknown critical fields. [S5][S6]

A delegation contains:

| Claim | Meaning |
|---|---|
| `version` | Certificate profile version |
| `realm_id` | Stable, random identifier for this messaging trust domain |
| `issuer_key_id` | Identifier of a locally trusted orchestrator signing key |
| `certificate_id` | Unique issuance identifier for revocation and auditing |
| `subject_endpoint_id` | The endpoint public key authorized by this certificate |
| `not_before`, `expires_at` | Validity interval |
| `permissions` | Exact topic names and allowed `publish` / `subscribe` actions |
| `limits` | Optional ceilings, such as payload size or subscription count |

Certificate limits can only restrict the receiver's local limits, not raise them. Version 1 permits **one delegation level**, root to endpoint; clients cannot issue further delegations.

### 4.2 Reusable join codes

The only public bootstrap is a `JoinCode`. Its trusted delivery pins the host identity and grants permission to enroll. The host is trusted to supply the initial root and realm over its authenticated enrollment connection. It carries 32 random secret bytes and is explicitly encoded as a pasteable `rtn-mq://join/…` string. Debug output omits the secret. No endpoint private key is included.

The host owner stores the secret hash, fixed permissions/limits, expiry, maximum uses, and a cache indexed by the authenticated joining endpoint ID. Different identities receive distinct certificates. The same identity recovers its still-valid cached certificate without using another registration; an expired grant may be renewed while the code is valid. Concurrent redemptions are serialized with issuance and membership registration before returning success. Revoked certificates are not recovered through their cached grant.

Defaults are one-hour code lifetime, one-hour certificate lifetime, and 256 distinct registrations per code. Lifetimes are 1 second–10 years; maximum uses are 1–256. Issued certificates cannot outlive the host certificate. The host checks the stored expiry and secret hash. On success, clients also check the expiry returned in its authenticated response. Codes contain no offline expiry metadata; an expired/pruned grant is rejected by the host as `Unauthorized`. Editing a code does not extend its host-side policy.

Active codes are bounded by `Config::max_topics`; unexpired issued-certificate records by `max_peers`; all retained state is metered against metadata limits. Membership records remain after disconnect and code expiry so connection admission and accounting cannot be bypassed. Expiring/revoking a code disables future enrollment through it; `deny_certificate` independently revokes an issued member certificate.

The default host keeps authority, grants, counters, membership records, and replay state in memory; restart creates a new realm and invalidates old codes. The optional persistent host stores authority, grants, redeemed identity counters, and membership records atomically in a bounded private file. The transport `Identity` remains a separate private file. Replay, subscription, queue, receipt, and revocation-snapshot state remains process-local.

### 4.3 Connection authorization

After the Iroh handshake completes, both endpoints exchange their certificates. Each endpoint:

1. Verifies the certificate signature against an already trusted root and checks the realm, validity interval, revocation state, and local policy.
2. Requires `subject_endpoint_id` to equal the identity authenticated by the Iroh connection.
3. On the host, requires the certificate ID and authenticated subject to match an issued membership record. On a joined peer, requires the remote endpoint ID to be its code-pinned host. A valid root signature alone does not admit an unregistered peer.
4. Authorizes each subscription or publication against the relevant exact-topic permission.

Iroh authenticates peer identities, but application authorization remains the application's responsibility. Its `Connection::remote_id()` exposes the authenticated endpoint identity. A copied certificate without possession of that endpoint's private key must not be enough to connect as that endpoint. [S1][S2]

Cache successful signature verification per certificate/session. Continue enforcing expiration and revocation on existing sessions, not just at initial connection time. On expiry, pause protected operations and require renewal through reauthorization or reconnect. The simplest v1 implementation reconnects with the renewed certificate.

### 4.4 Message signatures

To preserve the requested ability to verify a message as originating from an authorized client, **v1 signs each logical message once** with the endpoint signing key. The signed envelope binds:

```text
protocol domain and version
realm_id
publisher_endpoint_id
publisher_epoch
topic
sequence
creation and expiry timestamps
payload format / schema identifier
payload length
SHA-256(payload)
```

Use an unambiguous encoding and a distinct signature context, such as `iroh-mq/message/v1`, separate from the certificate context. The endpoint key API supports signing; do not implement Ed25519 manually. [S6][S13]

The receiver verifies the envelope signature, checks the payload digest, and requires the signer to match both the connected peer and the certificate subject. It then checks publish permission and message expiry. In v1, a peer may not forward another peer's signed messages.

Fan-out reuses the same immutable envelope, signature, and payload. Retries reuse the same logical message identity; they do not create a new publication. Certificate renewal with the same endpoint key does not require changing the message identity, but current permissions must still authorize its delivery.

Authenticated Iroh transport already provides channel authentication and integrity. Per-message signatures are retained here because independently verifiable messages were requested; they add hashing and signature work and must be included in benchmarks. A later, explicitly negotiated channel-authentication-only profile could omit them. Signatures do not by themselves provide replay prevention, confidentiality outside the connection, or proof of an application's processing result.

### 4.5 Revocation and key lifecycle

Use renewable, short-lived certificates for both ephemeral and long-running clients. Long-lived applications can keep a stable endpoint key while renewing authorization.

Receivers may apply signed revocation snapshots or administratively provisioned deny lists. Persist the highest accepted revocation version where rollback resistance is needed. An isolated receiver cannot know about an unseen revocation: the exposure window is bounded by certificate expiry or an enforced revocation-freshness deadline, not by certificates alone.

Use wall-clock time with a documented skew allowance for certificate and message expiry, and monotonic time for local retry timers. Large clock anomalies should fail closed for new protected operations. Key replacement requires a new certificate and contact update. Root rotation requires an explicit trust update or controlled overlap, never an untrusted peer's assertion.

## 5. Connection bootstrap and discovery

Join codes include the host endpoint ID and current bounded IP/relay hints. Default Iroh address lookup may resolve this already-known identity; it does not discover realm members or topic participants. Hosts should wait for `online(Duration)` before issuing relay-dependent codes. Direct-only LAN deployments omit that wait and bind a reachable local address.

No contact-export or arbitrary-address connect API is public. The joining endpoint dials the host after code redemption. Both sides exchange authenticated subscription interests over that connection; topic readiness is separate from transport establishment.

B and C joining A creates A–B and A–C sessions only. Neither receives the other's address, certificate, or subscription inventory. There is no peer directory, introduction mechanism, global membership search, or forwarding. Rejoin replays still-authorized local subscriptions and reuses their IDs within the running endpoint.

## 6. Topic and subscription semantics

A topic is identified by `(realm_id, topic_name)`. Topic names are case-sensitive, exact-match ASCII paths, such as `jobs/image-processing` or `workers/status`. Limit names to 256 bytes and reject empty names, empty path segments, wildcard characters, and invalid characters rather than normalizing them differently at different peers.

Slashes are organizational only. Subscribing to `jobs` does not subscribe to `jobs/image-processing`. A topic handle is created lazily and is not a globally coordinated resource.

For a small v1 API, allow **one active logical subscription per topic per endpoint**, with one owning receive handle. A second subscription to that same topic returns `AlreadySubscribed`. Multiple remote publishers can feed it. Distributed competing consumers are not supported: every subscribed endpoint receives its own delivery. An application can distribute received work internally.

The subscriber chooses a subscription ID and retains it for the lifetime of that local subscription. Reconnect uses the same ID to resume eligible pending deliveries. Destroying and recreating a subscription produces a new ID; it is not implicit history replay.

### Publication membership

The endpoint owner snapshots the set of currently connected, authorized, confirmed subscriptions when it admits a publication. That set determines the intended recipients. A late subscriber receives subsequent publications, not historical messages.

New publications do not target disconnected subscriptions in the memory-only baseline. Previously admitted, unacknowledged deliveries may retry to their original subscription IDs after reconnect, while the publisher still retains them and their deadline has not passed.

A publish with no eligible subscribers returns `NoSubscribers`; it must not silently imply delivery. Fan-out is not atomic across peers. A receipt identifies which recipients were admitted, rejected for capacity, or subsequently failed.

A subscriber becomes ready for a particular peer when that peer confirms its `SUBSCRIBE`. Readiness is per known peer, not a claim that all possible publishers have been found.

## 7. Message identity, delivery, and ordering

### Message identity

Assign a random 128-bit `publisher_epoch` when a publisher process starts. The endpoint owner assigns a monotonic 64-bit sequence per topic within that epoch. All local publisher handles for the same topic share this sequence allocator.

```text
MessageId = (
    realm_id,
    publisher_endpoint_id,
    publisher_epoch,
    topic,
    sequence
)
```

A retry retains this identity. Receiving the same identity with different immutable content is a protocol violation. Sequence numbers are not global offsets: a subscriber can legitimately miss sequence values because it joined later, disconnected, or was excluded by an explicit overflow decision.

### Delivery modes

| Mode | Behavior and guarantee boundary |
|---|---|
| `BestEffort` | No application-level retry after an uncertain outcome. Transport reliability does not turn this into crash-durable delivery. |
| `Acknowledged` | Retain each admitted recipient delivery and retry until processing ACK, permanent rejection, cancellation, expiry, or retry deadline. Duplicate delivery is possible. |

The acknowledged mode is an **at-least-once-style retry contract within the retained delivery window**, not an unconditional eventual-delivery promise. A deadline, lost sender state, permanently unavailable peer, or revoked permission can prevent successful delivery. Such outcomes must remain visible.

`publish().await` means local routing/admission has completed and returns a receipt. It does not mean subscribers have processed the message. The receipt can subsequently report processing outcomes for each admitted recipient.

The subscriber explicitly calls `ack()` only after successful application handling. A QUIC acknowledgement means transport progress, not application processing; closing a connection can abandon data not yet delivered to the application. [S2]

`nack(Retryable)` requests another attempt, subject to the existing deadline. `nack(Permanent)` ends that recipient's delivery and reports failure. Dropping a delivery without ACK is not successful processing; treat it as abandoned/retryable. Apply retry backoff so repeated handler failures cannot create a tight loop.

### Deduplication and retry state

Track `(subscription_id, MessageId)` as queued, processing, processed, or permanently rejected. A duplicate already being processed must not start another concurrent handler. A duplicate already processed should regenerate its ACK.

Bound deduplication state separately from payload memory. Do not silently evict still-needed deduplication records to admit more traffic. Retain terminal records through the accepted replay horizon, or explicitly reject resumption outside that horizon. After receiver restart, in-memory deduplication is lost and duplicates can reappear.

When processing succeeds but its ACK is lost, the sender cannot distinguish success from failure. Applications with external side effects should use the message ID as an idempotency key. Exactly-once effects would require an atomic relationship between application side effects and recorded processing state; a queue ACK alone cannot provide that.

### Ordering

Preserve first-attempt send order per publisher epoch and topic on each recipient's data stream. There is no total order across publishers or topics. Retries and reconnects may expose older messages after newer ones, and concurrent handlers may finish out of order.

A caller needing stricter per-publisher processing can limit that publisher's in-flight deliveries to one and handle retry/failure before advancing. This reduces throughput and still does not create cross-publisher ordering.

## 8. Queue limits, backpressure, and memory accounting

Use separate bounded accounting for local ingress, each peer's outbound backlog, each subscription's queued and processing deliveries, deduplication state, and endpoint-wide resident buffers.

**A message count alone is not a memory bound.** Charge payloads, envelopes, descriptors, retained retries, and application-held payload leases. Enforce transport buffering and connection limits alongside queue budgets.

### Initial configuration

| Setting | Suggested starting default |
|---|---:|
| Maximum payload | 1 MiB |
| Maximum metadata or control-frame body | 16 KiB |
| Outbound backlog per peer | 1,024 messages and 16 MiB |
| Subscription queued + processing budget | 1,024 messages and 16 MiB |
| Endpoint managed payload-buffer budget | 128 MiB |
| Endpoint metadata / deduplication budget | 32 MiB |
| Maximum connected peers | 256 |
| Maximum local topics | 256 |
| Maximum pending authenticated subscriptions per peer | 256 |
| Maximum delivery window | 5 minutes |
| Initial processing-ACK retry timer | 30 seconds, with backoff and jitter |
| Example shutdown drain timeout | 10 seconds |

These limits are ceilings, not eagerly allocated reservations. The endpoint-wide limit can become binding long before every per-peer allowance is consumed. Transport and runtime overhead require additional headroom; these settings are not a bound on the entire process's RSS.

### Overflow behavior

Default to **rejecting admission explicitly**, rather than dropping an already accepted acknowledged delivery. An async publisher may wait for local admission space up to its caller-supplied deadline; the endpoint owner itself must not block all peers while waiting for one slow recipient.

Offer `DropNewest` only as an explicit best-effort policy. Defer `DropOldest` because evicting an in-flight or already acknowledged delivery complicates correctness and buffer lifetime. Full fan-out admission is not a distributed transaction: a slow recipient can be rejected while healthy recipients proceed, and the receipt reports this partial outcome.

Reject oversized messages before allocating their payload buffers. Rate-limit unauthenticated connections, certificate verification, control frames, and malformed-frame handling separately from normal data traffic.

### Application-level credits

A subscriber grants a peer both message-slot and byte credits. A sender may transmit a DATA frame only within those grants. Charge the agreed frame/envelope overhead as well as payload bytes.

Credits are reservations against the subscriber's shared budget. If several publishers feed one subscription, do not grant each publisher the entire subscription capacity. Grant only capacity actually reserved for that peer, with a fair allocation policy and an explicit cap.

A dequeue does not necessarily free capacity: the application may still hold the message. Return capacity only after the relevant delivery state is released and its final payload lease is dropped. ACK can be transmitted earlier, but it does not authorize reuse of memory still borrowed by the application.

Credits restart from zero on a new connection. Fresh grants use the new session generation; old credits cannot be reused. Keep a separately bounded control path and enough transport headroom for ACKs and credit updates to avoid data-backpressure deadlock. QUIC flow control is additional protection, not a replacement for these application budgets.

## 9. Immutable buffers and minimal-copy payload handling

### Ownership model

A message owns an immutable payload handle. Queues hold small descriptors referring to that handle, not independent copies of the payload. Publisher fan-out creates per-recipient delivery state while sharing payload storage.

Use `bytes::Bytes` or an owner-backed equivalent beneath a **metered `PayloadLease`** abstraction. `Bytes` supports shared backing storage and explicit owners; the wrapper adds queue accounting and prevents untracked buffer ownership from escaping the library. [S7]

Expose borrowed bytes or segments to readers. Cloning a lease must preserve its accounting. An explicit `copy_payload()` may give the application an independent allocation, but that allocation is then the caller's responsibility.

```text
mutable construction buffer
    -> freeze into immutable payload lease
    -> publisher ingress descriptor
    -> shared payload + per-recipient delivery records
    -> Iroh send path

Iroh receive chunks
    -> bounded frame validation / assembly
    -> immutable payload lease
    -> subscription descriptor
    -> borrowed application reads
    -> final lease release
```

ACK state and memory lifetime are separate. A buffer returns to a pool only after every reader and every I/O operation that may still access it has released ownership. Fan-out to one slow subscriber can retain a shared buffer after all others finish.

### Serialization and framing

CBOR is the library's serialization format. Protocol metadata uses strict `minicbor` schemas, and signatures use COSE/CBOR. Applications encode structured payloads as CBOR and define their own schemas; the queue holds those encoded bytes in a metered immutable payload lease.

Applications decode payloads from `PayloadLease::as_bytes()` or `Delivery::payload()` and validate schema versions, types, collection sizes, nesting, and trailing bytes. The transport authenticates and bounds payload bytes but does not automatically decode the application schema.

Iroh exposes receive methods returning `Bytes` chunks without an additional copy at that API boundary. **Chunk boundaries do not correspond to messages or peer writes.** A frame may span chunks, and a chunk may contain several frames. [S8]

The baseline assembles each bounded payload into contiguous storage before exposing its lease. CBOR decoding uses that byte slice without an alignment-specific adapter; borrowed values must not outlive the payload lease.

### Meaning of “zero-copy” in this design

| Boundary | Intended behavior |
|---|---|
| Local descriptor handoff | No payload copy |
| Publisher fan-out in one process | Shared immutable payload, separate small recipient records |
| Borrowed decoding | No object-graph reconstruction when the chosen format/layout permits it |
| Receive-frame assembly | May copy to satisfy contiguity or alignment |
| QUIC, encryption, OS, and NIC | No blanket zero-copy guarantee |
| Two separate processes on one host | No shared-memory guarantee in v1 |

Payload hashing reads bytes but need not copy them. Encoding can still allocate. Small messages may perform better with a straightforward bounded copy than with elaborate scatter/gather bookkeeping; benchmark rather than assuming the most complicated path is fastest.

## 10. Lock-free handoffs and single-owner state

The central simplification is **ownership**, not “everything is atomic.” Start with one endpoint-owner task that owns mutable routing, delivery, and accounting state. It processes events without sharing those structures behind a global data-path mutex.

Use a bounded SPSC ring where there is exactly one logical producer and one logical consumer. Examples include a registered producer lane feeding the endpoint owner, the owner feeding a peer writer, and the owner feeding a subscription receive handle.

Each additional application producer gets its own lane. Do not clone an SPSC producer into concurrent writers. Network-reader lanes likewise have one producer each. Where an actual many-to-one channel is necessary, use a reviewed implementation and make its real progress guarantees explicit.

### How the ring works

The ring has fixed descriptor slots, a producer position, and a consumer position. The producer checks available capacity, initializes a free slot, and publishes its position with release ordering. The consumer observes that position with acquire ordering before reading the slot. After consuming, it releases the slot by updating its position; the producer acquires that update before reusing the slot.

These orderings are essential: publishing an index before initializing its descriptor can expose uninitialized data. The SPSC assumption is also essential; this is not a correct MPMC algorithm merely by replacing index changes with `fetch_add`. The Linux circular-buffer documentation explains the corresponding single-producer/single-consumer ordering pattern. [S9]

Use a maintained implementation with appropriate tests. Do not ship an ad hoc unsafe ring as the foundation of the library. Pad contended positions where measurements justify it and handle wraparound, cancellation, and dropping queued descriptors correctly.

### What is and is not claimed

Nonblocking `try_push` / `try_pop` on the chosen ring should complete without taking a mutex and return `Full` / `Empty` when they cannot proceed. A task waiting asynchronously for queue capacity is not itself a wait-free operation. Lock-free is a progress property, not merely the absence of a visible mutex.

The allocator, reference-count destruction, task scheduler, wakeup mechanism, crypto implementation, and Iroh internals may have different synchronization behavior. **The complete publish-to-network pipeline is not claimed to be formally lock-free.**

Empty/full waiting should park tasks, not spin continuously. Use a race-safe register-waker / recheck / wait pattern. Test lost-wakeup and cancellation cases. Keep buffers pooled where useful, but account for pool growth and reclamation instead of hiding them outside the memory budget.

A single endpoint owner is the v1 baseline. Add ownership shards only after profiling shows a bottleneck and their routing/ordering boundaries are specified. Thousands of deployed applications do not by themselves require a thread-per-core engine inside every application.

## 11. Iroh runtime, ESP logic reuse, and io_uring integration

### Keep the transport boundary intact

Run Iroh using its supported runtime path. The reviewed Iroh source uses the noq QUIC stack with Tokio runtime integration. This design does not assume an application can swap Iroh's UDP sockets onto an io_uring runtime by changing its own queue implementation. [S10]

Reuse the connection, identity-storage, invitation, and signing **logic** from the existing ESP project, whose local checkout is `~/code/arc` and whose crate is named `esp`. Implement the adapted logic in this project's own Rust modules. **ESP is not a dependency**: no Cargo path/git dependency, subprocess invocation, or runtime requirement for the ESP daemon or its configuration. See [ESP logic reuse](#esp-logic-reuse) for the source inventory and required adaptations, and [ESP validation to adapt](#esp-validation-to-adapt) for reusable test cases.

Messaging registers its own protocol identifier, `iroh-mq/1`, which can coexist with other explicitly registered protocols on an application-owned endpoint. ESP's certificate format, administrative delegation chains, and SSH port grants are not messaging credentials. Messaging uses the root-to-endpoint authorization and signed-envelope profiles in sections 4 and 12; messaging permissions must not implicitly authorize SSH access.

Apache Iggy's documented thread-per-core, pooled-buffer, io_uring architecture is useful inspiration, but its complete streaming-engine design is not automatically inherited by an Iroh-based embedded library. [S11]

### ESP logic reuse

**Reviewed:** September 4, 2026.  
**Source:** `~/code/arc`, package `esp`, commit `df01cb229a5bcd59544934236be50c3a38dcf161`.  

#### Decision

Reuse ESP's connection, identity, invitation, and signature-validation logic by adapting it into modules owned by `rtn-mq`. ESP is a source reference, not a Cargo dependency or a required service. This project must build and run without an ESP checkout, executable, daemon, or `~/.esp/config.yml`.

Use Iroh and the other selected upstream libraries directly, with dependency versions pinned and tested for this project. The reviewed ESP lockfile resolves Iroh to `1.0.3`; that is a known source baseline, not a claim about the latest release. ESP currently keeps these fundamentals in `src/main.rs`, so there is no standalone library interface to import.

Reusing logic does not mean migrating existing credentials. Endpoints generate independent keys and receive messaging-specific authorization. Application-supplied keys can be supported through the public identity API; startup must not implicitly read ESP's private state.

#### Source map

Paths in the ESP source column are relative to the reviewed checkout. The adapted implementation is owned by this crate: `identity`, `auth`, `enrollment`, `message`, `wire`, `buffer`, `queue`, and `endpoint` (with `owner` and `transport` submodules). The target column describes the corresponding responsibilities.

| Concern | ESP source in `src/main.rs` | Logic to retain | Adaptation in `rtn-mq` |
|---|---|---|---|
| Endpoint identity | `join`, `encode_secret_key`, `decode_secret_key` | Generate locally with `SecretKey::generate`; validate key representation and length; obtain identity from the public key. | `identity`: independent endpoint identity, with an optional explicit persistence path. The orchestrator signing key is separate from its enrollment transport key. |
| Private state | `read_private_config`, `write_private_config`, `write_private_config_temp`, metadata validation helpers | Private files, exclusive temporary-file creation, file sync, atomic replacement, Unix symlink/hard-link and permission checks. | `identity`: messaging-owned state format and caller-selected location. Bound file reads, check existing parent-directory permissions, and define equivalent protection or explicit limitations on other platforms. |
| Connection lifecycle | `daemon`, `sync_joined_config_once`, `handle_incoming_connection` | Inject a stable secret key into the endpoint; connect to known identities; use relay-capable connectivity; bound handshake/setup time; close resources on completion. | `transport`: native `iroh-mq/1`, explicit contact hints or configured address lookup, bounded admission, cancellation, and owned task cleanup. |
| Authenticated identity binding | `sync_control_config`, `validate_peer_report`, `verified_membership_for_peer`, `MembershipCertificate::matches_peer` | Derive the peer identity from `Connection::remote_id()` and require the signed subject to match it. A remembered peer is not automatically authorized. | `session`: mutual HELLO/READY validation against a locally trusted root, the configured realm, and current policy before protected traffic. |
| Invitation redemption | `Config::issue_invite`, `invite_grant_for_proof`, `consume_invite_proof`, `consume_invite_and_issue_membership`, `commit_config_change` | Store a secret hash at the issuer; bind the resulting grant to the authenticated joining endpoint; serialize consumption with issuance and persistence. | `join`: fixed exact-topic permissions, expiration, bounded reusable codes, distinct-identity limits, and a pinned host that supplies the initial root and realm. |
| Pending enrollment | `join_hello_from_config`, `hello_from_config`, `ensure_completed_join`, `save_completed_join` | Send the bearer secret only to the intended enrollment peer; complete validation before recording successful enrollment; remove pending proof afterward. | `join`: an explicit code-redemption exchange on the host endpoint. Normal messaging sessions carry certificates, never enrollment secrets. |
| Signing and verification | `MembershipCertificate::issue_for_network`, `verify_signature`, `signature_payload`; corresponding policy and revocation methods | Use Iroh's signing/verification APIs, bind all relevant claims, separate signature contexts, and fail on tampering. | `auth` and `message`: strict COSE_Sign1 Ed25519 profiles, exact authenticated bytes, messaging-specific claims and contexts. |
| Authorization intersection | `normalize_allowed_ports`, `ensure_port_allowed`, `ensure_membership_allows_port` | A signed grant can restrict local policy but cannot increase it. | `auth`: exact-topic publish/subscribe permissions and certificate ceilings intersected with local limits. |
| Revocation | `remember_revocations_in_config`, `is_node_revoked`, `terminate_revoked_connections`, `run_config_actor` | Verify updates before accepting them; cancel affected active connections; serialize state changes. | `auth` and endpoint owner: certificate IDs, root-issued updates or administrative deny lists, version/freshness policy, expiry checks, and visible failure of affected operations. |
| Bounded work | `run_acceptor`, `run_incoming_worker`, peer quota handling, `read_yaml_frame` | Bound inbound work, reject overload explicitly, validate frame lengths before allocating, and keep setup timeouts. | `wire` and `transport`: architecture section 12's 12-byte prefix and strict CBOR, with byte/count budgets and bounded control traffic. |
| State ownership | `spawn_config_actor`, `run_config_actor`, `commit_config_change` | One owner serializes mutations through bounded commands; failed validation or persistence does not publish a partially changed state. | Endpoint owner and enrollment state owner. Keep synchronous configuration persistence outside the messaging data path; reuse the ownership pattern, not the whole config actor. |

#### Changes required by the messaging design

##### Trust and signed records

ESP permits administrative membership chains rooted in the network creator. Messaging v1 permits only root-to-endpoint certificates. An authorized endpoint cannot enroll another endpoint by signing a child certificate. Keep the orchestrator's signing authority separate from transport identity, even when the orchestrator also operates an enrollment endpoint.

ESP membership signs network identity, endpoint identity, a connection ID, role, and allowed ports. Its reviewed membership schema has no validity interval or certificate issuance ID. Messaging adds realm, issuer key ID, certificate ID, validity, exact-topic permissions, and optional restrictive limits. Verify these at session establishment and continue enforcing expiry and revocation during the session and on retries.

ESP signs custom length-delimited fields using its own record encoding. Retain its use of standard signature APIs and distinct contexts, but implement the architecture's COSE/CBOR schemas independently. Do not pass ESP's `signature_payload` encoding off as the messaging wire profile. Specify the exact claims, protected headers, accepted encodings, and signature contexts, then freeze golden fixtures before interoperability is claimed.

Per-message signatures are new work. Sign the complete immutable envelope described in architecture section 4.4, including the payload digest, once per logical publication. Require the signer to equal both the authenticated peer and the certificate subject. Share the signed envelope and payload across fan-out and retries.

##### Invitations and private state

ESP's reviewed invite contains network, creator, inviter, invite ID, and secret; it has no expiration field. Messaging adds expiry and connection material while distinguishing the pinned authority signing key from the enrollment service's authenticated transport identity. A peer-supplied issuer key must never become a trusted root merely because it verifies a signature.

Retain hashed bearer-secret storage and serialized redemption. Generate secrets from a cryptographically secure random source, bound decoding before allocation, and rate-limit redemption. A future persistent store must commit code usage, issued authorization, and membership admission together before enrollment success. ESP's clone/validate/save/commit sequence is the reference for avoiding partial state publication, but its ignored parent-directory sync errors must not become a claim of crash-durable enrollment enforcement.

ESP consumes a code after one enrollment. This implementation deliberately extends that logic to reusable codes: each distinct endpoint consumes one of the configured uses, and same-endpoint recovery returns its own cached certificate. Shared usage limits and membership state are serialized by the host owner. There is no offline provisioning connection path.

The Unix private-file checks are useful source material. Platform behavior needs its own review: ESP's non-Unix permission helpers are no-ops, and existing directory permissions are not checked by its `validate_state_dir` function. Preserve the intended private-state invariant while adapting those helpers.

##### Connections and framing

Use explicit bootstrap peers, native messaging streams, mutual authorization, and the architecture's HELLO/READY exchange. ESP's SSH proxy commands, localhost TCP connections, local daemon control socket, peer names/short IDs, administrative directory propagation, ALPNs, and YAML framing are outside the messaging protocol.

The messaging session also needs deterministic simultaneous-dial resolution, subscription readiness, current-session binding, expiry handling, and bounded stream counts. ESP provides reference connection mechanics; those messaging state transitions must be implemented here. Transport completion must not be interpreted as an application's processing ACK.

### Useful optional Linux path

The clean first io_uring integration is a **local storage engine** for a later persistent outbox or inbox:

```text
endpoint owner
    -> bounded storage-command descriptors
    -> dedicated Linux io_uring driver
    -> append / read / sync operations
    -> bounded completion descriptors
    -> delivery-state updates
```

Batch journal operations and consider registered buffers when measurements justify their cost. Keep the portable storage implementation available behind the same interface. A memory-only endpoint has no journal I/O to accelerate; io_uring is not required to push descriptors through an in-memory queue.

Buffer registration alone does not establish a zero-copy network path. Fixed-buffer writes have specific buffer and completion requirements. Specialized zero-copy sends can require a separate notification before a buffer is safe to reuse. Cancellation requests are not proof that all kernel access has ended. [S12][S14]

Linux's documented io_uring zero-copy receive facility has specific NIC, flow-steering, and TCP-path requirements. It is not a general promise that Iroh's QUIC traffic is DMA'd directly into the final application message buffer. Treat a custom network-I/O backend as a separate, measured integration project. [S15]

## 12. Minimal wire protocol, kept in this document

A separate wire-protocol document is unnecessary for v1. Keep framing, authorization requirements, message schemas, and compatibility rules here until the implementation warrants splitting them out.

### Connection layout

Use one authenticated Iroh connection per peer pair within the realm. Either peer may dial; resolve simultaneous duplicate sessions deterministically after authentication. The dialing endpoint opens a bidirectional control stream and sends first.

After mutual authorization, use an ordered data stream per active publisher-to-subscriber topic binding, multiplexed over that connection. Bound stream counts. One slow topic should not prevent processing unrelated control messages, although streams still share connection and network resources. Iroh provides ordered streams and configurable stream/connection flow control. [S2]

No DATA is accepted before both peers complete authorization. Do not accept application DATA in QUIC 0-RTT in v1; process it only after the completed handshake and application authorization. The receive API documentation explicitly warns about replay risks for early data. [S8]

### Frame prefix

All frame lengths are byte lengths, and integers in the fixed prefix are big-endian:

```text
u32 body_len          # metadata + payload, excluding this 12-byte prefix
u8  frame_type
u8  flags
u16 reserved          # must be zero in v1
u32 metadata_len     # must be <= body_len
metadata[metadata_len]
payload[body_len - metadata_len]
```

Control frames have no payload, so `metadata_len == body_len`. DATA metadata contains the signed envelope and binding information; the payload remains a separate byte region. The negotiated maximum applies before any body allocation.

Metadata uses a strict, versioned CBOR schema. Certificate and message signatures use the fixed COSE profile defined above. Preserve exact authenticated bytes; do not accept one parsing interpretation for authorization and another for routing. Bound lengths, collection sizes, nesting, and partial-frame retention. Unknown required types or flags fail explicitly rather than being guessed.

### Implemented v1 encoding profile

All metadata is definite-length, minimally encoded CBOR. Arrays have exactly the listed lengths; no optional trailing fields, indefinite containers, unexpected maps, or trailing bytes are accepted. Parsers bound input before allocation and compare accepted values against canonical re-encoding. All IDs below are byte strings: realm, certificate, subscription, nonce, and epoch IDs are 16 bytes; Ed25519 public keys and SHA-256 digests are 32 bytes. Topics and schema/format names are text strings, limited to 256 bytes. Topic segments accept ASCII letters, digits, `_`, `-`, and `.`; `/` separates nonempty segments.

The fixed signature container is an **untagged COSE_Sign1** array `[protected, {}, payload, signature]`. `protected` is exactly the byte string `a10127`, encoding `{1: -8}`. Only Ed25519 keys and 64-byte signatures are accepted. The signature input is CBOR `["Signature1", protected, external_aad, payload]`, following RFC 9052 [S5]. `external_aad` is the byte string naming the relevant context below. Unknown/duplicate protected headers and all nonempty unprotected maps fail. Signed payload bytes are preserved exactly.

| Signed record | Context | Payload array |
|---|---|---|
| Delegation | `iroh-mq/certificate/v1` | `[1, realm, issuer_public_key, certificate_id, subject_public_key, not_before, expires_at, permissions, limits]` |
| Message | `iroh-mq/message/v1` | `[1, realm, publisher_public_key, epoch, topic, sequence, created_at, expires_at, format, payload_length, sha256, delivery_mode]` |
| Revocation snapshot | `iroh-mq/revocation/v1` | `[1, realm, version, issued_at, expires_at, certificate_ids]` |

Permissions are sorted, unique `[topic, mask]` pairs; mask `1` grants publish, `2` subscribe, and `3` both. `limits` is `[max_payload, max_subscriptions]`, with zero meaning no additional certificate ceiling. The issuer public key itself is the key ID. Timestamps are Unix seconds. The mode is `0` for best effort or `1` for acknowledged, and is included in the signature. Snapshots are cumulative at the receiver, capped at 4,096 denied certificate IDs, and must increase the accepted version. Accepting a snapshot also enables its freshness deadline.

Handshake metadata is `HELLO = [1, certificate_bytes, local_nonce, max_payload, max_topics, max_delivery_window_seconds]` and `READY = [1, local_nonce, remote_nonce]`. The certificate binds the realm. After mutual READY, the shared session generation is 16 TLS exporter bytes, using label `iroh-mq/session/v1` and the realm ID as context. Normal completed Iroh handshakes are used; there is no DATA 0-RTT path. Duplicate connections prefer the lexicographically smaller `(dialer_endpoint_id, dialer_nonce)` pair at both ends.

| Type byte | Frame | Metadata array |
|---|---|---|
| 1 | HELLO | As above |
| 2 | READY | As above |
| 3 | SUBSCRIBE | `[1, session, topic, subscription_id, mode]` |
| 4 | SUBACK | `[1, session, topic, subscription_id, result]` |
| 5 | UNSUBSCRIBE | `[1, session, topic, subscription_id]` |
| 6 | CREDIT | `[1, session, topic, subscription_id, slots, bytes]` |
| 7 | DATA | `[1, session, subscription_id, signed_message_bytes]` |
| 8 / 9 | ACK / NACK | `[1, session, topic, subscription_id, publisher_epoch, sequence, result]` |
| 11 | ERROR | `[1, session, reason_code]` |
| 12 | GOODBYE | `[1, session]` |

SUBACK result `0` accepts, `1` denies permission, and `2` rejects capacity. ACK result is `0`; NACK `1` is retryable and `2` permanent. Type `10` is unassigned and rejected. The authenticated peer, realm, topic, epoch and sequence determine the relevant message identity; acknowledgements must refer to an addressed pending delivery or retained terminal receipt.

CREDIT uses `slots = 0, bytes > 0` to request capacity for an actual pending frame; it is not a grant. The receiver fairly rotates outstanding requests and grants `slots = 1` with a byte ceiling covering the negotiated maximum payload, 16 KiB metadata, and the 12-byte frame prefix. Only one unconsumed grant is allowed per binding. `slots = 0, bytes = 0` returns/cancels unused capacity. This prevents idle publishers from reserving all receiver memory. A sender consumes a grant only for a frame within its byte ceiling, and cannot apply a grant from another session or subscription.

Join enrollment uses `iroh-mq/join/2` on the same Iroh endpoint as messaging (`iroh-mq/1`). The compact code is `rtn-mq://join/` followed by unpadded base64url of canonical CBOR `[3, host_endpoint_public_key, routes, secret]`. The host key and random secret are 32 bytes each. The public 16-byte code ID is derived as the first 16 bytes of SHA-256 over `b"iroh-mq/join-code-id/v3" || secret`, separate from the stored SHA-256 secret hash. It is not repeated in the code. Code versions 1 and 2 and enrollment protocol version 1 are unsupported; upgrade both sides and generate fresh codes. Messaging and certificate schemas remain version 1.

Routes are a definite array of 1–16 entries. Each entry is `[kind, value]`: kind `0` carries a 6-byte IPv4 address/port byte string; kind `1` carries a 26-byte IPv6 address/port/flow-info/scope-ID byte string; kind `2` carries a relay URL string of at most 1,024 bytes. Address bytes are followed by the 2-byte port and, for IPv6, 4-byte flow info and 4-byte scope ID, all integers in network byte order. Routes follow Iroh's `EndpointAddr` ordering. If any relay is available, only relay routes are included; otherwise all IP routes are retained. Duplicate routes, mixed relay/IP routes, invalid types, and other noncanonical encodings are rejected by re-encoding. The encoded code is at most 32 KiB; unsupported prefixes/versions, indefinite arrays, wrong sizes, and trailing data are rejected.

A relay route allows Iroh to establish contact and negotiate direct connectivity without listing every network interface in the code. This requires a reachable relay for bootstrap; direct-only deployments preserve their IP hints and require no address directory. Custom relay URLs are preserved verbatim in canonical URL form. One IPv4 route produces a 121-character code; one `https://usw1-1.relay.n0.iroh.link./` route produces 161 characters, including the prefix. There is no ESP dependency or external short-code service.

Join HELLO contains `[2, code_id, secret]` (at most 128 bytes of metadata). Successful READY contains `[2, realm, authority_public_key, code_expires_at, certificate_bytes]`; failure is type 11 with `[2, reason]`, where `1` means unauthorized (including expired or revoked codes) and `2` means capacity exhausted. Unknown reasons are rejected. The realm is 16 bytes; the authority key is 32 bytes. The response fits the existing 16 KiB metadata bound and 15 KiB certificate bound. Request, response, and code schemas are CBOR. The certificate subject is bound to `Connection::remote_id()`; credentials are never accepted as authorization for another transport key. Secrets appear only on the authenticated join connection, never on a DATA session.

Iroh authenticates the host key pinned in the code before the client sends its secret or accepts bootstrap metadata. On a first join, the client trusts that authenticated host to choose the authority and realm, then verifies the certificate signature, subject binding, realm, and validity and checks the returned code expiry. On a rejoin, the returned authority and realm must match existing trust before any local certificate replacement; the owner also enforces current revocations. A host restarted with the same transport key but a new authority/realm requires a fresh `join`, not `rejoin`. No root/realm placeholder is used while binding the client transport.

Enrollment uses the same bounded accept quotas, rate limits, timeout, and scratch-memory reservations as messaging. `join()` completes registration locally after certificate verification and the mutual HELLO/READY handshake; subscription readiness requires `wait_ready` or publisher-side admission handling. Unregistered certificates are rejected by the host owner even if otherwise root-signed.

Independent Python CBOR and Ed25519 fixtures for join codes, delegation, envelope, HELLO, and DATA live in `tests/fixtures`, with their generator in `tools/generate_fixtures.py`. Rust verification and encoding are checked against those fixtures.

### Frame families

| Frame | Purpose |
|---|---|
| `HELLO` | Protocol version, realm, certificate, limits, session generation |
| `READY` | Confirm successful peer authorization and compatible limits |
| `SUBSCRIBE` | Exact topic, subscription ID, requested delivery mode |
| `SUBACK` | Confirm or reject that subscription and negotiated settings |
| `UNSUBSCRIBE` | End a subscription binding |
| `CREDIT` | Grant reserved message-slot and byte capacity for this session/binding |
| `DATA` | Signed message envelope and payload |
| `ACK` | Application processing completed for the identified delivery |
| `NACK` | Retryable or permanent rejection with a bounded reason code |
| `ERROR` | Protocol, authorization, or limit failure |
| `GOODBYE` | Planned shutdown and end of new admission |

ACK, NACK, and credit records are bound to the authenticated peer, current session, subscription, and relevant delivery identity. Reject acknowledgements for deliveries not addressed to that peer. Coalesce control updates only with explicit bounds; never let ACK aggregation grow indefinitely.

Changing a message's delivery mode or signature requirements silently is forbidden. Protocol-major changes use a different ALPN; minor features require explicit compatibility negotiation. Produce golden encoding fixtures before implementation is considered interoperable.

## 13. Persistence and large-message extensions

### Memory-only baseline

Pending messages, deduplication records, and queue contents disappear when their process crashes. Successfully acknowledging a message does not create a library-managed durable record. A sender cannot keep delivering after it has permanently disappeared.

This is an explicit product choice, not a limitation of brokerless architectures in general. Brokerless endpoints can be durable when they maintain local persistent state.

### Optional persistent outbox / inbox

A persistent sender records the message and its admitted recipient set before reporting **durable local acceptance**. It also records per-recipient terminal outcomes and reconstructs pending deliveries during recovery. Never replay an old publication to today's subscriber set as though those were its original recipients.

A persistent receiver can journal accepted messages before reporting **durable receipt**, but durable receipt remains different from application processing ACK. Durable deduplication must be coordinated with the application's side effects before making stronger processing claims.

Specify journal records, checksums, torn-write recovery, sync boundaries, disk-full behavior, and retention before enabling durable receipts. Write completion is not automatically a power-loss durability boundary. Use batching where allowed, but acknowledge durability only after the configured persistence barrier succeeds.

Local journals are not replicas. A destroyed sender disk can lose an outbox. Disk-full or failed sync must produce errors, not silently downgrade acknowledged durability to memory-only behavior.

### Large payloads

V1 returns `MessageTooLarge` above the configured inline limit. A future blob-reference mode may send an authenticated content hash and size, then fetch the object through a separately authorized Iroh protocol.

That extension must define blob availability, retention, access control, garbage collection, and when the message may be ACKed. A content hash verifies content identity; it is not an authorization token or a guarantee that somebody still stores the bytes.

## 14. Public API

The only constructors are `MessagingEndpoint::host(config, identity, permissions)` and `MessagingEndpoint::join(config, identity, &code)`. `Config::new()` configures networking and budgets; root/realm trust is established internally by hosting or by the response from the code-pinned authenticated host. The root signing key is never the endpoint transport key.

```rust
use rtn_mq::*;
use std::time::Duration;

async fn create_host() -> Result<(MessagingEndpoint, JoinCode)> {
    let host = MessagingEndpoint::host(Config::new(), Identity::generate(),
        vec![Permission::both("jobs")?]).await?;
    host.online(Duration::from_secs(30)).await?;
    let code = host.issue_join_code(JoinOptions::new(vec![Permission::both("jobs")?])).await?;
    Ok((host, code))
}
```

`JoinCode` exposes `id()`, `host_id()`, `encode()`, and `decode()`. Offline root, realm, and expiry getters are removed because those values are fetched during enrollment. Share `code.encode()` privately. A joining process decodes it with `JoinCode::decode`, supplies its own identity to `join`, and uses the existing `subscribe`, `publisher`, receipt, and ACK/NACK APIs. `rejoin(&code)` preserves the running endpoint's identity, publisher epoch, pending IDs, and authorized subscription IDs. A code must be valid and target the same host/realm; raw address-based reconnect is not available.

`revoke_join_code(code.id())` stops enrollment through a code. `certificate()` exposes the local certificate for audit/revocation; `deny_certificate(id)` revokes a member independently of its code. There are no external-certificate startup, standalone enrollment, contact invite, or direct-address connect APIs and no compatibility wrappers.

Public waits accept `Duration`, including `wait_ready`, `wait_for_processing`, and `online`. One timeout covers all receipt recipients or readiness updates. Timeout does not cancel admitted delivery. Shutdown uses `ShutdownMode::Immediate` or `ShutdownMode::Drain { timeout: Duration::from_secs(10) }`; the deadline is computed internally.

See [USER_GUIDE.md](USER_GUIDE.md), [examples/direct.rs](examples/direct.rs), and [examples/two_computers.rs](examples/two_computers.rs) for runnable workflows.

## 15. Failures, shutdown, and observability

| Situation | Required behavior |
|---|---|
| Slow subscriber | Stop granting capacity; bound the sender backlog; keep healthy recipients progressing |
| Peer disconnects | Mark its subscription bindings inactive for new publications; retain eligible existing deliveries until their deadline |
| Processing ACK is lost | Retry with the same identity; regenerate ACK when deduplication state proves completion |
| Certificate expires or is revoked | Stop new protected operations and reject unauthorized retries; notify callers |
| Host unavailable | Host-to-peer sessions stop; enrollment/rejoin cannot complete; retained deliveries remain bounded by their deadlines |
| Publisher crashes | Memory-only pending deliveries are lost; no durability claim |
| Subscriber crashes | Memory-only queued messages and deduplication state are lost; retained sender deliveries may be retried |
| Oversized or malformed frame | Reject before unbounded allocation; rate-limit repeated abuse |
| Managed memory exhausted | Apply the configured explicit admission policy; never grow without bounds |
| Shutdown deadline expires | Report unfinished or uncertain deliveries and release resources safely |

Revocation cannot recall plaintext or side effects already delivered to an application. A transport relay or network outage is also distinct from an application broker failure: there is no alternate broker holding the message unless an endpoint explicitly persisted it.

Graceful shutdown stops new admissions, advertises shutdown, and drains eligible deliveries for up to the caller's timeout duration. Then it reports unresolved recipients, closes sessions, and waits for owned I/O buffers to become safe to release. Immediate shutdown makes no draining promise.

Expose counters for admitted, rejected, processed, retried, expired, and dropped deliveries. Expose queue depth **and** bytes, processing in-flight counts, outstanding credits, managed resident bytes, retained payload leases, deduplication occupancy, and copy/coalescing counts.

Measure publish-to-processing-ACK latency at the sender with a monotonic clock, and local queue/handler times independently. Cross-host timestamp subtraction requires clock assumptions and should not be mislabeled as precise latency.

Include peer connection state, reconnects, certificate expiry, and authorization failures. Keep metric labels bounded; message IDs and arbitrary topic strings belong in sampled traces or structured events, not unbounded metric-cardinality dimensions. Avoid logging payloads, invitation secrets, or private keys.

## 16. Scaling model

The intended deployment can contain thousands of applications, but v1 assumes a **sparse communication graph**. Each application connects to the publishers or subscribers relevant to its work.

For `N` applications, a full mesh needs `N(N-1)/2` connections: 1,000 applications would require 499,500 peer pairs. That is not the default topology.

For a publisher emitting `r` messages/second with average payload `s` bytes to `f` subscribers, payload egress is approximately:

```text
egress_bytes_per_second = r * s * f
```

This excludes signatures, metadata, transport overhead, and retransmissions. Sharing one local payload allocation avoids repeated local payload copies; it does **not** eliminate transmitting bytes to each remote recipient.

Outbox state grows with unresolved recipient deliveries, while shared payload memory grows with retained unique payloads. One slow recipient may dominate retention. Control these with per-peer limits, delivery deadlines, and global caps rather than relying on the application's total deployment size as a capacity estimate.

A very large fan-out topic may eventually need a forwarding overlay or brokers. That is a different topology decision and should not be added invisibly to this direct-only v1.

## 17. Implementation milestones and acceptance tests

### Milestone 1: Secure direct messaging

Implement host/join lifecycle, reusable-code enrollment, registered-member admission, mutual certificate validation, native Iroh protocol registration, exact topics, subscription readiness, and signed DATA frames. Verify direct and relayed paths with two and then three peers. One host should authorize multiple independently keyed peers without forwarding messages between them.

#### Implementation order and ESP adaptation

1. Define strict topics, identity types, delegation claims, and the COSE signature profiles with golden fixtures. Adapt private-state helpers into an optional messaging-owned store.
2. Implement internal root issuance and verification plus join-code-only host admission, including wrong-root/realm/subject, expiry, permission, registration, and revocation rejection.
3. Adapt endpoint creation, authenticated peer binding, timeouts, and bounded connection admission. Implement mutual HELLO/READY and deterministic session ownership.
4. Implement exact-topic SUBSCRIBE/SUBACK readiness and signed DATA using the framing and baseline resource bounds in the architecture. Keep the public delivery guarantees limited to the behavior actually implemented.
5. Verify reusable-code enrollment and two/three-peer host communication over direct and relay-only paths, including concurrency, bounded uses, code revocation, and same-key response recovery.

ACK/NACK receipts, credits, retry/reconnect semantics, and deduplication continue under Milestone 2. Metered buffer optimization, borrowed access to CBOR payload bytes, and SPSC specialization remain Milestone 3. ESP reuse does not supply these messaging guarantees.

### Milestone 2: Bounded queue and delivery semantics

Implement message identity, per-recipient receipts, credits, ACK/NACK, retry deadlines, reconnect resumption, and explicit no-subscriber/partial-fan-out results. Exercise slow consumers, lost ACKs, certificate expiry during an active session, and sender/receiver termination.

### Milestone 3: Buffer and concurrency optimization

Implement metered immutable payload ownership, measured fan-out sharing, borrowed access to CBOR payload bytes, and reviewed SPSC handoffs. Test ring interleavings with an appropriate concurrency model checker, and use memory-safety testing for any unsafe code. Test cancellation, wakeup races, retained leases, and buffer reuse while I/O is in flight.

### Milestone 4: Optional durability and Linux optimization

Only after the memory baseline is correct, add the journal interface and recovery semantics. Compare portable storage against an io_uring implementation. Inject disk-full, partial-write, sync-failure, and crash-at-boundary scenarios before exposing durable receipts.

### Current implementation and validation boundary

Milestones 1 and 2 have a runnable memory-only implementation: join-code-only host startup and reusable enrollment, mutual authorization, signed messages, exact topics, subscription readiness, receipts, credits, ACK/NACK, expiry, revocation, renewal, explicit reconnect, cancellation, and drain deadlines. Renewal keeps the endpoint key, publisher epoch, pending message IDs, and still-authorized subscription IDs; peers reconnect to exchange the new certificate. Applications choose reconnect timing and refresh contact hints.

The baseline also implements metered shared payload leases and `rtrb` SPSC rings for topic writer/subscription lanes. CBOR protocol parsing uses bounded schemas; application CBOR decoders can read directly from leased byte slices. Actual MPSC ingress/event paths remain bounded Tokio channels. Ring push/pop operations use rtrb's implementation; async notifications are separately synchronized, so the complete enqueue/wakeup path is not claimed to be lock-free. Tests exercise cross-thread ring wraparound, cancelled waits, closure, retained leases, and shutdown. A reusable allocation pool, formal model checking, cross-platform memory-safety runs, and broader optimization studies remain follow-up work.

The implementation caps inline payloads at 1 MiB and metadata at 16 KiB. Queues and certificate/delivery state are charged to configured budgets before admission. Payload charges include backing capacity plus a conservative 256-byte ownership allowance; receive grants reserve the maximum payload plus this allowance. Queue storage stays charged until both queue endpoints are dropped. Certificate accounting survives session replacement and retained deliveries. Deduplication records remain bounded and are retained through the message expiry horizon. Terminal receipt history adds one handshake-timeout grace period to tolerate late acknowledgements. Receive grants also reserve the future deduplication record before advertising capacity. A receiver uses QUIC STOP_SENDING code 1 when a subscription closes before DATA admission; this retires the topic stream without closing unrelated streams. Expired in-flight messages are discarded with a permanent NACK. Metrics expose current/high-water charges and unfinished shutdown deliveries; they are not a process-RSS bound.

Private-key persistence is implemented for Unix with explicit private-directory/file checks and atomic replacement. Persistent host enrollment uses the same private-file posture and recovers authority, join grants, redemptions, and memberships. Other platforms use application-provided key stores. Queues, subscriptions, replay state, and runtime revocation version state remain in memory. Restart-resistant revocation rollback protection still requires application-managed trust-state persistence.

The suite includes direct and relay-only two/three-peer tests, a real stolen-certificate handshake, authenticated bootstrap fixtures and certificate validation, rejoin rejection after same-key host realm replacement, unaddressed ACK rejection, reusable-code enrollment races, usage limits, code revocation, and same-key response recovery, renewal, active/disconnected revocation, expiry, partial fan-out, abandoned processing, lost ACK recovery, and budget retention across reconnects. The local relay test disables direct IP transports, so a direct connection cannot accidentally satisfy it. No durability or io_uring storage claim is made.

`examples/benchmark.rs` emits configurable direct-loopback measurements for payload size, fan-out, publish-to-processing-ACK latency, throughput, and sender budget high-water marks. These smoke measurements do not replace the complete performance/network fault-injection matrix below.

### Required test matrix

| Area | Minimum checks |
|---|---|
| Authorization | Wrong root, wrong realm, stolen certificate without key, wrong topic permission, malformed claims, expired certificate, revocation update |
| Framing | Truncation at every boundary, excessive lengths, invalid metadata, unsupported versions, arbitrary QUIC chunk splits |
| Delivery | ACK loss, duplicate DATA, reconnect, no subscribers, late subscriber, retry deadline, conflicting payload under one message ID |
| Memory | Large and tiny messages, full fan-out, held payload leases after ACK, budget exhaustion, bounded deduplication |
| Concurrency | SPSC ownership, wraparound, stalled participants, lost wakeups, cancellation, shutdown with outstanding buffers |
| Network | Direct path, relay fallback, latency, loss, disconnect, simultaneous dialing |
| Performance | Throughput, CPU, allocation count, copy bytes, resident memory, and p50/p95/p99 latency |

Benchmark representative payloads such as 128 B, 1 KiB, 64 KiB, and 1 MiB, and fan-outs such as 1, 10, and 100. Include signature verification, slow-consumer conditions, and the actual configured queue limits. Report hardware, dependency versions, network conditions, and whether traffic was direct or relayed. Do not publish numeric performance promises before these measurements exist.

### ESP validation to adapt

The reviewed ESP tests in `tests/config.rs` and `tests/internal.rs` provide useful behavior cases:

| Existing coverage | Messaging equivalent |
|---|---|
| Membership tampering and invalid issuer rejection | Alter signed claims, substitute the root, use the wrong realm or peer key, and attempt endpoint-issued delegation. |
| Invite grants signed into membership; delegated port widening rejected | Sign exact-topic permissions and limits; reject unauthorized topics, actions, and attempts to widen local limits. |
| Invite consumed once; concurrent actor redemption; same-node recovery | Race independently keyed redeemers against a shared configured use limit; issue distinct certificates and recover a lost response only for its original subject. |
| Pending proof sent only during join; incomplete join not saved | Never send a secret on a data session or to another peer; expose enrollment success only after validation and commit. |
| Known peers without valid membership rejected | Reject a configured contact or copied certificate unless the connection identity and current authorization both validate. |
| Revocation cancels active connections | Stop protected operations in established sessions after revocation, expiry, or freshness failure. |
| Private files, directories, loose modes, symlinks, and hard links | Adapt the file tests and add bounds, existing-directory protection, persistence-failure, and supported-platform cases. |
| Peer quotas and bounded shared lists | Exercise connection, certificate, control-frame, subscription, and metadata limits without unbounded allocation. |

Add the messaging-specific signature, framing, delivery, memory, and network tests in the required test matrix above. The ESP tests are useful references; passing them does not validate the new protocol.

On the reviewed checkout, `cargo test --locked --test config --test internal` passed **46 tests** (6 config and 40 internal). That pre-implementation run exercised ESP. The new crate now has independent authorization, framing, queue, storage, enrollment, direct/relay messaging, renewal, and delivery tests; see the validation commands in `README.md`.

## 18. Final v1 boundary

The first release is an embedded, authenticated, direct pub/sub system with exact topics, join-code-only bootstrap, signed delegations and message envelopes, bounded memory, processing acknowledgements, and explicit retry/failure semantics.

Its implementation should optimize ownership and eliminate unnecessary local payload copies while preserving Iroh's supported transport path. Optional durability, io_uring storage, large blobs, shared-memory IPC, request/reply, wildcard subscriptions, and consumer groups can be added independently after their semantics are specified.

The essential separation is:

> **Iroh connects identities. The orchestrator authorizes identities. Topics select interested connected peers. Each endpoint owns the queues and delivery obligations it has explicitly accepted.**

## References and verification notes

References were reviewed on September 4, 2026. They support the underlying library and protocol facts; queue policies, defaults, schemas, and release boundaries above are proposed design decisions. This document is not a security audit. The memory baseline is implemented in this crate; the optional extensions remain design guidance. Dependency versions are pinned, and independent encoding/signature fixtures are maintained in `tests/fixtures`.

- **[S1] Iroh crate documentation:** identity authentication, encrypted QUIC connectivity, and relay behavior. <https://docs.rs/iroh/latest/iroh/>
- **[S2] Iroh `Connection`:** authenticated remote identity, stream behavior, flow control, and closure semantics. <https://docs.rs/iroh/latest/iroh/endpoint/struct.Connection.html>
- **[S3] Iroh address lookup:** resolving known endpoint identities to contact information. <https://docs.iroh.computer/concepts/address-lookup>
- **[S4] Iroh endpoints:** endpoint identity and address persistence considerations. <https://docs.iroh.computer/concepts/endpoints>
- **[S5] RFC 9052, COSE:** signed containers, signature structures, and strict encoding requirements. <https://www.rfc-editor.org/rfc/rfc9052.html>
- **[S6] RFC 8032, EdDSA:** the Ed25519 signature construction. <https://www.rfc-editor.org/rfc/rfc8032.html>
- **[S7] Rust `bytes::Bytes`:** shared byte storage and owner-controlled lifetimes. <https://docs.rs/bytes/latest/bytes/struct.Bytes.html>
- **[S8] Iroh `RecvStream`:** chunked reads, framing limitations, and early-data considerations. <https://docs.rs/iroh/latest/iroh/endpoint/struct.RecvStream.html>
- **[S9] Linux circular buffers:** single-producer/single-consumer ownership and memory ordering. <https://docs.kernel.org/core-api/circular-buffers.html>
- **[S10] Iroh manifest:** reviewed runtime and transport integration dependencies. <https://github.com/n0-computer/iroh/blob/main/iroh/Cargo.toml>
- **[S11] Apache Iggy architecture:** thread-per-core design, io_uring, and buffer pooling. <https://iggy.apache.org/docs/introduction/architecture/>
- **[S12] liburing fixed-buffer writes:** registered-buffer operation semantics. <https://man7.org/linux/man-pages/man3/io_uring_prep_write_fixed.3.html>
- **[S13] Iroh `SecretKey`:** endpoint public-key and signing API. <https://docs.rs/iroh/latest/iroh/struct.SecretKey.html>
- **[S14] liburing zero-copy sends:** send notifications and buffer lifetime. <https://man7.org/linux/man-pages/man3/io_uring_prep_send_zc.3.html>
- **[S15] Linux io_uring zero-copy receive:** networking and hardware requirements. <https://docs.kernel.org/networking/iou-zcrx.html>
