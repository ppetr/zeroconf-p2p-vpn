# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

- Build: `cargo build` (release: `cargo build --release`)
- Format: `cargo fmt` (config in `.rustfmt.toml`; don't pass `-- --edition=...`, cargo already does). The "can't set `wrap_comments`" warning on stable is expected. Check with `cargo fmt --check`; run it before every commit so formatting never needs a separate cleanup.
- Cross-compiled release binaries (Docker, into `dist/`): `docker/cross/build.sh <target-triple>` or `docker/cross/release-all.sh`, run from the repo root.
- Version control is `jj` colocated with git (`.jj` and `.git` both present); finish work with `jj new`.
- Run all tests: `cargo test`
- Run a single test: `cargo test <test_name>` (e.g. `cargo test test_insert_and_get_single_ip`)
- Run tests in one module: `cargo test relay::tests::`
- Two-node Docker integration test (from `docker/`): `cargo build` at the repo root first, then `docker compose up --build`; the scripted end-to-end test is `docker/integration-test.sh` (a `bats` script that brings up `node-alice`/`node-bob` containers and streams 100MB between them over the VPN).

Note: `.cargo/config.toml` sets `-C target-cpu=x86-64-v3` for Linux/macOS x86_64 builds, so binaries built here are not portable to older CPUs.

## Architecture

This is a zero-config, peer-to-peer VPN daemon (see `README.rst` for the design rationale). There is no central server: two peers connect directly over QUIC (via the `iroh` crate) once they know each other's Ed25519 public key, and each side deterministically derives its own VPN IP address from that key. The daemon only ever talks to the single peer it was started with — there's no generic mesh relaying of other peers' traffic.

Treat `README.rst`'s "Architecture plan" section as an aspirational roadmap, not a spec of the current code — some details there (e.g. raw `rtnetlink`, `quinn` directly, OTLP telemetry) differ from what's actually implemented (`net-route` crate, `iroh`, plain `tracing`/Prometheus).

`main.rs` wires everything together and drives three concurrent async loops via `tokio::join!`:
1. **`tun_loop`** (`Tun::control`) — reads/writes raw IP packets from/to the TUN device using a preallocated buffer pool.
2. **`connect_loop`** — waits for a connection on the `PeerLink`, performs the `Peer::handshake` (exchanging `Advertise` control messages), registers the peer's advertised routes with `Relay::insert`, then runs `ConnectedPeer::recv_loop` to pump inbound QUIC datagrams to the TUN write side.
3. **`tun_rx_loop`** — for each packet read from TUN, looks up the destination IP in `Relay`, hands it to the matching peer's `send_packet`, and otherwise (or on send failure) synthesizes an ICMP unreachable/too-big reply via `IcmpGateway`.

Key modules:

- **`connection/`** — a reusable, protocol-agnostic single-peer reconnection state machine, generic over a `ManagedConnection` trait:
  - `actor.rs` (`Actor`) owns the one currently-active connection in a `watch` channel. Direction preference (`Incoming` vs `Outgoing`) is decided deterministically by comparing the two peers' keys, so both sides converge on the same connection without extra negotiation.
  - `connect.rs` (`OutgoingConnectLoop`) retries outgoing connects with exponential backoff whenever no connection is active, submitting successes into the `Actor`.
  - `iroh.rs` adapts `iroh::endpoint::Connection` to `ManagedConnection`.
  - `peer.rs` (`PeerLink`/`PeerLinkHandle`) composes the above for one specific remote peer and also exposes an `IncomingReceiver` for connections accepted by the global Iroh listener in `main.rs`.
- **`peer.rs`** (`Peer`/`ConnectedPeer`) — per-connection protocol logic: the handshake (send/receive `Advertise`), datagram send/receive, MTU-exceeded ICMP replies, and ECN-based congestion handling (`route::ecn`) that marks or drops outgoing packets under QUIC send-buffer backpressure instead of queueing unboundedly.
- **`relay.rs`** (`Relay<T, R>`) — a `DashMap<IpAddr, Peer>` that is the dispatch table used by `tun_rx_loop`. Inserting/removing a peer's IP transactionally adds/removes a real kernel route via a `ScopedRoute` (`route.rs`), so the map and the OS routing table stay in sync; a failed route insert rolls back the whole batch.
- **`route.rs`** — `RoutingTable` trait, `NetRouteHandle` (real implementation via the `net_route` crate), and `ScopedRoute`, an RAII guard that removes its route on drop.
- **`addr.rs`** — deterministic, verifiable IPv6 address generation: an address is derived from an Ed25519 signature over the target subnet, within the fixed ULA prefix `fdbd:a6ce:654d::/48`. This is the mechanism that lets peers self-assign non-colliding addresses without a central allocator; `verify_signed_ipnet` is used to validate addresses peers advertise.
- **`tun.rs` / `tun/packet.rs`** — TUN device wrapper (`tun_rs`) and packet types (`RxPacket`/`TxPacket`); `IcmpGateway` builds ICMPv4/v6 error replies (unreachable, packet-too-big).
- **`buffer_pool.rs`** — fixed-size pool of reusable byte buffers for TUN reads, to avoid per-packet allocation.
- **`proto.rs`** — the control-plane protocol: `ControlRequest`/`ControlResponse` messages (defined in `proto/p2p_vpn/control/v1/control.proto`, compiled by `build.rs` via `prost-build`) exchanged over a QUIC bidirectional stream, currently used for the `Advertise` handshake.
- **`error.rs`** — `ExtractedErrorCode` normalizes `std::io::Error` / `anyhow::Error` / `thin_status::ThinStatus` into consistent Prometheus metric label pairs (`ERROR_CODE`/`ERROR_KIND`); also has loop/task shutdown helpers that treat `Cancelled` as a non-error.
- **`osal/`** — OS abstraction layer; currently just Linux/libc errno classification for retryable TUN I/O errors.

Build info: `build.rs` embeds the git revision and `git describe` output (`-modified` suffix = dirty tree); `build_info.rs` exposes them via the `p2p_vpn_build_info` metric, the startup log line and `--version`. Builds without a usable `.git` (e.g. in Docker) pass `ZEROCONF_GIT_REV` / `ZEROCONF_GIT_DESCRIBE` instead; `docker/cross/build.sh` does this.

Observability: `tracing` (`RUST_LOG` env var) for logs, `metrics` + `metrics-exporter-prometheus` for a Prometheus endpoint. Most modules record both.

## Possible future direction (not MVP)

`ConnectedPeer::recv_control_loop` already lets a peer receive a follow-up `Advertise` after the
initial handshake, on top of the same, already-open `Connection` (exercised by
`peer::tests::recv_control_loop_returns_updated_routes`). This could eventually be used to
renegotiate a node's advertised routes when its local configuration changes, without dropping and
reopening the underlying QUIC connection (which may be comparatively expensive to (re-)establish).
Nothing currently calls `send_advertise` a second time or drives `recv_control_loop` outside of
tests — `main.rs`'s `connect_loop` only performs the initial handshake. This is intentionally out
of scope for the MVP.
