//! In-process test harness: binds two `iroh` endpoints on loopback, with relaying and address
//! discovery disabled, and connects them directly to each other. This lets `Peer`/`ConnectedPeer`
//! be exercised against a real QUIC connection instead of a mock of `iroh::endpoint::Connection`
//! (whose surface is wide enough, and shared with `proto::write_control`/`read_control`, that a
//! trait abstraction would just move the mocking problem elsewhere).

use bytes::BufMut;
use ipnet::IpNet;
use iroh::endpoint::{presets, Connection, Endpoint};
use iroh::{EndpointAddr, RelayMode, SecretKey, TransportAddr};
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use crate::addr;
use crate::buffer_pool::BufferPool;
use crate::peer::{CommonPeerConfig, PeerConfig};
use crate::proto::v1::{Advertise, HostAddress};
use crate::tun::packet::{IcmpGateway, RxPacket};

/// ALPN used for test connections; arbitrary, but must match on both sides.
const TEST_ALPN: &[u8] = b"zeroconf-p2p-vpn/test/1.0";

/// One side of a directly-connected test pair: a live QUIC `Connection` plus the `SecretKey`
/// that identifies it (needed to sign `Advertise` addresses on that side). The `Endpoint` is
/// kept alive for as long as `Node` lives, since `conn` depends on it.
pub struct Node {
    pub conn: Connection,
    pub secret_key: SecretKey,
    endpoint: Endpoint,
}

impl Node {
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Closes the underlying `Endpoint`. Dropping a `Node` without calling this first still
    /// works, but logs a noisy `ERROR` since `iroh` expects an explicit close for a graceful
    /// shutdown.
    pub async fn close(self) {
        self.endpoint.close().await;
    }
}

/// Binds two local `iroh` endpoints (no relay, no discovery service) and connects them directly
/// to each other. Panics on failure, since this is test-only setup code.
pub async fn connect_pair() -> (Node, Node) {
    let key_a = SecretKey::generate();
    let key_b = SecretKey::generate();
    let ep_a = bind(key_a.clone()).await;
    let ep_b = bind(key_b.clone()).await;

    // Only offer a loopback address: `ep_b.addr()`'s automatically-discovered candidates also
    // include other local interfaces (e.g. a Docker bridge gateway) that aren't actually
    // routable back to us in this sandbox, which makes `Endpoint::connect` hang until it times
    // out.
    let b_port = ep_b
        .bound_sockets()
        .into_iter()
        .find_map(|addr| addr.is_ipv4().then_some(addr.port()))
        .expect("endpoint should have bound an IPv4 socket");
    let b_addr = EndpointAddr {
        id: ep_b.id(),
        addrs: BTreeSet::from([TransportAddr::Ip(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            b_port,
        ))]),
    };

    // Both the client's full `connect()` and the server's full `accept()` + handshake must be
    // polled concurrently in the same `join!`: the client's `connect()` future only resolves
    // once the server has driven its `Incoming` to a `Connection`, so awaiting that sequentially
    // after this `join!` would deadlock (the client would never receive a response to drive its
    // side of the handshake forward).
    let (conn_a, conn_b) = tokio::join!(ep_a.connect(b_addr, TEST_ALPN), async {
        let incoming =
            ep_b.accept().await.expect("endpoint closed while accepting a test connection");
        incoming.await.expect("incoming test connection failed")
    });
    let conn_a = conn_a.expect("outgoing test connection failed");

    (
        Node { conn: conn_a, secret_key: key_a, endpoint: ep_a },
        Node { conn: conn_b, secret_key: key_b, endpoint: ep_b },
    )
}

async fn bind(secret_key: SecretKey) -> Endpoint {
    // `presets::Minimal` sets only the mandatory crypto provider, unlike `presets::N0`, which
    // also wires up n0.computer's DNS/pkarr discovery service and would try (and time out)
    // reaching the network in a sandboxed test environment. We don't need discovery here: the
    // peer address is passed directly via `Endpoint::connect`.
    Endpoint::builder(presets::Minimal)
        .secret_key(secret_key)
        .alpns(vec![TEST_ALPN.to_vec()])
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .expect("failed to bind a local test endpoint")
}

/// Builds an `Advertise` self-signed by `secret_key`, advertising a fresh address within
/// `subnet`.
pub fn advertise_for(secret_key: &SecretKey, subnet: &IpNet) -> Advertise {
    let (net, signature) = addr::generate_signed_ipnet(subnet, secret_key);
    Advertise {
        own_addresses: vec![HostAddress {
            peer_network: net.to_string(),
            peer_network_signature: signature.to_bytes().to_vec(),
        }],
    }
}

/// A `CommonPeerConfig` for tests: same defaults as production, except a short handshake
/// timeout, so that a hung handshake fails the test quickly instead of after a full minute.
pub fn common_config(icmp_gateway: IcmpGateway) -> Arc<CommonPeerConfig> {
    let mut common = CommonPeerConfig::new(icmp_gateway);
    common.handshake_timeout = Duration::from_secs(5);
    Arc::new(common)
}

/// Convenience to build a `PeerConfig` from a harness `Node`.
pub fn peer_config(node: &Node, common: Arc<CommonPeerConfig>, advertise: Advertise) -> PeerConfig {
    PeerConfig { common, conn: node.conn.clone(), advertise }
}

/// Builds an `RxPacket` wrapping `data`, for tests that push a packet through
/// `Peer::send_packet`. `data` doesn't need to be a well-formed IP packet unless the test
/// exercises a code path (e.g. the MTU-exceeded ICMP reply) that parses it.
pub async fn rx_packet(data: &[u8]) -> RxPacket {
    let mut pool = BufferPool::new(1, data.len(), metrics::gauge!("test_rx_packet_pool"));
    let mut buffer = pool.pop().await;
    buffer.put_slice(data);
    RxPacket::new(buffer.into())
}
