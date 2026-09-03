use anyhow::{Context, Error, Result};
use bytes::Bytes;
use ipnet::IpNet;
use iroh::endpoint::Connection;
use iroh::PublicKey;
use metrics::*;
use secure_p2p_transport::wait_for_direct;
use std::fmt::Write;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use thin_status::{ErrorCode, ThinStatus};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

mod conn_metrics;
#[cfg(test)]
pub(crate) mod test_util;
mod validate_addr;

use crate::addr;
use crate::buffer_pool::PooledSlice;
use crate::error::ExtractedErrorCode;
use crate::proto;
use crate::proto::v1::control_request;
use crate::proto::v1::ControlRequest;
use crate::route::ecn;
use crate::tun::packet as tun;

#[derive(Clone, Debug)]
pub struct CommonPeerConfig {
    pub allowed_networks: Vec<IpNet>,
    pub handshake_timeout: Duration,
    pub icmp_gateway: tun::IcmpGateway,
}

impl CommonPeerConfig {
    pub fn new(icmp_gateway: tun::IcmpGateway) -> CommonPeerConfig {
        CommonPeerConfig {
            allowed_networks: vec![IpNet::V6(addr::VPN_IPV6_DEFAULT_ALLOWED)],
            handshake_timeout: Duration::from_mins(1),
            icmp_gateway,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PeerConfig {
    pub common: Arc<CommonPeerConfig>,
    pub conn: Connection,
    pub advertise: proto::v1::Advertise,
}

#[derive(Clone, Debug)]
pub struct RoutesChanged(pub Vec<IpAddr>);

#[derive(Clone, Debug)]
pub struct Peer {
    config: PeerConfig,
    max_send_buffer_space: f32,
}

impl Peer {
    const ECN_THRESHOLD: f32 = 0.5;

    pub fn new(config: PeerConfig) -> Self {
        let max_send_buffer_space = config.conn.datagram_send_buffer_space() as f32;
        Peer {
            config,
            max_send_buffer_space,
        }
    }

    pub fn public_key(&self) -> PublicKey {
        self.config.conn.remote_id()
    }

    /// Send a packet to the peer over the QUIC connection.
    ///
    /// Synchronous and non-blocking: if the packet exceeds the connection's datagram MTU, or the
    /// datagram send buffer is under enough backpressure that the ECN/AQM logic drops it, an ICMP
    /// reply for the caller is returned instead (or `None` if none could be built).
    fn send_packet(&self, packet: tun::RxPacket) -> Result<Option<tun::TxPacket>, anyhow::Error> {
        // TODO: Check networks etc.
        // Check the datagram size; if it's larger than the QUIC limit, attempt to negotiate it.
        if let Some(mtu) = self.config.conn.max_datagram_size() {
            if (&packet).len() > mtu {
                let mtu = std::cmp::min(mtu, u16::MAX as usize) as u16;
                let mut buf = bytes::BytesMut::with_capacity(128);
                match self.config.common.icmp_gateway.generate_reply(
                    &mut buf,
                    &packet,
                    tun::IcmpType::packet_too_big(mtu),
                ) {
                    Ok(addr) => {
                        let buf = tun::TxPacket::new(buf.freeze());
                        tracing::debug!(packet = ?buf, "Sending ICMP packet to reduce MTU to {}", mtu);
                        histogram!(description: "ICMP packets to reduce MTU",
                            unit: metrics::Unit::Bytes,
                            "p2p_vpn_peer_icmp_mtu",
                            "ip" => if addr.is_ipv6() { "v6" } else { "v4" },
                        )
                        .record(mtu);
                        return Ok(Some(buf));
                    }
                    Err(err) => {
                        tracing::warn!(error = ?err, key = self.public_key().to_z32());
                        histogram!(description: "Errors when generating ICMP packets to reduce MTU",
                            "p2p_vpn_peer_icmp_mtu_errors", ExtractedErrorCode::from_anyhow(&err)).record(mtu);
                    }
                }
                return Ok(None);
            }
        }

        let populated_at = packet.populated_at;
        let mut packet = packet.data.to_buffer();
        // Check the output queue size and drop packets progressively.
        let fullness =
            1.0 - self.config.conn.datagram_send_buffer_space() as f32 / self.max_send_buffer_space;
        if !ecn::linear_aqm(Self::ECN_THRESHOLD, fullness) {
            if ecn::process_packet_congestion(&mut packet) == ecn::PacketAction::Drop {
                // TODO: Record this state with a metric.
                return Ok(None);
            }
        }

        let result = self
            .config
            .conn
            .send_datagram(Bytes::from_owner(PooledSlice::from(packet)));
        // TODO: Record the Result in the metric.
        histogram!(description: "Total time processing a packet TUN->QUIC (ms)",
                   unit: metrics::Unit::Milliseconds,
                   "p2p_vpn_tun_to_quic")
        .record(tun::elapsed_millis(populated_at));
        // TODO: Assing `ErrorCode` instead of wrapping in `AnyHow` based on the error.
        result?;
        Ok(None)
    }

    /// Returns the set of routes negotiated as part of the handshake.
    pub async fn handshake(self) -> Result<(ConnectedPeer, RoutesChanged)> {
        wait_for_direct(&self.config.conn).await?;
        let handshake = async {
            let send = self.send_advertise();
            let receive = self.recv_control();
            let (send, receive) = tokio::join!(send, receive);
            send?;
            Ok::<_, Error>(receive?)
        };
        let (handshake,) = tokio::join!(timeout(self.config.common.handshake_timeout, handshake));
        let handshake = handshake.context(format!(
            "Failed to finish handshake within the deadline {:?}",
            self.config.common.handshake_timeout
        ))??;
        let routes = match handshake {
            Some(routes) => routes,
            None => anyhow::bail!("Handshake returned no routes"),
        };
        // TODO: Track also unsuccessful handshakes.
        tracing::info!(
            peer = self.public_key().to_z32(),
            "Handshake successfully completed"
        );
        counter!(description: "Successful handshakes", "p2p_vpn_peer_handshakes").increment(1);
        Ok((ConnectedPeer { peer: self }, routes))
    }

    /// Sends an Advertise handshake.
    async fn send_advertise(&self) -> Result<()> {
        let cmd = control_request::Command::Advertise(self.config.advertise.clone());
        let _span = tracing::debug_span!(
            "send_advertise",
            peer = self.public_key().to_z32(),
            "Sending Command::Advertise {:?}",
            cmd
        );
        let control = ControlRequest {
            command: Some(cmd),
            ..Default::default()
        };
        Ok(proto::control_to_status(
            proto::write_control(&self.config.conn, &control).await?,
        )?)
    }

    /// Waits for a single control message and processes it.
    ///
    /// Returns an error if as the result the connection is closed.
    async fn recv_control(&self) -> Result<Option<RoutesChanged>> {
        let _span = tracing::debug_span!(
            "recv_control",
            peer = self.public_key().to_z32(),
            "Receiving ControlRequest"
        );
        counter!(description: "Received v1::ControlRequest messages",
                 "p2p_vpn_peer_recv_control_message")
        .increment(1);
        let routes = proto::read_control(&self.config.conn, async |r| {
            self.handle_control_request(&r).await
        })
        .await?;
        Ok(routes)
    }

    /// Returns an error iff the connection should be disconnected.
    async fn handle_control_request(
        &self,
        request: &ControlRequest,
    ) -> Result<Option<RoutesChanged>, ThinStatus> {
        let mut addr_errors = Vec::new();
        match &request.command {
            Some(control_request::Command::Advertise(a)) => {
                let (addrs, errors) = validate_addr::validate_addresses(
                    &self.config.common.allowed_networks,
                    &a,
                    &self.public_key(),
                );
                if !errors.is_empty() {
                    tracing::info!(peer = self.public_key().to_z32(), errors = ?errors, "Errors parsing peer addresses");
                    addr_errors = errors;
                }
                let mut new_routes = Vec::new();
                new_routes.reserve(addrs.len());
                for a in addrs {
                    new_routes.push(a.addr());
                }
                if new_routes.is_empty() {
                    let mut status = ThinStatus::builder(ErrorCode::FailedPrecondition);
                    let _ = write!(status, "No available routes to the peer; {:?}", addr_errors);
                    let status = status.build();
                    proto::close_connection(&self.config.conn, &status);
                    return Err(status);
                }
                return Ok(Some(RoutesChanged(new_routes)));
            }
            None => (),
        };
        Ok(None)
    }
}

#[derive(Clone, Debug)]
pub struct ConnectedPeer {
    peer: Peer,
}

impl ConnectedPeer {
    pub fn public_key(&self) -> PublicKey {
        self.peer.public_key()
    }

    /// Receive packets from this peer and pass them to `tx_packet`.
    pub async fn recv_loop(&mut self, tx_packet: mpsc::Sender<tun::TxPacket>) -> Result<()> {
        let cancel = CancellationToken::new();
        // This is fine if the number of peers is low. Should there be a lot (hundreds or
        // thousands), then having too high cardinality of this metric could start to be
        // problematic.
        let _quinn_metrics = conn_metrics::QuinnMetrics::new(vec![metrics::Label::new(
            "peer",
            self.public_key().to_z32(),
        )])
        .spawn_exporter(
            self.peer.config.conn.clone(),
            Duration::from_secs(5),
            cancel.clone(),
        );
        let _drop_guard = cancel.drop_guard();

        loop {
            let bytes = self.peer.config.conn.read_datagram().await?;
            tx_packet.send(tun::TxPacket::new(bytes)).await?;
        }
    }

    /// See [`Peer::send_packet`].
    pub fn send_packet(
        &self,
        packet: tun::RxPacket,
    ) -> Result<Option<tun::TxPacket>, anyhow::Error> {
        self.peer.send_packet(packet)
    }

    /// Processes control messages until one that updates routing is received.
    pub async fn recv_control_loop(&self) -> Result<RoutesChanged> {
        loop {
            match self.peer.recv_control().await? {
                Some(routes) => return Ok(routes),
                None => (),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::endpoint::VarInt;

    #[tokio::test]
    async fn handshake_exchanges_routes() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_test_writer()
            .try_init();
        let (node_a, node_b) = test_util::connect_pair().await;
        let common = test_util::common_config(tun::IcmpGateway::default());

        let subnet = IpNet::V6(addr::vpn_subnet(0));
        let advertise_a = test_util::advertise_for(&node_a.secret_key, &subnet);
        let advertise_b = test_util::advertise_for(&node_b.secret_key, &subnet);

        let peer_a = Peer::new(test_util::peer_config(&node_a, common.clone(), advertise_a));
        let peer_b = Peer::new(test_util::peer_config(&node_b, common, advertise_b));

        let (result_a, result_b) = tokio::join!(peer_a.handshake(), peer_b.handshake());
        let (connected_a, routes_a) = result_a.expect("A's handshake should succeed");
        let (connected_b, routes_b) = result_b.expect("B's handshake should succeed");

        assert_eq!(connected_a.public_key(), node_b.secret_key.public());
        assert_eq!(connected_b.public_key(), node_a.secret_key.public());
        assert_eq!(routes_a.0.len(), 1);
        assert_eq!(routes_b.0.len(), 1);

        node_a.close().await;
        node_b.close().await;
    }

    #[tokio::test]
    async fn handshake_rejects_address_outside_allowed_networks() {
        let (node_a, node_b) = test_util::connect_pair().await;
        let common = test_util::common_config(tun::IcmpGateway::default());

        // A advertises an IPv4 address, which falls outside B's (default) IPv6-only
        // `allowed_networks`, so B must reject the handshake.
        let disallowed_subnet: IpNet = "10.0.0.0/24".parse().unwrap();
        let advertise_a = test_util::advertise_for(&node_a.secret_key, &disallowed_subnet);
        let advertise_b =
            test_util::advertise_for(&node_b.secret_key, &IpNet::V6(addr::vpn_subnet(0)));

        let peer_a = Peer::new(test_util::peer_config(&node_a, common.clone(), advertise_a));
        let peer_b = Peer::new(test_util::peer_config(&node_b, common, advertise_b));

        let (result_a, result_b) = tokio::join!(peer_a.handshake(), peer_b.handshake());

        // B rejects A's advertise and closes the connection with a `ControlResponse` carrying
        // the failure status; A observes that failure when reading the response to its own
        // `send_advertise`, so BOTH sides' `handshake()` fail here, even though only A's address
        // was invalid.
        assert!(result_a.is_err(), "A's handshake should fail: {result_a:?}");
        assert!(result_b.is_err(), "B's handshake should fail: {result_b:?}");

        node_a.close().await;
        node_b.close().await;
    }

    #[tokio::test]
    async fn handshake_fails_if_connection_closes_mid_handshake() {
        let (node_a, node_b) = test_util::connect_pair().await;
        let common = test_util::common_config(tun::IcmpGateway::default());

        let subnet = IpNet::V6(addr::vpn_subnet(0));
        let advertise_b = test_util::advertise_for(&node_b.secret_key, &subnet);
        let peer_b = Peer::new(test_util::peer_config(&node_b, common, advertise_b));

        // Close A's side instead of running its handshake, simulating a peer that disconnects
        // mid-handshake. B's `handshake()` must fail promptly, not hang until its own timeout.
        node_a
            .conn
            .close(VarInt::from_u32(0), b"simulated disconnect");

        let started = std::time::Instant::now();
        let result = peer_b.handshake().await;
        assert!(result.is_err(), "B's handshake should fail: {result:?}");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "B's handshake should fail promptly on connection close, not wait out its own timeout"
        );

        node_a.close().await;
        node_b.close().await;
    }

    #[tokio::test]
    async fn handshake_times_out_if_peer_never_responds() {
        let (node_a, node_b) = test_util::connect_pair().await;

        // A deliberately short deadline: this test waits out the whole `handshake_timeout`, so a
        // 5s deadline (like `test_util::common_config` uses elsewhere) would make it slow. If
        // this turns out flaky under load in CI, mark it `#[ignore]` with an explanation instead
        // of just raising the deadline back up.
        let short_timeout = Duration::from_millis(200);
        let mut common = CommonPeerConfig::new(tun::IcmpGateway::default());
        common.handshake_timeout = short_timeout;

        let subnet = IpNet::V6(addr::vpn_subnet(0));
        let advertise_b = test_util::advertise_for(&node_b.secret_key, &subnet);
        let peer_b = Peer::new(test_util::peer_config(
            &node_b,
            Arc::new(common),
            advertise_b,
        ));

        // A never runs its own handshake (never sends an `Advertise` or responds to B's), but
        // its connection stays open — unlike `handshake_fails_if_connection_closes_mid_handshake`,
        // this exercises the deadline itself rather than an immediate connection-closed error.
        let started = std::time::Instant::now();
        let result = peer_b.handshake().await;
        let elapsed = started.elapsed();

        assert!(result.is_err(), "B's handshake should fail: {result:?}");
        assert!(
            elapsed >= short_timeout,
            "should wait out the full handshake_timeout, took {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "should fail close to the configured handshake_timeout, took {elapsed:?}"
        );

        node_a.close().await;
        node_b.close().await;
    }

    #[tokio::test]
    async fn send_packet_delivers_datagram_end_to_end() {
        let (node_a, node_b) = test_util::connect_pair().await;
        let common = test_util::common_config(tun::IcmpGateway::default());

        let subnet = IpNet::V6(addr::vpn_subnet(0));
        let advertise_a = test_util::advertise_for(&node_a.secret_key, &subnet);
        let advertise_b = test_util::advertise_for(&node_b.secret_key, &subnet);

        let peer_a = Peer::new(test_util::peer_config(&node_a, common.clone(), advertise_a));
        let peer_b = Peer::new(test_util::peer_config(&node_b, common, advertise_b));

        let (result_a, result_b) = tokio::join!(peer_a.handshake(), peer_b.handshake());
        let (connected_a, _) = result_a.expect("A's handshake should succeed");
        let (mut connected_b, _) = result_b.expect("B's handshake should succeed");

        let (tx, mut rx) = mpsc::channel(1);
        tokio::spawn(async move {
            let _ = connected_b.recv_loop(tx).await;
        });

        let payload = b"hello over quic";
        let packet = test_util::rx_packet(payload).await;
        let icmp_reply = connected_a
            .send_packet(packet)
            .expect("send_packet should succeed for a packet under the connection's MTU");
        assert!(
            icmp_reply.is_none(),
            "a packet under the MTU shouldn't trigger an ICMP reply"
        );

        let received = timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("B should receive A's datagram before the test timeout")
            .expect("the recv_loop channel shouldn't close");
        assert_eq!(&received.data[..], payload);

        node_a.close().await;
        node_b.close().await;
    }

    #[tokio::test]
    async fn recv_control_loop_returns_updated_routes() {
        let (node_a, node_b) = test_util::connect_pair().await;
        let common = test_util::common_config(tun::IcmpGateway::default());

        let subnet = IpNet::V6(addr::vpn_subnet(0));
        let advertise_a = test_util::advertise_for(&node_a.secret_key, &subnet);
        let advertise_b = test_util::advertise_for(&node_b.secret_key, &subnet);

        let peer_a = Peer::new(test_util::peer_config(&node_a, common.clone(), advertise_a));
        let peer_b = Peer::new(test_util::peer_config(&node_b, common, advertise_b));

        let (result_a, result_b) = tokio::join!(peer_a.handshake(), peer_b.handshake());
        let (connected_a, _) = result_a.expect("A's handshake should succeed");
        let (connected_b, _) = result_b.expect("B's handshake should succeed");

        // Simulate A re-advertising after the initial handshake (e.g. following a config
        // change): send a second `Advertise` on a fresh stream, independent of the one used
        // during the handshake, and confirm `recv_control_loop` picks it up.
        let (send_result, recv_result) = tokio::join!(
            connected_a.peer.send_advertise(),
            connected_b.recv_control_loop(),
        );
        send_result.expect("A's second advertise should send successfully");
        let routes = recv_result.expect("B's recv_control_loop should return the updated routes");
        assert_eq!(routes.0.len(), 1);

        node_a.close().await;
        node_b.close().await;
    }
}
