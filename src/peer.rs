use anyhow::{Context, Error, Result};
use bytes::Bytes;
use ipnet::IpNet;
use iroh::endpoint::{Connection, VarInt};
use iroh::PublicKey;
use metrics::*;
use secure_p2p_transport::wait_for_direct;
use std::fmt::Write;
use std::sync::Arc;
use std::time::Duration;
use thin_status::{ErrorCode, ThinStatus};
use tokio::sync::mpsc;
use tokio::time::timeout;

mod conn_metrics;
mod validate_addr;

use crate::addr;
use crate::buffer_pool::PooledSlice;
use crate::error::ExtractedErrorCode;
use crate::proto;
use crate::proto::v1::control_request;
use crate::proto::v1::ControlRequest;
use crate::route;
use crate::route::ecn;
use crate::tun::packet as tun;

#[derive(Clone)]
pub struct CommonPeerConfig {
    pub allowed_networks: Vec<IpNet>,
    pub handshake_timeout: Duration,
    pub route_table: route::NetRouteHandle,
    own_net: IpNet,
}

impl CommonPeerConfig {
    pub fn new(route_table: route::NetRouteHandle, own_net: IpNet) -> CommonPeerConfig {
        CommonPeerConfig {
            allowed_networks: vec![IpNet::V6(addr::VPN_IPV6_DEFAULT_ALLOWED)],
            handshake_timeout: Duration::from_mins(1),
            route_table: route_table,
            own_net,
        }
    }
}

#[derive(Clone)]
pub struct PeerConfig {
    pub common: Arc<CommonPeerConfig>,
    pub conn: Connection,
    pub advertise: proto::v1::Advertise,
}

// TODO: Refactor into the actor pattern other components are using (`communicate` should consume
// `self` and create a clonable, async handle).
#[derive(Clone)]
pub struct Peer {
    config: PeerConfig,
    icmp_gateway: tun::IcmpGateway,
    max_send_buffer_space: f32,
}

impl Peer {
    const ECN_THRESHOLD: f32 = 0.5;

    pub fn new(config: PeerConfig) -> Self {
        let icmp_gateway = tun::IcmpGateway::from_addr(config.common.own_net.addr());
        let max_send_buffer_space = config.conn.datagram_send_buffer_space() as f32;
        Peer {
            config,
            icmp_gateway,
            max_send_buffer_space,
        }
    }

    pub fn public_key(&self) -> PublicKey {
        self.config.conn.remote_id()
    }

    pub async fn communicate(
        &mut self,
        rx_packet: &mut mpsc::Receiver<tun::RxPacket>,
        tx_packet: mpsc::Sender<tun::TxPacket>,
    ) -> Result<()> {
        let routes = self.handshake().await?;
        // Main loop. -------
        tracing::info!(
            peer = self.public_key().to_z32(),
            "Handshake successfully completed"
        );
        counter!(description: "Successful handshakes", "p2p_vpn_peer_handshakes").increment(1);

        // This is fine if the number of peers is low. Should there be a lot (hundreds or
        // thousands), then having too high cardinality of this metric could start to be
        // problematic.
        let quin_metrics = conn_metrics::QuinnMetrics::new(vec![metrics::Label::new(
            "peer",
            self.public_key().to_z32(),
        )])
        .spawn_exporter(self.config.conn.clone(), Duration::from_secs(5));

        let control = self.recv_control_loop(routes);
        let send = async {
            while let Some(packet) = rx_packet.recv().await {
                // TODO: Process/record the error part of the result.
                if let Ok(Some(icmp_packet)) = self.recv_packet(packet) {
                    // TODO: Process/record the error part of the result.
                    let _ = tx_packet.send(icmp_packet).await;
                }
            }
        };
        let recv = async {
            Ok::<(), Error>(loop {
                let bytes = self.config.conn.read_datagram().await?;
                tx_packet.send(tun::TxPacket::new(bytes)).await?;
            })
        };
        tokio::select! {
            r = control => r?,
            r = send => r,
            r = recv => r?,
        };
        quin_metrics.abort();
        Ok(())
    }

    /// Send a packet to the peer. If the packet is too large, an ICMP response packet is returned
    /// instead.
    pub fn recv_packet(
        &self,
        packet: tun::RxPacket,
    ) -> Result<Option<tun::TxPacket>, anyhow::Error> {
        // TODO: Check networks etc.
        // Check the datagram size; if it's larger than the QUIC limit, attempt to negotiate it.
        if let Some(mtu) = self.config.conn.max_datagram_size() {
            if (&packet).len() > mtu {
                let mtu = std::cmp::min(mtu, u16::MAX as usize) as u16;
                let mut buf = bytes::BytesMut::with_capacity(128);
                match self.icmp_gateway.generate_reply(
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

    /// Returns the set of routes to be passed to the `recv_control_loop`.
    async fn handshake(&self) -> Result<Vec<route::ScopedRoute>> {
        wait_for_direct(&self.config.conn).await?;
        let handshake = async {
            let send = self.send_advertise();
            let mut routes = Vec::new();
            let receive = self.recv_control(&mut routes);
            let (send, receive) = tokio::join!(send, receive);
            send?;
            receive?;
            Ok::<_, Error>(routes)
        };
        let (handshake,) = tokio::join!(timeout(self.config.common.handshake_timeout, handshake));
        handshake.context(format!(
            "Failed to finish handshake within the deadline {:?}",
            self.config.common.handshake_timeout
        ))?
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
    async fn recv_control(&self, routes: &mut Vec<route::ScopedRoute>) -> Result<()> {
        let _span = tracing::debug_span!(
            "recv_control",
            peer = self.public_key().to_z32(),
            "Receiving ControlRequest"
        );
        counter!(description: "Received v1::ControlRequest messages",
                 "p2p_vpn_peer_recv_control_message")
        .increment(1);
        Ok(proto::read_control(&self.config.conn, async |r| {
            self.handle_control_request(&r, routes).await
        })
        .await?)
    }

    /// Returns an error iff the connection should be disconnected.
    async fn handle_control_request(
        &self,
        request: &ControlRequest,
        routes: &mut Vec<route::ScopedRoute>,
    ) -> Result<(), ThinStatus> {
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
                let common = &self.config.common;
                routes.clear();
                for a in addrs {
                    let routing = common.route_table.clone();
                    let scoped = route::ScopedRoute::new(routing, a.addr()).await?;
                    routes.push(scoped);
                }
            }
            None => (),
        };
        if routes.is_empty() {
            let mut status = ThinStatus::builder(ErrorCode::FailedPrecondition);
            let _ = write!(status, "No available routes to the peer; {:?}", addr_errors);
            let status = status.build();
            self.send_disconnect(&status);
            return Err(status);
        }
        Ok(())
    }

    async fn recv_control_loop(&self, mut routes: Vec<route::ScopedRoute>) -> Result<()> {
        loop {
            self.recv_control(&mut routes).await?;
        }
    }

    fn send_disconnect(&self, status: &ThinStatus) {
        self.config.conn.close(
            VarInt::from_u32(i32::from(status.code_raw()) as u32),
            status.message().as_bytes(),
        )
    }
}
