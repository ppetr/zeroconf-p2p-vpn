use anyhow::{Context, Error, Result};
use bytes::Bytes;
use ipnet::IpNet;
use iroh::endpoint::{Connection, VarInt};
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
    own_net: IpNet,
}

impl CommonPeerConfig {
    pub fn new(own_net: IpNet) -> CommonPeerConfig {
        CommonPeerConfig {
            allowed_networks: vec![IpNet::V6(addr::VPN_IPV6_DEFAULT_ALLOWED)],
            handshake_timeout: Duration::from_mins(1),
            own_net,
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

    /// See `ConnectedPeer::send_packet`.
    fn send_packet(&self, packet: tun::RxPacket) -> Result<Option<tun::TxPacket>, anyhow::Error> {
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
                    self.send_disconnect(&status);
                    return Err(status);
                }
                return Ok(Some(RoutesChanged(new_routes)));
            }
            None => (),
        };
        Ok(None)
    }

    fn send_disconnect(&self, status: &ThinStatus) {
        self.config.conn.close(
            VarInt::from_u32(i32::from(status.code_raw()) as u32),
            status.message().as_bytes(),
        )
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

    /// Send a packet to the peer. If the packet is too large, an ICMP response packet is returned
    /// to the caller instead.
    ///
    /// This method is synchronous: If the Quinn connection can't handle the packet, a
    /// corresponding ICMP packet is returned instead (or dropped, if the sender doesn't support
    /// it).
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
