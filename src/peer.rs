use anyhow::{Context, Error, Result};
use bytes::Bytes;
use ipnet::IpNet;
use iroh::endpoint::{Connection, VarInt};
use iroh::PublicKey;
use metrics::*;
use secure_p2p_transport::wait_for_direct;
use std::sync::Arc;
use std::time::Duration;
use thin_status::{ErrorCode, ThinStatus};
use tokio::sync::mpsc;
use tokio::time::timeout;

mod validate_addr;

use crate::addr;
use crate::error::ExtractedErrorCode;
use crate::proto;
use crate::proto::v1::control;
use crate::proto::v1::{Control, Disconnect, Status};
use crate::route;
use crate::tun::packet as tun;

pub struct CommonPeerConfig {
    pub allowed_networks: Vec<IpNet>,
    pub handshake_timeout: Duration,
    pub route_table: Arc<net_route::Handle>,
    /// `if_index`: The system index of the TUN interface for adding/removing routes.
    tun_if_index: u32,
    own_net: IpNet,
}

impl CommonPeerConfig {
    pub fn new(
        route_table: Arc<net_route::Handle>,
        tun_if_index: u32,
        own_net: IpNet,
    ) -> CommonPeerConfig {
        CommonPeerConfig {
            allowed_networks: vec![IpNet::V6(addr::VPN_IPV6_DEFAULT_ALLOWED)],
            handshake_timeout: Duration::from_mins(1),
            route_table: route_table,
            tun_if_index,
            own_net,
        }
    }
}

pub struct PeerConfig {
    pub common: Arc<CommonPeerConfig>,
    pub conn: Connection,
    pub advertise: proto::v1::Advertise,
}

pub struct Peer {
    config: PeerConfig,
}

impl Peer {
    pub fn new(config: PeerConfig) -> Self {
        Peer { config }
    }

    pub fn public_key(&self) -> PublicKey {
        self.config.conn.remote_id()
    }

    pub async fn communicate(
        &mut self,
        mut rx_packet: mpsc::Receiver<tun::RxPacket>,
        tx_packet: mpsc::Sender<tun::TxPacket>,
    ) -> Result<()> {
        let routes = self.handshake().await?;
        // Main loop. -------
        tracing::info!(
            peer = self.public_key().to_z32(),
            "Handshake successfully completed"
        );
        counter!(description: "Successful handshakes", "p2p_vpn_peer_handshakes").increment(1);
        let control = self.recv_control_loop(routes);
        let send = async {
            let icmp_gateway = tun::IcmpGateway::from_addr(self.config.common.own_net.addr());

            while let Some(packet) = rx_packet.recv().await {
                // TODO: Check networks etc.
                if let Some(mtu) = self.config.conn.max_datagram_size() {
                    if (&packet).len() > mtu {
                        let mtu = std::cmp::min(mtu, u16::MAX as usize) as u16;
                        let mut buf = bytes::BytesMut::with_capacity(128);
                        match icmp_gateway.generate_reply(
                            &mut buf,
                            &packet,
                            tun::IcmpType::packet_too_big(mtu),
                        ) {
                            Ok(addr) => {
                                let buf = tun::TxPacket { data: buf.freeze() };
                                tracing::debug!(packet = ?buf, "Sending ICMP packet to reduce MTU to {}", mtu);
                                histogram!(description: "ICMP packets to reduce MTU",
                                    unit: metrics::Unit::Bytes,
                                    "p2p_vpn_peer_icmp_mtu",
                                    "ip" => if addr.is_ipv6() { "v6" } else { "v4" },
                                )
                                .record(mtu);
                                let _ = tx_packet.send(buf).await;
                            }
                            Err(err) => {
                                tracing::warn!(error = ?err, key = self.public_key().to_z32());
                                histogram!(description: "Errors when generating ICMP packets to reduce MTU",
                                    "p2p_vpn_peer_icmp_mtu_errors", ExtractedErrorCode::from_anyhow(&err)).record(mtu);
                            }
                        }
                        continue;
                    }
                }
                // TODO: Deal with Result
                let _ = self
                    .config
                    .conn
                    .send_datagram_wait(Bytes::from_owner(packet.data))
                    .await;
            }
        };
        let recv = async {
            Ok::<(), Error>(loop {
                let bytes = self.config.conn.read_datagram().await?;
                tx_packet.send(tun::TxPacket { data: bytes }).await?;
            })
        };
        tokio::select! {
            r = control => r?,
            r = send => r,
            r = recv => r?,
        };
        Ok(())
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
        let cmd = control::Command::Advertise(self.config.advertise.clone());
        tracing::debug_span!(
            "send_advertise",
            peer = self.public_key().to_z32(),
            "Sending Command::Advertise {:?}",
            cmd
        );
        let control = Control {
            command: Some(cmd),
            ..Default::default()
        };
        proto::write_control(&self.config.conn, &control).await
    }

    /// Waits for a single control message and processes it.
    ///
    /// Returns an error if as the result the connection is closed.
    async fn recv_control(&self, routes: &mut Vec<route::ScopedRoute>) -> Result<()> {
        tracing::debug_span!(
            "recv_control",
            peer = self.public_key().to_z32(),
            "Receiving control command"
        );
        counter!(description: "Received v1::Control messages",
                 "p2p_vpn_peer_recv_control_message")
        .increment(1);
        let control = proto::read_control(&self.config.conn).await;
        // Ignore malformed messages.
        let control = match control {
            Err(e) => {
                tracing::info!(
                    error = ?e,
                    "Received a malformed message from the peer, ignoring"
                );
                counter!(description: "Received malformed v1::Control messages",
                    "p2p_vpn_peer_recv_control_message_errors", ExtractedErrorCode::from_anyhow(&e))
                .increment(1);
                return Ok(());
            }
            Ok(c) => c,
        };
        match control.command {
            Some(control::Command::Advertise(a)) => {
                let (addrs, errors) = validate_addr::validate_addresses(
                    &self.config.common.allowed_networks,
                    &a,
                    &self.public_key(),
                );
                if !errors.is_empty() {
                    tracing::info!(peer = self.public_key().to_z32(), errors = ?errors, "Errors parsing peer addresses");
                }
                let common = &self.config.common;
                routes.clear();
                for a in addrs {
                    let routing = common.route_table.clone();
                    let scoped =
                        route::ScopedRoute::new(routing, common.tun_if_index, a.addr()).await?;
                    routes.push(scoped);
                }
            }
            Some(control::Command::Disconnect(_)) => {
                self.config
                    .conn
                    .close(VarInt::from_u32(0), b"Requested disconnect");
                anyhow::bail!("Peer requested Disconnect: {:?}", control);
            }
            None => (),
        };
        if routes.is_empty() {
            let status = ThinStatus::builder(ErrorCode::FailedPrecondition)
                .message("No available routes to the peer")
                .build();
            return self.send_disconnect(status).await;
        }
        Ok(())
    }

    async fn recv_control_loop(&self, mut routes: Vec<route::ScopedRoute>) -> Result<()> {
        loop {
            self.recv_control(&mut routes).await?;
        }
    }

    async fn send_disconnect(&self, status: ThinStatus) -> Result<()> {
        let control = Control {
            status: Some(Status {
                code: status.code_raw().get(),
                message: Some(status.message().to_string()),
            }),
            command: Some(control::Command::Disconnect(Disconnect {})),
            ..Default::default()
        };
        let written = proto::write_control(&self.config.conn, &control).await;
        let Ok(_) = written else {
            let msg = format!("Unable to send a Disconnect message; {}", status);
            self.config
                .conn
                .close(VarInt::from_u32(1), (&msg).as_bytes());
            return written.context(msg);
        };
        Err(status.into())
    }
}
