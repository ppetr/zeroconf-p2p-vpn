use anyhow::{Context, Error, Result};
use bytes::Bytes;
use ipnet::IpNet;
use iroh::endpoint::{Connection, VarInt};
use iroh::{PublicKey, Signature};
use secure_p2p_transport::wait_for_direct;
use std::sync::Arc;
use std::time::Duration;
use thin_status::{ErrorCode, ThinStatus};
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::addr;
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
        let control = self.recv_control_loop(routes);
        let send = async {
            let icmp_gateway = tun::IcmpGateway::from_addr(self.config.common.own_net.addr());

            while let Some(packet) = rx_packet.recv().await {
                // TODO: Check networks etc.
                if let Some(mtu) = self.config.conn.max_datagram_size() {
                    if (&packet).len() > mtu {
                        let mtu = std::cmp::min(mtu, 1500) as u16;
                        let mut buf = bytes::BytesMut::with_capacity(128);
                        match icmp_gateway.generate_reply(
                            &mut buf,
                            &packet,
                            tun::IcmpType::packet_too_big(mtu),
                        ) {
                            Ok(_) => {
                                let buf = tun::TxPacket { data: buf.freeze() };
                                tracing::debug!(packet = ?buf, "Sending ICMP packet to reduce MTU to {}", mtu);
                                let _ = tx_packet.send(buf).await;
                            }
                            // TODO: Deal with Result
                            Err(e) => tracing::warn!(
                                error = e.to_string(),
                                key = self.public_key().to_z32()
                            ),
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
        let control = proto::read_control(&self.config.conn).await;
        // Ignore malformed messages.
        let control = match control {
            Err(e) => {
                tracing::info!(
                    error = ?e,
                    "Received a malformed message from the peer, ignoring"
                );
                return Ok(());
            }
            Ok(c) => c,
        };
        match control.command {
            Some(control::Command::Advertise(a)) => {
                let (addrs, errors) = validate_addresses(
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

/// Returns addresses that pass signature verification (`verify_signed_ipnet`) and that are also
/// subnets of (at least one of) the given `allowed_nets`.
/// Returns errors for networks that failed parsing/validation.
/// Peer networks that passed validation, but are outside `allowed_nets`, are silently skipped.
pub fn validate_addresses(
    allowed_nets: &[IpNet],
    advertise: &proto::v1::Advertise,
    key: &PublicKey,
) -> (Vec<IpNet>, Vec<Error>) {
    let mut valid = Vec::<IpNet>::with_capacity(advertise.own_addresses.len());
    let mut errors = Vec::<Error>::with_capacity(advertise.own_addresses.len());
    for host in &advertise.own_addresses {
        match validate_address(host, key) {
            Ok(net) if is_subnet_of_any(&net, allowed_nets) => valid.push(net),
            Ok(_) => (),
            Err(e) => {
                let e = e.context(format!("when validating network '{}'", host.peer_network));
                tracing::info!(error = e.to_string(), key = key.to_z32());
                errors.push(e);
            }
        }
    }
    (valid, errors)
}

/// Validates a `v1::HostAddress` against the host's public key.
fn validate_address(host: &proto::v1::HostAddress, key: &PublicKey) -> Result<IpNet> {
    let net: IpNet = host.peer_network.parse()?;
    let signature = Signature::try_from(host.peer_network_signature.as_slice())
        .context("Invalid cryptographic signature")?;
    addr::verify_signed_ipnet(host.peer_network.parse()?, key, &signature)?;
    Ok(net)
}

fn is_subnet_of_any(net: &IpNet, allowed: &[IpNet]) -> bool {
    allowed.into_iter().any(|a| a.contains(net))
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;
    use std::str::FromStr;

    // Helper to create a valid proto::v1::HostAddress for testing
    fn make_host_address(net: &IpNet, secret_key: &SecretKey) -> proto::v1::HostAddress {
        let (ipnet, signature) = addr::generate_signed_ipnet(net, secret_key);
        proto::v1::HostAddress {
            peer_network: ipnet.to_string(),
            peer_network_signature: signature.to_bytes().to_vec(),
        }
    }

    #[test]
    fn test_validate_addresses_all_valid() {
        let secret_key = SecretKey::generate();
        let public_key = secret_key.public();
        let allowed_nets = vec![
            IpNet::from_str("10.0.0.0/8").unwrap(),
            IpNet::from_str("2001:db8::/32").unwrap(),
        ];
        let advertise = proto::v1::Advertise {
            own_addresses: vec![
                make_host_address(&IpNet::from_str("10.1.2.3/24").unwrap(), &secret_key),
                make_host_address(
                    &IpNet::from_str("2001:db8:cafe::42/48").unwrap(),
                    &secret_key,
                ),
            ],
        };

        let (valid, errors) = validate_addresses(&allowed_nets, &advertise, &public_key);

        assert_eq!(valid.len(), 2, "{:?}", errors);
        assert!(errors.is_empty());
        // Verify that the parsed networks are matching the structural subnets
        assert!(valid.iter().any(|n| allowed_nets[0].contains(n)));
        assert!(valid.iter().any(|n| allowed_nets[1].contains(n)));
    }

    #[test]
    fn test_validate_addresses_silently_skips_outside_allowed() {
        let secret_key = SecretKey::generate();
        let public_key = secret_key.public();
        let allowed_nets = vec![IpNet::from_str("10.0.0.0/8").unwrap()];
        // This network is cryptographically valid but outside allowed_nets
        let advertise = proto::v1::Advertise {
            own_addresses: vec![make_host_address(
                &IpNet::from_str("192.168.1.0/24").unwrap(),
                &secret_key,
            )],
        };
        let (valid, errors) = validate_addresses(&allowed_nets, &advertise, &public_key);

        // Should be empty because it's not allowed, but NO error because signature is correct.
        assert!(valid.is_empty());
        assert!(errors.is_empty());
    }

    #[test]
    fn test_validate_addresses_error_invalid_ip_format() {
        let public_key = SecretKey::generate().public();
        let allowed_nets = vec![IpNet::from_str("10.0.0.0/8").unwrap()];

        let advertise = proto::v1::Advertise {
            own_addresses: vec![proto::v1::HostAddress {
                peer_network: "invalid-ip-format/24".to_string(),
                peer_network_signature: vec![0u8; 64],
            }],
        };

        let (valid, errors) = validate_addresses(&allowed_nets, &advertise, &public_key);

        assert!(valid.is_empty());
        assert_eq!(errors.len(), 1);

        let err_msg = format!("{:?}", errors[0]);
        assert!(err_msg.contains("when validating network 'invalid-ip-format/24'"));
    }

    #[test]
    fn test_validate_addresses_error_invalid_signature_length() {
        let public_key = SecretKey::generate().public();
        let allowed_nets = vec![IpNet::from_str("10.0.0.0/8").unwrap()];

        let advertise = proto::v1::Advertise {
            own_addresses: vec![proto::v1::HostAddress {
                peer_network: "10.1.1.42/24".to_string(),
                // Ed25519 signatures must be exactly 32 bytes
                peer_network_signature: vec![0u8; 32],
            }],
        };

        let (valid, errors) = validate_addresses(&allowed_nets, &advertise, &public_key);

        assert!(valid.is_empty());
        assert_eq!(errors.len(), 1);

        let err_msg = format!("{:?}", errors[0]);
        assert!(err_msg.contains("Invalid cryptographic signature"));
    }

    #[test]
    fn test_validate_addresses_error_signature_verification_failed() {
        let alice_key = SecretKey::generate();
        let charlie_key = SecretKey::generate(); // Wrong key

        let allowed_nets = vec![IpNet::from_str("10.0.0.0/8").unwrap()];
        let net = IpNet::from_str("10.1.1.0/24").unwrap();

        // Alice signs it, but Bob will check it against Charlie's public key
        let advertise = proto::v1::Advertise {
            own_addresses: vec![make_host_address(&net, &alice_key)],
        };

        let (valid, errors) = validate_addresses(&allowed_nets, &advertise, &charlie_key.public());

        assert!(valid.is_empty());
        assert_eq!(errors.len(), 1);

        let err_msg = format!("{:?}", errors[0]);
        assert!(err_msg.contains("signature"), "{}", err_msg);
    }

    #[test]
    fn test_validate_addresses_combined_matrix() {
        let secret_key = SecretKey::generate();
        let public_key = secret_key.public();
        let allowed_nets = vec![IpNet::from_str("10.0.0.0/8").unwrap()];

        let valid_net = IpNet::from_str("10.1.1.0/24").unwrap();
        let outside_net = IpNet::from_str("192.168.1.0/24").unwrap();

        let advertise = proto::v1::Advertise {
            own_addresses: vec![
                make_host_address(&valid_net, &secret_key), // 1. Valid and allowed
                make_host_address(&outside_net, &secret_key), // 2. Valid but skipped
                proto::v1::HostAddress {
                    // 3. Error: Malformed
                    peer_network: "parse-fail".to_string(),
                    peer_network_signature: vec![0u8; 64],
                },
            ],
        };

        let (valid, errors) = validate_addresses(&allowed_nets, &advertise, &public_key);

        assert_eq!(valid.len(), 1);
        assert_eq!(errors.len(), 1);

        assert!(
            valid_net.contains(&valid[0]),
            "{} should be in {}",
            valid[0],
            valid_net
        );
        assert!(format!("{:?}", errors[0]).contains("parse-fail"));
    }
}
