use anyhow::{ensure, Context};
use backoff;
use metrics::IntoLabels;
use secure_p2p_transport::{load_key_from_disk, N0Discovery, NodeExtraConfig, TransportNode};
use std::env;
#[allow(unused_imports)]
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{info, level_filters::LevelFilter};
use tracing_subscriber::fmt::format::FmtSpan;

mod addr;
mod buffer_pool;
mod config;
mod connection;
mod error;
mod osal;
mod peer;
mod proto;
mod relay;
mod route;
mod tun;

fn get_metrics_addr() -> std::net::SocketAddr {
    let port: u16 = env::var("METRICS_PORT")
        .map(|p| p.parse().expect("METRICS_PORT must be a valid u16 number"))
        .unwrap_or_else(|_| 9189);
    std::net::SocketAddr::new(std::net::Ipv6Addr::UNSPECIFIED.into(), port)
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
        .init();
    info!(
        "Logging level is {:?}; change the RUST_LOG environment variable to set a different level",
        LevelFilter::current()
    );
    metrics_exporter_prometheus::PrometheusBuilder::new()
        .with_http_listener(get_metrics_addr())
        .install()
        .expect("failed to install Prometheus metrics recorder/exporter");

    let tun = tun::Tun::new(None).await?;
    info!("TUN device {} opened.", tun.if_name);

    let net_route_handle = route::NetRouteHandle::new(tun.if_index())?;

    let args: Vec<String> = std::env::args().collect();
    let args = args.iter().map(|s| s.as_str()).collect::<Vec<&str>>();
    let alpn = Arc::new(b"zeroconf-p2p-vpn/vpn/1.0".to_vec());
    let node_config = NodeExtraConfig {
        n0_discovery: N0Discovery::NoN0,
        use_dht: false,
        use_mdns: true,
    };
    let mut backoff = backoff::ExponentialBackoff::default();
    backoff.max_elapsed_time = None;
    let backoff = backoff;

    let (config, secret_key, mut link) = match args.as_slice() {
        [_argv0, config_path] => {
            info!("Setting up a node");
            let config = config::Config::load(config_path)?;
            let secret_key = load_key_from_disk(&config.private_key_path)?;
            info!("My public key: '{}'", secret_key.public().to_z32());

            let mut peers = config.peers.iter();
            let (peer_name, peer_key) = peers
                .next()
                .context("configuration's [peers] section must contain exactly one peer")?;
            ensure!(
                peers.next().is_none(),
                "configuration's [peers] section must contain exactly one peer, found more than one"
            );
            info!(
                "Connecting to peer '{}': '{}'",
                peer_name,
                peer_key.to_z32()
            );
            let peer_key = *peer_key;

            let node = TransportNode::new(secret_key.clone(), alpn.to_vec(), &node_config).await?;

            let link = connection::PeerLink::new(connection::IrohConnector {
                local: node.endpoint(),
                peer: peer_key,
                alpn: alpn.clone(),
            });
            let (link, _) = link.spawn(backoff, CancellationToken::new());

            let incoming = link.incoming_receiver();
            tokio::spawn(async move {
                let mut conn_queue = node.listen_any();
                while let Some(connection) = conn_queue.recv().await {
                    if let Err(status) = incoming.send(connection).await {
                        tracing::warn!(error = ?status, "failed to submit an incoming connection");
                    }
                }
            });

            (config, secret_key, link)
        }
        _ => panic!(
            "Usage: {} <config-file-path>",
            args.first().copied().unwrap_or("zeroconf-p2p-vpn")
        ),
    };
    let (rx_uring, mut rx_handle) = mpsc::channel::<tun::RxPacket>(64);
    let (tx_handle, tx_uring) = mpsc::channel::<tun::TxPacket>(64);
    let tun_loop = async {
        let opts = tun::TunControlOpts {
            buffer_pool: 512,
            tx_packet: tx_uring,
            rx_packet: rx_uring,
        };
        tun.control(opts).await
    };

    let (own_net, own_net_sig) = addr::generate_signed_ipnet(
        &ipnet::IpNet::V6(addr::vpn_subnet(config.subnet)),
        &secret_key,
    );
    tracing::warn!("My VPN address: {}", own_net.addr());
    tun.add_if_addr(own_net.addr()).await?;

    let icmp_gateway = tun::IcmpGateway::from_addr(own_net.addr());

    // TODO: Cancellation.
    let relay = relay::Relay::new(net_route_handle.clone());
    let connect_loop = async {
        let advertise = proto::v1::Advertise {
            own_addresses: vec![proto::v1::HostAddress {
                peer_network: own_net.to_string(),
                peer_network_signature: own_net_sig.to_bytes().to_vec(),
            }],
        };
        let common_config = Arc::new(peer::CommonPeerConfig::new(icmp_gateway.clone()));

        Ok::<(), anyhow::Error>(loop {
            let Some(conn) = link.next_connection().await? else {
                info!("Disconnected");
                continue;
            };

            info!("Connected, starting a communication loop");
            let peer_config = peer::PeerConfig {
                common: common_config.clone(),
                conn,
                advertise: advertise.clone(),
            };

            let peer = peer::Peer::new(peer_config);
            let (mut peer, routes) = peer.handshake().await?;
            relay.insert(&routes.0, peer.clone()).await?;
            // TODO: Update routes from recv_control_loop.
            let _ = peer.recv_loop(tx_handle.clone()).await?;
        })
    };
    let tun_rx_loop = async {
        while let Some(packet) = rx_handle.recv().await {
            let span = tracing::debug_span!(
                "p2p_tun_rx_loop",
                dest_ip = tracing::field::Empty,
                peer = tracing::field::Empty,
                "Processing packet received from TUN"
            );
            let icmp_packet: Option<_> = if let Some(peer) = tun::inet_slice(&packet.data)
                .ok()
                .as_ref()
                .and_then(tun::destination_ip)
                .as_ref()
                .and_then(|dest_ip| {
                    tracing::record_all!(span, dest_ip = ?dest_ip);
                    relay.get(dest_ip)
                }) {
                tracing::record_all!(span, peer = ?peer.public_key().to_z32());
                match peer.send_packet(packet) {
                    Ok(icmp_packet) => icmp_packet,
                    Err(err) => {
                        tracing::debug!(peer = ?peer.public_key().to_z32(), err = ?err,
                                        "Error sending packet to peer");
                        metrics::counter!(
                            "p2p_vpn_tun_rx_loop_send_packet",
                            error::ExtractedErrorCode::from_anyhow(&err).into_labels()
                        )
                        .increment(1);
                        None
                    }
                }
            } else {
                let mut buf = bytes::BytesMut::with_capacity(128);
                icmp_gateway
                    .generate_reply(&mut buf, &packet, tun::IcmpType::unreachable_net())
                    .ok()
                    .map(|_| tun::TxPacket::new(buf.into()))
            };
            if let Some(packet) = icmp_packet {
                if let Err(err) = tx_handle.try_send(packet) {
                    tracing::debug!(err = ?err, "Error sending return ICMP packet");
                    metrics::counter!(
                        "p2p_vpn_tun_rx_loop_return_icmp",
                        error::ExtractedErrorCode::from_anyhow(&err.into()).into_labels()
                    )
                    .increment(1);
                }
            }
        }
    };

    let _ = tokio::join!(tun_loop, connect_loop, tun_rx_loop);
    Ok(())
}
