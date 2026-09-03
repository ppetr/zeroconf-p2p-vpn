use backoff;
use futures_util::future::join_all;
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
mod session;
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

    let args: Vec<String> = std::env::args().collect();
    let config_path = match args.as_slice() {
        [_argv0, config_path] => config_path.clone(),
        _ => panic!(
            "Usage: {} <config-file-path>",
            args.first()
                .map(String::as_str)
                .unwrap_or("zeroconf-p2p-vpn")
        ),
    };

    info!("Setting up a node");
    let config = config::Config::load(&config_path)?;
    let secret_key = load_key_from_disk(&config.private_key_path)?;
    info!("My public key: '{}'", secret_key.public().to_z32());

    if config.peers.is_empty() {
        info!("No peers configured in '{}', nothing to do", config_path);
        return Ok(());
    }

    let tun = tun::Tun::new(None).await?;
    info!("TUN device {} opened.", tun.if_name);

    let net_route_handle = route::NetRouteHandle::new(tun.if_index())?;

    let alpn = Arc::new(b"zeroconf-p2p-vpn/vpn/1.0".to_vec());
    let node_config = NodeExtraConfig {
        n0_discovery: N0Discovery::NoN0,
        use_dht: false,
        use_mdns: true,
    };
    let mut backoff = backoff::ExponentialBackoff::default();
    backoff.max_elapsed_time = None;
    let backoff = backoff;

    let node = TransportNode::new(secret_key.clone(), alpn.to_vec(), &node_config).await?;
    let endpoint = node.endpoint();

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
    let advertise = proto::v1::Advertise {
        own_addresses: vec![proto::v1::HostAddress {
            peer_network: own_net.to_string(),
            peer_network_signature: own_net_sig.to_bytes().to_vec(),
        }],
    };
    let common_config = Arc::new(peer::CommonPeerConfig::new(icmp_gateway.clone()));

    // TODO: Cancellation.
    let root_cancel = CancellationToken::new();
    let relay = Arc::new(relay::Relay::new(net_route_handle.clone()));
    let mut incoming_router = connection::IncomingRouter::new();
    let mut links = Vec::with_capacity(config.peers.len());
    for (name, peer_key) in &config.peers {
        info!("Configuring peer '{}': '{}'", name, peer_key.to_z32());
        let link = connection::PeerLink::new(connection::IrohConnector {
            local: endpoint.clone(),
            peer: *peer_key,
            alpn: alpn.clone(),
        });
        let (handle, _join) = link.spawn(backoff.clone(), root_cancel.child_token());
        incoming_router.register(*peer_key, handle.incoming_receiver());
        links.push((name.clone(), handle));
    }

    // The global listener accepts connections from any peer; the router forwards each to the
    // matching peer's link by the remote's public key.
    tokio::spawn(incoming_router.run(node.listen_any()));

    let sessions_loop = join_all(links.into_iter().map(|(name, handle)| {
        session::PeerSession::new(
            session::PeerSessionConfig {
                name,
                common: common_config.clone(),
                advertise: advertise.clone(),
            },
            handle,
            relay.clone(),
            tx_handle.clone(),
        )
        .run()
    }));
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

    let _ = tokio::join!(tun_loop, sessions_loop, tun_rx_loop);
    Ok(())
}
