use anyhow::Context;
use iroh::PublicKey;
use secure_p2p_transport::{load_key_from_disk, N0Discovery, NodeExtraConfig, TransportNode};
use std::env;
#[allow(unused_imports)]
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{info, level_filters::LevelFilter};
use tracing_subscriber::fmt::format::FmtSpan;

mod addr;
mod buffer_pool;
mod connection;
mod error;
mod osal;
mod peer;
mod proto;
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

    let net_route_handle = Arc::new(net_route::Handle::new()?);
    let tun = tun::Tun::new(None).await?;

    info!("TUN device {} opened.", tun.if_name);

    let args: Vec<String> = std::env::args().collect();
    let args = args.iter().map(|s| s.as_str()).collect::<Vec<&str>>();
    let alpn = b"zeroconf-p2p-vpn/vpn/1.0".to_vec();
    let node_config = NodeExtraConfig {
        n0_discovery: N0Discovery::NoN0,
        use_dht: false,
        use_mdns: true,
    };
    let (secret_key, _node, conn) = match args.as_slice() {
        [_argv0, secret_file, peer_base32] => {
            info!("Setting up a client node");
            let secret_key = load_key_from_disk(secret_file)?;
            info!("My public key: '{}'", secret_key.public().to_z32());
            let peer_key = PublicKey::from_z32(peer_base32)
                .context(format!("When decoding public key '{}'", peer_base32))?;
            let node = TransportNode::new(secret_key.clone(), alpn, &node_config).await?;
            let conn = node.connect(peer_key).await?;
            (secret_key, node, conn)
        }
        [_argv0, secret_file] => {
            info!("Setting up a server node");
            let secret_key = load_key_from_disk(secret_file)?;
            info!("My public key: '{}'", secret_key.public().to_z32());
            let node = TransportNode::new(secret_key.clone(), alpn, &node_config).await?;
            let mut conn_queue = node.listen_any();
            (
                secret_key,
                node,
                conn_queue
                    .recv()
                    .await
                    .ok_or(anyhow::anyhow!("Didn't receive a listening connection"))?,
            )
        }
        _ => panic!("Unexpected command line arguments: {:?}", args),
    };
    info!("Connected");

    let (own_net, own_net_sig) = addr::generate_signed_ipnet(
        &ipnet::IpNet::V6(addr::VPN_IPV6_DEFAULT_SUBNET0),
        &secret_key,
    );
    tracing::warn!("My VPN address: {}", own_net.addr());
    tun.add_if_addr(own_net.addr()).await?;

    info!("Starting a communication loop");
    let common_config = Arc::new(peer::CommonPeerConfig::new(
        net_route_handle,
        tun.if_index(),
        own_net,
    ));
    let (rx_uring, rx_handle) = mpsc::channel::<tun::RxPacket>(64);
    let (tx_handle, tx_uring) = mpsc::channel::<tun::TxPacket>(64);
    let tun_loop = async {
        let opts = tun::TunControlOpts {
            buffer_pool: 512,
            tx_packet: tx_uring,
            rx_packet: rx_uring,
        };
        tun.control(opts).await
    };

    let advertise = proto::v1::Advertise {
        own_addresses: vec![proto::v1::HostAddress {
            peer_network: own_net.to_string(),
            peer_network_signature: own_net_sig.to_bytes().to_vec(),
        }],
    };
    let peer_config = peer::PeerConfig {
        common: common_config.clone(),
        conn,
        advertise,
    };
    let p2p_loop = async move {
        let mut peer = peer::Peer::new(peer_config);
        peer.communicate(rx_handle, tx_handle).await
    };
    tokio::select! {
        r = tun_loop => r,
        r = p2p_loop => r,
    }
}
