use dns_host_config::{DnsRoute, DnsRouteConfig};
use futures_util::future::join_all;
use iroh::endpoint::Connection;
use iroh_persistent::PersistentConnection;
use metrics::IntoLabels;
use crate::route::RoutingTable;
use secure_p2p_transport::{load_key_from_disk, TransportNode};
use std::env;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{info, level_filters::LevelFilter};
use tracing_subscriber::fmt::format::FmtSpan;

mod addr;
mod buffer_pool;
mod config;
mod connection;
mod dns;
mod error;
mod generate;
mod osal;
mod peer;
mod proto;
mod relay;
mod route;
mod session;
mod show;
mod tun;

/// Builds an ICMP error reply of `icmp_type` for `packet`, or `None` if one can't be produced.
fn icmp_reply(
    gateway: &tun::IcmpGateway,
    packet: &tun::RxPacket,
    icmp_type: tun::IcmpType,
) -> Option<tun::TxPacket> {
    let mut buf = bytes::BytesMut::with_capacity(128);
    gateway.generate_reply(&mut buf, packet, icmp_type).ok().map(|_| tun::TxPacket::new(buf.into()))
}

fn get_metrics_addr() -> std::net::SocketAddr {
    let port: u16 = env::var("METRICS_PORT")
        .map(|p| p.parse().expect("METRICS_PORT must be a valid u16 number"))
        .unwrap_or_else(|_| 9189);
    std::net::SocketAddr::new(std::net::Ipv6Addr::UNSPECIFIED.into(), port)
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let args: Vec<String> = std::env::args().collect();
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    let config_path = match argv.as_slice() {
        [_argv0, "show", config_path] => return show::run(config_path),
        [_argv0, "generate", config_path] => return generate::run(config_path),
        [_argv0, config_path] => *config_path,
        _ => {
            let prog = argv.first().copied().unwrap_or("zeroconf-p2p-vpn");
            panic!(
                "Usage: {prog} <config-file-path>\n       \
                 {prog} show <config-file-path>\n       \
                 {prog} generate <config-file-path>"
            );
        }
    };

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| {
            // iroh logs its internal relay/QUIC/portmapper machinery at INFO, which floods the
            // journal; RUST_LOG still overrides this entirely when set.
            tracing_subscriber::EnvFilter::new("info,iroh=warn,portmapper=warn")
        });
    // Respect the https://no-color.org/ convention: tracing_subscriber only disables ANSI
    // output when it doesn't detect a terminal, which doesn't help on a Windows console that
    // doesn't support VT100 escape sequences.
    let ansi = env::var_os("NO_COLOR").is_none();
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(ansi)
        // Just CLOSE, not ENTER: tracing_subscriber emits an ENTER event every time an
        // instrumented future is polled, not just once when the span is created, so a
        // long-lived span (e.g. a peer connection, instrumented for its whole lifetime) would
        // log once per poll -- in practice, once per packet.
        .with_span_events(FmtSpan::CLOSE)
        .init();
    info!(
        "Logging level is {:?}; change the RUST_LOG environment variable to set a different level",
        LevelFilter::current()
    );
    metrics_exporter_prometheus::PrometheusBuilder::new()
        .with_http_listener(get_metrics_addr())
        .install()
        .expect("failed to install Prometheus metrics recorder/exporter");

    info!("Setting up a node");
    let config = config::Config::load(config_path)?;
    let secret_key = load_key_from_disk(&config.private_key_path)?;
    info!("My public key: '{}'", secret_key.public().to_z32());

    if config.peers.is_empty() {
        info!("No peers configured in '{}', nothing to do", config_path);
        return Ok(());
    }

    let tun = tun::Tun::new(config.tun.name.as_deref(), &config.tun.description).await?;
    info!("TUN device {} opened.", tun.if_name);

    let net_route_handle = route::NetRouteHandle::new(tun.if_index())?;

    let alpn: Vec<u8> = b"zeroconf-p2p-vpn/vpn/1.0".to_vec();

    let node = TransportNode::new(secret_key.clone(), alpn.clone(), &config.discovery).await?;
    let endpoint = node.endpoint();

    let (rx_uring, mut rx_handle) = mpsc::channel::<tun::RxPacket>(64);
    let (tx_handle, tx_uring) = mpsc::channel::<tun::TxPacket>(64);
    let tun_loop = async {
        let opts =
            tun::TunControlOpts { buffer_pool: 512, tx_packet: tx_uring, rx_packet: rx_uring };
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

    let dns_names =
        config.dns.as_ref().map(|dns_cfg| Arc::new(dns::PeerNames::new(dns_cfg.suffix.clone())));
    let dns_dispatch = match (&config.dns, &dns_names) {
        (Some(dns_cfg), Some(names)) => {
            // A dedicated address for our own local resolver, derived from (and guaranteed
            // distinct from) our own VPN address. It only ever gets a kernel route below, never
            // `tun.add_if_addr`: an address actually assigned to the interface is delivered
            // locally by the kernel (loopback-style) and would never reach `tun_rx_loop`.
            let dns_server_addr = match own_net.addr() {
                IpAddr::V6(addr) => Ipv6Addr::from_bits(addr.to_bits() ^ 1),
                IpAddr::V4(_) => unreachable!("VPN addresses are always IPv6"),
            };
            net_route_handle.insert(IpAddr::V6(dns_server_addr)).await?;
            info!(
                %dns_server_addr, suffix = %dns_cfg.suffix,
                "DNS resolution of peer names enabled"
            );

            #[cfg(target_os = "linux")]
            {
                let route_config = DnsRouteConfig::new(
                    vec![IpAddr::V6(dns_server_addr)],
                    vec![dns_cfg.suffix.clone()],
                )?;
                let mut host_dns = dns_host_config::linux::LinuxDnsRoute::probe(
                    env!("CARGO_PKG_NAME"),
                )
                .await;
                if let Err(err) = host_dns.set(&tun.if_name, &route_config).await {
                    tracing::warn!(
                        error = ?err,
                        "Failed to configure the host's DNS resolver for peer names"
                    );
                }
            }
            #[cfg(not(target_os = "linux"))]
            tracing::warn!(
                "No automatic host DNS integration exists yet for this platform; point the \
                 system resolver at {dns_server_addr} for '{}' lookups to work",
                dns_cfg.suffix
            );

            Some((dns_stack::dns::DnsConfig { server_addr: dns_server_addr }, names.clone()))
        }
        _ => None,
    };

    // TODO: Cancellation.
    let root_cancel = CancellationToken::new();
    let relay: Arc<relay::Relay<peer::ConnectedPeer>> =
        Arc::new(relay::Relay::new(net_route_handle.clone()));
    let mut incoming_router = connection::IncomingRouter::new();
    let mut links = Vec::with_capacity(config.peers.len());
    for (name, peer_key) in &config.peers {
        info!("Configuring peer '{}': '{}'", name, peer_key.to_z32());
        let (incoming_tx, incoming_rx) = mpsc::channel::<Connection>(4);
        incoming_router.register(*peer_key, incoming_tx);
        let link = PersistentConnection::builder(endpoint.clone(), *peer_key, alpn.clone())
            .incoming(futures_util::stream::unfold(incoming_rx, |mut rx| async move {
                rx.recv().await.map(|conn| (conn, rx))
            }))
            // Matches the QUIC close code this project used to send for this kind of internal
            // housekeeping close before switching to `iroh_persistent`
            // (`thin_status::ErrorCode::Aborted`). Nothing currently parses it back on either
            // side; kept only for continuity/debuggability on the wire.
            .close_code(10u32)
            .cancellation(root_cancel.child_token())
            .spawn();
        links.push((name.clone(), link));
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
                dns_names: dns_names.clone(),
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
            let dest_ip = tun::inet_slice(&packet.data).ok().as_ref().and_then(tun::destination_ip);
            if let Some(dest_ip) = &dest_ip {
                tracing::record_all!(span, dest_ip = ?dest_ip);
            }
            if let Some((dns_cfg, resolver)) = &dns_dispatch {
                if dest_ip == Some(IpAddr::V6(dns_cfg.server_addr)) {
                    if let Some(reply) =
                        dns_stack::dns::handle_packet(dns_cfg, resolver.as_ref(), packet.data.as_ref())
                            .await
                    {
                        if let Err(err) = tx_handle.try_send(tun::TxPacket::new(reply.into())) {
                            tracing::debug!(err = ?err, "Error sending DNS reply");
                        }
                    }
                    continue;
                }
            }
            let icmp_packet: Option<_> = match dest_ip.and_then(|ip| relay.get(&ip)) {
                Some(relay::Dispatch::Connected(peer)) => {
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
                }
                // A known peer in its reconnect gap gets a host-unreachable reply.
                Some(relay::Dispatch::Parked) => {
                    icmp_reply(&icmp_gateway, &packet, tun::IcmpType::unreachable_host())
                }
                // A destination that belongs to no configured peer gets network-unknown.
                None => icmp_reply(&icmp_gateway, &packet, tun::IcmpType::unreachable_net()),
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
