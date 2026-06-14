use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{info, level_filters::LevelFilter, warn};
use tracing_subscriber::fmt::format::FmtSpan;

mod addr;
mod buffer_pool;
mod osal;
mod peer;
mod proto;
mod route;
mod tun;

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

    let net_route_handle = Arc::new(net_route::Handle::new()?);
    let tun = tun::Tun::new(net_route_handle.clone(), None).await?;
    tun.add_if_addr(IpAddr::V4(Ipv4Addr::new(10, 33, 33, 1)))
        .await?;
    let _route = tun
        .add_route(IpAddr::V4(Ipv4Addr::new(10, 33, 33, 254)))
        .await?;

    info!("TUN device {} opened. Starting echo loop...", tun.if_name);

    let (rx_uring, mut _rx_handle) = mpsc::channel::<buffer_pool::PooledSlice>(64);
    let (_tx_handle, tx_uring) = mpsc::channel::<buffer_pool::PooledSlice>(64);
    let opts = tun::TunControlOpts {
        buffer_pool: 512,
        tx_packet: tx_uring,
        rx_packet: rx_uring,
    };
    if let Err(err) = tun.control(opts).await {
        warn!("{:?}", err)
    }
    Ok(())
}
