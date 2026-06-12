use std::net::{IpAddr, Ipv4Addr};
use tokio::sync::mpsc;
use tracing::{info, level_filters::LevelFilter, warn};
use tracing_subscriber::fmt::format::FmtSpan;

mod addr;
mod osal;
mod proto;

fn main() -> Result<(), anyhow::Error> {
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

    tokio_uring::start(async {
        let globals = osal::Globals::new().await?;
        let tun = osal::Tun::new(&globals, None).await?;
        let _if_addr = tun
            .add_if_addr(IpAddr::V4(Ipv4Addr::new(10, 33, 33, 1)))
            .await?;
        let _route = tun
            .add_route(IpAddr::V4(Ipv4Addr::new(10, 33, 33, 254)))
            .await?;

        info!(
            "TUN device {} opened via tokio-uring. Starting echo loop...",
            tun.if_name
        );

        let (rx_uring, mut _rx_handle) = mpsc::channel::<osal::PooledSlice>(64);
        let (_tx_handle, tx_uring) = mpsc::channel::<osal::PooledSlice>(64);
        let opts = osal::TunControlOpts {
            buffer_pool: 512,
            tx_packet: tx_uring,
            rx_packet: rx_uring,
        };
        if let Err(err) = tun.control(opts).await {
            warn!("{:?}", err)
        }
        Ok(())
    })
}
