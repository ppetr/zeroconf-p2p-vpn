use anyhow::Context;
use std::net::{IpAddr, Ipv4Addr};
use tokio::sync::mpsc;
use tracing::{info, level_filters::LevelFilter, warn};
use tracing_subscriber::fmt::format::FmtSpan;

mod osal;

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

        let mut buffer_pool = osal::BufferPool::new(64, 2048)?;
        let (rx_uring, mut _rx_handle) = mpsc::channel::<osal::PooledSlice>(64);
        let (_tx_handle, mut tx_uring) = mpsc::channel::<osal::PooledSlice>(64);
        let tun_ref = &tun;

        let rx_task = async move {
            Ok::<(), anyhow::Error>(loop {
                let buf = match buffer_pool.pop().await.read_frame(&tun_ref.file).await {
                    Err(err) if osal::tun::error::is_tun_transient(&err) => continue,
                    r => r?,
                };
                info!("Received packet of length {}", (&buf).len());
                if !buf.is_empty() {
                    rx_uring.send(buf).await?;
                }
            })
        };
        let tx_task = async move {
            Ok::<(), anyhow::Error>(loop {
                let buf = tx_uring.recv().await.context("Channel dropped")?;
                match buf.write_frame(&tun_ref.file).await {
                    Err(err) if osal::tun::error::is_tun_transient(&err) => continue,
                    r => r?,
                };
            })
        };
        if let Err(err) = tokio::select! {
            err = rx_task => {
                err.context("rx task")
            }
            err = tx_task => {
                err.context("tx task")
            }
        } {
            warn!("{:?}", err)
        }
        Ok(())
    })
}
