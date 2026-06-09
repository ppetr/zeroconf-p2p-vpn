use std::net::{IpAddr, Ipv4Addr};
use tracing::{info, level_filters::LevelFilter};
use tracing_subscriber::fmt::format::FmtSpan;

mod buffer_pool;
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

        let mut buffer_pool = buffer_pool::BufferPool::new(64, 2048)?;
        loop {
            let buf = buffer_pool.pop().await.read_frame(&tun.file).await?;
            if buf.is_empty() {
                continue;
            }

            let n = (&buf).len();
            info!("Received raw packet of length: {} bytes!", n); // Byte 9 of an IPv4 header contains the Protocol (1 = ICMP / Ping)
            if n > 20 {
                info!("Protocol Byte {}", (&buf)[9]);
            }
            /*
            let (write_result, written_buf) = tun.file.write_at(read_buf.slice(..n), 0).submit().await;
            write_result?;

            buf = written_buf.into_inner();
            */
        }
    })
}
