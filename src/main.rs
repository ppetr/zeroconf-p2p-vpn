use std::net::{IpAddr, Ipv4Addr};
use tracing::info;
use tracing_subscriber::fmt::format::FmtSpan;

mod osal;

fn main() -> Result<(), anyhow::Error> {
    // Look for RUST_LOG; if not found, default to "info"
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_span_events(FmtSpan::ENTER | FmtSpan::CLOSE)
        .init();

    tokio_uring::start(async {
        let globals = osal::Globals::new().await?;
        let tun = osal::Tun::new(&globals, None).await?;
        let _route = tun
            .add_route(IpAddr::V4(Ipv4Addr::new(10, 33, 33, 1)))
            .await?;

        info!(
            "TUN device {} opened via tokio-uring. Starting echo loop...",
            tun.if_name
        );

        let mut buf = vec![0u8; 2048];

        loop {
            let (result, read_buf) = tun.file.read_at(buf, 0).await;
            let n = result?;

            if n == 0 {
                buf = read_buf;
                continue;
            }

            info!("Received raw packet of length: {} bytes!", n); // Byte 9 of an IPv4 header contains the Protocol (1 = ICMP / Ping)
            if n > 20 {
                info!("Protocol Byte {}", read_buf[9]);
            }
            buf = read_buf;
            /*
            let (write_result, written_buf) = tun.file.write_at(read_buf.slice(..n), 0).submit().await;
            write_result?;

            buf = written_buf.into_inner();
            */
        }
    })
}
