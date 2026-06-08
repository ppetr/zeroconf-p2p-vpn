mod osal;

fn main() -> Result<(), anyhow::Error> {
    tokio_uring::start(async {
        let globals = osal::Globals::new().await?;
        let tun = osal::Tun::new(&globals, None).await?;

        println!(
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

            println!("Received raw packet of length: {} bytes!", n); // Byte 9 of an IPv4 header contains the Protocol (1 = ICMP / Ping)
            if n > 20 {
                println!("Protocol Byte: {}", read_buf[9]);
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
