use anyhow::Result;
use buf_list::BufList;
use bytes::Bytes;
use iroh::endpoint::{Connection, RecvStream, VarInt};
use prost::Message;
use thin_status::{ErrorCode::*, ThinStatus};

pub mod p2p_vpn {
    pub mod control {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/p2p_vpn.control.v1.rs"));
        }
    }
}

pub use p2p_vpn::control::v1;

const MAX_MESSAGE_SIZE: usize = 2048;

// Wait for an unidirectional stream and accept a `v1::Control` message from it.
pub async fn read_control(conn: &Connection) -> Result<v1::Control> {
    let mut stream = conn.accept_uni().await?;
    let control = read_control_stream(&mut stream).await;
    let _closed_stream_is_fine = stream.stop(
        /*error_code=*/ VarInt::from_u32(control.as_ref().map_or(1, |_| 0)),
    );
    control
}

async fn read_control_stream(stream: &mut RecvStream) -> Result<v1::Control> {
    let buf_list = read_to_end(stream, MAX_MESSAGE_SIZE).await?;
    let control = v1::Control::decode(buf_list)?;
    tracing::debug!(control = ?control, "Read control command");
    Ok(control)
}

// Open an unidirectional stream and send a `v1::Control` message to it.
pub async fn write_control(conn: &Connection, control: &v1::Control) -> Result<()> {
    let mut buf = Vec::with_capacity(MAX_MESSAGE_SIZE);
    control.encode(&mut buf)?;
    let mut stream = conn.open_uni().await?;
    let result = stream.write_all(&buf).await;
    tracing::debug_span!("Waiting for the peer to receive all data");
    stream.finish()?;
    stream.stopped().await?;
    Ok(result?)
}

/// Reads the stream to its end and accumulates all chunks in a `BufList`.
pub async fn read_to_end(recv: &mut RecvStream, max_bytes: usize) -> Result<BufList> {
    let mut buffer_list = BufList::new();
    let mut scratchpad = [Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new()];
    loop {
        match recv.read_chunks(&mut scratchpad).await? {
            Some(chunks_filled) => {
                for chunk in &mut scratchpad[0..chunks_filled] {
                    buffer_list.push_chunk(std::mem::take(chunk));
                    if buffer_list.num_bytes() >= max_bytes {
                        anyhow::bail!(ThinStatus::builder(OutOfRange)
                            .message(&format!(
                                "stream longer than the limit of {} bytes",
                                max_bytes
                            ))
                            .build())
                    }
                }
            }
            None => break, // All chunks collected.
        }
    }
    Ok(buffer_list)
}
