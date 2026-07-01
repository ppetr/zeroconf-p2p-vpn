use anyhow::Result;
use buf_list::BufList;
use bytes::Bytes;
use iroh::endpoint::{Connection, RecvStream, SendStream, VarInt};
use metrics::*;
use prost::Message;
use std::fmt::Debug;
use std::num::NonZeroI32;
use thin_status::{ErrorCode::*, ThinStatus};

use crate::error::ExtractedErrorCode;

pub mod p2p_vpn {
    pub mod control {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/p2p_vpn.control.v1.rs"));
        }
    }
}

pub use p2p_vpn::control::v1;

const MAX_MESSAGE_SIZE: usize = 2048;

fn status_to_control(status: ThinStatus) -> v1::ControlResponse {
    v1::ControlResponse {
        status: Some(v1::Status {
            code: i32::from(status.code_raw()),
            message: Some(status.message().to_string()),
        }),
    }
}

pub fn control_to_status(response: v1::ControlResponse) -> Result<(), ThinStatus> {
    match response.status {
        Some(v1::Status { code, message }) if let Some(code) = NonZeroI32::new(code) => {
            Err(ThinStatus::builder(code)
                .message(message.as_deref().unwrap_or(""))
                .build())
        }
        _ => Ok(()),
    }
}

/// Wait for an unidirectional stream and accept a `v1::ControlRequest` message from it.
pub async fn read_control<F>(conn: &Connection, f: F) -> Result<()>
where
    F: AsyncFnOnce(v1::ControlRequest) -> Result<(), ThinStatus>,
{
    let (send, mut recv) = conn.accept_bi().await?;
    let request = match read_control_stream(&mut recv).await {
        Err(e) => {
            let e = e.context("Received a malformed message from the peer");
            tracing::info!(error = ?e);
            counter!(description: "Received malformed v1::ControlRequest messages",
                "p2p_vpn_proto_read_control_message_errors", ExtractedErrorCode::from_anyhow(&e))
            .increment(1);
            return Err(e);
        }
        Ok(r) => r,
    };
    let response = f(request).await;
    let response: v1::ControlResponse = match response {
        Ok(()) => Default::default(),
        Err(status) => status_to_control(status),
    };
    write_control_stream(send, &response).await
}

async fn read_control_stream<P: Message + Debug + Default>(stream: &mut RecvStream) -> Result<P> {
    let buf_list = read_to_end(stream, MAX_MESSAGE_SIZE).await?;
    let control = P::decode(buf_list);
    tracing::debug!(control = ?control, "Read control command");
    let _closed_stream_is_fine = stream.stop(/*error_code=*/ VarInt::from_u32(
        control.as_ref().map_or(Aborted as i32, |_| 0) as u32,
    ));
    Ok(control?)
}

/// Open an unidirectional stream and send a `v1::ControlRequest` message to it.
pub async fn write_control(
    conn: &Connection,
    control: &v1::ControlRequest,
) -> Result<v1::ControlResponse> {
    let (send, mut recv) = conn.open_bi().await?;
    write_control_stream(send, control).await?;
    read_control_stream(&mut recv).await
}

/// Send a `v1::ControlRequest` message to a `SendStream`.
pub async fn write_control_stream<P: Message>(mut send: SendStream, message: &P) -> Result<()> {
    let mut buf = Vec::with_capacity(MAX_MESSAGE_SIZE);
    message.encode(&mut buf)?;
    let result = send.write_all(&buf).await;
    tracing::debug_span!("Waiting for the peer to receive all data");
    send.finish()?;
    send.stopped().await?;
    result?;
    Ok(())
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
