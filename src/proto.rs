use anyhow::Result;
use buf_list::BufList;
use bytes::Bytes;
use iroh::endpoint::{Connection, RecvStream, SendStream, VarInt};
use metrics::*;
use prost::Message;
use std::fmt::Debug;
use std::num::NonZeroI32;
use thin_status::{ErrorCode::*, ThinStatus, ThinStatusExt};

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

/// Close `conn` at the QUIC layer, carrying `status`'s code and message in the connection-close
/// frame. This is what the peer reads back as a `ThinStatus` when its own in-flight request
/// resolves with a connection-closed error.
pub fn close_connection(conn: &Connection, status: &ThinStatus) {
    conn.close(VarInt::from_u32(i32::from(status.code_raw()) as u32), status.message().as_bytes());
}

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
            Err(ThinStatus::builder(code).message(message.as_deref().unwrap_or("")).build())
        }
        _ => Ok(()),
    }
}

/// Accept a bidirectional stream, read a `v1::ControlRequest` from it, run `f`, and send `f`'s
/// outcome back as a `v1::ControlResponse` on the same stream.
pub async fn read_control<F, R>(conn: &Connection, f: F) -> Result<R, ThinStatus>
where
    F: AsyncFnOnce(v1::ControlRequest) -> Result<R, ThinStatus>,
{
    let (send, mut recv) = conn.accept_bi().await.map_err(|e| e.error_code(FailedPrecondition))?;
    let request = match read_control_stream(&mut recv).await {
        Err(e) => {
            let e = e.context("Received a malformed message from the peer");
            tracing::info!(error = ?e);
            counter!(description: "Received malformed v1::ControlRequest messages",
                "p2p_vpn_proto_read_control_message_errors", ExtractedErrorCode::from_anyhow(&e))
            .increment(1);
            return Err(e.error_code(DataLoss));
        }
        Ok(r) => r,
    };
    let response = f(request).await;
    let control_response: v1::ControlResponse = match &response {
        Ok(_) => Default::default(),
        Err(status) => status_to_control(status.clone()),
    };
    write_control_stream(send, &control_response).await.map_err(|e| e.error_code(Aborted))?;
    response
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

/// Open a bidirectional stream, send `control` on it, and read back the peer's `v1::ControlResponse`.
pub async fn write_control(
    conn: &Connection,
    control: &v1::ControlRequest,
) -> Result<v1::ControlResponse> {
    let (send, mut recv) = conn.open_bi().await?;
    write_control_stream(send, control).await?;
    read_control_stream(&mut recv).await
}

/// Encode `message` and write it to `send`, then wait for the peer to acknowledge receipt of the
/// whole stream.
pub async fn write_control_stream<P: Message>(mut send: SendStream, message: &P) -> Result<()> {
    let mut buf = Vec::with_capacity(MAX_MESSAGE_SIZE);
    message.encode(&mut buf)?;
    let result = send.write_all(&buf).await;
    let _span = tracing::debug_span!("Waiting for the peer to receive all data");
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

#[cfg(test)]
mod tests {
    use super::*;
    use thin_status::ErrorCode;

    fn status(code: i32, message: Option<&str>) -> v1::ControlResponse {
        v1::ControlResponse {
            status: Some(v1::Status { code, message: message.map(str::to_string) }),
        }
    }

    #[test]
    fn control_to_status_is_ok_when_no_status_is_present() {
        assert_eq!(control_to_status(v1::ControlResponse { status: None }), Ok(()));
    }

    #[test]
    fn default_control_response_maps_to_ok() {
        // This is exactly what `read_control` writes back on the success path.
        assert_eq!(control_to_status(v1::ControlResponse::default()), Ok(()));
    }

    #[test]
    fn control_to_status_treats_zero_code_as_ok_even_with_a_message() {
        assert_eq!(control_to_status(status(0, None)), Ok(()));
        assert_eq!(control_to_status(status(0, Some("ignored"))), Ok(()));
    }

    #[test]
    fn control_to_status_maps_a_known_nonzero_code_and_message_to_err() {
        let err = control_to_status(status(ErrorCode::Internal as i32, Some("boom"))).unwrap_err();
        assert_eq!(err.code(), Some(ErrorCode::Internal));
        assert_eq!(err.message(), "boom");
    }

    #[test]
    fn control_to_status_uses_an_empty_message_when_none_is_given() {
        let err = control_to_status(status(ErrorCode::Aborted as i32, None)).unwrap_err();
        assert_eq!(err.code(), Some(ErrorCode::Aborted));
        assert_eq!(err.message(), "");
    }

    #[test]
    fn control_to_status_passes_through_codes_that_are_not_known_error_codes() {
        let err = control_to_status(status(9999, Some("weird"))).unwrap_err();
        assert_eq!(err.code_raw().get(), 9999);
        assert_eq!(err.code(), None);
        assert_eq!(err.message(), "weird");

        let negative = control_to_status(status(-7, None)).unwrap_err();
        assert_eq!(negative.code_raw().get(), -7);
        assert_eq!(negative.code(), None);
    }

    #[test]
    fn status_to_control_serializes_code_and_message() {
        let response = status_to_control(
            ThinStatus::builder(ErrorCode::InvalidArgument).message("nope").build(),
        );
        let status = response.status.expect("status should be populated");
        assert_eq!(status.code, ErrorCode::InvalidArgument as i32);
        assert_eq!(status.message.as_deref(), Some("nope"));
    }

    #[test]
    fn status_to_control_emits_an_empty_message_when_the_status_has_none() {
        let response = status_to_control(ThinStatus::builder(ErrorCode::Aborted).build());
        let status = response.status.expect("status should be populated");
        assert_eq!(status.code, ErrorCode::Aborted as i32);
        assert_eq!(status.message.as_deref(), Some(""));
    }

    #[test]
    fn status_survives_a_control_round_trip() {
        let original = ThinStatus::builder(ErrorCode::DataLoss).message("half gone").build();
        let restored = control_to_status(status_to_control(original.clone())).unwrap_err();
        assert_eq!(restored.code(), Some(ErrorCode::DataLoss));
        assert_eq!(restored.message(), "half gone");
        assert_eq!(restored, original);
    }
}
