use anyhow::Result;
use iroh::endpoint::{Connection, RecvStream, VarInt};
use prost::Message;

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
    let buf = stream.read_to_end(MAX_MESSAGE_SIZE).await?;
    let control = v1::Control::decode(buf.as_slice())?;
    tracing::debug!("Read control command: {:?}", control);
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
