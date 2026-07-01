use bytes::Bytes;

pub use crate::buffer_pool::PooledSlice;

pub struct TxPacket {
    pub data: Bytes,
}

pub struct RxPacket {
    pub data: PooledSlice,
    // IP address of the incoming packet will be added here.
}
