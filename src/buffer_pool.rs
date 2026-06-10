use anyhow::Result;
use tokio_uring::buf::fixed::{FixedBuf, FixedBufPool};
use tokio_uring::fs;

/// A fixed-size, preallocated pool of `Vec<u8>` buffers.
pub struct BufferPool {
    buf_size: usize,
    pool: FixedBufPool<Vec<u8>>,
}

impl BufferPool {
    pub fn new(count: usize, buf_size: usize) -> Result<BufferPool> {
        let pool =
            FixedBufPool::new(std::iter::repeat_with(|| Vec::with_capacity(buf_size)).take(count));
        pool.register()?;
        // TODO: unregister
        Ok(BufferPool { buf_size, pool })
    }

    /// Gets an empty buffer from the pool. If no buffer is available, blocks until one is
    /// reclaimed.
    pub async fn pop(&mut self) -> PooledBuffer {
        PooledBuffer {
            buffer: self.pool.next(self.buf_size).await,
        }
    }
}

/// Holds a `FixedBuf` together with a reference that'll return it back to the respective
/// `BufferPool` on destruction.
pub struct PooledBuffer {
    buffer: FixedBuf,
}

impl PooledBuffer {
    /// Reads a frame from `dev` (at offset 0) and returns it as a read-only buffer slice.
    pub async fn read_frame(self, dev: &fs::File) -> std::io::Result<PooledSlice> {
        let PooledBuffer { buffer } = self;
        let (length, read_buf) = dev.read_fixed_at(buffer, 0).await;
        length?;
        Ok(PooledBuffer { buffer: read_buf }.into())
    }

    /// Reads a frame from `dev` at offset 0 and returns it as a read-only buffer slice.
    pub async fn write_frame(self, dev: &fs::File) -> std::io::Result<()> {
        let PooledBuffer { buffer } = self;
        let buf_len = (&buffer).len();
        let (written_len, _write_buf) = dev.write_fixed_at(buffer, 0).await;
        let written_len = written_len?;
        if written_len != buf_len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Buffer length {} != written {}", buf_len, written_len),
            ));
        }
        Ok(())
    }
}

impl std::ops::Deref for PooledBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.buffer.deref()
    }
}

impl std::ops::DerefMut for PooledBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.buffer.deref_mut()
    }
}

pub struct PooledSlice {
    owned: PooledBuffer,
}

/// Creates a read-only view of this buffer. Keeps the ownership of the underlying buffer so that it
/// can be returned to its `BufferPool` on destruction.
impl From<PooledBuffer> for PooledSlice {
    fn from(buf: PooledBuffer) -> Self {
        PooledSlice { owned: buf }
    }
}

impl std::ops::Deref for PooledSlice {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.owned.deref()
    }
}
