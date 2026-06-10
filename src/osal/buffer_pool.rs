use anyhow::Result;
use tokio::sync::mpsc;
use tokio_uring::fs;

/// A fixed-size, preallocated pool of `Vec<u8>` buffers.
pub struct BufferPool {
    pool: mpsc::Receiver<Vec<u8>>,
    reclaim: mpsc::Sender<Vec<u8>>,
}

impl BufferPool {
    pub fn new(count: usize, buf_size: usize) -> Result<BufferPool> {
        let (tx, rx) = mpsc::channel(count);
        for _ in 0..count {
            tx.try_send(Vec::with_capacity(buf_size))?;
        }
        Ok(BufferPool {
            pool: rx,
            reclaim: tx,
        })
    }

    /// Gets an empty buffer from the pool. If no buffer is available, blocks until one is
    /// reclaimed.
    pub async fn pop(&mut self) -> PooledBuffer {
        PooledBuffer {
            buffer: self
                .pool
                .recv()
                .await
                .expect("`pool` can't be closed since it's held by `self`"),
            reclaim: self.reclaim.downgrade(),
        }
    }
}

/// Holds a buffer together with a reference that'll return it back to the respective
/// `BufferPool` on destruction.
pub struct PooledBuffer {
    buffer: Vec<u8>,
    reclaim: mpsc::WeakSender<Vec<u8>>,
}

impl PooledBuffer {
    /// Reads a frame from `dev` (at offset 0) and returns it as a read-only buffer slice.
    pub async fn read_frame(mut self, dev: &fs::File) -> std::io::Result<PooledSlice> {
        let buffer = std::mem::take(&mut self.buffer);
        let (length, read_buf) = dev.read_at(buffer, 0).await;
        length?;
        Ok(PooledBuffer {
            buffer: read_buf,
            reclaim: self.reclaim.clone(),
        }
        .into())
    }

    /// Writes a frame to `dev` at offset 0 and lets the buffer to be returned to the pool.
    pub async fn write_frame(mut self, dev: &fs::File) -> std::io::Result<()> {
        let buffer = std::mem::take(&mut self.buffer);
        let buf_len = (&buffer).len();
        let (written_len, _write_buf) = dev.write_at(buffer, 0).submit().await;
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

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        if self.buffer.is_empty() {
            return;
        }
        if let Some(sender) = self.reclaim.upgrade() {
            match sender.try_send(std::mem::take(&mut self.buffer)) {
                Ok(()) => (),
                Err(mpsc::error::TrySendError::Closed(_)) => (),
                err => err.expect("can't happen: `pool` is full"),
            }
        }
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

impl PooledSlice {
    /// Writes a frame to `dev` at offset 0 and lets the buffer to be returned to the pool.
    pub async fn write_frame(self, dev: &fs::File) -> std::io::Result<()> {
        self.owned.write_frame(dev).await
    }
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
