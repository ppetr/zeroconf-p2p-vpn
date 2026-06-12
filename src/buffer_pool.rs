use tokio::sync::mpsc;
use tun_rs::AsyncDevice;

/// A fixed-size, preallocated pool of `Vec<u8>` buffers.
pub struct BufferPool {
    pool: mpsc::Receiver<Vec<u8>>,
    reclaim: mpsc::Sender<Vec<u8>>,
}

impl BufferPool {
    pub fn new(count: usize, buf_size: usize) -> BufferPool {
        let (tx, rx) = mpsc::channel(count);
        for _ in 0..count {
            tx.try_send(Vec::with_capacity(buf_size))
                .expect("when filling up BufferPool");
        }
        BufferPool {
            pool: rx,
            reclaim: tx,
        }
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
    pub async fn read_frame(mut self, dev: &AsyncDevice) -> std::io::Result<PooledSlice> {
        tracing::info!("Reading frame");
        unsafe {
            self.buffer.set_len(self.buffer.capacity());
        }
        let len = dev.recv(&mut self.buffer).await?;
        unsafe {
            self.buffer.set_len(len);
        }
        Ok(self.into())
    }

    /// Writes a frame to `dev` at offset 0 and lets the buffer to be returned to the pool.
    pub async fn write_frame(self, dev: &AsyncDevice) -> std::io::Result<()> {
        let written_len = dev.send(&self.buffer).await?;
        if written_len != self.buffer.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "Buffer length {} != written {}",
                    self.buffer.len(),
                    written_len
                ),
            ));
        }
        Ok(())
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        assert!(self.buffer.capacity() > 0);
        // Ensure no uninitialized memory leaks out.
        unsafe {
            self.buffer.set_len(0);
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
    pub async fn write_frame(self, dev: &AsyncDevice) -> std::io::Result<()> {
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
