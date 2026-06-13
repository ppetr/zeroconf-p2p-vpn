use tokio::sync::mpsc;
use tun_rs::AsyncDevice;

/// A fixed-size, preallocated pool of `Box<[u8]>` buffers.
pub struct BufferPool {
    pool: mpsc::Receiver<Box<[u8]>>,
    reclaim: mpsc::Sender<Box<[u8]>>,
}

impl BufferPool {
    pub fn new(count: usize, buf_size: usize) -> BufferPool {
        let (tx, rx) = mpsc::channel(count);
        for _ in 0..count {
            let mut v = Vec::with_capacity(buf_size);
            v.resize(buf_size, 0);
            tx.try_send(v.into_boxed_slice()).expect("when filling up BufferPool");
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
    /// Preallocated and initialized to a given capacity/
    buffer: Box<[u8]>,
    reclaim: mpsc::WeakSender<Box<[u8]>>,
}

impl PooledBuffer {
    pub fn into_slice(self, filled_len: usize) -> PooledSlice {
        PooledSlice{ owned: self, filled_len }
    }

    /// Reads a frame from `dev` (at offset 0) and returns it as a read-only buffer slice.
    pub async fn read_frame(mut self, dev: &AsyncDevice) -> std::io::Result<PooledSlice> {
        let len = dev.recv(&mut self.buffer).await?;
        Ok(self.into_slice(len))
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
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
    filled_len: usize,
}

impl PooledSlice {
    /// Writes a frame to `dev` at offset 0 and lets the buffer to be returned to the pool.
    pub async fn write_frame(self, dev: &AsyncDevice) -> std::io::Result<()> {
        let written_len = dev.send(&self.owned.buffer).await?;
        if written_len != self.filled_len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "Buffer length {} != written {}",
                    self.filled_len,
                    written_len
                ),
            ));
        }
        Ok(())
    }
}

impl std::ops::Deref for PooledSlice {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.owned[..self.filled_len]
    }
}
