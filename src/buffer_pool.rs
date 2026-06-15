use bytes::buf::{BufMut, UninitSlice};
use std::ops::{Deref, DerefMut};
use tokio::io::ReadBuf;
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
            tx.try_send(v.into_boxed_slice())
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
            filled_len: 0,
            reclaim: self.reclaim.downgrade(),
        }
    }
}

/// Holds a buffer together with a reference that'll return it back to the respective
/// `BufferPool` on destruction.
pub struct PooledBuffer {
    /// Preallocated and initialized to a given capacity/
    buffer: Box<[u8]>,
    filled_len: usize,
    reclaim: mpsc::WeakSender<Box<[u8]>>,
}

impl PooledBuffer {
    /// Returns a scoped `ReadBuf` that allows appending to the slice.
    pub fn read_buf<'a>(&'a mut self) -> UpdatingReadBuf<'a> {
        let filled_before = self.filled_len;
        UpdatingReadBuf {
            target: &mut self.filled_len,
            buf: ReadBuf::new(&mut self.buffer[filled_before..]),
        }
    }

    /// Reads a frame from `dev` and returns it as a read-only buffer slice.
    pub async fn read_frame(mut self, dev: &AsyncDevice) -> std::io::Result<PooledSlice> {
        {
            let mut updater = self.read_buf();
            let len = dev.recv(&mut updater.initialized_mut()).await?;
            (&mut updater).advance(len);
        }
        Ok(self.into())
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

unsafe impl BufMut for PooledBuffer {
    fn chunk_mut(&mut self) -> &mut UninitSlice {
        UninitSlice::new(&mut self.buffer[self.filled_len..])
    }

    unsafe fn advance_mut(&mut self, cnt: usize) {
        if cnt > self.remaining_mut() {
            panic!(
                "advance_mut called at offset {} with value {} beyond the buffer size {}",
                cnt,
                self.filled_len,
                self.buffer.len()
            );
        }
        self.filled_len += cnt;
    }

    fn remaining_mut(&self) -> usize {
        self.buffer.len() - self.filled_len
    }
}

/// Writes a frame to `dev` and lets the buffer to be returned to the pool.
pub async fn write_frame(buffer: &[u8], dev: &AsyncDevice) -> std::io::Result<()> {
    let written_len = dev.send(buffer).await?;
    if written_len != buffer.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Buffer length {} != written {}", buffer.len(), written_len),
        ));
    }
    Ok(())
}

impl Deref for PooledBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.buffer[..self.filled_len]
    }
}

pub struct UpdatingReadBuf<'a> {
    target: &'a mut usize,
    buf: ReadBuf<'a>,
}

/// Advances filled size of the underlying `PooledBuffer`.
impl<'a> Drop for UpdatingReadBuf<'a> {
    fn drop(&mut self) {
        *self.target += self.buf.filled().len()
    }
}

impl<'a> Deref for UpdatingReadBuf<'a> {
    type Target = ReadBuf<'a>;

    fn deref(&self) -> &Self::Target {
        &self.buf
    }
}

impl<'a> DerefMut for UpdatingReadBuf<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buf
    }
}

/// An owning, read-only view to a `PooledBuffer`.
pub struct PooledSlice {
    owned: PooledBuffer,
}

impl PooledSlice {
    pub fn clear(self) -> PooledBuffer {
        self.owned
    }
}

impl Deref for PooledSlice {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.owned
    }
}

impl AsRef<[u8]> for PooledSlice {
    fn as_ref(&self) -> &[u8] {
        self.deref()
    }
}

impl From<PooledBuffer> for PooledSlice {
    fn from(owned: PooledBuffer) -> PooledSlice {
        PooledSlice { owned }
    }
}
