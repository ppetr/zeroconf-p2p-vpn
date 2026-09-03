use bytes::buf::{BufMut, UninitSlice};
use std::ops::{Deref, DerefMut};
use tokio::io::ReadBuf;
use tokio::sync::mpsc;
use tun_rs::AsyncDevice;

/// A fixed-size, preallocated pool of `Box<[u8]>` buffers.
pub struct BufferPool {
    pool: mpsc::Receiver<Box<[u8]>>,
    reclaim: mpsc::Sender<Box<[u8]>>,
    capacity_gauge: metrics::Gauge,
}

impl BufferPool {
    pub fn new(count: usize, buf_size: usize, capacity_gauge: metrics::Gauge) -> BufferPool {
        let (tx, rx) = mpsc::channel(count);
        capacity_gauge.set(count as u32);
        for _ in 0..count {
            tx.try_send(vec![0u8; buf_size].into_boxed_slice())
                .expect("when filling up BufferPool");
        }
        BufferPool {
            pool: rx,
            reclaim: tx,
            capacity_gauge,
        }
    }

    /// Gets an empty buffer from the pool. If no buffer is available, blocks until one is
    /// reclaimed.
    pub async fn pop(&mut self) -> PooledBuffer {
        let result = PooledBuffer {
            buffer: self
                .pool
                .recv()
                .await
                .expect("`pool` can't be closed since it's held by `self`"),
            filled_len: 0,
            reclaim: self.reclaim.downgrade(),
            capacity_gauge: self.capacity_gauge.clone(),
        };
        metrics::gauge!("p2p_vpn_buffer_pool_active").increment(1);
        report_available(&self.reclaim, &self.capacity_gauge);
        result
    }
}

fn report_available(sender: &mpsc::Sender<Box<[u8]>>, capacity_gauge: &metrics::Gauge) {
    capacity_gauge.set((sender.max_capacity() - sender.capacity()) as u32);
}

/// Holds a buffer together with a reference that'll return it back to the respective
/// `BufferPool` on destruction.
pub struct PooledBuffer {
    /// Preallocated and initialized to given capacity.
    buffer: Box<[u8]>,
    filled_len: usize,
    reclaim: mpsc::WeakSender<Box<[u8]>>,
    capacity_gauge: metrics::Gauge,
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
            metrics::gauge!("p2p_vpn_buffer_pool_active").decrement(1);
            report_available(&sender, &self.capacity_gauge);
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
        let msg = format!("Buffer length {} != written {}", buffer.len(), written_len);
        tracing::warn!(msg);
        return Err(std::io::Error::new(std::io::ErrorKind::Other, msg));
    }
    Ok(())
}

impl Deref for PooledBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.buffer[..self.filled_len]
    }
}

impl DerefMut for PooledBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buffer[..self.filled_len]
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
    pub fn to_buffer(self) -> PooledBuffer {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn pool(count: usize, buf_size: usize) -> BufferPool {
        BufferPool::new(count, buf_size, metrics::Gauge::noop())
    }

    #[tokio::test]
    async fn new_prefills_count_buffers_of_the_requested_size() {
        let mut pool = pool(3, 16);
        for _ in 0..3 {
            let buf = pool.pop().await;
            assert_eq!(buf.remaining_mut(), 16);
            assert_eq!(buf.len(), 0); // nothing filled yet
        }
    }

    #[tokio::test]
    #[ntest::timeout(2000)]
    async fn pop_blocks_until_a_buffer_is_returned() {
        tokio::time::pause();
        let mut pool = pool(1, 8);

        let buf = pool.pop().await;
        // The only buffer is checked out, so a further pop cannot make progress.
        assert!(tokio::time::timeout(Duration::from_millis(50), pool.pop())
            .await
            .is_err());

        drop(buf); // returns the buffer to the pool
        assert!(tokio::time::timeout(Duration::from_millis(50), pool.pop())
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn dropping_a_buffer_after_the_pool_is_gone_does_not_panic() {
        let mut pool = pool(1, 8);
        let buf = pool.pop().await;
        drop(pool);
        // The `WeakSender` can no longer be upgraded, so `Drop` is a silent no-op.
        drop(buf);
    }

    #[tokio::test]
    async fn buf_mut_writes_are_visible_through_deref() {
        let mut pool = pool(1, 8);
        let mut buf = pool.pop().await;

        buf.put_slice(&[1, 2, 3]);
        assert_eq!(&buf[..], &[1, 2, 3]);
        assert_eq!(buf.remaining_mut(), 5);

        buf.put_slice(&[4, 5]);
        assert_eq!(&buf[..], &[1, 2, 3, 4, 5]);
        assert_eq!(buf.remaining_mut(), 3);
    }

    #[tokio::test]
    #[should_panic(expected = "beyond the buffer size")]
    async fn advance_mut_past_capacity_panics() {
        let mut pool = pool(1, 4);
        let mut buf = pool.pop().await;
        unsafe { buf.advance_mut(5) };
    }

    #[tokio::test]
    async fn read_buf_commits_the_written_region_on_drop() {
        let mut pool = pool(1, 8);
        let mut buf = pool.pop().await;

        {
            let mut read_buf = buf.read_buf();
            read_buf.put_slice(&[7, 7, 7]);
        }
        assert_eq!(&buf[..], &[7, 7, 7]);
        assert_eq!(buf.remaining_mut(), 5);

        // A second scoped write appends after the first.
        {
            let mut read_buf = buf.read_buf();
            read_buf.put_slice(&[8]);
        }
        assert_eq!(&buf[..], &[7, 7, 7, 8]);
    }

    #[tokio::test]
    async fn pooled_slice_exposes_the_filled_bytes_and_converts_back() {
        let mut pool = pool(1, 8);
        let mut buf = pool.pop().await;
        buf.put_slice(&[4, 5, 6]);

        let slice: PooledSlice = buf.into();
        assert_eq!(slice.as_ref(), &[4, 5, 6]);
        assert_eq!(&slice[..], &[4, 5, 6]);

        let buf = slice.to_buffer();
        assert_eq!(&buf[..], &[4, 5, 6]);
        assert_eq!(buf.remaining_mut(), 5);
    }

    #[tokio::test]
    #[ntest::timeout(2000)]
    async fn dropping_a_pooled_slice_returns_the_buffer_to_the_pool() {
        tokio::time::pause();
        let mut pool = pool(1, 8);

        let slice: PooledSlice = pool.pop().await.into();
        assert!(tokio::time::timeout(Duration::from_millis(50), pool.pop())
            .await
            .is_err());

        drop(slice);
        assert!(tokio::time::timeout(Duration::from_millis(50), pool.pop())
            .await
            .is_ok());
    }
}
