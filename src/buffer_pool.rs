use tokio::sync::mpsc;
use tokio_uring::fs;

/// A fixed-size, preallocated pool of `Vec<u8>` buffers.
pub struct BufferPool {
    tx: mpsc::Sender<Vec<u8>>,
    rx: mpsc::Receiver<Vec<u8>>,
}

impl BufferPool {
    pub fn new(count: usize, buf_size: usize) -> BufferPool {
        let (tx, rx) = mpsc::channel(count);
        for _ in 0..count {
            tx.try_send(Vec::<u8>::with_capacity(buf_size)).unwrap();
        }
        BufferPool { tx, rx }
    }

    /// Gets an empty buffer from the pool. If no buffer is available, blocks until one is
    /// reclaimed.
    pub async fn pop(&mut self) -> BorrowedBuffer {
        BorrowedBuffer {
            return_queue: self.tx.clone(),
            buffer: self.rx.recv().await.expect("mpsc dropped unexpectedly"),
        }
    }
}

/// Holds a `Vec<u8>` together with a reference that'll return it back to the respective
/// `BufferPool` on destruction.
pub struct BorrowedBuffer {
    return_queue: mpsc::Sender<Vec<u8>>,
    pub buffer: Vec<u8>,
}

impl BorrowedBuffer {
    pub async fn read_frame(&mut self, file: &fs::File) -> std::io::Result<()> {
        let (length, read_buf) = file.read_at(std::mem::take(&mut self.buffer), 0).await;
        self.buffer = read_buf;
        length?;
        Ok(())
    }

    /// Creates a read-only view of this buffer. Keeps the ownership of the underlying `Vec<u8>` so
    /// that it can be returned to its `BufferPool` on destruction.
    pub fn slice(self) -> BorrowedSlice {
        BorrowedSlice { buffer: self }
    }
}

impl Drop for BorrowedBuffer {
    fn drop(&mut self) {
        if self.buffer.capacity() > 0 {
            let mut buf = std::mem::take(&mut self.buffer);
            buf.clear(); // Keeps capacity intact, resets indices
                         // TrySendError::Full never occurs.
                         // And we can safely ignore TrySendError::Closed.
            let _ = self.return_queue.try_send(buf);
        }
    }
}

pub struct BorrowedSlice {
    buffer: BorrowedBuffer,
}

impl BorrowedSlice {
    pub fn as_slice(&self) -> &[u8] {
        self.buffer.buffer.as_slice()
    }
}

impl std::ops::Deref for BorrowedSlice {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}
