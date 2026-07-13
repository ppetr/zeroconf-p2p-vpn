use std::convert::Infallible;
use std::sync::Arc;
use thin_status::{ErrorCode::*, ThinStatus, ThinStatusExt};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum Direction {
    Incoming,
    Outgoing,
}

/// Trait abstracting operations required by the actor over a connection handle.
///
pub trait ManagedConnection: std::fmt::Debug + Send + Sync + 'static {
    type Key: Ord + Clone;
    /// Allows determining if a connection being closed (reported by `spawn_closed_watcher`) is the
    /// current one.
    type ConnectionId: PartialEq<Self>;

    /// Whether this direction is Incoming or Outgoing.
    fn direction(&self) -> Direction;
    /// Close this connection with a reason.
    fn close_connection(self, status: ThinStatus);
    /// Spawns an asynchronous thread that notifies `on_close` once this connection is closed.
    fn spawn_closed_watcher(&self, on_close: mpsc::Sender<Self::ConnectionId>);
}

pub struct Actor<C: ManagedConnection> {
    preferred: Direction,
    watch_tx: watch::Sender<Option<C>>,
    conn_tx: mpsc::Sender<C>,
    conn_rx: mpsc::Receiver<C>,
}

impl<C: ManagedConnection> Actor<C> {
    /// Creates a new instance, provided the necessary pieces to attach a threat that opens new
    /// connections on demand.
    ///
    /// `local_key` - the key of the local connection, to be compared with `C::peer_key()`.
    /// `watch_tx` - notifications of new or dropped connections are sent to this `watch`.
    pub fn new(local_key: C::Key, remote_key: C::Key, watch_tx: watch::Sender<Option<C>>) -> Self {
        let (conn_tx, conn_rx) = mpsc::channel(32);
        Self {
            preferred: if local_key > remote_key {
                Direction::Outgoing
            } else {
                Direction::Incoming
            },
            watch_tx,
            conn_tx,
            conn_rx,
        }
    }

    /// Allows callers to subscribe to connection changes.
    pub fn subscribe(&self) -> watch::Receiver<Option<C>> {
        self.watch_tx.subscribe()
    }

    /// Both incoming and outgoing connections are submitted to this queue.
    pub fn connection_queue(&self) -> mpsc::Sender<C> {
        self.conn_tx.clone()
    }

    pub async fn run(&mut self, cancellation: CancellationToken) -> Result<Infallible, ThinStatus> {
        let _cancel = cancellation.drop_guard_ref();
        let (closed_tx, mut closed_rx) = mpsc::channel(32);

        let result = loop {
            tokio::select! {
                _ = cancellation.cancelled() => break Cancelled.into(),
                c = self.conn_rx.recv() => if let Some(conn) = c {
                        self.handle_connection_candidate(&closed_tx, conn)
                    } else {
                        break "Incoming connection queue closed".error_code(FailedPrecondition)
                    },
                Some(closed_conn) = closed_rx.recv() => self.handle_connection_closed(closed_conn),
            }
        };
        self.watch_tx.send_if_modified(|current| {
            if let Some(conn) = std::mem::replace(current, None) {
                conn.close_connection(result.clone());
            }
            // Do not notify the connector as we won't accept any more connections.
            false
        });
        Err(result)
    }

    fn handle_connection_candidate(&self, closed_tx: &mpsc::Sender<C::ConnectionId>, new_conn: C) {
        self.watch_tx.send_if_modified(|current| {
            // Apply transition directly to the authoritative Watch channel
            match &mut *current {
                Some(current) if new_conn.direction() != self.preferred => {
                    tracing::debug!("Rejecting new {:?}; current: {:?}", new_conn, current);
                    new_conn.close_connection(
                        "Rejected by deterministic preference rule".error_code(Aborted),
                    );
                    false
                }
                current => {
                    tracing::debug!("Replacing current {:?} by new {:?}", current, new_conn);
                    // Spawn monitoring task for the newly installed connection
                    new_conn.spawn_closed_watcher(closed_tx.clone());
                    // Update authoritative watch state without emitting intermediate None
                    let replaced = std::mem::replace(current, Some(new_conn));
                    // Gracefully close the replaced connection after watch state transition
                    if let Some(old_conn) = replaced {
                        old_conn.close_connection(
                            "Replaced by new connection following deterministic preference rule"
                                .error_code(Aborted),
                        );
                    }
                    true
                }
            }
        });
    }

    fn handle_connection_closed(&self, closed_conn_id: C::ConnectionId) {
        self.watch_tx.send_if_modified(|current| {
            // Only clear state if the closed connection matches the current authoritative handle exactly
            if let Some(active) = current {
                if closed_conn_id == *active {
                    *current = None;
                    return true;
                }
            }
            false
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::OnceLock;

    use tokio::sync::{mpsc, watch};
    use tokio::time::{timeout, Duration};
    use tokio_util::sync::CancellationToken;

    #[derive(Clone, Debug)]
    struct FakeConnection {
        id: isize,
        direction: Direction,
        closed_tx: watch::Sender<bool>,
        closed_rx: watch::Receiver<bool>,
        closed_signal: Arc<OnceLock<mpsc::Sender<isize>>>,
    }

    impl FakeConnection {
        fn new(id: isize, direction: Direction) -> Self {
            let (closed_tx, closed_rx) = watch::channel(false);
            Self {
                id,
                direction,
                closed_tx,
                closed_rx,
                closed_signal: Arc::new(OnceLock::new()),
            }
        }

        fn was_closed(&self) -> bool {
            *self.closed_rx.borrow()
        }

        async fn close_from_remote(&self) {
            self.closed_signal
                .get()
                .expect("closed watcher was not installed")
                .send(self.id)
                .await
                .unwrap();
        }
    }

    impl PartialEq<FakeConnection> for isize {
        fn eq(&self, other: &FakeConnection) -> bool {
            *self == other.id
        }
    }

    impl ManagedConnection for FakeConnection {
        type Key = isize;
        type ConnectionId = isize;

        fn direction(&self) -> Direction {
            self.direction
        }

        fn close_connection(self, _: ThinStatus) {
            let _ = self.closed_tx.send(true);
        }

        fn spawn_closed_watcher(&self, on_close: mpsc::Sender<Self::ConnectionId>) {
            self.closed_signal
                .set(on_close)
                .expect("closed watcher installed twice");
        }
    }

    struct TestActor {
        sender: mpsc::Sender<FakeConnection>,
        receiver: watch::Receiver<Option<FakeConnection>>,
        cancellation: CancellationToken,
    }

    impl TestActor {
        fn new(local_key: isize, remote_key: isize) -> Self {
            let (watch_tx, watch_rx) = watch::channel(None);

            let cancellation = CancellationToken::new();

            let mut actor = Actor::new(local_key, remote_key, watch_tx);

            let sender = actor.connection_queue();

            let cancellation_clone = cancellation.clone();
            tokio::spawn(async move { actor.run(cancellation_clone).await });

            TestActor {
                sender,
                receiver: watch_rx,
                cancellation,
            }
        }

        async fn send(&mut self, conn: &FakeConnection) {
            self.sender.send(conn.clone()).await.unwrap();
        }

        async fn send_and_wait(&mut self, conn: &FakeConnection) -> FakeConnection {
            self.sender.send(conn.clone()).await.unwrap();
            self.wait_for_connection()
                .await
                .expect("connection was not installed")
        }

        async fn wait_for_connection(&mut self) -> Option<FakeConnection> {
            timeout(Duration::from_secs(1), async {
                self.receiver
                    .changed()
                    .await
                    .expect("Connection queue closed");
                self.receiver.borrow_and_update().clone()
            })
            .await
            .expect("timed out waiting for a connection")
        }
    }

    #[tokio::test]
    async fn subscribe_initially_returns_none() {
        let mut actor = TestActor::new(1, 2);

        assert!(actor.receiver.borrow_and_update().is_none());

        actor.cancellation.cancel();
    }

    #[tokio::test]
    async fn accepts_first_connection_even_if_not_preferred() {
        let mut actor = TestActor::new(1, 2);

        // Local key is smaller, therefore incoming is preferred.
        // The first connection is accepted regardless of direction.

        let conn = FakeConnection::new(1, Direction::Outgoing);

        let current = actor.send_and_wait(&conn).await;

        assert_eq!(current.id, 1);
        assert!(!conn.was_closed());

        actor.cancellation.cancel();
    }

    #[tokio::test]
    async fn preferred_connection_replaces_existing_connection() {
        let mut actor = TestActor::new(2, 1);

        // Local key is larger, therefore outgoing is preferred.
        let incoming = FakeConnection::new(1, Direction::Incoming);
        let outgoing = FakeConnection::new(2, Direction::Outgoing);

        let _ = actor.send_and_wait(&incoming).await;
        let current = actor.send_and_wait(&outgoing).await;

        assert_eq!(current.id, outgoing.id);
        assert!(incoming.was_closed());
        assert!(!outgoing.was_closed());

        actor.cancellation.cancel();
    }

    #[tokio::test]
    async fn non_preferred_connection_is_rejected() {
        let mut actor = TestActor::new(2, 1);

        // Local key is larger, therefore outgoing is preferred.
        let outgoing = FakeConnection::new(1, Direction::Outgoing);
        let incoming = FakeConnection::new(2, Direction::Incoming);

        let _ = actor.send_and_wait(&outgoing).await;
        actor.send(&incoming).await;

        timeout(Duration::from_secs(1), async {
            while !incoming.was_closed() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("timed out waiting for `incoming` to be closed by `actor`");

        assert!(!actor.receiver.has_changed().unwrap());
        let current = actor
            .receiver
            .borrow_and_update()
            .clone()
            .expect("connection was not installed");
        assert_eq!(current.id, outgoing.id);

        actor.cancellation.cancel();
    }

    #[tokio::test]
    async fn closing_active_connection_clears_watch() {
        let mut actor = TestActor::new(1, 2);

        let conn = FakeConnection::new(1, Direction::Incoming);

        let _ = actor.send_and_wait(&conn).await;

        conn.close_from_remote().await;

        let current = actor.wait_for_connection().await;
        assert!(current.is_none());

        actor.cancellation.cancel();
    }

    #[tokio::test]
    async fn closing_replaced_connection_is_ignored() {
        let mut actor = TestActor::new(2, 1);

        let old = FakeConnection::new(1, Direction::Incoming);
        let new = FakeConnection::new(2, Direction::Outgoing);

        let _ = actor.send_and_wait(&old).await;

        let _ = actor.send_and_wait(&new).await;

        old.close_from_remote().await;

        let current = actor
            .receiver
            .borrow_and_update()
            .clone()
            .expect("connection was not installed");

        assert_eq!(current.id, new.id);

        actor.cancellation.cancel();
    }

    #[tokio::test]
    async fn shutdown_closes_active_connection() {
        let mut actor = TestActor::new(1, 2);

        let mut conn = FakeConnection::new(1, Direction::Incoming);

        let current = actor.send_and_wait(&conn).await;
        assert_eq!(current.id, conn.id);
        conn.closed_rx.mark_unchanged();

        actor.cancellation.cancel();

        conn.closed_rx.changed().await.unwrap();
        assert!(conn.was_closed());
    }

    #[tokio::test]
    async fn preference_depends_on_key_order() {
        let mut actor_a = TestActor::new(1, 2);
        let mut actor_b = TestActor::new(2, 1);

        let incoming = FakeConnection::new(1, Direction::Incoming);
        let outgoing = FakeConnection::new(2, Direction::Outgoing);

        let selected_a = actor_a.send_and_wait(&incoming).await;
        let selected_b = actor_b.send_and_wait(&outgoing).await;

        assert_eq!(selected_a.direction, Direction::Incoming);
        assert_eq!(selected_b.direction, Direction::Outgoing);

        actor_a.cancellation.cancel();
        actor_b.cancellation.cancel();
    }
}
