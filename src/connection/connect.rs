use backoff::backoff::Backoff;
use std::convert::Infallible;
use thin_status::{ErrorCode::*, ThinStatus, ThinStatusExt};
use tokio::sync::{mpsc, watch, Notify};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

pub trait OutgoingConnector {
    type Connection: Send;
    type Error: std::fmt::Debug + std::fmt::Display;

    async fn connect(&self) -> Result<Self::Connection, Self::Error>;
}

pub struct OutgoingConnectLoop<C: OutgoingConnector> {
    connector: C,
    watch_rx: watch::Receiver<Option<C::Connection>>,
    tx: mpsc::Sender<C::Connection>,
}

impl<C: OutgoingConnector> OutgoingConnectLoop<C> {
    pub fn new(
        connector: C,
        watch_rx: watch::Receiver<Option<C::Connection>>,
        tx: mpsc::Sender<C::Connection>,
    ) -> Self {
        Self {
            connector,
            watch_rx,
            tx,
        }
    }

    pub async fn run(
        mut self,
        retry_backoff: &mut impl Backoff,
        cancellation: CancellationToken,
    ) -> Result<Infallible, ThinStatus> {
        retry_backoff.reset();
        let _cancel = cancellation.drop_guard_ref();
        let err = loop {
            // Read the current state and mark it as seen
            if self.watch_rx.borrow_and_update().is_some() {
                tracing::debug!("Connection is active; resetting back-off and waiting until a new connection is needed");
                tokio::select! {
                    _ = cancellation.cancelled() => break Cancelled.into(),
                    changed_res = self.watch_rx.changed() => if let Err(e) = changed_res { break e.error_code(FailedPrecondition) },
                }
                retry_backoff.reset();
                continue;
            }

            tracing::debug!("No connection active; attempting to reconnect");
            let Some(delay) = retry_backoff.next_backoff() else {
                // ExponentialBackoff runs indefinitely by default,
                // but if limits are customized, exit when max elapsed time is reached.
                break "Backoff exhausted, terminating connection loop"
                    .error_code(FailedPrecondition);
            };

            if delay > std::time::Duration::ZERO {
                let span = tracing::debug_span!("backoff_sleep");
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {
                        // Backoff delay expired, proceed to connect
                    }
                    changed_res = self.watch_rx.changed() => {
                        span.record("interrupted", "connected/disconnected event");
                        if let Err(e) = changed_res {
                            break e.error_code(FailedPrecondition);
                        }
                        tracing::debug!("Connection update, resetting the backoff");
                        retry_backoff.reset();
                        continue;
                    }
                    _ = cancellation.cancelled() => break Cancelled.into(),
                }
            }

            tracing::debug!("Initiating a new connection");
            tokio::select! {
                r = self.connector.connect() => match r {
                    Ok(connection) => {
                        tracing::debug!("Submitting a connection to the queue");
                        if let Err(e) = self.tx.send(connection).await {
                            tracing::debug!("Connection queue dropped, terminating the loop");
                            break e.error_code(FailedPrecondition);
                        }

                        // Wait for the self update to reflect in the watch channel
                        // to avoid immediately reading the stale None state in the next iteration.
                        tokio::select! {
                            _ = cancellation.cancelled() => break Cancelled.into(),
                            changed_res = self.watch_rx.changed() => if let Err(e) = changed_res { break e.error_code(FailedPrecondition) },
                        }
                        tracing::debug!("Successfully submitted a connection to the queue");
                        retry_backoff.reset();
                    }
                    Err(err) => {
                        tracing::info!(error = ?err, "Connection attempt failed, retrying with a back-off");
                    }
                },
                _ = cancellation.cancelled() => break Cancelled.into(),
            }
        };
        tracing::info!(error = ?err, "Exiting connector loop");
        Err(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::Duration;
    use tokio::sync::{mpsc, watch};

    #[derive(Debug)]
    struct MockBackoff {
        delays: Vec<Duration>,
        index: isize,
        reset_tx: watch::Sender<isize>,
        reset_rx: watch::Receiver<isize>,
    }

    impl MockBackoff {
        fn new(delays: Vec<Duration>) -> Self {
            let (reset_tx, reset_rx) = watch::channel(0);
            Self {
                delays,
                index: -1,
                reset_tx,
                reset_rx,
            }
        }
    }

    impl backoff::backoff::Backoff for MockBackoff {
        fn next_backoff(&mut self) -> Option<Duration> {
            self.index += 1;
            self.delays.get(self.index as usize).copied()
        }

        fn reset(&mut self) {
            self.reset_tx.send(self.index + 1).unwrap();
            self.index = -1;
        }
    }

    struct MockConnector {
        /// Mutex allows mutating the vector even in non-`mut` `connect` function.
        connect_results: Mutex<Vec<Result<i32, &'static str>>>,
        connected: Notify,
    }

    impl MockConnector {
        fn new(mut results: Vec<Result<i32, &'static str>>) -> Self {
            results.reverse(); // FIFO order from a vector
            Self {
                connect_results: Mutex::new(results),
                connected: Notify::new(),
            }
        }
    }

    impl OutgoingConnector for MockConnector {
        type Connection = i32;
        type Error = &'static str;

        async fn connect(&self) -> Result<Self::Connection, Self::Error> {
            self.connected.notify_one();
            let mut guard = self.connect_results.lock().unwrap();
            guard.pop().unwrap_or(Err("No more configured results"))
        }
    }

    // --- Tests ---

    #[tokio::test]
    #[test_log::test]
    #[ntest::timeout(300)]
    async fn test_successful_connection_flow() {
        // Scenario: Starts with None -> Connects successfully -> Sends to mpsc ->
        //           Waits for watch_rx to update -> Resets backoff -> Enters active state loop.
        tokio::time::pause();

        let (watch_tx, mut watch_rx) = watch::channel(None);
        let (mpsc_tx, mut mpsc_rx) = mpsc::channel(1);

        let connector = MockConnector::new(vec![Ok(42)]);
        let mut backoff = MockBackoff::new(vec![Duration::from_secs(1)]);
        let mut reset_rx = backoff.reset_rx.clone();

        let cancellation = CancellationToken::new();

        let connector_fut = OutgoingConnectLoop::new(connector, watch_rx.clone(), mpsc_tx)
            .run(&mut backoff, cancellation.clone());
        let scenario_fut = async {
            // Advance time to trigger the connect attempt after its initial backoff delay
            tokio::time::advance(Duration::from_secs(1)).await;

            // Verify the connection object was sent to the pipeline
            let received = mpsc_rx.recv().await.unwrap();
            assert_eq!(received, 42);

            // Simulate the manager updating the watch channel with the new active connection
            watch_tx.send(Some(42)).unwrap();
            assert!(
                timeout(Duration::from_millis(200), reset_rx.changed()).await.is_ok(),
                "Reset should be called after successful connection and watch channel update synchronization.");

            // Trigger a disconnect request to break the active loop and allow termination
            watch_rx.mark_unchanged();
            watch_tx.send(None).unwrap();
            let _ = watch_rx.changed().await.unwrap();
            assert!(
                timeout(Duration::from_millis(100), reset_rx.changed())
                    .await
                    .is_ok(),
                "Reset should be called after resetting the connection to None"
            );

            cancellation.cancel();
        };

        let (Err(result), _) = tokio::join!(connector_fut, scenario_fut);
        tracing::info!("{}", result);
    }

    #[tokio::test]
    #[test_log::test]
    #[ntest::timeout(300)]
    async fn test_backoff_interrupted_by_external_connection() {
        // Scenario: Starts with None -> Fails once -> Next backoff is 10s ->
        //           During sleep, external system provides connection (Some) ->
        //           Sleep is interrupted -> Backoff resets -> Waits in active loop.
        tokio::time::pause();

        let (watch_tx, watch_rx) = watch::channel(None);
        let (mpsc_tx, _mpsc_rx) = mpsc::channel(1);

        let connector = MockConnector::new(vec![Err("Failed")]);
        let mut backoff = MockBackoff::new(vec![Duration::from_secs(10)]);
        let mut reset_rx = backoff.reset_rx.clone();

        let connector_fut = OutgoingConnectLoop::new(connector, watch_rx, mpsc_tx)
            .run(&mut backoff, CancellationToken::new());
        let scenario_fut = async {
            // Process the first failure and enter the 10-second backoff sleep
            tokio::time::advance(Duration::from_millis(100)).await;

            // Simulate external entity establishing a connection after 2 seconds
            tokio::time::advance(Duration::from_secs(2)).await;
            reset_rx.mark_unchanged();
            watch_tx.send(Some(777)).unwrap();
            assert!(
                timeout(Duration::from_millis(100), reset_rx.changed()).await.is_ok(),
                "Reset should be called exactly when the select! backoff sleep was interrupted by Some");

            // Drop the channel to break the loop and finish the test
            drop(watch_tx);
        };

        let (Err(result), _) = tokio::join!(connector_fut, scenario_fut);
        tracing::info!("{}", result);
    }

    #[tokio::test]
    #[test_log::test]
    #[ntest::timeout(300)]
    async fn test_backoff_interrupted_by_explicit_immediate_retry() {
        // Scenario: Starts with None -> Fails -> Backoff is 10s ->
        //           User sends None again to force immediate retry ->
        //           Sleep is interrupted -> Backoff resets -> Connects immediately.
        tokio::time::pause();

        let (watch_tx, watch_rx) = watch::channel(None);
        let (mpsc_tx, mut mpsc_rx) = mpsc::channel(1);

        let connector = MockConnector::new(vec![Err("Failed"), Ok(99)]);
        let mut backoff = MockBackoff::new(vec![Duration::from_secs(10), Duration::from_secs(1)]);
        let mut reset_rx = backoff.reset_rx.clone();

        let cancellation = CancellationToken::new();
        let connector_fut = OutgoingConnectLoop::new(connector, watch_rx, mpsc_tx)
            .run(&mut backoff, cancellation.clone());

        let scenario_fut = async {
            // Process the first failure and enter the 10-second sleep
            tokio::time::advance(Duration::from_millis(100)).await;

            // Force an immediate retry by explicitly pushing None again
            reset_rx.mark_unchanged();
            watch_tx.send(None).unwrap();
            assert!(
                timeout(Duration::from_millis(100), reset_rx.changed())
                    .await
                    .is_ok(),
                "Reset should be called when select! was interrupted by the explicit None signal"
            );

            // The delay was reset, so the next backoff fetched is 1s. Advance to trigger it.
            tokio::time::advance(Duration::from_secs(1)).await;

            // Verify it proceeded to connect immediately and successfully
            let received = mpsc_rx.recv().await.unwrap();
            assert_eq!(received, 99);

            cancellation.cancel();
            drop(watch_tx);
        };

        let (Err(result), _) = tokio::join!(connector_fut, scenario_fut);
        tracing::info!("{}", result);
    }
}
