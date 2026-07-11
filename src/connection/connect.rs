use backoff::backoff::Backoff;
use tokio::sync::{mpsc, watch};

pub trait OutgoingConnector {
    type Connection: Send;
    type Error: std::fmt::Debug + std::fmt::Display;

    async fn connect(&self) -> Result<Self::Connection, Self::Error>;

    async fn connect_loop(
        &mut self,
        retry_backoff: &mut impl Backoff,
        mut watch_rx: watch::Receiver<Option<Self::Connection>>,
        tx: mpsc::Sender<Self::Connection>,
    ) {
        loop {
            // Read the current state and mark it as seen
            if watch_rx.borrow_and_update().is_some() {
                tracing::debug!("Connection is active; resetting back-off and waiting until a new connection is needed");
                if watch_rx.changed().await.is_err() {
                    break;
                }
                retry_backoff.reset();
                continue;
            }

            tracing::debug!("No connection active; attempting to reconnect");
            let Some(delay) = retry_backoff.next_backoff() else {
                // ExponentialBackoff runs indefinitely by default,
                // but if limits are customized, exit when max elapsed time is reached.
                tracing::warn!("Backoff exhausted, terminating connection loop");
                break;
            };

            if !delay.is_zero() {
                let span = tracing::debug_span!("backoff_sleep");
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {
                        // Backoff delay expired, proceed to connect
                    }
                    changed_res = watch_rx.changed() => {
                        span.record("interrupted", "connected/disconnected event");
                        if changed_res.is_err() {
                            break;
                        }
                        tracing::debug!("Connection update, resetting the backoff");
                        retry_backoff.reset();
                        continue;
                    }
                }
            }

            tracing::debug!("Initiating a new connection");
            match self.connect().await {
                Ok(connection) => {
                    if tx.send(connection).await.is_err() {
                        tracing::debug!("Connection queue dropped, terminating the loop");
                        break;
                    }

                    // Wait for the self update to reflect in the watch channel
                    // to avoid immediately reading the stale None state in the next iteration.
                    if watch_rx.changed().await.is_err() {
                        break;
                    }
                    tracing::debug!("Successfully submitted a connection");
                    retry_backoff.reset();
                }
                Err(err) => {
                    tracing::info!(error = ?err, "Connection attempt failed, retrying with a back-off");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::Duration;
    use tokio::sync::{mpsc, watch};

    struct MockBackoff {
        delays: Vec<Duration>,
        index: isize,
        reset_count: usize,
    }

    impl MockBackoff {
        fn new(delays: Vec<Duration>) -> Self {
            Self {
                delays,
                index: -1,
                reset_count: 0,
            }
        }
    }

    impl backoff::backoff::Backoff for MockBackoff {
        fn next_backoff(&mut self) -> Option<Duration> {
            self.index += 1;
            self.delays.get(self.index as usize).copied()
        }

        fn reset(&mut self) {
            self.reset_count += 1;
            self.index = -1;
        }
    }

    struct MockConnector {
        /// Mutex allows mutating the vector even in non-`mut` `connect` function.
        connect_results: Mutex<Vec<Result<i32, &'static str>>>,
    }

    impl MockConnector {
        fn new(mut results: Vec<Result<i32, &'static str>>) -> Self {
            results.reverse(); // FIFO order from a vector
            Self {
                connect_results: Mutex::new(results),
            }
        }
    }

    impl OutgoingConnector for MockConnector {
        type Connection = i32;
        type Error = &'static str;

        async fn connect(&self) -> Result<Self::Connection, Self::Error> {
            let mut guard = self.connect_results.lock().unwrap();
            guard
                .pop()
                .unwrap_or(Err("No more configured results"))
        }
    }

    // --- Tests ---

    #[tokio::test]
    #[test_log::test]
    async fn test_successful_connection_flow() {
        // Scenario: Starts with None -> Connects successfully -> Sends to mpsc ->
        //           Waits for watch_rx to update -> Resets backoff -> Enters active state loop.
        tokio::time::pause();

        let (watch_tx, mut watch_rx) = watch::channel(None);
        let (mpsc_tx, mut mpsc_rx) = mpsc::channel(1);

        let mut connector = MockConnector::new(vec![Ok(42)]);
        let mut backoff = MockBackoff::new(vec![Duration::from_secs(1)]);

        let connector_fut = connector.connect_loop(&mut backoff, watch_rx.clone(), mpsc_tx);
        let scenario_fut = async {
            // Advance time to trigger the connect attempt after its initial backoff delay
            tokio::time::advance(Duration::from_secs(1)).await;

            // Verify the connection object was sent to the pipeline
            let received = mpsc_rx.recv().await.unwrap();
            assert_eq!(received, 42);

            // Simulate the manager updating the watch channel with the new active connection
            watch_rx.mark_unchanged();
            watch_tx.send(Some(42)).unwrap();
            let _ = watch_rx.changed().await.unwrap();

            // Trigger a disconnect request to break the active loop and allow termination
            watch_rx.mark_unchanged();
            watch_tx.send(None).unwrap();
            let _ = watch_rx.changed().await.unwrap();
            drop(mpsc_rx);
        };

        tokio::join!(connector_fut, scenario_fut);

        // Reset should be called after successful connection and watch channel update
        // synchronization.
        assert!(backoff.reset_count >= 1);
    }

    #[tokio::test]
    #[test_log::test]
    async fn test_backoff_interrupted_by_external_connection() {
        // Scenario: Starts with None -> Fails once -> Next backoff is 10s ->
        //           During sleep, external system provides connection (Some) ->
        //           Sleep is interrupted -> Backoff resets -> Waits in active loop.
        tokio::time::pause();

        let (watch_tx, watch_rx) = watch::channel(None);
        let (mpsc_tx, _mpsc_rx) = mpsc::channel(1);

        let mut connector = MockConnector::new(vec![Err("Failed")]);
        let mut backoff = MockBackoff::new(vec![Duration::from_secs(10)]);

        let connector_fut = connector.connect_loop(&mut backoff, watch_rx, mpsc_tx);

        let scenario_fut = async {
            // Process the first failure and enter the 10-second backoff sleep
            tokio::time::advance(Duration::from_millis(100)).await;

            // Simulate external entity establishing a connection after 2 seconds
            tokio::time::advance(Duration::from_secs(2)).await;
            watch_tx.send(Some(777)).unwrap();
            tokio::task::yield_now().await;

            // Drop the channel to break the loop and finish the test
            drop(watch_tx);
        };

        tokio::join!(connector_fut, scenario_fut);

        // Reset should be called exactly when the select! backoff sleep was interrupted by Some
        assert_eq!(backoff.reset_count, 1);
    }

    #[tokio::test]
    #[test_log::test]
    async fn test_backoff_interrupted_by_explicit_immediate_retry() {
        // Scenario: Starts with None -> Fails -> Backoff is 10s ->
        //           User sends None again to force immediate retry ->
        //           Sleep is interrupted -> Backoff resets -> Connects immediately.
        tokio::time::pause();

        let (watch_tx, watch_rx) = watch::channel(None);
        let (mpsc_tx, mut mpsc_rx) = mpsc::channel(1);

        let mut connector = MockConnector::new(vec![Err("Failed"), Ok(99)]);
        let mut backoff = MockBackoff::new(vec![Duration::from_secs(10), Duration::from_secs(1)]);

        let connector_fut = connector.connect_loop(&mut backoff, watch_rx, mpsc_tx);

        let scenario_fut = async {
            // Process the first failure and enter the 10-second sleep
            tokio::time::advance(Duration::from_millis(100)).await;

            // Force an immediate retry by explicitly pushing None again
            watch_tx.send(None).unwrap();
            tokio::task::yield_now().await;

            // The delay was reset, so the next backoff fetched is 1s. Advance to trigger it.
            tokio::time::advance(Duration::from_secs(1)).await;

            // Verify it proceeded to connect immediately and successfully
            let received = mpsc_rx.recv().await.unwrap();
            assert_eq!(received, 99);

            drop(mpsc_rx);
            drop(watch_tx);
        };

        tokio::join!(connector_fut, scenario_fut);

        // Reset should be called when select! was interrupted by the explicit None signal
        assert!(backoff.reset_count >= 1);
    }
}
