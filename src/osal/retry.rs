use std::future::Future;
use std::io;
use std::time::Duration;

use backoff::backoff::Backoff;

/// Windows error code for `ERROR_NOT_FOUND`.
///
/// Several IP Helper APIs (unicast address registration, IP forward table entries) return it
/// transiently for a short window right after a TUN adapter is created, until the OS finishes
/// registering the adapter internally. Never produced by any other platform, so treating it as
/// retryable everywhere is harmless.
const WINDOWS_ERROR_NOT_FOUND: i32 = 1168;

/// Retries `op` with exponential backoff for as long as it fails with the transient Windows
/// `ERROR_NOT_FOUND` a freshly created TUN adapter returns; any other error, or exhausting the
/// backoff budget, returns immediately.
pub async fn retry_on_windows_not_found<T, F, Fut>(mut op: F) -> io::Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = io::Result<T>>,
{
    let mut backoff = backoff::ExponentialBackoff {
        initial_interval: Duration::from_millis(50),
        max_interval: Duration::from_millis(500),
        max_elapsed_time: Some(Duration::from_secs(2)),
        ..Default::default()
    };
    loop {
        let result = op().await;
        match &result {
            Ok(_) => return result,
            Err(err) if err.raw_os_error() == Some(WINDOWS_ERROR_NOT_FOUND) => {
                let Some(delay) = backoff.next_backoff() else {
                    return result;
                };
                tracing::debug!(?delay, "adapter not yet ready, retrying");
                tokio::time::sleep(delay).await;
            }
            Err(_) => return result,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[tokio::test]
    async fn succeeds_immediately_without_retrying() {
        let calls = AtomicU32::new(0);
        let result = retry_on_windows_not_found(|| {
            calls.fetch_add(1, Ordering::SeqCst);
            async { Ok(()) }
        })
        .await;
        assert!(result.is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn retries_only_on_the_transient_error_until_it_succeeds() {
        let calls = AtomicU32::new(0);
        let result = retry_on_windows_not_found(|| {
            let attempt = calls.fetch_add(1, Ordering::SeqCst);
            async move {
                if attempt < 2 {
                    Err(io::Error::from_raw_os_error(WINDOWS_ERROR_NOT_FOUND))
                } else {
                    Ok(())
                }
            }
        })
        .await;
        assert!(result.is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn returns_other_errors_immediately() {
        let calls = AtomicU32::new(0);
        let result: io::Result<()> = retry_on_windows_not_found(|| {
            calls.fetch_add(1, Ordering::SeqCst);
            async { Err(io::Error::other("permanent failure")) }
        })
        .await;
        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
