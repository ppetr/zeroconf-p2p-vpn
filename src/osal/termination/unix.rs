use std::io;

use tokio::signal::unix::{signal, SignalKind};
use tokio_util::sync::CancellationToken;

/// Dropped once the daemon finished its cleanup; nothing to do here, as a signal does not make
/// the OS kill the process.
pub struct Guard;

/// Cancels `shutdown` on the first SIGINT or SIGTERM. Must be called inside a Tokio runtime.
pub fn install(shutdown: CancellationToken) -> io::Result<Guard> {
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    tokio::spawn(async move {
        tokio::select! {
            _ = interrupt.recv() => {}
            _ = terminate.recv() => {}
        }
        crate::osal::service_manager::notify_stopping();
        shutdown.cancel();
    });
    Ok(Guard)
}
