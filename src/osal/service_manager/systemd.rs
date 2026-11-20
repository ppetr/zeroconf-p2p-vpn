//! The systemd readiness protocol (`Type=notify`), via the `NOTIFY_SOCKET` datagram socket, and
//! native journal logging.

use sd_notify::NotifyState;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

fn notify(state: NotifyState, what: &str) {
    if let Err(err) = sd_notify::notify(&[state]) {
        tracing::warn!(%err, "Cannot notify systemd about {what}");
    }
}

/// Reports that the daemon finished starting up and is serving (`READY=1`).
pub fn notify_ready() {
    notify(NotifyState::Ready, "readiness");
}

/// Reports that the daemon began shutting down (`STOPPING=1`).
pub fn notify_stopping() {
    notify(NotifyState::Stopping, "shutdown");
}

/// Installs a `tracing` subscriber that writes native journal records, so event and span fields
/// become filterable journal fields (prefixed `F_`).
///
/// Does nothing and hands `filter` back when the daemon was not started with its stderr connected
/// to the journal (`JOURNAL_STREAM` unset) or the journal socket is unavailable.
pub fn init_native_logging(filter: EnvFilter) -> Result<(), EnvFilter> {
    if std::env::var_os("JOURNAL_STREAM").is_none() {
        return Err(filter);
    }
    match tracing_journald::layer() {
        Ok(journald) => {
            tracing_subscriber::registry().with(filter).with(journald).init();
            Ok(())
        }
        Err(_) => Err(filter),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixDatagram;

    // Only test touching `NOTIFY_SOCKET`, so it cannot race with another test over the variable.
    #[test]
    fn sends_ready_and_stopping_to_the_notify_socket() {
        let path = std::env::temp_dir().join(format!("notify-test-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let socket = UnixDatagram::bind(&path).unwrap();
        std::env::set_var("NOTIFY_SOCKET", &path);

        let mut buf = [0u8; 64];
        notify_ready();
        let n = socket.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"READY=1\n");
        notify_stopping();
        let n = socket.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"STOPPING=1\n");

        std::env::remove_var("NOTIFY_SOCKET");
        let _ = std::fs::remove_file(&path);
    }
}
