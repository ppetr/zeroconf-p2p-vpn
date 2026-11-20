//! The systemd readiness protocol (`Type=notify`), via the `NOTIFY_SOCKET` datagram socket.

use sd_notify::NotifyState;

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
