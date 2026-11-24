//! Integration with the service manager that started the daemon, if any: lifecycle notifications
//! and native logging.
//!
//! All functions are no-ops when the daemon was not started by a service manager (e.g. run from a
//! terminal) and on platforms without a supported one.

#[cfg(windows)]
pub mod windows;

#[cfg(target_os = "linux")]
mod systemd;
#[cfg(target_os = "linux")]
pub use systemd::{init_native_logging, notify_ready, notify_stopping};

/// Reports that the daemon finished starting up and is serving.
#[cfg(not(target_os = "linux"))]
pub fn notify_ready() {}

/// Reports that the daemon began shutting down.
#[cfg(all(unix, not(target_os = "linux")))]
pub fn notify_stopping() {}

/// Installs service-manager-native logging; there is none here, so `filter` is handed back.
#[cfg(not(target_os = "linux"))]
pub fn init_native_logging(
    filter: tracing_subscriber::EnvFilter,
) -> Result<(), tracing_subscriber::EnvFilter> {
    Err(filter)
}
