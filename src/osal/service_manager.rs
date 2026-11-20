//! Lifecycle notifications to the service manager that started the daemon, if any.
//!
//! Both functions are no-ops when the daemon was not started by a service manager (e.g. run from a
//! terminal) and on platforms without a supported one.

#[cfg(target_os = "linux")]
mod systemd;
#[cfg(target_os = "linux")]
pub use systemd::{notify_ready, notify_stopping};

/// Reports that the daemon finished starting up and is serving.
#[cfg(not(target_os = "linux"))]
pub fn notify_ready() {}

/// Reports that the daemon began shutting down.
#[cfg(not(target_os = "linux"))]
pub fn notify_stopping() {}
