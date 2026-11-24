//! Turns the platform's termination requests into the cancellation of a token, and lets the
//! platform wait for the daemon's cleanup where it would otherwise kill the process early.
//!
//! Only for running from a console; a Windows service is stopped by the service control manager.
//! Unix: SIGINT and SIGTERM. Windows: Ctrl-C, Ctrl-Break and console close.

#[cfg(any(windows, test))]
mod cleanup_gate;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
pub use unix::install;
#[cfg(windows)]
pub use windows::install;
