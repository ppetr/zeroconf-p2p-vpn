use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use windows_sys::core::BOOL;
use windows_sys::Win32::System::Console::{
    SetConsoleCtrlHandler, CTRL_BREAK_EVENT, CTRL_CLOSE_EVENT, CTRL_C_EVENT,
};

use super::cleanup_gate::CleanupGate;

/// How long the handler for close waits for the cleanup. Windows kills the process about 5 s after
/// that event (at the latest when the handler returns), so this stays below that.
const CLEANUP_WAIT_LIMIT: Duration = Duration::from_secs(4);

struct State {
    shutdown: CancellationToken,
    requested: AtomicBool,
    cleanup: CleanupGate,
}

/// One handler per process, and the OS gives it no context.
static STATE: OnceLock<State> = OnceLock::new();

/// Tells the handler that the cleanup is finished; dropped at the end of the daemon's run.
pub struct Guard;

impl Drop for Guard {
    fn drop(&mut self) {
        if let Some(state) = STATE.get() {
            state.cleanup.finish();
        }
    }
}

/// Cancels `shutdown` on the first termination request. For close it then holds the OS back until
/// the returned guard is dropped, since the process is killed as soon as the handler returns.
///
/// Logoff and shutdown are not covered: Windows does not send them as console control events to a
/// process that has user32.dll or gdi32.dll loaded, as this one has through its dependencies.
/// Run as a service to get a clean stop on shutdown.
pub fn install(shutdown: CancellationToken) -> io::Result<Guard> {
    let state =
        State { shutdown, requested: AtomicBool::new(false), cleanup: CleanupGate::default() };
    if STATE.set(state).is_err() {
        return Err(io::Error::other("the console control handler is already installed"));
    }
    // SAFETY: `handler` has the signature the OS expects and stays valid for the whole process.
    if unsafe { SetConsoleCtrlHandler(Some(handler), 1) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Guard)
}

/// Runs on a thread the OS creates for each event, so blocking here does not stall the daemon.
/// Must not panic.
unsafe extern "system" fn handler(event: u32) -> BOOL {
    let Some(state) = STATE.get() else { return 0 };
    match event {
        // Returning TRUE also for repeated requests: the cleanup is already under way, and
        // falling through to the default handler would kill the process in the middle of it.
        CTRL_C_EVENT | CTRL_BREAK_EVENT => {
            request(state);
            1
        }
        CTRL_CLOSE_EVENT => {
            request(state);
            state.cleanup.wait(CLEANUP_WAIT_LIMIT);
            1
        }
        _ => 0,
    }
}

fn request(state: &State) {
    if !state.requested.swap(true, Ordering::AcqRel) {
        state.shutdown.cancel();
    }
}
