use std::sync::{Condvar, Mutex, PoisonError};
use std::time::Duration;

/// Lets a thread wait, for a bounded time, until the daemon has finished its cleanup.
#[derive(Default)]
pub struct CleanupGate {
    finished: Mutex<bool>,
    changed: Condvar,
}

impl CleanupGate {
    pub fn finish(&self) {
        *self.finished.lock().unwrap_or_else(PoisonError::into_inner) = true;
        self.changed.notify_all();
    }

    /// Returns whether the cleanup finished within `limit`.
    pub fn wait(&self, limit: Duration) -> bool {
        let finished = self.finished.lock().unwrap_or_else(PoisonError::into_inner);
        let (finished, _) = self
            .changed
            .wait_timeout_while(finished, limit, |finished| !*finished)
            .unwrap_or_else(PoisonError::into_inner);
        *finished
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Instant;

    #[test]
    fn wait_times_out_when_cleanup_does_not_finish() {
        let gate = CleanupGate::default();
        let started = Instant::now();
        assert!(!gate.wait(Duration::from_millis(50)));
        assert!(started.elapsed() >= Duration::from_millis(50));
    }

    #[test]
    fn wait_returns_at_once_when_already_finished() {
        let gate = CleanupGate::default();
        gate.finish();
        let started = Instant::now();
        assert!(gate.wait(Duration::from_secs(10)));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn wait_is_woken_by_finish_from_another_thread() {
        let gate = Arc::new(CleanupGate::default());
        let waiter = {
            let gate = gate.clone();
            std::thread::spawn(move || gate.wait(Duration::from_secs(10)))
        };
        std::thread::sleep(Duration::from_millis(50));
        gate.finish();
        assert!(waiter.join().unwrap());
    }

    #[test]
    fn several_waiters_are_all_released() {
        let gate = Arc::new(CleanupGate::default());
        let waiters: Vec<_> = (0..3)
            .map(|_| {
                let gate = gate.clone();
                std::thread::spawn(move || gate.wait(Duration::from_secs(10)))
            })
            .collect();
        std::thread::sleep(Duration::from_millis(50));
        gate.finish();
        assert!(waiters.into_iter().all(|waiter| waiter.join().unwrap()));
    }
}
