//! Detects changes in the kind (direct or relayed) of a connection's selected path.

use std::time::{Duration, Instant};

use iroh::endpoint::{Connection, PathInfoList, PathWatcher};
use iroh::Watcher;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathKind {
    Direct,
    Relay,
}

impl PathKind {
    pub fn as_str(self) -> &'static str {
        match self {
            PathKind::Direct => "direct",
            PathKind::Relay => "relay",
        }
    }
}

/// Kind of the selected path, or `None` while no path is selected.
pub type SelectedPath = Option<PathKind>;

/// Starts tracking the selected path of `conn`; the receiver always holds its latest kind.
///
/// The background task ends when the connection closes, `cancel` fires, or every receiver is
/// dropped, so consumers need no explicit shutdown.
pub fn spawn(conn: &Connection, cancel: CancellationToken) -> watch::Receiver<SelectedPath> {
    let mut paths = conn.paths();
    let (tx, rx) = watch::channel(selected_kind(&paths.get()));
    tokio::spawn(run(paths, tx, cancel));
    rx
}

async fn run(mut paths: PathWatcher, tx: watch::Sender<SelectedPath>, cancel: CancellationToken) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = tx.closed() => break,
            updated = paths.updated() => match updated {
                Ok(list) => {
                    let kind = selected_kind(&list);
                    tx.send_if_modified(|current| {
                        let changed = *current != kind;
                        *current = kind;
                        changed
                    });
                }
                Err(_) => break,
            },
        }
    }
}

/// Calls `on_relayed` whenever the selected path turns relayed and `on_direct` when it is direct
/// again, and resolves once the path has been relayed for `grace` without a direct one in between.
/// A moment without any selected path changes nothing.
///
/// Never resolves if the tracking task ends first.
pub async fn watch_relayed(
    mut selected: watch::Receiver<SelectedPath>,
    grace: Duration,
    mut on_relayed: impl FnMut(),
    mut on_direct: impl FnMut(),
) {
    // The `Ref` guards `wait_for` returns are dropped right away: they are not `Send`.
    loop {
        if selected.wait_for(|kind| *kind == Some(PathKind::Relay)).await.is_err() {
            break;
        }
        on_relayed();
        let direct_again =
            async { selected.wait_for(|kind| *kind == Some(PathKind::Direct)).await.is_err() };
        tokio::select! {
            _ = tokio::time::sleep(grace) => return,
            ended = direct_again => if ended { break },
        }
        on_direct();
    }
    std::future::pending::<()>().await;
}

fn selected_kind(paths: &PathInfoList) -> SelectedPath {
    paths.iter().find(|path| path.is_selected()).map(|path| {
        if path.is_relay() {
            PathKind::Relay
        } else {
            PathKind::Direct
        }
    })
}

/// A change of the selected path kind between two known states.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PathChange {
    pub from: PathKind,
    pub to: PathKind,
    /// How long the path had been of kind `from`.
    pub after: Duration,
}

/// Turns the stream of observed path kinds into changes between known kinds.
#[derive(Debug, Default)]
pub struct ChangeTracker {
    current: Option<(PathKind, Instant)>,
}

impl ChangeTracker {
    pub fn observe(&mut self, kind: SelectedPath, now: Instant) -> Option<PathChange> {
        let kind = kind?;
        match self.current {
            Some((previous, since)) if previous != kind => {
                self.current = Some((kind, now));
                Some(PathChange { from: previous, to: kind, after: now - since })
            }
            Some(_) => None,
            None => {
                self.current = Some((kind, now));
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::test_util::connect_pair;
    use std::sync::{Arc, Mutex};
    use tokio::time::timeout;

    const WAIT: Duration = Duration::from_secs(5);

    #[test]
    fn tracker_reports_only_changes_between_known_kinds() {
        let t0 = Instant::now();
        let at = |secs| t0 + Duration::from_secs(secs);
        let mut tracker = ChangeTracker::default();

        assert_eq!(tracker.observe(None, at(0)), None);
        assert_eq!(tracker.observe(Some(PathKind::Direct), at(1)), None);
        assert_eq!(tracker.observe(Some(PathKind::Direct), at(2)), None);
        assert_eq!(tracker.observe(None, at(3)), None);
        assert_eq!(
            tracker.observe(Some(PathKind::Relay), at(11)),
            Some(PathChange {
                from: PathKind::Direct,
                to: PathKind::Relay,
                after: Duration::from_secs(10)
            })
        );
        assert_eq!(
            tracker.observe(Some(PathKind::Direct), at(71)),
            Some(PathChange {
                from: PathKind::Relay,
                to: PathKind::Direct,
                after: Duration::from_secs(60)
            })
        );
    }

    const GRACE: Duration = Duration::from_secs(30);

    type Events = Arc<Mutex<Vec<&'static str>>>;

    async fn advance(secs: u64) {
        tokio::time::sleep(Duration::from_secs(secs)).await;
    }

    fn spawn_watch(
        selected: SelectedPath,
    ) -> (watch::Sender<SelectedPath>, Events, tokio::task::JoinHandle<()>) {
        let (tx, rx) = watch::channel(selected);
        let events = Events::default();
        let (on_relayed, on_direct) = (events.clone(), events.clone());
        let task = tokio::spawn(watch_relayed(
            rx,
            GRACE,
            move || on_relayed.lock().unwrap().push("relayed"),
            move || on_direct.lock().unwrap().push("direct"),
        ));
        (tx, events, task)
    }

    #[tokio::test(start_paused = true)]
    async fn watch_relayed_fires_after_the_grace_of_continuous_relay() {
        let (tx, events, task) = spawn_watch(Some(PathKind::Direct));
        advance(5).await;
        assert!(events.lock().unwrap().is_empty());
        tx.send_replace(Some(PathKind::Relay));
        advance(29).await;
        assert!(!task.is_finished());
        advance(2).await;
        assert!(task.is_finished());
        assert_eq!(*events.lock().unwrap(), ["relayed"]);
    }

    #[tokio::test(start_paused = true)]
    async fn watch_relayed_restarts_the_countdown_when_direct_returns() {
        let (tx, events, task) = spawn_watch(Some(PathKind::Relay));
        advance(20).await;
        tx.send_replace(Some(PathKind::Direct));
        advance(5).await;
        tx.send_replace(Some(PathKind::Relay));
        advance(29).await;
        assert!(!task.is_finished());
        advance(2).await;
        assert!(task.is_finished());
        assert_eq!(*events.lock().unwrap(), ["relayed", "direct", "relayed"]);
    }

    #[tokio::test(start_paused = true)]
    async fn watch_relayed_does_not_fire_while_direct() {
        let (_tx, events, task) = spawn_watch(Some(PathKind::Direct));
        advance(300).await;
        assert!(!task.is_finished());
        assert!(events.lock().unwrap().is_empty());
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn watch_relayed_counts_through_gaps_without_a_selected_path() {
        let (tx, events, task) = spawn_watch(Some(PathKind::Relay));
        advance(10).await;
        tx.send_replace(None);
        advance(10).await;
        tx.send_replace(Some(PathKind::Relay));
        advance(11).await;
        assert!(task.is_finished());
        assert_eq!(*events.lock().unwrap(), ["relayed"]);
    }

    #[tokio::test(start_paused = true)]
    async fn watch_relayed_never_fires_after_the_sender_is_gone() {
        let (tx, _events, task) = spawn_watch(Some(PathKind::Relay));
        drop(tx);
        advance(120).await;
        assert!(!task.is_finished());
        task.abort();
    }

    #[tokio::test]
    async fn reports_direct_path_and_stops_when_cancelled() {
        let (a, b) = connect_pair().await;
        let cancel = CancellationToken::new();
        let (tx, rx) = watch::channel(None);
        let task = tokio::spawn(run(a.conn.paths(), tx, cancel.clone()));

        let mut rx = rx;
        timeout(WAIT, rx.wait_for(|kind| *kind == Some(PathKind::Direct)))
            .await
            .expect("no direct path observed")
            .unwrap();

        cancel.cancel();
        timeout(WAIT, task).await.expect("monitor ignored cancellation").unwrap();
        a.close().await;
        b.close().await;
    }

    #[tokio::test]
    async fn stops_when_all_receivers_are_dropped() {
        let (a, b) = connect_pair().await;
        let (tx, rx) = watch::channel(None);
        let task = tokio::spawn(run(a.conn.paths(), tx, CancellationToken::new()));

        drop(rx);
        timeout(WAIT, task).await.expect("monitor outlived its consumers").unwrap();
        a.close().await;
        b.close().await;
    }

    #[tokio::test]
    async fn stops_when_the_connection_closes() {
        let (a, b) = connect_pair().await;
        let (tx, _rx) = watch::channel(None);
        let task = tokio::spawn(run(a.conn.paths(), tx, CancellationToken::new()));

        a.conn.close(0u32.into(), b"test");
        timeout(WAIT, task).await.expect("monitor outlived its connection").unwrap();
        a.close().await;
        b.close().await;
    }
}
