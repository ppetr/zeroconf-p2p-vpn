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
