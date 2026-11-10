//! Logs how a connection's path changes between direct and relayed, with a snapshot of what iroh
//! knows about the remote at that moment.

use iroh::endpoint::{Connection, Endpoint};
use metrics::counter;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::path_monitor::{self, ChangeTracker};

/// What iroh knows about one connection and its remote, formatted for a single log line.
/// The fields are only read through `Debug`.
#[derive(Debug)]
#[allow(dead_code)]
pub struct Snapshot {
    side: &'static str,
    close_reason: Option<String>,
    paths: Vec<String>,
    remote_addrs: Vec<String>,
    local_addrs: Vec<String>,
    net_report: String,
}

impl Snapshot {
    pub async fn capture(endpoint: &Endpoint, conn: &Connection) -> Self {
        let paths = conn
            .paths()
            .into_iter()
            .map(|path| {
                format!(
                    "{:?}{}{} rtt={:?}",
                    path.remote_addr(),
                    if path.is_selected() { " selected" } else { "" },
                    if path.is_closed() { " closed" } else { "" },
                    path.rtt(),
                )
            })
            .collect();
        let remote_addrs = endpoint
            .remote_info(conn.remote_id())
            .await
            .map(|info| {
                info.addrs().map(|addr| format!("{:?} {:?}", addr.addr(), addr.usage())).collect()
            })
            .unwrap_or_default();
        let local_addrs = endpoint.addr().addrs.iter().map(|addr| format!("{addr:?}")).collect();
        let net_report = match endpoint.last_net_report() {
            Some(report) => format!(
                "udp_v4={} udp_v6={} mapping_varies_by_dest_v4={:?} mapping_varies_by_dest_v6={:?} \
                 preferred_relay={:?}",
                report.udp_v4,
                report.udp_v6,
                report.mapping_varies_by_dest_ipv4,
                report.mapping_varies_by_dest_ipv6,
                report.preferred_relay,
            ),
            None => "none yet".to_owned(),
        };
        Snapshot {
            side: if conn.side().is_client() { "client" } else { "server" },
            close_reason: conn.close_reason().map(|reason| format!("{reason:?}")),
            paths,
            remote_addrs,
            local_addrs,
            net_report,
        }
    }
}

/// Logs a snapshot of the connection, e.g. when something went wrong with it.
pub async fn log_snapshot(endpoint: &Endpoint, conn: &Connection, peer: &str, reason: &str) {
    let snapshot = Snapshot::capture(endpoint, conn).await;
    info!(peer, reason, ?snapshot, "Path diagnostics");
}

/// Watches the connection's selected path and logs every change between direct and relayed.
///
/// The task ends with the connection or when `cancel` fires.
pub fn spawn_change_logger(
    endpoint: Endpoint,
    conn: Connection,
    peer: String,
    cancel: CancellationToken,
) {
    let mut selected = path_monitor::spawn(&conn, cancel.clone());
    tokio::spawn(async move {
        let mut tracker = ChangeTracker::default();
        let mut observed = *selected.borrow_and_update();
        loop {
            if let Some(change) = tracker.observe(observed, std::time::Instant::now()) {
                counter!(
                    description: "Changes of a connection's selected path between direct and relayed",
                    "p2p_vpn_peer_path_changes_total",
                    "peer" => peer.clone(),
                    "from" => change.from.as_str(),
                    "to" => change.to.as_str(),
                )
                .increment(1);
                let snapshot = Snapshot::capture(&endpoint, &conn).await;
                info!(
                    peer,
                    from = change.from.as_str(),
                    to = change.to.as_str(),
                    after = ?change.after,
                    ?snapshot,
                    "Connection path changed"
                );
            }
            tokio::select! {
                _ = cancel.cancelled() => break,
                changed = selected.changed() => if changed.is_err() { break },
            }
            observed = *selected.borrow_and_update();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::test_util::connect_pair;

    #[tokio::test]
    async fn snapshot_describes_the_selected_path() {
        let (a, b) = connect_pair().await;
        let snapshot = Snapshot::capture(a.endpoint(), &a.conn).await;

        assert_eq!(snapshot.side, "client");
        assert_eq!(snapshot.close_reason, None);
        assert!(snapshot.paths.iter().any(|path| path.contains("selected")), "{snapshot:?}");
        assert!(!snapshot.remote_addrs.is_empty(), "{snapshot:?}");

        let snapshot = Snapshot::capture(b.endpoint(), &b.conn).await;
        assert_eq!(snapshot.side, "server");
        a.close().await;
        b.close().await;
    }
}
