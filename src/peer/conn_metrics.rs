use iroh::endpoint::{Connection, ConnectionStats, PathStats};
use metrics::{gauge, Gauge, Label, Unit};
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio::time::interval;

pub struct QuinnMetrics {
    pub datagram_tx: Gauge,
    pub datagram_rx: Gauge,
    pub rtt: Gauge,
    pub cwnd: Gauge,
    pub congestion_events: Gauge,
    pub lost_packets: Gauge,
    pub lost_bytes: Gauge,
    pub sent_plpmtud_probes: Gauge,
    pub lost_plpmtud_probes: Gauge,
    pub black_holes_detected: Gauge,
    pub current_mtu: Gauge,
}

impl QuinnMetrics {
    pub fn new(labels: Vec<Label>) -> Self {
        Self {
            datagram_tx: gauge!(
                description: "The number of datagrams sent",
                unit: Unit::Count,
                "p2p_vpn_peer_quinn_datagram_tx",
                labels.clone(),
            ),
            datagram_rx: gauge!(
                description: "The number of datagrams received",
                unit: Unit::Count,
                "p2p_vpn_peer_quinn_datagram_rx",
                labels.clone(),
            ),

            rtt: gauge!(
                description: "Current best estimate of this connection’s latency (round-trip-time)",
                unit: Unit::Seconds,
                "p2p_vpn_peer_quinn_rtt_seconds",
                labels.clone(),
            ),
            cwnd: gauge!(
                description: "Current congestion window of the connection",
                "p2p_vpn_peer_quinn_cwnd",
                labels.clone(),
            ),
            congestion_events: gauge!(
                description: "Congestion events on the connection",
                unit: Unit::Count,
                "p2p_vpn_peer_quinn_congestion_events_total",
                labels.clone(),
            ),
            lost_packets: gauge!(
                description: "The amount of packets lost on the current path",
                unit: Unit::Count,
                "p2p_vpn_peer_quinn_lost_packets_total",
                labels.clone(),
            ),
            lost_bytes: gauge!(
                description: "The amount of bytes lost on the current path",
                unit: Unit::Bytes,
                "p2p_vpn_peer_quinn_lost_bytes_total",
                labels.clone(),
            ),
            sent_plpmtud_probes: gauge!(
                description: "The amount of PLPMTUD probe packets sent on the current path (also counted by sent_packets)",
                unit: Unit::Count,
                "p2p_vpn_peer_quinn_sent_plpmtud_probes_total",
                labels.clone(),
            ),
            lost_plpmtud_probes: gauge!(
                description: "The amount of PLPMTUD probe packets lost on the current path (ignored by lost_packets and lost_bytes)",
                unit: Unit::Count,
                "p2p_vpn_peer_quinn_lost_plpmtud_probes_total",
                labels.clone(),
            ),
            black_holes_detected: gauge!(
                description: "The number of times a black hole was detected in the current path",
                unit: Unit::Count,
                "p2p_vpn_peer_quinn_black_holes_detected_total",
                labels.clone(),
            ),
            current_mtu: gauge!(
                description: "Largest UDP payload size the current path currently supports",
                unit: Unit::Bytes,
                "p2p_vpn_peer_quinn_current_mtu_bytes",
                labels,
            ),
        }
    }

    /// Spawns a background loop that periodically records metrics from a Quinn Connection.
    ///
    /// Returns a `tokio::task::JoinHandle<()>` which can be used to abort or monitor the loop.
    pub fn spawn_exporter(self, connection: Connection, period: Duration) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = interval(period);
            loop {
                ticker.tick().await;
                if let Some(reason) = connection.close_reason() {
                    tracing::debug!(reason = ?reason, "Connection closed, stopping metrics exporter");
                    break;
                }
                self.update_connection(&connection.stats());
                if let Some(path) = connection
                    .paths()
                    .into_iter()
                    .find(|path| path.is_selected())
                {
                    if let Some(stats) = path.stats() {
                        self.update_path(&stats);
                    } else {
                        tracing::debug!(path = ?path, "Path found, but connection reference was dropped");
                    }
                }
            }
        })
    }

    pub fn update_connection(&self, stats: &ConnectionStats) {
        self.datagram_tx.set(stats.frame_tx.datagram as f64);
        self.datagram_rx.set(stats.frame_rx.datagram as f64);
    }

    pub fn update_path(&self, stats: &PathStats) {
        self.rtt.set(stats.rtt.as_secs_f64());
        self.cwnd.set(stats.cwnd as f64);
        self.congestion_events.set(stats.congestion_events as f64);
        self.lost_packets.set(stats.lost_packets as f64);
        self.lost_bytes.set(stats.lost_bytes as f64);
        self.sent_plpmtud_probes
            .set(stats.sent_plpmtud_probes as f64);
        self.lost_plpmtud_probes
            .set(stats.lost_plpmtud_probes as f64);
        self.black_holes_detected
            .set(stats.black_holes_detected as f64);
        self.current_mtu.set(stats.current_mtu as f64);
    }
}
