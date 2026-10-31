//! Per-peer supervision loop.
//!
//! `PeerSession` owns one `iroh_persistent::PersistentConnection` and, for every connection that
//! link yields, runs the handshake, registers the negotiated routes in the shared `Relay`, and
//! pumps inbound datagrams to the TUN write side until the connection drops. It then parks the
//! peer's routes (keeps them installed but marked offline, so `tun_rx_loop` answers ICMP
//! host-unreachable) and waits for the link to reconnect. Routes are only fully withdrawn when
//! the session ends.
//!
//! This is the multi-peer generalization of what `main.rs` used to do inline for a single peer.
//! Unlike that loop, a failure here (handshake, relay insert, receive loop) is logged and counted
//! and the session keeps going, so one misbehaving peer can't take down the process.

use std::net::IpAddr;
use std::sync::Arc;

use iroh::endpoint::Connection;
use iroh_persistent::PersistentConnection;
use metrics::{counter, IntoLabels};
use tokio::sync::mpsc;
use tracing::{info, info_span, warn, Instrument};

use crate::dns::PeerNames;
use crate::error::ExtractedErrorCode;
use crate::peer::{self, CommonPeerConfig, ConnectedPeer};
use crate::proto;
use crate::relay::Relay;
use crate::tun;

/// Static per-peer configuration for a `PeerSession`.
#[derive(Clone, Debug)]
pub struct PeerSessionConfig {
    /// Human-readable peer name from the configuration's `[peers]` table; used for logs, the
    /// `peer` metric label, and (if set) the name's DNS entry.
    pub name: String,
    pub common: Arc<CommonPeerConfig>,
    pub advertise: proto::v1::Advertise,
    /// DNS peer-name registry to keep in sync with this peer's negotiated addresses, if DNS
    /// resolution (`[dns]` in the config) is enabled.
    pub dns_names: Option<Arc<PeerNames>>,
}

/// Drives a single peer: reconnect loop, handshake, route registration, receive loop.
pub struct PeerSession {
    config: PeerSessionConfig,
    link: PersistentConnection,
    relay: Arc<Relay<ConnectedPeer>>,
    tx_packet: mpsc::Sender<tun::TxPacket>,
}

impl PeerSession {
    pub fn new(
        config: PeerSessionConfig,
        link: PersistentConnection,
        relay: Arc<Relay<ConnectedPeer>>,
        tx_packet: mpsc::Sender<tun::TxPacket>,
    ) -> Self {
        PeerSession { config, link, relay, tx_packet }
    }

    /// Runs until the underlying `PersistentConnection`'s background tasks end; on every other
    /// error it logs, counts, and retries.
    pub async fn run(mut self) {
        let mut routes: Vec<IpAddr> = Vec::new();
        loop {
            let conn = match self.link.changed().await {
                Ok(Some(conn)) => conn,
                Ok(None) => {
                    info!(peer = %self.config.name, "Peer disconnected");
                    self.park_routes(&routes);
                    continue;
                }
                Err(err) => {
                    // The internal `PersistentConnection` task is gone; this session can't
                    // recover.
                    counter!(
                        description: "Peer sessions stopped because their link task ended",
                        "p2p_vpn_peer_session_link_ended",
                        vec![metrics::Label::new("peer", self.config.name.clone())]
                    )
                    .increment(1);
                    warn!(peer = %self.config.name, error = ?err,
                          "Peer link task ended, stopping session");
                    self.withdraw_routes(&mut routes).await;
                    return;
                }
            };

            let remote_addr = peer::remote_addr(&conn)
                .map(|addr| addr.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            // Spans a whole connection's lifetime with the same fields, so that the `enter`/`close`
            // events tracing_subscriber emits for it (see `main.rs`) double as connect/disconnect
            // log lines for free, without a matching explicit log call at the other end.
            let span = info_span!("peer_connection", peer = %self.config.name, %remote_addr);
            self.run_connection(conn, &remote_addr, &mut routes).instrument(span).await;
        }
    }

    /// Runs one established connection to completion: the application-level handshake, relay
    /// route registration, and the receive loop, in that order. Returns once the connection drops
    /// or a step fails; `routes` is updated in place to reflect whatever ended up registered.
    async fn run_connection(
        &mut self,
        conn: Connection,
        remote_addr: &str,
        routes: &mut Vec<IpAddr>,
    ) {
        info!(peer = %self.config.name, remote_addr, "Connected, starting the communication loop");
        let peer_config = peer::PeerConfig {
            common: self.config.common.clone(),
            conn,
            advertise: self.config.advertise.clone(),
        };

        let (mut connected, changed) = match peer::Peer::new(peer_config).handshake().await {
            Ok(result) => result,
            Err(err) => {
                self.count_error(
                    "p2p_vpn_peer_session_handshake_errors",
                    "Handshake failures in a peer session",
                    &err,
                );
                warn!(peer = %self.config.name, error = ?err, "Handshake failed");
                return;
            }
        };

        // Sync the relay to the freshly negotiated set: addresses the peer dropped since last
        // time are withdrawn, the rest are re-armed in place without touching their routes.
        if let Err(err) = self.relay.reconcile(&changed.0, routes, connected.clone()).await {
            self.count_error(
                "p2p_vpn_peer_session_relay_insert_errors",
                "Failures registering a peer's routes in the relay",
                &anyhow::Error::new(err),
            );
            warn!(peer = %self.config.name, "Failed to register peer routes in the relay");
            // `reconcile` rolled its batch back, so nothing of ours is left in the relay.
            routes.clear();
            return;
        }
        *routes = changed.0.clone();
        if let Some(dns_names) = &self.config.dns_names {
            dns_names.set(&self.config.name, routes.clone());
        }

        if let Err(err) = connected.recv_loop(self.tx_packet.clone()).await {
            self.count_error(
                "p2p_vpn_peer_session_recv_loop_errors",
                "Peer receive loop terminations with an error",
                &err,
            );
            warn!(peer = %self.config.name, error = ?err, "Receive loop ended with an error");
        }

        // The connection dropped: park its routes (keep them installed, marked offline) and
        // wait for the link to reconnect.
        self.park_routes(routes);
    }

    /// Fully withdraws the peer's routes from the relay (kernel route included). Used only when
    /// the session itself is ending.
    async fn withdraw_routes(&self, routes: &mut Vec<IpAddr>) {
        if !routes.is_empty() {
            self.relay.remove(routes).await;
            routes.clear();
        }
        if let Some(dns_names) = &self.config.dns_names {
            dns_names.remove(&self.config.name);
        }
    }

    /// Marks the peer's routes offline for the reconnect gap, leaving `routes` populated so the
    /// next handshake can diff against it and a later session end can withdraw them.
    fn park_routes(&self, routes: &[IpAddr]) {
        if !routes.is_empty() {
            self.relay.park(routes);
        }
    }

    fn count_error(&self, metric: &'static str, description: &'static str, err: &anyhow::Error) {
        let mut labels = ExtractedErrorCode::from_anyhow(err).into_labels();
        labels.push(metrics::Label::new("peer", self.config.name.clone()));
        counter!(description: description, metric, labels).increment(1);
    }
}
