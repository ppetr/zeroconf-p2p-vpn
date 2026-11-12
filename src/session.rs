//! Per-peer supervision.
//!
//! `PeerSession` hands a `SessionHandler` to an `iroh_persistent` link. For every connection the
//! link installs, the handler runs the handshake, registers the negotiated routes in the shared
//! `Relay`, and pumps inbound datagrams to the TUN write side until the connection drops. It then
//! parks the peer's routes (keeps them installed but marked offline, so `tun_rx_loop` answers ICMP
//! host-unreachable) while the link reconnects. Routes are only fully withdrawn when the link ends.
//!
//! The handler reports to the link whether the connection was worth keeping (`Outcome`), which
//! drives the link's redial backoff: a connection that fails its setup, is cancelled before the
//! setup finishes (the link cancels a connection the peer closed), or dies right after it, keeps
//! the backoff growing.
//!
//! A connection whose selected path stays relayed (it started direct: the handshake waits for it)
//! is ended deliberately, because iroh does not get such a connection back to a direct path; a
//! fresh connection does. See `RELAY_GRACE` and `STABLE_DIRECT`.
//! While the path is relayed the peer's routes are parked, so no traffic loads the relay.
//!
//! A failure in a connection (handshake, relay insert, receive loop) is logged and counted and the
//! link keeps going, so one misbehaving peer can't take down the process.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use iroh::endpoint::{Connection, Endpoint};
use iroh_persistent::{Builder, ConnectionHandler, Outcome, PersistentLink};
use metrics::{counter, IntoLabels};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, info_span, warn, Instrument};

use crate::dns::PeerNames;
use crate::error::ExtractedErrorCode;
use crate::path_diagnostics;
use crate::path_monitor;
use crate::peer::{self, CommonPeerConfig, ConnectedPeer};
use crate::proto;
use crate::relay::Relay;
use crate::tun;

/// A connection that was set up successfully but ended sooner than this after its setup counts as
/// failed, so that a peer that keeps dropping the connection right away is redialed with a growing
/// backoff.
const MIN_USEFUL_CONNECTION: Duration = Duration::from_secs(5);

/// How long a connection may stay relayed, uninterrupted by a direct path, before it is ended and
/// redialed. Long enough for iroh's own recovery (observed within 20-40 s) and for short network
/// hiccups, short enough that the relay's latency does not linger.
const RELAY_GRACE: Duration = Duration::from_secs(30);

/// A connection that was direct for at least this long before it fell back to relay was healthy;
/// its redial starts with the initial backoff. A shorter one counts as failed, so that a link that
/// can't hold a direct path is redialed with a growing backoff instead of in a tight cycle.
const STABLE_DIRECT: Duration = Duration::from_secs(120);

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
    /// The endpoint the peer's connections belong to; only used to diagnose their paths.
    pub endpoint: Endpoint,
}

/// Drives a single peer: reconnect loop, handshake, route registration, receive loop.
pub struct PeerSession {
    name: String,
    link: PersistentLink<SessionHandler>,
}

impl PeerSession {
    /// Starts `link` right away, in a span that attributes the logs of its tasks (e.g.
    /// "preferred direction: ...") to this peer, which would be ambiguous with more than one peer.
    pub fn new(
        config: PeerSessionConfig,
        link: Builder,
        relay: Arc<Relay<ConnectedPeer>>,
        tx_packet: mpsc::Sender<tun::TxPacket>,
    ) -> Self {
        let name = config.name.clone();
        let handler = SessionHandler { config, relay, tx_packet, routes: Vec::new() };
        let link =
            info_span!("peer_link", peer = name.as_str()).in_scope(|| link.spawn_with(handler));
        PeerSession { name, link }
    }

    /// Runs until the link ends (normally on cancellation); then withdraws the peer's routes.
    pub async fn run(self) {
        let name = self.name;
        let end = self.link.join().await;
        if let Err(err) = end.result {
            counter!(
                description: "Peer sessions stopped because their link task failed",
                "p2p_vpn_peer_session_link_ended",
                vec![metrics::Label::new("peer", name.clone())]
            )
            .increment(1);
            warn!(peer = %name, error = ?err, "Peer link task failed, stopping session");
        }
        match end.handler {
            Some(mut handler) => handler.withdraw_routes().await,
            // The peer's routes stay installed; `main` removes whatever is left on shutdown.
            None => error!(peer = %name, "Peer handler was lost; its routes were not withdrawn"),
        }
    }
}

/// Serves the connections of one peer; see the module documentation.
struct SessionHandler {
    config: PeerSessionConfig,
    relay: Arc<Relay<ConnectedPeer>>,
    tx_packet: mpsc::Sender<tun::TxPacket>,
    /// The addresses registered in the relay for this peer.
    routes: Vec<IpAddr>,
}

impl ConnectionHandler for SessionHandler {
    async fn handle(&mut self, conn: Connection, cancel: CancellationToken) -> Outcome {
        let remote_addr = peer::remote_addr(&conn)
            .map(|addr| addr.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        // Spans a whole connection's lifetime with the same fields, so that the `enter`/`close`
        // events tracing_subscriber emits for it (see `main.rs`) double as connect/disconnect
        // log lines for free, without a matching explicit log call at the other end.
        let span = info_span!("peer_connection", peer = %self.config.name, %remote_addr);
        let outcome = self.run_connection(conn, &remote_addr, cancel).instrument(span).await;
        // The connection is gone: keep the routes installed but marked offline until the link
        // reconnects.
        self.park_routes();
        outcome
    }
}

impl SessionHandler {
    /// Runs one established connection to completion: the application-level handshake, relay
    /// route registration, and the receive loop, in that order. Returns once the connection drops,
    /// a step fails or `cancel` fires; `self.routes` reflects whatever ended up registered.
    async fn run_connection(
        &mut self,
        conn: Connection,
        remote_addr: &str,
        cancel: CancellationToken,
    ) -> Outcome {
        info!(peer = %self.config.name, remote_addr, "Connected, starting the communication loop");
        let monitors_cancel = cancel.child_token();
        let _stop_monitors = monitors_cancel.clone().drop_guard();
        path_diagnostics::spawn_change_logger(
            self.config.endpoint.clone(),
            conn.clone(),
            self.config.name.clone(),
            monitors_cancel.clone(),
        );
        let peer_config = peer::PeerConfig {
            common: self.config.common.clone(),
            conn: conn.clone(),
            advertise: self.config.advertise.clone(),
        };

        let handshake = tokio::select! {
            result = peer::Peer::new(peer_config).handshake() => result,
            // `cancel` also fires when the peer closes the connection, so this is no success.
            _ = cancel.cancelled() => return Outcome::Failed,
        };
        let (mut connected, changed) = match handshake {
            Ok(result) => result,
            Err(err) => {
                self.count_error(
                    "p2p_vpn_peer_session_handshake_errors",
                    "Handshake failures in a peer session",
                    &err,
                );
                warn!(peer = %self.config.name, error = ?err, "Handshake failed");
                self.log_path_snapshot(&conn, "handshake failed").await;
                return Outcome::Failed;
            }
        };

        // Sync the relay to the freshly negotiated set: addresses the peer dropped since last
        // time are withdrawn, the rest are re-armed in place without touching their routes.
        if let Err(err) = self.relay.reconcile(&changed.0, &self.routes, connected.clone()).await {
            self.count_error(
                "p2p_vpn_peer_session_relay_insert_errors",
                "Failures registering a peer's routes in the relay",
                &anyhow::Error::new(err),
            );
            warn!(peer = %self.config.name, "Failed to register peer routes in the relay");
            // `reconcile` rolled its batch back, so nothing of ours is left in the relay.
            self.routes.clear();
            return Outcome::Failed;
        }
        self.routes = changed.0.clone();
        if let Some(dns_names) = &self.config.dns_names {
            dns_names.set(&self.config.name, self.routes.clone());
        }

        let established = Instant::now();
        // While the path is relayed the routes are parked, so that no traffic (e.g. a large
        // transfer) loads the relay; they are re-armed if the path turns direct again.
        let peer_handle = connected.clone();
        let relayed = path_monitor::watch_relayed(
            path_monitor::spawn(&conn, monitors_cancel),
            RELAY_GRACE,
            || {
                warn!(peer = %self.config.name, "Path turned relayed, pausing traffic");
                self.relay.park(&self.routes);
            },
            || {
                info!(peer = %self.config.name, "Path is direct again, resuming traffic");
                self.relay.unpark(&self.routes, peer_handle.clone());
            },
        );
        let mut fell_back_to_relay = false;
        // A cancellation (the peer closed the connection, it was replaced, or shutdown) ends the
        // loop like a dropped connection does; the connection's age then decides the outcome.
        let received = tokio::select! {
            result = connected.recv_loop(self.tx_packet.clone()) => result,
            _ = cancel.cancelled() => Ok(()),
            _ = relayed => {
                fell_back_to_relay = true;
                Ok(())
            }
        };
        if let Err(err) = received {
            self.count_error(
                "p2p_vpn_peer_session_recv_loop_errors",
                "Peer receive loop terminations with an error",
                &err,
            );
            warn!(peer = %self.config.name, error = ?err, "Receive loop ended with an error");
            self.log_path_snapshot(&conn, "receive loop failed").await;
        }
        let age = established.elapsed();
        if fell_back_to_relay {
            counter!(
                description: "Connections ended because their path stayed relayed",
                "p2p_vpn_peer_relay_fallbacks",
                "peer" => self.config.name.clone()
            )
            .increment(1);
            warn!(peer = %self.config.name, ?age, "Connection stayed relayed, ending it to redial");
            self.log_path_snapshot(&conn, "relayed too long").await;
            return if age >= RELAY_GRACE + STABLE_DIRECT {
                Outcome::Done
            } else {
                Outcome::Failed
            };
        }
        if age < MIN_USEFUL_CONNECTION {
            Outcome::Failed
        } else {
            Outcome::Done
        }
    }

    async fn log_path_snapshot(&self, conn: &Connection, reason: &str) {
        path_diagnostics::log_snapshot(&self.config.endpoint, conn, &self.config.name, reason)
            .await;
    }

    /// Fully withdraws the peer's routes from the relay (kernel route included). Used only when
    /// the link itself is ending.
    async fn withdraw_routes(&mut self) {
        if !self.routes.is_empty() {
            self.relay.remove(&self.routes).await;
            self.routes.clear();
        }
        if let Some(dns_names) = &self.config.dns_names {
            dns_names.remove(&self.config.name);
        }
    }

    /// Marks the peer's routes offline for the reconnect gap, leaving `self.routes` populated so the
    /// next handshake can diff against it and a later session end can withdraw them.
    fn park_routes(&self) {
        if !self.routes.is_empty() {
            self.relay.park(&self.routes);
        }
    }

    fn count_error(&self, metric: &'static str, description: &'static str, err: &anyhow::Error) {
        let mut labels = ExtractedErrorCode::from_anyhow(err).into_labels();
        labels.push(metrics::Label::new("peer", self.config.name.clone()));
        counter!(description: description, metric, labels).increment(1);
    }
}
