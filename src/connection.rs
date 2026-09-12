//! Routes accepted (incoming) connections to the right peer's `iroh_persistent::PersistentConnection`.
//!
//! Per-peer reconnection (dial-on-drop, deterministic conflict resolution between two
//! simultaneous dials) is handled by the `iroh_persistent` crate; this module only does the part
//! that's left as the caller's job: a single global Iroh listener accepts connections from any
//! peer, and `IncomingRouter` demultiplexes them by the remote's public key into each configured
//! peer's inbound channel (fed into that peer's `PersistentConnection::builder().incoming(...)`).
//! A connection from a peer that isn't in the configuration is closed; `iroh_persistent` itself
//! re-validates the remote key on its side, so this router doesn't need to.
//!
//! The map is built once at startup (`register`) and never mutated afterwards.

use std::collections::HashMap;

use iroh::endpoint::{Connection, VarInt};
use iroh::EndpointId;
use tokio::sync::mpsc;

#[derive(Debug, Default)]
pub struct IncomingRouter {
    by_peer: HashMap<EndpointId, mpsc::Sender<Connection>>,
}

impl IncomingRouter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a configured peer's inbound channel, keyed by the peer's public key. Call once
    /// per peer at startup, before `run`.
    pub fn register(&mut self, key: EndpointId, incoming: mpsc::Sender<Connection>) {
        self.by_peer.insert(key, incoming);
    }

    /// Forwards every connection from `incoming` to the matching peer's channel until the channel
    /// closes.
    pub async fn run(self, mut incoming: mpsc::Receiver<Connection>) {
        while let Some(conn) = incoming.recv().await {
            self.dispatch(conn).await;
        }
    }

    async fn dispatch(&self, conn: Connection) {
        let remote = conn.remote_id();
        match self.by_peer.get(&remote) {
            Some(sender) => {
                if sender.send(conn).await.is_err() {
                    metrics::counter!("p2p_vpn_incoming_router_submit_errors").increment(1);
                    tracing::warn!(peer = %remote,
                        "Failed to submit an incoming connection to the peer link: channel closed");
                }
            }
            None => {
                metrics::counter!("p2p_vpn_incoming_router_unknown_peer").increment(1);
                tracing::warn!(peer = %remote,
                    "Rejecting an incoming connection from a peer not in the configuration");
                conn.close(VarInt::from_u32(0), b"unknown peer");
            }
        }
    }
}
