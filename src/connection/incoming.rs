//! Routes accepted (incoming) connections to the right peer's `PeerLink`.
//!
//! The global Iroh listener accepts connections from any peer. `IncomingRouter` holds the
//! `IncomingReceiver` of every configured peer's `PeerLink`, keyed by the peer's public key, and
//! forwards each accepted connection to the matching one. A connection from a peer that isn't in
//! the configuration is closed.
//!
//! The map is built once at startup (`register`) and never mutated afterwards.

use std::collections::HashMap;

use iroh::endpoint::{Connection, VarInt};
use iroh::EndpointId;
use metrics::IntoLabels;
use tokio::sync::mpsc;

use super::peer::IncomingReceiver;
use crate::error::ExtractedErrorCode;

#[derive(Debug, Default)]
pub struct IncomingRouter {
    by_peer: HashMap<EndpointId, IncomingReceiver>,
}

impl IncomingRouter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a configured peer's `PeerLink` `IncomingReceiver`, keyed by the peer's public
    /// key. Call once per peer at startup, before `run`.
    pub fn register(&mut self, key: EndpointId, incoming: IncomingReceiver) {
        self.by_peer.insert(key, incoming);
    }

    /// Forwards every connection from `incoming` to the matching peer's link until the channel
    /// closes.
    pub async fn run(self, mut incoming: mpsc::Receiver<Connection>) {
        while let Some(conn) = incoming.recv().await {
            self.dispatch(conn).await;
        }
    }

    async fn dispatch(&self, conn: Connection) {
        let remote = conn.remote_id();
        match self.by_peer.get(&remote) {
            Some(receiver) => {
                if let Err(status) = receiver.send(conn).await {
                    let err = anyhow::Error::new(status);
                    metrics::counter!(
                        "p2p_vpn_incoming_router_submit_errors",
                        ExtractedErrorCode::from_anyhow(&err).into_labels()
                    )
                    .increment(1);
                    tracing::warn!(peer = %remote, error = ?err,
                        "Failed to submit an incoming connection to the peer link");
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
