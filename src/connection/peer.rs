use backoff::backoff::Backoff;
use iroh::{endpoint::Connection, EndpointId};
use std::fmt::Write;
use thin_status::{ErrorCode, ThinStatus, ThinStatusExt};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::{CancellationToken, DropGuard};

use super::actor::*;
use super::connect::*;
use super::iroh::*;
use crate::error;

#[derive(Debug)]
pub struct PeerLink {
    pub connector: IrohConnector,
    conn_tx: mpsc::Sender<IrohConnection>,
    watch_rx: watch::Receiver<Option<IrohConnection>>,
    pub task: tokio::task::JoinHandle<Result<(), ThinStatus>>,
    _cancellation: DropGuard,
}

impl PeerLink {
    pub fn new(connector: IrohConnector, connect_backoff: impl Backoff + Send + 'static) -> Self {
        let (watch_tx, watch_rx) = watch::channel(None);

        let cancellation = CancellationToken::new();
        let drop_guard = cancellation.clone().drop_guard();

        let actor = Actor::new(connector.local.addr().id, connector.peer, watch_tx);
        let (actor, actor_join) = actor.spawn(cancellation.clone());
        let outgoing_join =
            OutgoingConnectLoop::new(connector.clone(), watch_rx.clone(), actor.conn_tx.clone())
                .spawn(connect_backoff, cancellation);
        let task = tokio::spawn(async move {
            error::await_loop_result(outgoing_join).await?;
            error::await_loop_result(actor_join).await
        });
        let link = PeerLink {
            connector,
            watch_rx,
            conn_tx: actor.conn_tx,
            task,
            _cancellation: drop_guard,
        };
        link
    }

    /// Returns a `Connection` created by either the `OutgoingConnectLoop` managed internally, or
    /// submitted by `send_incoming`.
    pub fn connection(&self) -> Option<Connection> {
        self.watch_rx.borrow().as_ref().map(|c| c.conn.clone())
    }

    /// Waits for a new connection to become available.
    pub async fn next_connection(&mut self) -> Result<Option<Connection>, watch::error::RecvError> {
        self.watch_rx.changed().await?;
        Ok(self
            .watch_rx
            .borrow_and_update()
            .as_ref()
            .map(|c| c.conn.clone()))
    }

    /// Returns a receiver object that accepts incoming connections.
    pub fn incoming_receiver(&self) -> IncomingReceiver {
        IncomingReceiver {
            conn_tx: self.conn_tx.clone(),
            peer_id: self.connector.peer,
        }
    }
}

/// Accepts incoming connections.
pub struct IncomingReceiver {
    conn_tx: mpsc::Sender<IrohConnection>,
    peer_id: EndpointId,
}

impl IncomingReceiver {
    pub async fn send(&self, conn: Connection) -> Result<(), ThinStatus> {
        let conn = IrohConnection { conn };
        if let Err(builder) = crate::check_eq!(conn.conn.remote_id(), self.peer_id) {
            let mut builder = builder.code(ErrorCode::InvalidArgument);
            let _ = write!(
                builder,
                "; remote peer address doesn't match the configured one"
            );
            let status = builder.build();
            conn.close(status.clone());
            return Err(status);
        }
        self.conn_tx
            .send(conn)
            .await
            .map_err(|e| e.error_code(ErrorCode::FailedPrecondition))
    }
}
