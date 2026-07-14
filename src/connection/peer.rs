use backoff::backoff::Backoff;
use iroh::{endpoint::Connection, EndpointId};
use std::fmt::Write;
use std::sync::Arc;
use thin_status::{ErrorCode, ThinStatus, ThinStatusExt};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::{CancellationToken, DropGuard};

use super::actor::*;
use super::connect::*;
use super::iroh::*;
use crate::error;

#[derive(Debug)]
pub struct PeerLink {
    connector: IrohConnector,
}

impl PeerLink {
    pub fn new(connector: IrohConnector) -> Self {
        PeerLink { connector }
    }

    pub fn spawn(
        self,
        connect_backoff: impl Backoff + Send + 'static,
        cancellation: CancellationToken,
    ) -> (PeerLinkHandle, JoinHandle<Result<(), ThinStatus>>) {
        let (watch_tx, watch_rx) = watch::channel(None);

        let drop_guard = cancellation.clone().drop_guard();

        let actor = Actor::new(
            self.connector.local.addr().id,
            self.connector.peer,
            watch_tx,
        );
        let (actor, actor_join) = actor.spawn(cancellation.clone());
        let outgoing_join = OutgoingConnectLoop::new(
            self.connector.clone(),
            watch_rx.clone(),
            actor.conn_tx.clone(),
        )
        .spawn(connect_backoff, cancellation);
        let task = tokio::spawn(async move {
            error::await_loop_result(outgoing_join).await?;
            error::await_loop_result(actor_join).await
        });
        (
            PeerLinkHandle {
                actor,
                connector: self.connector,
                watch_rx,
                _cancellation: Arc::new(drop_guard),
            },
            task,
        )
    }
}

#[derive(Clone, Debug)]
pub struct PeerLinkHandle {
    actor: ActorHandle<IrohConnection>,
    pub connector: IrohConnector,
    watch_rx: watch::Receiver<Option<IrohConnection>>,
    _cancellation: Arc<DropGuard>,
}

impl PeerLinkHandle {
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
            conn_tx: self.actor.conn_tx.clone(),
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
