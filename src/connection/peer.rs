use backoff::backoff::Backoff;
use iroh::endpoint::Connection;
use std::convert::Infallible;
use thin_status::{ErrorCode, ThinStatus};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::{CancellationToken, DropGuard};

use super::actor::*;
use super::connect::*;
use super::iroh::*;

pub struct PeerLink {
    pub connector: IrohConnector,
    conn_tx: mpsc::Sender<IrohConnection>,
    watch_rx: watch::Receiver<Option<IrohConnection>>,
    pub task: tokio::task::JoinHandle<ThinStatus>,
    cancellation: DropGuard,
}

impl PeerLink {
    pub fn new(
        connector: IrohConnector,
        mut connect_backoff: impl Backoff + Send + 'static,
    ) -> Self {
        let (watch_tx, watch_rx) = watch::channel(None);

        let cancellation = CancellationToken::new();
        let drop_guard = cancellation.clone().drop_guard();

        let mut actor = Actor::new(connector.local.addr().id, connector.peer, watch_tx);
        let conn_tx = actor.connection_queue();
        let outgoing =
            OutgoingConnectLoop::new(connector.clone(), watch_rx.clone(), conn_tx.clone());
        let task = tokio::spawn(async move {
            let (Err(actor_err), Err(mut err)) = tokio::join!(
                actor.run(cancellation.clone()),
                outgoing.run(&mut connect_backoff, cancellation.clone())
            );
            if err.code_or_unknown() != ErrorCode::Cancelled {
                tracing::error!(error = ?err, "Outgoing connector terminated unexpectedly");
            }
            if actor_err.code_or_unknown() != ErrorCode::Cancelled {
                tracing::error!(error = ?actor_err, "Actor terminated unexpectedly");
                err = actor_err;  // Keep the non-cancelled error.
            }
            err
        });
        let link = PeerLink {
            connector,
            watch_rx,
            conn_tx,
            task,
            cancellation: drop_guard,
        };
        link
    }

    /// Returns a `Connection` created by either
    pub fn connection(&self) -> Option<Connection> {
        self.watch_rx.borrow().as_ref().map(|c| c.conn.clone())
    }

    pub async fn send_incoming(
        &self,
        conn: Connection,
    ) -> Result<(), mpsc::error::SendError<IrohConnection>> {
        self.conn_tx.send(IrohConnection { conn }).await
    }
}
