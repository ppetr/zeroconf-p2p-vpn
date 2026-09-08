use iroh::endpoint::{ConnectError, Connection, Endpoint, Side};
use iroh::EndpointId;
use std::sync::Arc;
use thin_status::ThinStatus;
use tokio::sync::mpsc;

use super::actor::*;
use super::connect::*;
use crate::proto;

#[derive(Clone, Debug)]
pub struct IrohConnection {
    pub conn: Connection,
}

impl PartialEq<IrohConnection> for Connection {
    fn eq(&self, other: &IrohConnection) -> bool {
        self.stable_id() == other.conn.stable_id()
    }
}

impl ManagedConnection for IrohConnection {
    type Key = EndpointId;
    type ConnectionId = Connection;

    fn direction(&self) -> Direction {
        match self.conn.side() {
            Side::Client => Direction::Outgoing,
            Side::Server => Direction::Incoming,
        }
    }

    fn close(self, status: ThinStatus) {
        proto::close_connection(&self.conn, &status);
    }

    fn spawn_closed_watcher(&self, on_close: mpsc::Sender<Self::ConnectionId>) {
        let clone = self.conn.clone();
        tokio::spawn(async move {
            let _ = clone.closed().await;
            let _ = on_close.send(clone).await;
        });
    }
}

#[derive(Clone, Debug)]
pub struct IrohConnector {
    pub local: Endpoint,
    pub peer: EndpointId,
    pub alpn: Arc<Vec<u8>>,
}

impl OutgoingConnector for IrohConnector {
    type Connection = IrohConnection;
    type Error = ConnectError;

    async fn connect(&self) -> Result<IrohConnection, Self::Error> {
        Ok(IrohConnection { conn: self.local.connect(self.peer, self.alpn.as_ref()).await? })
    }
}
