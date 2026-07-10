use iroh::endpoint::{Connection, Side, VarInt};
use iroh::EndpointId;
use thin_status::ThinStatus;
use tokio::sync::mpsc;

use super::actor::*;

#[derive(Clone, Debug)]
struct IrohConnection {
    conn: Connection,
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

    fn close_connection(self, status: ThinStatus) {
        self.conn.close(
            VarInt::from_u32(i32::from(status.code_raw()) as u32),
            status.message().as_bytes(),
        )
    }

    fn spawn_closed_watcher(&self, on_close: mpsc::Sender<Self::ConnectionId>) {
        let clone = self.conn.clone();
        tokio::spawn(async move {
            let _ = clone.closed().await;
            let _ = on_close.send(clone).await;
        });
    }
}
