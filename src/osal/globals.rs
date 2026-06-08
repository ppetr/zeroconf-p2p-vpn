use rtnetlink::{new_connection, Handle};
use tokio;

pub struct Globals {
    pub rtnetlink: Handle,
}

impl Globals {
    pub async fn new() -> std::io::Result<Globals> {
        let (connection, handle, _) = new_connection()?;
        tokio::spawn(connection);
        Ok(Globals { rtnetlink: handle })
    }
}
