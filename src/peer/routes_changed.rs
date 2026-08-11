use thin_status::ThinStatus;

pub trait RoutesChanged {
    /// Called when a peer's routing addresses have changed as result of a handshake negotiation.
    /// If the returned value is `Err`, the connection is terminated.
    async fn update_routes(&mut self, routes: &[std::net::IpAddr]) -> Result<(), ThinStatus>;
}
