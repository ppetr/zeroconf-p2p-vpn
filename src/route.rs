use futures_util::FutureExt;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::{info_span, Instrument};

/// An RAII guard that keeps an IP route active until it is dropped.
///
/// When instantiated via `ScopedRoute::new`, the specified IP address is routed through the
/// provided network interface index. When the instance falls out of scope, a background thread
/// automatically deletes the route from the OS routing table.
pub struct ScopedRoute {
    handle: Arc<net_route::Handle>,
    if_index: u32,
    dest_ip: IpAddr,
}

impl ScopedRoute {
    /// Constructs a new `ScopedRoute` and immediately registers it with the system routing table.
    ///
    /// # Arguments
    /// * `handle` - An active [`net_route::Handle`] connection.
    /// * `if_index` - The system numerical index of the target network interface.
    /// * `dest_ip` - The destination IP address (IPv4 or IPv6) to route.
    pub async fn new(
        handle: Arc<net_route::Handle>,
        if_index: u32,
        dest_ip: IpAddr,
    ) -> Result<Self, std::io::Error> {
        let this = Self {
            handle: handle.clone(),
            if_index,
            dest_ip,
        };

        let _span = info_span!("scoped_route_add", %this.dest_ip, this.if_index);

        let route = this.route_entry();
        this.handle.add(&route).await?;

        Ok(this)
    }

    fn route_entry(&self) -> net_route::Route {
        let prefix = match self.dest_ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };

        net_route::Route::new(self.dest_ip, prefix).with_ifindex(self.if_index)
    }
}

impl Drop for ScopedRoute {
    fn drop(&mut self) {
        let dest_ip = self.dest_ip;
        let span = info_span!("scoped_route_del", %self.dest_ip, self.if_index);

        let handle = self.handle.clone();
        let route = self.route_entry();

        tokio::spawn(
            async move {
                handle.delete(&route).await
            }
            .instrument(span)
            .map(move |result| {
                if result.is_err() {
                    metrics::counter!(
                        "scoped_route_cleanup_errors_total",
                        "ip_version" => match dest_ip { IpAddr::V4(_) => "v4", IpAddr::V6(_) => "v6" }
                    )
                    .increment(1);
                }
            }),
        );
    }
}
