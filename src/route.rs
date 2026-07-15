use futures_util::FutureExt;
use metrics::IntoLabels;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::{info_span, Instrument};

use crate::error::ExtractedErrorCode;

#[derive(Clone)]
pub struct NetRouteHandle {
    pub handle: Arc<net_route::Handle>,
}

impl NetRouteHandle {
    pub fn new() -> Result<Self, std::io::Error> {
        Ok(Self {
            handle: Arc::new(net_route::Handle::new()?),
        })
    }
}

impl std::fmt::Debug for NetRouteHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Use the debug_struct helper to match the standard Debug output style
        f.debug_struct("NetRouteHandle")
            .field("handle", &format_args!("{:p}", Arc::as_ptr(&self.handle)))
            .finish()
    }
}

/// Handles are equal their handles are the same `Arc` (there should be just one in the whole
/// process anyway).
impl PartialEq<NetRouteHandle> for NetRouteHandle {
    fn eq(&self, other: &NetRouteHandle) -> bool {
        Arc::as_ptr(&self.handle) == Arc::as_ptr(&other.handle)
    }
}

impl Eq for NetRouteHandle {}

impl std::hash::Hash for NetRouteHandle {
    fn hash<H: std::hash::Hasher>(&self, hasher: &mut H) {
        Arc::as_ptr(&self.handle).hash(hasher);
    }
}

/// An RAII guard that keeps an IP route active until it is dropped.
///
/// When instantiated via `ScopedRoute::new`, the specified IP address is routed through the
/// provided network interface index. When the instance falls out of scope, a background thread
/// automatically deletes the route from the OS routing table.
#[derive(Debug, PartialEq, Eq)]
pub struct ScopedRoute {
    handle: NetRouteHandle,
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
        handle: NetRouteHandle,
        if_index: u32,
        dest_ip: IpAddr,
    ) -> Result<Self, std::io::Error> {
        let this = Self {
            handle,
            if_index,
            dest_ip,
        };

        let _span = info_span!("scoped_route_add", %this.dest_ip, this.if_index);

        let route = this.route_entry();
        this.handle.handle.add(&route).await?;
        metrics::gauge!("p2p_vpn_route_scoped_route_active",
            "ip" => if dest_ip.is_ipv6() { "v6" } else { "v4" })
        .increment(1);

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
                metrics::gauge!("p2p_vpn_route_scoped_route_active",
                    "ip" => if dest_ip.is_ipv6() { "v6" } else { "v4" })
                .decrement(1);
                handle.handle.delete(&route).await
            }
            .instrument(span)
            .map(move |result| match result {
                Err(err) => {
                    let mut labels = ExtractedErrorCode::from_io(&err).into_labels();
                    labels.push(metrics::Label::new(
                        "ip",
                        if dest_ip.is_ipv6() { "v6" } else { "v4" },
                    ));
                    metrics::counter!("scoped_route_cleanup_errors_total", labels).increment(1);
                }
                _ => {}
            }),
        );
    }
}
