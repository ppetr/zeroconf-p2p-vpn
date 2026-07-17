use futures_util::future::FutureExt;
use metrics::IntoLabels;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::{info_span, Instrument};

use crate::error::ExtractedErrorCode;

pub trait RoutingTable: Clone + Send + Sync + std::fmt::Debug {
    fn insert(
        &self,
        dest_ip: IpAddr,
    ) -> impl std::future::Future<Output = Result<(), std::io::Error>> + Send;
    fn remove(
        &self,
        dest_ip: IpAddr,
    ) -> impl std::future::Future<Output = Result<(), std::io::Error>> + Send;
}

#[derive(Clone)]
pub struct NetRouteHandle {
    pub handle: Arc<net_route::Handle>,
    if_index: u32,
}

impl RoutingTable for NetRouteHandle {
    /// Register a route to the stored interface in the system routing table.
    async fn insert(&self, dest_ip: IpAddr) -> Result<(), std::io::Error> {
        let span = info_span!("p2p_vpn_route_add", %dest_ip, self.if_index);

        let route = self.route_entry(dest_ip);
        self.handle.add(&route).instrument(span).await?;
        metrics::gauge!("p2p_vpn_route_add",
            "ip" => if dest_ip.is_ipv6() { "v6" } else { "v4" })
        .increment(1);
        Ok(())
    }

    /// Unregister a route to the stored interface in the system routing table.
    async fn remove(&self, dest_ip: IpAddr) -> Result<(), std::io::Error> {
        let span = info_span!("route_del", %dest_ip, self.if_index);

        let route = self.route_entry(dest_ip);
        self.handle.delete(&route).instrument(span).await?;
        metrics::gauge!("p2p_vpn_route_route_active",
            "ip" => if dest_ip.is_ipv6() { "v6" } else { "v4" })
        .decrement(1);
        Ok(())
    }
}

impl NetRouteHandle {
    /// Constructs an instance using a newly created `net_route::Handle` and an interface index.
    pub fn new(if_index: u32) -> Result<Self, std::io::Error> {
        Ok(Self::from_handle(
            Arc::new(net_route::Handle::new()?),
            if_index,
        ))
    }

    pub fn from_handle(handle: Arc<net_route::Handle>, if_index: u32) -> Self {
        Self { handle, if_index }
    }

    fn route_entry(&self, dest_ip: IpAddr) -> net_route::Route {
        let prefix = match dest_ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        net_route::Route::new(dest_ip, prefix).with_ifindex(self.if_index)
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
    dest_ip: IpAddr,
}

impl ScopedRoute {
    /// Constructs a new `ScopedRoute` and immediately registers it with the system routing table.
    ///
    /// # Arguments
    /// * `handle` - An active [`net_route::Handle`] connection.
    /// * `dest_ip` - The destination IP address (IPv4 or IPv6) to route.
    pub async fn new(handle: NetRouteHandle, dest_ip: IpAddr) -> Result<Self, std::io::Error> {
        let this = Self {
            handle,
            dest_ip: dest_ip.clone(),
        };
        this.handle.insert(dest_ip).await?;
        Ok(this)
    }

    pub fn dest_ip(&self) -> &IpAddr {
        &self.dest_ip
    }

    pub async fn drop_async(self) -> Result<(), std::io::Error> {
        Self::drop_detached(self.handle.clone(), self.dest_ip).await
    }

    async fn drop_detached(handle: NetRouteHandle, dest_ip: IpAddr) -> Result<(), std::io::Error> {
        handle.remove(dest_ip).await
    }
}

impl Drop for ScopedRoute {
    fn drop(&mut self) {
        let is_ipv6 = self.dest_ip().is_ipv6();
        let future = Self::drop_detached(self.handle.clone(), self.dest_ip);
        tokio::spawn(future.map(move |result| match result {
            Err(err) => {
                let mut labels = ExtractedErrorCode::from_io(&err).into_labels();
                labels.push(metrics::Label::new("ip", if is_ipv6 { "v6" } else { "v4" }));
                metrics::counter!("scoped_route_cleanup_errors_total", labels).increment(1);
            }
            _ => {}
        }));
    }
}
