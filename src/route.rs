use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;
use tracing::{info_span, Instrument};

use crate::osal;

pub mod ecn;

pub trait RoutingTable: Clone + Send + Sync + std::fmt::Debug + 'static {
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
    ///
    /// On Windows, `CreateIpForwardEntry2` can fail with the same transient `ERROR_NOT_FOUND` as
    /// [`crate::tun::Tun::add_if_addr`] for a short window right after the TUN adapter is
    /// created, so this is retried the same way via [`osal::retry_on_windows_not_found`].
    async fn insert(&self, dest_ip: IpAddr) -> Result<(), std::io::Error> {
        let span = info_span!("p2p_vpn_route_add", %dest_ip, self.if_index);

        let route = self.route_entry(dest_ip);
        osal::retry_on_windows_not_found(|| self.handle.add(&route)).instrument(span).await?;
        let ip = if dest_ip.is_ipv6() { "v6" } else { "v4" };
        metrics::counter!("p2p_vpn_route_add_total", "ip" => ip).increment(1);
        metrics::gauge!("p2p_vpn_route_active", "ip" => ip).increment(1);
        Ok(())
    }

    /// Unregister a route to the stored interface in the system routing table. See [`Self::insert`]
    /// about the retry.
    async fn remove(&self, dest_ip: IpAddr) -> Result<(), std::io::Error> {
        let span = info_span!("p2p_vpn_route_del", %dest_ip, self.if_index);

        let route = self.route_entry(dest_ip);
        osal::retry_on_windows_not_found(|| self.handle.delete(&route)).instrument(span).await?;
        let ip = if dest_ip.is_ipv6() { "v6" } else { "v4" };
        metrics::gauge!("p2p_vpn_route_active", "ip" => ip).decrement(1);
        Ok(())
    }
}

impl NetRouteHandle {
    /// Constructs an instance using a newly created `net_route::Handle` and an interface index.
    pub fn new(if_index: u32) -> Result<Self, std::io::Error> {
        Ok(Self::from_handle(Arc::new(net_route::Handle::new()?), if_index))
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

/// A guard that tracks one IP address routed through a `RoutingTable`, and panics on `Drop` if it
/// wasn't disposed of correctly via [`ScopedRoute::drop_async`].
///
/// Unlike a typical RAII guard, `ScopedRoute` does NOT itself hold a `RoutingTable` handle —
/// callers (in practice, just `Relay`) already hold their own handle and control the exact
/// ordering of insert/remove OS operations relative to their own bookkeeping (e.g. `Relay` must
/// remove a replaced route before inserting its replacement, since both target the same OS-level
/// route). `ScopedRoute` only exists to make forgetting that removal a hard error instead of a
/// silent leak.
#[derive(Debug, PartialEq, Eq)]
pub struct ScopedRoute {
    dest_ip: IpAddr,
}

impl ScopedRoute {
    /// Constructs a new `ScopedRoute` and immediately registers it with the system routing table
    /// via `handle`.
    ///
    /// `Self` is only constructed (and so becomes subject to the `Drop` guard below) once the
    /// route is actually active.
    pub async fn new<R: RoutingTable>(handle: &R, dest_ip: IpAddr) -> Result<Self, std::io::Error> {
        // ... otherwise a failed insert would immediately trip the "forgot to call drop_async"
        // panic for a route that was never inserted in the first place.
        handle.insert(dest_ip).await?;
        Ok(Self { dest_ip })
    }

    /// Removes the route via `handle` and consumes `self`, returning the destination IP on
    /// success.
    ///
    /// This is the only correct way to dispose of a `ScopedRoute` — merely letting one fall out
    /// of scope panics (see `Drop` below). `self` is marked released regardless of whether the
    /// removal succeeds: on failure there's nothing else the caller could do differently with the
    /// guard, so keeping it alive to force a retry would just be an extra footgun for no benefit —
    /// callers that do care should inspect the returned `Err` and act on it themselves.
    pub async fn drop_async<R: RoutingTable>(
        mut self,
        handle: &R,
    ) -> Result<IpAddr, std::io::Error> {
        let dest_ip = std::mem::replace(&mut self.dest_ip, IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        handle.remove(dest_ip).await.map(|()| dest_ip)
    }
}

impl Drop for ScopedRoute {
    /// Only guards against forgetting to call `drop_async` — panics if it wasn't called, rather
    /// than removing the route itself. See `drop_async`'s docs for why.
    fn drop(&mut self) {
        if !self.dest_ip.is_unspecified() {
            panic!(
                "ScopedRoute for {} was dropped without calling drop_async() first",
                self.dest_ip
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// A `RoutingTable` that always succeeds, for exercising `ScopedRoute` itself in isolation.
    #[derive(Clone, Debug)]
    struct FakeRoutingTable;

    impl RoutingTable for FakeRoutingTable {
        async fn insert(&self, _dest_ip: IpAddr) -> Result<(), std::io::Error> {
            Ok(())
        }
        async fn remove(&self, _dest_ip: IpAddr) -> Result<(), std::io::Error> {
            Ok(())
        }
    }

    /// A `RoutingTable` whose `remove` always fails, to check `drop_async`'s failure path.
    #[derive(Clone, Debug)]
    struct FailingRemoveRoutingTable;

    impl RoutingTable for FailingRemoveRoutingTable {
        async fn insert(&self, _dest_ip: IpAddr) -> Result<(), std::io::Error> {
            Ok(())
        }
        async fn remove(&self, _dest_ip: IpAddr) -> Result<(), std::io::Error> {
            Err(std::io::Error::other("mock remove failure"))
        }
    }

    #[tokio::test]
    async fn drop_async_returns_the_ip_and_lets_the_route_drop_without_panicking() {
        let dest_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let route = ScopedRoute::new(&FakeRoutingTable, dest_ip).await.unwrap();
        assert_eq!(route.drop_async(&FakeRoutingTable).await.unwrap(), dest_ip);
        // Reaching this point without a panic is part of the assertion: `drop_async` above
        // already marked the route as cleaned up, so the `Drop` impl won't fire its panic below.
    }

    #[tokio::test]
    async fn drop_async_marks_the_route_released_even_if_removal_fails() {
        let dest_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
        let route = ScopedRoute::new(&FakeRoutingTable, dest_ip).await.unwrap();
        assert!(route.drop_async(&FailingRemoveRoutingTable).await.is_err());
        // Reaching this point without a panic is part of the assertion: even though removal
        // failed, `drop_async` still marks the route released — there's nothing else the caller
        // could do differently with the guard, so keeping it alive would just be a footgun.
    }

    #[tokio::test]
    #[should_panic(expected = "drop_async()")]
    async fn dropping_without_drop_async_panics() {
        let _route = ScopedRoute::new(&FakeRoutingTable, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
            .await
            .unwrap();
        // Falls out of scope here without calling `drop_async` first.
    }
}
