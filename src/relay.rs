use dashmap::DashMap;
use futures_util::future::{join_all, try_join_all};
use metrics::IntoLabels;
use std::collections::HashSet;
use std::fmt::Debug;
use std::net::IpAddr;
use thin_status::ThinStatus;
use tokio::sync::{Mutex, MutexGuard};

use crate::error::ExtractedErrorCode;
use crate::route::{NetRouteHandle, RoutingTable, ScopedRoute};

#[derive(Debug)]
struct PeerValue<T> {
    /// `Some` while a peer is connected; `None` once it has been parked (its connection dropped
    /// but the `route` is kept installed so packets keep reaching our TUN).
    value: Option<T>,
    route: ScopedRoute,
}

/// Outcome of a [`Relay::get`] lookup for a destination IP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dispatch<T> {
    /// A peer is connected and its route is live; the packet can be sent to it.
    Connected(T),
    /// The IP belongs to a known peer that is currently offline (the reconnect gap). The route
    /// is still installed; the caller should answer with an ICMP host-unreachable.
    Parked,
}

/// Keeps a list of values (peers) in a sharded map (`DashMap`) indexed by `IpAddr`.
#[derive(Debug)]
pub struct Relay<T: Clone + Debug, R: RoutingTable = NetRouteHandle> {
    // TODO: Use some clever async single-flight mechanism to just combine requests to each IP
    // address and run their requests in parallel.
    handle: Mutex<R>,
    peer_map: DashMap<IpAddr, PeerValue<T>>,
}

impl<T: Clone + Debug + Send + Sync + 'static, R: RoutingTable> Relay<T, R> {
    pub fn new(handle: R) -> Self {
        Relay { handle: Mutex::new(handle), peer_map: DashMap::new() }
    }

    /// Look up the peer bound to `dest_ip`.
    ///
    /// Returns [`Dispatch::Connected`] with a clone of the value while the peer is connected,
    /// [`Dispatch::Parked`] if the IP belongs to a known-but-offline peer, and `None` if no peer
    /// has ever advertised this address.
    ///
    /// Optimized for performance so that it can be efficiently called for each incoming TUN packet.
    pub fn get(&self, dest_ip: &IpAddr) -> Option<Dispatch<T>> {
        self.peer_map.get(dest_ip).map(|e| match &e.value().value {
            Some(v) => Dispatch::Connected(v.clone()),
            None => Dispatch::Parked,
        })
    }

    pub async fn insert(&self, dest_ips: &[IpAddr], value: T) -> Result<(), ThinStatus> {
        let _span = tracing::info_span!("p2p_vpn_relay_insert");
        let locked = self.handle.lock().await;
        let locked = &locked;
        let value_ref = &value;
        let result = try_join_all(dest_ips.iter().map(|ip| async move {
            // If this IP already has an entry (a parked peer reconnecting, or a peer
            // re-advertising an address it already claimed), keep the installed `ScopedRoute`
            // as-is and just swap the live value back in. The route is fully determined by the
            // IP, so recreating it would only churn the kernel table.
            if let Some(mut entry) = self.peer_map.get_mut(ip) {
                entry.value = Some(value_ref.clone());
                return Ok(());
            }
            match ScopedRoute::new(&**locked, *ip).await {
                Err(err) => {
                    tracing::error!(error = ?err, dest_ip = ?ip, peer = ?value_ref.clone(),
                                    "Errors inserting route to the system routing tables");
                    Err(err)
                }
                Ok(scoped) => {
                    self.peer_map
                        .insert(*ip, PeerValue { value: Some(value_ref.clone()), route: scoped });
                    Ok(())
                }
            }
        }))
        .await;

        match &result {
            Ok(_) => Ok(()),
            Err(err) => {
                self.remove_locked(locked, dest_ips).await;
                metrics::counter!(
                    "p2p_vpn_relay_insert_errors",
                    ExtractedErrorCode::from_io(err).into_labels()
                )
                .increment(1);
                Err(err.into())
            }
        }
    }

    /// Bring the relay in line with a peer's current advertised address set.
    ///
    /// `previous` is the peer's last-registered set (empty on the first handshake). Addresses in
    /// `previous` but not in `current` are removed and their routes torn down; every address in
    /// `current` is then (re-)inserted, re-arming any parked or still-present entry in place. On
    /// failure the `current` batch is rolled back exactly like [`Self::insert`] (the `previous`
    /// removals are not restored), so the caller should treat the peer as having no routes.
    pub async fn reconcile(
        &self,
        current: &[IpAddr],
        previous: &[IpAddr],
        value: T,
    ) -> Result<(), ThinStatus> {
        let keep: HashSet<IpAddr> = current.iter().copied().collect();
        let stale: Vec<IpAddr> = previous.iter().copied().filter(|ip| !keep.contains(ip)).collect();
        if !stale.is_empty() {
            self.remove(&stale).await;
        }
        self.insert(current, value).await
    }

    /// Mark the peers bound to `dest_ips` as offline without touching their routes.
    ///
    /// The `ScopedRoute` for each IP stays installed, so packets keep arriving at our TUN (where
    /// the caller answers with an ICMP host-unreachable) instead of the kernel rejecting them for
    /// lack of a route. A later [`Self::insert`] re-arms the entry in place; [`Self::remove`]
    /// tears it down for good. IPs with no entry are ignored.
    pub fn park(&self, dest_ips: &[IpAddr]) {
        let _span = tracing::info_span!("p2p_vpn_relay_park");
        for ip in dest_ips {
            if let Some(mut entry) = self.peer_map.get_mut(ip) {
                entry.value = None;
            }
        }
    }

    pub async fn remove(&self, dest_ips: &[IpAddr]) {
        let _span = tracing::info_span!("p2p_vpn_relay_remove");
        self.remove_locked(&self.handle.lock().await, dest_ips).await
    }

    async fn remove_locked(&self, locked: &MutexGuard<'_, R>, dest_ips: &[IpAddr]) {
        let _ = join_all(dest_ips.iter().map(|ip| async move {
            // Prefer removing via the tracked `ScopedRoute` if we have one: it's the same route
            // `insert` created. If there's no entry (e.g. rolling back an `insert` whose
            // `ScopedRoute::new` itself failed), fall back to a best-effort direct removal in
            // case the OS partially applied it anyway.
            let result = match self.peer_map.remove(ip) {
                Some((_, old)) => old.route.drop_async(&**locked).await.map(|_ip| ()),
                None => locked.remove(*ip).await,
            };
            if let Err(err) = &result {
                tracing::error!(error = ?err, dest_ip = ?ip,
                    "Errors removing route to the system routing tables");
                metrics::counter!(
                    "p2p_vpn_relay_remove_errors",
                    ExtractedErrorCode::from_io(err).into_labels()
                )
                .increment(1);
            }
        }))
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error, ErrorKind};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::{Arc, Mutex as StdMutex};

    /// In-memory fake route handle for isolated unit testing
    #[derive(Debug, Clone)]
    pub struct MockRouteHandle {
        pub active_routes: Arc<StdMutex<HashSet<IpAddr>>>,
        pub should_fail: Arc<StdMutex<bool>>,
    }

    impl MockRouteHandle {
        pub fn new() -> Self {
            Self {
                active_routes: Arc::new(StdMutex::new(HashSet::new())),
                should_fail: Arc::new(StdMutex::new(false)),
            }
        }

        pub fn set_fail(&self, fail: bool) {
            *self.should_fail.lock().unwrap() = fail;
        }

        pub fn has_route(&self, ip: &IpAddr) -> bool {
            self.active_routes.lock().unwrap().contains(ip)
        }
    }

    impl RoutingTable for MockRouteHandle {
        async fn insert(&self, dest_ip: IpAddr) -> Result<(), std::io::Error> {
            if *self.should_fail.lock().unwrap() {
                return Err(Error::new(ErrorKind::PermissionDenied, "Mock OS route insert error"));
            }
            self.active_routes.lock().unwrap().insert(dest_ip);
            Ok(())
        }

        async fn remove(&self, dest_ip: IpAddr) -> Result<(), std::io::Error> {
            self.active_routes.lock().unwrap().remove(&dest_ip);
            Ok(())
        }
    }

    fn connected<T>(v: T) -> Option<Dispatch<T>> {
        Some(Dispatch::Connected(v))
    }

    fn parked<T>() -> Option<Dispatch<T>> {
        Some(Dispatch::Parked)
    }

    // Helper functions to generate mock IP addresses
    fn ip4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn ip6(a: u16, b: u16) -> IpAddr {
        IpAddr::V6(Ipv6Addr::new(a, b, 0, 0, 0, 0, 0, 1))
    }

    #[tokio::test]
    async fn test_insert_and_get_single_ip() {
        let mock_handle = MockRouteHandle::new();
        let relay = Relay::new(mock_handle.clone());

        let ip = ip4(192, 168, 1, 10);
        let peer_val = "peer_1".to_string();

        let ips = vec![ip];
        let result = relay.insert(&ips, peer_val.clone()).await;

        assert!(result.is_ok(), "Insert should succeed for valid IP");
        assert!(mock_handle.has_route(&ip), "Route must be registered in mock table");
        assert_eq!(relay.get(&ip), connected("peer_1".to_string()));

        relay.remove(&ips).await;
    }

    #[tokio::test]
    async fn test_insert_and_get_multiple_ips() {
        let mock_handle = MockRouteHandle::new();
        let relay = Relay::new(mock_handle.clone());

        let ip1 = ip4(10, 0, 0, 1);
        let ip2 = ip4(10, 0, 0, 2);
        let ip3 = ip6(0x2001, 0xdb8);
        let peer_val = 42;

        let ips = vec![ip1, ip2, ip3];
        let result = relay.insert(&ips, peer_val).await;

        assert!(result.is_ok());
        assert!(mock_handle.has_route(&ip1));
        assert!(mock_handle.has_route(&ip2));
        assert!(mock_handle.has_route(&ip3));

        assert_eq!(relay.get(&ip1), connected(42));
        assert_eq!(relay.get(&ip2), connected(42));
        assert_eq!(relay.get(&ip3), connected(42));

        relay.remove(&ips).await;
    }

    #[tokio::test]
    async fn test_get_non_existent_ip() {
        let mock_handle = MockRouteHandle::new();
        let relay: Relay<String, MockRouteHandle> = Relay::new(mock_handle);

        let ip = ip4(172, 16, 0, 1);
        assert_eq!(relay.get(&ip), None);
    }

    #[tokio::test]
    async fn test_remove_ips() {
        let mock_handle = MockRouteHandle::new();
        let relay = Relay::new(mock_handle.clone());

        let ip1 = ip4(192, 168, 10, 1);
        let ip2 = ip4(192, 168, 10, 2);
        let peer_val = "node_alpha".to_string();

        let ips = vec![ip1, ip2];
        relay.insert(&ips, peer_val).await.unwrap();

        assert_eq!(relay.get(&ip1), connected("node_alpha".to_string()));
        assert!(mock_handle.has_route(&ip1));

        // Remove only ip1
        let remove_ips = vec![ip1];
        relay.remove(&remove_ips).await;

        assert_eq!(relay.get(&ip1), None, "ip1 should be removed from relay map");
        assert!(!mock_handle.has_route(&ip1), "ip1 should be removed from mock routing table");
        assert_eq!(
            relay.get(&ip2),
            connected("node_alpha".to_string()),
            "ip2 should remain in map"
        );
        assert!(mock_handle.has_route(&ip2), "ip2 should remain in mock routing table");

        relay.remove(&[ip2]).await;
    }

    #[tokio::test]
    async fn test_overwrite_existing_ip() {
        let mock_handle = MockRouteHandle::new();
        let relay = Relay::new(mock_handle.clone());

        let ip = ip4(192, 168, 100, 5);
        let peer_val1 = "initial_peer".to_string();
        let peer_val2 = "updated_peer".to_string();

        let ips = vec![ip];
        relay.insert(&ips, peer_val1).await.unwrap();
        assert_eq!(relay.get(&ip), connected("initial_peer".to_string()));

        relay.insert(&ips, peer_val2).await.unwrap();
        assert_eq!(relay.get(&ip), connected("updated_peer".to_string()));
        assert!(
            mock_handle.has_route(&ip),
            "route must still be active after overwriting the IP with a new peer value \
             (the existing entry is re-armed in place, keeping the same OS-level route)"
        );

        relay.remove(&ips).await;
    }

    #[tokio::test]
    async fn test_insert_failure_rollback() {
        let mock_handle = MockRouteHandle::new();
        let relay = Relay::new(mock_handle.clone());

        let ip1 = ip4(10, 0, 0, 1);
        let ip2 = ip4(10, 0, 0, 2);
        let ips = vec![ip1, ip2];

        // Force the mock routing table to fail on route insertion
        mock_handle.set_fail(true);

        let result = relay.insert(&ips, "fail_node".to_string()).await;

        assert!(result.is_err(), "Insert must return error when route creation fails");
        assert_eq!(relay.get(&ip1), None, "Map must rollback and remain empty on failure");
        assert_eq!(relay.get(&ip2), None, "Map must rollback and remain empty on failure");
    }

    #[tokio::test]
    async fn test_concurrent_access_get_and_insert() {
        let mock_handle = MockRouteHandle::new();
        let relay = Arc::new(Relay::new(mock_handle.clone()));

        let ip = ip4(10, 1, 1, 1);
        let peer_val = "concurrent_node".to_string();

        let relay_clone = Arc::clone(&relay);

        // Writer task executing concurrently
        let writer_handle = tokio::spawn(async move {
            let ips = vec![ip];
            relay_clone.insert(&ips, peer_val).await
        });

        // Reader task executing concurrently
        let relay_reader = Arc::clone(&relay);
        let reader_handle = tokio::spawn(async move {
            for _ in 0..100 {
                let _ = relay_reader.get(&ip);
                tokio::task::yield_now().await;
            }
        });

        let (writer_res, _) = tokio::join!(writer_handle, reader_handle);
        assert!(writer_res.unwrap().is_ok());
        assert_eq!(relay.get(&ip), connected("concurrent_node".to_string()));
        assert!(mock_handle.has_route(&ip));

        relay.remove(&[ip]).await;
    }

    #[tokio::test]
    async fn park_marks_the_entry_offline_and_keeps_the_route() {
        let mock_handle = MockRouteHandle::new();
        let relay = Relay::new(mock_handle.clone());

        let ip = ip4(10, 9, 0, 1);
        relay.insert(&[ip], "peer".to_string()).await.unwrap();

        relay.park(&[ip]);

        assert_eq!(relay.get(&ip), parked());
        assert!(
            mock_handle.has_route(&ip),
            "parking must leave the kernel route installed so packets still reach our TUN"
        );

        relay.remove(&[ip]).await;
    }

    #[tokio::test]
    async fn insert_rearms_a_parked_entry_without_recreating_the_route() {
        let mock_handle = MockRouteHandle::new();
        let relay = Relay::new(mock_handle.clone());

        let ip = ip4(10, 9, 0, 2);
        relay.insert(&[ip], "old".to_string()).await.unwrap();
        relay.park(&[ip]);

        // Any attempt to create a fresh route now fails; re-arming a parked entry must not need one.
        mock_handle.set_fail(true);
        relay
            .insert(&[ip], "new".to_string())
            .await
            .expect("re-arming a parked entry must not create a new route");

        assert_eq!(relay.get(&ip), connected("new".to_string()));
        assert!(mock_handle.has_route(&ip));

        mock_handle.set_fail(false);
        relay.remove(&[ip]).await;
    }

    #[tokio::test]
    async fn park_ignores_unknown_ips() {
        let mock_handle = MockRouteHandle::new();
        let relay: Relay<String, MockRouteHandle> = Relay::new(mock_handle);

        let ip = ip4(203, 0, 113, 7);
        relay.park(&[ip]); // must not panic
        assert_eq!(relay.get(&ip), None);
    }

    #[tokio::test]
    async fn remove_tears_down_a_parked_entry() {
        let mock_handle = MockRouteHandle::new();
        let relay = Relay::new(mock_handle.clone());

        let ip = ip4(10, 9, 0, 4);
        relay.insert(&[ip], "peer".to_string()).await.unwrap();
        relay.park(&[ip]);

        relay.remove(&[ip]).await;

        assert_eq!(relay.get(&ip), None);
        assert!(!mock_handle.has_route(&ip));
    }

    #[tokio::test]
    async fn reconcile_drops_addresses_the_peer_no_longer_advertises() {
        let mock_handle = MockRouteHandle::new();
        let relay = Relay::new(mock_handle.clone());

        let ip1 = ip4(10, 8, 0, 1);
        let ip2 = ip4(10, 8, 0, 2);
        let ip3 = ip4(10, 8, 0, 3);

        let previous = vec![ip1, ip2];
        relay.insert(&previous, "v1".to_string()).await.unwrap();
        relay.park(&previous);

        // The peer reconfigured its network: keeps ip2, drops ip1, adds ip3.
        let current = vec![ip2, ip3];
        relay.reconcile(&current, &previous, "v2".to_string()).await.unwrap();

        assert_eq!(relay.get(&ip1), None, "dropped address is withdrawn");
        assert!(!mock_handle.has_route(&ip1), "its route is torn down");

        assert_eq!(
            relay.get(&ip2),
            connected("v2".to_string()),
            "kept address is re-armed in place"
        );
        assert!(mock_handle.has_route(&ip2));

        assert_eq!(
            relay.get(&ip3),
            connected("v2".to_string()),
            "newly advertised address is added"
        );
        assert!(mock_handle.has_route(&ip3));

        relay.remove(&current).await;
    }

    #[tokio::test]
    async fn reconcile_rolls_back_the_new_batch_on_route_failure() {
        let mock_handle = MockRouteHandle::new();
        let relay = Relay::new(mock_handle.clone());

        let ip1 = ip4(10, 7, 0, 1);
        let ip2 = ip4(10, 7, 0, 2);
        let ip3 = ip4(10, 7, 0, 3);

        let previous = vec![ip1, ip2];
        relay.insert(&previous, "v1".to_string()).await.unwrap();
        relay.park(&previous);

        // ip1 is dropped (stale), ip3 is newly advertised but its route creation fails.
        mock_handle.set_fail(true);
        let current = vec![ip2, ip3];
        let result = relay.reconcile(&current, &previous, "v2".to_string()).await;

        assert!(result.is_err());
        assert_eq!(relay.get(&ip1), None, "stale address stays withdrawn");
        assert_eq!(relay.get(&ip2), None, "re-armed entry is rolled back too");
        assert_eq!(relay.get(&ip3), None, "failed insert leaves nothing");
        assert!(!mock_handle.has_route(&ip1));
    }
}
