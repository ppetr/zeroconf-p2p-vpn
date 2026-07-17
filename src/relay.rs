use dashmap::DashMap;
use futures_util::future::{join_all, try_join_all};
use metrics::IntoLabels;
use std::fmt::Debug;
use std::net::IpAddr;
use thin_status::ThinStatus;
use tokio::sync::{Mutex, MutexGuard};

use crate::error::ExtractedErrorCode;
use crate::route::{NetRouteHandle, RoutingTable};

#[derive(Clone, Debug)]
pub struct PeerValue<T>(T);

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
        Relay {
            handle: Mutex::new(handle),
            peer_map: DashMap::new(),
        }
    }

    /// Return a clone of a value bound to `dest_ip`, if one is present.
    ///
    /// If the value is still being added, or already being removed (`task` is still running),
    /// `None` is returned. If `task` failed, also `None` is returned.
    ///
    /// Optimized for performance so that it can be efficiently called for each incoming TUN packet.
    pub fn get(&self, dest_ip: &IpAddr) -> Option<T> {
        self.peer_map.get_mut(dest_ip).map(|e| e.value().0.clone())
    }

    pub async fn insert(&self, dest_ips: &[IpAddr], value: PeerValue<T>) -> Result<(), ThinStatus> {
        let _span = tracing::info_span!("p2p_vpn_relay_insert");
        let locked = self.handle.lock().await;
        let locked = &locked;
        let value_ref = &value;
        let result = try_join_all(dest_ips.into_iter().map(|ip| async move {
            let result = locked.insert((*ip).clone()).await;
            if let Err(err) = &result {
                tracing::error!(error = ?err, dest_ip = ?ip, peer = ?value_ref,
                    "Errors inserting route to the system routing tables");
            }
            result
        }))
        .await;

        match &result {
            Ok(_) => {
                for ip in dest_ips {
                    self.peer_map.insert((*ip).clone(), value.clone());
                }
                Ok(())
            }
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

    pub async fn remove(&self, dest_ips: &[IpAddr]) {
        let _span = tracing::info_span!("p2p_vpn_relay_remove");
        self.remove_locked(&mut self.handle.lock().await, dest_ips)
            .await
    }

    pub async fn remove_locked(&self, locked: &MutexGuard<'_, R>, dest_ips: &[IpAddr]) {
        for ip in dest_ips {
            self.peer_map.remove(ip);
        }
        let _ = join_all(dest_ips.into_iter().map(|ip| async {
            let result = locked.remove((*ip).clone()).await;
            if let Err(err) = &result {
                tracing::error!(error = ?err, dest_ip = ?(*ip).clone(),
                    "Errors removing route to the system routing tables");
                let _ = metrics::counter!(
                    "p2p_vpn_relay_remove_errors",
                    ExtractedErrorCode::from_io(err).into_labels()
                );
            }
        }))
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::future::Future;
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
                return Err(Error::new(
                    ErrorKind::PermissionDenied,
                    "Mock OS route insert error",
                ));
            }
            self.active_routes.lock().unwrap().insert(dest_ip);
            Ok(())
        }

        async fn remove(&self, dest_ip: IpAddr) -> Result<(), std::io::Error> {
            self.active_routes.lock().unwrap().remove(&dest_ip);
            Ok(())
        }
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
        let peer_val = PeerValue("peer_1".to_string());

        let ips = vec![ip];
        let result = relay.insert(&ips, peer_val.clone()).await;

        assert!(result.is_ok(), "Insert should succeed for valid IP");
        assert!(
            mock_handle.has_route(&ip),
            "Route must be registered in mock table"
        );
        assert_eq!(relay.get(&ip), Some("peer_1".to_string()));
    }

    #[tokio::test]
    async fn test_insert_and_get_multiple_ips() {
        let mock_handle = MockRouteHandle::new();
        let relay = Relay::new(mock_handle.clone());

        let ip1 = ip4(10, 0, 0, 1);
        let ip2 = ip4(10, 0, 0, 2);
        let ip3 = ip6(0x2001, 0xdb8);
        let peer_val = PeerValue(42);

        let ips = vec![ip1, ip2, ip3];
        let result = relay.insert(&ips, peer_val).await;

        assert!(result.is_ok());
        assert!(mock_handle.has_route(&ip1));
        assert!(mock_handle.has_route(&ip2));
        assert!(mock_handle.has_route(&ip3));

        assert_eq!(relay.get(&ip1), Some(42));
        assert_eq!(relay.get(&ip2), Some(42));
        assert_eq!(relay.get(&ip3), Some(42));
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
        let peer_val = PeerValue("node_alpha".to_string());

        let ips = vec![ip1, ip2];
        relay.insert(&ips, peer_val).await.unwrap();

        assert_eq!(relay.get(&ip1), Some("node_alpha".to_string()));
        assert!(mock_handle.has_route(&ip1));

        // Remove only ip1
        let remove_ips = vec![ip1];
        relay.remove(&remove_ips).await;

        assert_eq!(
            relay.get(&ip1),
            None,
            "ip1 should be removed from relay map"
        );
        assert!(
            !mock_handle.has_route(&ip1),
            "ip1 should be removed from mock routing table"
        );
        assert_eq!(
            relay.get(&ip2),
            Some("node_alpha".to_string()),
            "ip2 should remain in map"
        );
        assert!(
            mock_handle.has_route(&ip2),
            "ip2 should remain in mock routing table"
        );
    }

    #[tokio::test]
    async fn test_overwrite_existing_ip() {
        let mock_handle = MockRouteHandle::new();
        let relay = Relay::new(mock_handle);

        let ip = ip4(192, 168, 100, 5);
        let peer_val1 = PeerValue("initial_peer".to_string());
        let peer_val2 = PeerValue("updated_peer".to_string());

        let ips = vec![ip];
        relay.insert(&ips, peer_val1).await.unwrap();
        assert_eq!(relay.get(&ip), Some("initial_peer".to_string()));

        relay.insert(&ips, peer_val2).await.unwrap();
        assert_eq!(relay.get(&ip), Some("updated_peer".to_string()));
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

        let result = relay.insert(&ips, PeerValue("fail_node".to_string())).await;

        assert!(
            result.is_err(),
            "Insert must return error when route creation fails"
        );
        assert_eq!(
            relay.get(&ip1),
            None,
            "Map must rollback and remain empty on failure"
        );
        assert_eq!(
            relay.get(&ip2),
            None,
            "Map must rollback and remain empty on failure"
        );
    }

    #[tokio::test]
    async fn test_concurrent_access_get_and_insert() {
        let mock_handle = MockRouteHandle::new();
        let relay = Arc::new(Relay::new(mock_handle.clone()));

        let ip = ip4(10, 1, 1, 1);
        let peer_val = PeerValue("concurrent_node".to_string());

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
        assert_eq!(relay.get(&ip), Some("concurrent_node".to_string()));
        assert!(mock_handle.has_route(&ip));
    }
}
