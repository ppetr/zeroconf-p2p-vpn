use futures_util::FutureExt;
use rtnetlink::{packet_route::route::RouteMessage, Handle, RouteMessageBuilder};
use std::net::IpAddr;
use tracing::{info_span, Instrument};

use crate::osal::Globals;

/// An RAII guard that keeps an IP route active until it is dropped.
///
/// When instantiated via `ScopedRoute::new`, the specified IP address is routed through the
/// provided network interface index. When the instance falls out of scope, a background thread
/// automatically deletes the route from the kernel.
pub struct ScopedRoute {
    handle: Handle,
    if_index: u32,
    dest_ip: IpAddr,
}

impl ScopedRoute {
    /// Constructs a new `ScopedRoute` and immediately registers it with the Linux kernel.
    ///
    /// # Arguments
    /// * `handle` - An active [`rtnetlink::Handle`](https://docs.rs) connection.
    /// * `if_index` - The system numerical index of the target network interface.
    /// * `dest_ip` - The destination IP address (IPv4 or IPv6) to route.
    pub async fn new(
        globals: &Globals,
        if_index: u32,
        dest_ip: IpAddr,
    ) -> Result<Self, rtnetlink::Error> {
        let this = Self {
            handle: globals.rtnetlink.clone(),
            if_index,
            dest_ip,
        };
        let _span = info_span!("scoped_route_add", %this.dest_ip, this.if_index);
        this.handle.route().add(this.message()).execute().await?;
        Ok(this)
    }

    fn message(&self) -> RouteMessage {
        match self.dest_ip {
            IpAddr::V4(v4_addr) => RouteMessageBuilder::<std::net::Ipv4Addr>::new()
                .destination_prefix(v4_addr, 32)
                .output_interface(self.if_index)
                .build(),
            IpAddr::V6(v6_addr) => RouteMessageBuilder::<std::net::Ipv6Addr>::new()
                .destination_prefix(v6_addr, 128)
                .output_interface(self.if_index)
                .build(),
        }
    }
}

impl Drop for ScopedRoute {
    fn drop(&mut self) {
        let dest_ip = self.dest_ip;
        let span = info_span!("scoped_route_del", %self.dest_ip, self.if_index);
        // Since Drop must be synchronous, we offload the asynchronous
        // route elimination cleanup request onto the Tokio executor.
        let handle = self.handle.clone();
        let message = self.message();
        tokio::spawn(
            async move {
                // Direct equivalent to: ip route del <dest_ip> dev <interface>
                handle.route().del(message).execute().await
            }
            .instrument(span)
            .map(move |result| {
                if let Err(_) = result {
                    metrics::counter!(
                      "scoped_route_cleanup_errors_total",
                      "ip_version" => match dest_ip { IpAddr::V4(_) => "v4", IpAddr::V6(_) => "v6" })
                    .increment(1);
                }
            }),
        );
    }
}
