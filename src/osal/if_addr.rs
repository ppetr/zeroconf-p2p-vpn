use futures_util::FutureExt;
use rtnetlink::{packet_route::address::AddressMessage, Handle};
use std::net::IpAddr;
use tracing::{info_span, Instrument};

use crate::osal::Globals;

/// An RAII guard that keeps an IP attached to an interface until it is dropped.
pub struct ScopedIfAddr {
    handle: Handle,
    if_index: u32,
    ip: IpAddr,
    message: AddressMessage,
}

impl ScopedIfAddr {
    /// Constructs a new `ScopedIfAddr` and immediately registers it with the Linux kernel.
    ///
    /// # Arguments
    /// * `handle` - An active [`rtnetlink::Handle`](https://docs.rs) connection.
    /// * `if_index` - The system numerical index of the target network interface.
    /// * `ip` - The destination IP address (IPv4 or IPv6) to assign.
    pub async fn new(
        globals: &Globals,
        if_index: u32,
        ip: IpAddr,
    ) -> Result<Self, rtnetlink::Error> {
        let _span = info_span!("scoped_if_addr_add", %ip, if_index);
        let mut request = globals
            .rtnetlink
            .address()
            .add(if_index, ip, Self::prefix_len(&ip));
        let message = request.message_mut().clone();
        request.execute().await?;
        Ok(Self {
            handle: globals.rtnetlink.clone(),
            if_index,
            ip,
            message,
        })
    }

    fn prefix_len(ip: &IpAddr) -> u8 {
        match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        }
    }
}

impl Drop for ScopedIfAddr {
    fn drop(&mut self) {
        let ip = self.ip;
        let span = info_span!("scoped_if_addr_del", %self.ip, self.if_index);
        // Since Drop must be synchronous, we offload the asynchronous
        // route elimination cleanup request onto the Tokio executor.
        let handle = self.handle.clone();
        let message = self.message.clone();
        tokio::spawn(
            async move { handle.address().del(message).execute().await }
                .instrument(span)
                .map(move |result| {
                    if let Err(_) = result {
                        metrics::counter!(
                      "scoped_ip_addr_cleanup_errors_total",
                      "ip_version" => match ip { IpAddr::V4(_) => "v4", IpAddr::V6(_) => "v6" })
                        .increment(1);
                    }
                }),
        );
    }
}
