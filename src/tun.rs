use anyhow::{Context, Result};
use metrics::*;
use std::net::IpAddr;
use tokio::sync::mpsc;
use tun_rs::{AsyncDevice, DeviceBuilder};

pub mod packet;
pub use packet::*;

use crate::buffer_pool::{write_frame, BufferPool};
use crate::error::ExtractedErrorCode;
use crate::osal;

pub struct TunControlOpts {
    pub buffer_pool: usize,
    pub tx_packet: mpsc::Receiver<TxPacket>,
    pub rx_packet: mpsc::Sender<RxPacket>,
}

pub struct Tun {
    pub device: AsyncDevice,
    pub if_name: String,
    if_index: u32,
}

impl Tun {
    pub async fn new(if_name: Option<&str>) -> Result<Tun> {
        let builder = DeviceBuilder::new();
        let builder = if let Some(name) = if_name {
            builder.name(name)
        } else {
            builder
        };
        let dev = builder
            .build_async()
            .context("Failed to convert TUN device into async device")?;
        let name = dev.name()?;
        let if_index = dev.if_index().context("failed to get the device index")?;
        Ok(Tun {
            device: dev,
            if_name: name,
            if_index,
        })
    }

    pub fn if_index(&self) -> u32 {
        self.if_index
    }

    /// Assigns an IP address to the local TUN interface.
    pub async fn add_if_addr(&self, ip: IpAddr) -> Result<()> {
        match ip {
            IpAddr::V4(a) => self.device.add_address_v4(a, 32),
            IpAddr::V6(a) => self.device.add_address_v6(a, 128),
        }
        .context(format!(
            "when setting network address '{}' on TUN device '{}'",
            ip, self.if_name
        ))
    }

    pub async fn control(&self, opts: TunControlOpts) -> Result<()> {
        let pool_gauge = gauge!(
            description: "The capacity of the internal buffer pool; 0 means starvation",
            "p2p_vpn_tun_read_buffer_pool_capacity",
            "if_name" => self.if_name.clone(),
        );
        let recv_packets_histogram = histogram!(
            description: "Size of packets received from a TUN interface",
            unit: metrics::Unit::Bytes,
            "p2p_vpn_tun_recv_packets_size",
            "if_name" => self.if_name.clone(),
        );
        let send_packets_histogram = histogram!(
            description: "Size of packets sent to a TUN interface",
            unit: metrics::Unit::Bytes,
            "p2p_vpn_tun_send_packets_size",
            "if_name" => self.if_name.clone(),
        );

        let mut buffer_pool = BufferPool::new(opts.buffer_pool, 2048, pool_gauge);
        let dev = &self.device;

        let if_name = &self.if_name;
        let rx_packet = opts.rx_packet;
        let rx_task = async move {
            Ok::<(), anyhow::Error>(loop {
                let buf = match buffer_pool.pop().await.read_frame(dev).await {
                    Err(err) if osal::is_tun_transient(&err) => {
                        let mut labels = ExtractedErrorCode::from_io(&err).into_labels();
                        labels.push(metrics::Label::new("if_name", if_name.clone()));
                        counter!(description: "Read errors during the TUN read loop that we consider as transient (retryable)",
                                 "p2p_vpn_tun_read_transient_errors", labels).increment(1);
                        continue;
                    }
                    r => r?,
                };
                recv_packets_histogram.record(buf.len() as u32);
                if buf.len() > 0 {
                    rx_packet.send(RxPacket::new(buf.into())).await?;
                }
            })
        };

        let mut tx_packet = opts.tx_packet;
        let tx_task = async move {
            Ok::<(), anyhow::Error>(loop {
                let bytes = tx_packet.recv().await.context("Channel dropped")?;
                send_packets_histogram.record(bytes.len() as u32);
                match write_frame(&bytes.data, dev).await {
                    Err(err) if osal::is_tun_transient(&err) => {
                        let mut labels = ExtractedErrorCode::from_io(&err).into_labels();
                        labels.push(metrics::Label::new("if_name", if_name.clone()));
                        counter!(description: "Send errors during the TUN read loop that we consider as transient (retryable)",
                                 "p2p_vpn_tun_send_transient_errors", labels).increment(1);
                    }
                    r => r?,
                };
                histogram!(description: "Total time processing a packet QUIC->TUN (ms)",
                           unit: metrics::Unit::Milliseconds,
                           "p2p_vpn_tun_from_quic")
                .record(packet::elapsed_millis(bytes.populated_at));
            })
        };

        tokio::select! {
            err = rx_task => {
                err.context("rx task")
            }
            err = tx_task => {
                err.context("tx task")
            }
        }
    }
}
