use anyhow::{anyhow, Context, Result};
use bytes::{BufMut, Bytes};
use etherparse::{icmpv4, Icmpv4Type, Icmpv6Type, IpHeaders, Ipv4Header};
use etherparse::{InternetSlice, PacketBuilder, SlicedPacket};
use std::net::IpAddr;
use std::ops::Deref;

pub use crate::buffer_pool::PooledSlice;

pub struct TxPacket {
    pub data: Bytes,
}

pub struct RxPacket {
    pub data: PooledSlice,
    // IP address of the incoming packet will be added here.
}

impl Deref for RxPacket {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

/// Extracts the source and the destination addresses.
pub fn inet_slice<'a>(slice: &'a (impl AsRef<[u8]> + ?Sized)) -> Result<InternetSlice<'a>> {
    SlicedPacket::from_ip(slice.as_ref())
        .context("parsing packet IP addresses")
        .and_then(|sliced| {
            sliced
                .net
                .ok_or(anyhow!("no network information in packet"))
        })
}

pub fn generate_mtu_too_large(
    buffer: impl BufMut,
    original_packet: &[u8],
    max_mtu: u16,
) -> Result<IpAddr> {
    if original_packet.is_empty() {
        anyhow::bail!("Empty packet");
    }

    let icmp_payload = &original_packet[..std::cmp::min(original_packet.len(), 64)];
    match inet_slice(original_packet)? {
        etherparse::InternetSlice::Ipv4(ip) => {
            // An ICMPv4 response shouldn't prevert fragmentation to avoid further loops/bouncing
            // packets. Since this isn't supported by `PacketBuilder` directly, we need to build an
            // `Ipv4Header` from scratch.
            let ip_header = Ipv4Header {
                dont_fragment: false,
                time_to_live: 64,
                source: ip.header().source(),
                destination: ip.header().destination(),
                ..Default::default()
            };
            PacketBuilder::ip(IpHeaders::Ipv4(ip_header, Default::default()))
                .icmpv4(Icmpv4Type::DestinationUnreachable(
                    icmpv4::DestUnreachableHeader::FragmentationNeeded {
                        next_hop_mtu: max_mtu,
                    },
                ))
                .write(&mut buffer.writer(), &icmp_payload)
                .context("building ICMPv4 packet")?;
            Ok(IpAddr::V4(ip.header().source_addr()))
        }
        etherparse::InternetSlice::Ipv6(ip) => {
            PacketBuilder::ipv6(ip.header().source(), ip.header().destination(), 64)
                .icmpv6(Icmpv6Type::PacketTooBig {
                    mtu: max_mtu as u32,
                })
                .write(&mut buffer.writer(), &icmp_payload)
                .context("building ICMPv6 packet")?;
            Ok(IpAddr::V6(ip.header().source_addr()))
        }
        _ => anyhow::bail!("IP version mismatch"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use std::net::{Ipv4Addr, Ipv6Addr};
    #[allow(unused_imports)]
    use std::str::FromStr;

    // Minimal valid IPv4 UDP packet (20B IP + 8B UDP)
    // Src: 192.168.1.10, Dst: 8.8.8.8
    const MOCK_IPV4_PACKET: [u8; 28] = [
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x2d, 0xc0, 0xa8, 0x01,
        0x0a, 0x08, 0x08, 0x08, 0x08, 0x0b, 0xb8, 0x0b, 0xb8, 0x00, 0x08, 0x00, 0x00,
    ];

    // Minimal valid IPv6 UDP packet (40B IP + 8B UDP)
    // Src: 2001:db8::fe1, Dst: 2001:db8::fe2
    const MOCK_IPV6_PACKET: [u8; 48] = [
        0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x11, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0xe1, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0xe2, 0x0b, 0xb8, 0x0b, 0xb8, 0x00,
        0x08, 0x00, 0x00,
    ];

    #[test]
    fn test_ipv4_mtu_too_large() {
        let mut buf = BytesMut::with_capacity(128);

        // Request MTU 1400 (0x0578)
        let to_addr = generate_mtu_too_large(&mut buf, &MOCK_IPV4_PACKET, 1400).unwrap();

        let expected = [
            // IPv4 Header
            0x45, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0xa9, 0x03, 0xc0, 0xa8,
            0x01, 0x0a, 0x08, 0x08, 0x08, 0x08,
            // ICMPv4 Header (Type 3, Code 4, Checksum, MTU 1400 at the end)
            0x03, 0x04, 0x90, 0xed, 0x00, 0x00, 0x05, 0x78, // Original payload
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x2d, 0xc0, 0xa8,
            0x01, 0x0a, 0x08, 0x08, 0x08, 0x08, 0x0b, 0xb8, 0x0b, 0xb8, 0x00, 0x08, 0x00, 0x00,
        ];

        assert_eq!(buf.as_ref(), &expected[..]);
        assert_eq!(to_addr, IpAddr::from_str("192.168.1.10").unwrap());
    }

    #[test]
    fn test_ipv6_mtu_too_large() {
        let mut buf = BytesMut::with_capacity(128);

        // Request MTU 1280 (0x00000500)
        let to_addr = generate_mtu_too_large(&mut buf, &MOCK_IPV6_PACKET, 1280).unwrap();

        let expected = [
            // IPv6 Header (Src: 2001:db8::fe1, Dst: 2001:db8::fe2, NextHeader: 58 (ICMPv6), PayloadLen: 56)
            0x60, 0x00, 0x00, 0x00, 0x00, 0x38, 0x3a, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0xe1, 0x20, 0x01, 0x0d, 0xb8,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0xe2,
            // ICMPv6 Packet Too Big (Type: 2, Code: 0, Checksum, MTU: 0x00000500)
            0x02, 0x00, 0x79, 0x62, 0x00, 0x00, 0x05, 0x00,
            // Original payload appended (48B)
            0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x11, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0xe1, 0x20, 0x01, 0x0d, 0xb8,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0xe2, 0x0b, 0xb8,
            0x0b, 0xb8, 0x00, 0x08, 0x00, 0x00,
        ];

        assert_eq!(buf.as_ref(), &expected[..]);
        assert_eq!(to_addr, IpAddr::from_str("2001:db8::fe1").unwrap());
    }
}
