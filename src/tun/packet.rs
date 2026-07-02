use anyhow::{anyhow, Context, Result};
use bytes::{BufMut, Bytes};
use etherparse::{icmpv4, icmpv6, Icmpv4Type, Icmpv6Type, IpHeaders, Ipv4Header};
use etherparse::{InternetSlice, PacketBuilder, PacketHeaders, SlicedPacket};
use pretty_hex::PrettyHex;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Deref;

pub use crate::buffer_pool::PooledSlice;

fn format_packet(packet: &[u8], f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let mut builder = f.debug_struct("TxPacket");
    if let Ok(sliced) = PacketHeaders::from_ip_slice(packet) {
        builder.field("sliced", &sliced);
    }
    builder.field("payload", &packet.hex_dump()).finish()
}

pub struct TxPacket {
    pub data: Bytes,
}

impl Deref for TxPacket {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl std::fmt::Debug for TxPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        format_packet(&self, f)
    }
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

impl std::fmt::Debug for RxPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        format_packet(&self, f)
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

/// TODO
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct IcmpGateway {
    pub own_ipv4: Option<Ipv4Addr>,
    pub own_ipv6: Option<Ipv6Addr>,
}

impl IcmpGateway {
    pub fn from_addr(addr: IpAddr) -> Self {
        let mut gateway: Self = Default::default();
        match addr {
            IpAddr::V4(ip) => gateway.own_ipv4 = Some(ip),
            IpAddr::V6(ip) => gateway.own_ipv6 = Some(ip),
        };
        gateway
    }

    /// Generates a response ICMP packet to `original_packet` into `buffer`.
    /// The caller provides variants for both ICMPv4 and ICMPv6 packets.
    ///
    /// Returns the address where to send the response packet, that is, the source of `original_packet`.
    pub fn generate_reply(
        &self,
        buffer: impl BufMut,
        original_packet: &[u8],
        icmp_type: IcmpType,
    ) -> Result<IpAddr> {
        anyhow::ensure!(!original_packet.is_empty(), "Empty packet");

        let icmp_payload = &original_packet[..std::cmp::min(original_packet.len(), 64)];
        match (inet_slice(original_packet)?, &self.own_ipv4, &self.own_ipv6) {
            (InternetSlice::Ipv4(ip), Some(gateway), _) => {
                // An ICMPv4 response shouldn't prevert fragmentation to avoid further loops/bouncing
                // packets. Since this isn't supported by `PacketBuilder` directly, we need to build an
                // `Ipv4Header` from scratch.
                let ip_header = Ipv4Header {
                    dont_fragment: false,
                    time_to_live: 64,
                    source: gateway.octets(),
                    destination: ip.header().source(),
                    ..Default::default()
                };
                PacketBuilder::ip(IpHeaders::Ipv4(ip_header, Default::default()))
                    .icmpv4(icmp_type.v4)
                    .write(&mut buffer.writer(), &icmp_payload)
                    .context("building ICMPv4 packet")?;
                Ok(IpAddr::V4(ip.header().source_addr()))
            }
            (InternetSlice::Ipv6(ip), _, Some(gateway)) => {
                PacketBuilder::ipv6(gateway.octets(), ip.header().source(), 64)
                    .icmpv6(icmp_type.v6)
                    .write(&mut buffer.writer(), &icmp_payload)
                    .context("building ICMPv6 packet")?;
                Ok(IpAddr::V6(ip.header().source_addr()))
            }
            (slice, _, _) => anyhow::bail!(
                "No address configured/available for protocol {:?}: {:?}",
                slice,
                self
            ),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IcmpType {
    v4: Icmpv4Type,
    v6: Icmpv6Type,
}

impl IcmpType {
    pub fn unreachable_net() -> Self {
        Self {
            v4: Icmpv4Type::DestinationUnreachable(icmpv4::DestUnreachableHeader::NetworkUnknown),
            v6: Icmpv6Type::DestinationUnreachable(icmpv6::DestUnreachableCode::NoRoute),
        }
    }

    pub fn unreachable_host() -> Self {
        Self {
            v4: Icmpv4Type::DestinationUnreachable(icmpv4::DestUnreachableHeader::Host),
            v6: Icmpv6Type::DestinationUnreachable(icmpv6::DestUnreachableCode::Address),
        }
    }

    pub fn packet_too_big(mtu: u16) -> Self {
        Self {
            v4: Icmpv4Type::DestinationUnreachable(
                icmpv4::DestUnreachableHeader::FragmentationNeeded { next_hop_mtu: mtu },
            ),
            v6: Icmpv6Type::PacketTooBig { mtu: mtu as u32 },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
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
        let gateway = IcmpGateway::from_addr(IpAddr::from_str("8.8.4.4").unwrap());
        let mut buf = BytesMut::with_capacity(128);
        // Request MTU 1400 (0x0578)
        let to_addr = gateway
            .generate_reply(&mut buf, &MOCK_IPV4_PACKET, IcmpType::packet_too_big(1400))
            .unwrap();

        let expected = [
            // IPv4 Header
            0x45, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0xad, 0x07, 0x08, 0x08,
            0x04, 0x04, 0xc0, 0xa8, 0x01, 0x0a,
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
        let gateway = IcmpGateway::from_addr(IpAddr::from_str("2001:db8::1").unwrap());
        let mut buf = BytesMut::with_capacity(128);
        // Request MTU 1280 (0x00000500)
        let to_addr = gateway
            .generate_reply(&mut buf, &MOCK_IPV6_PACKET, IcmpType::packet_too_big(1280))
            .unwrap();

        let expected = [
            // IPv6 Header (Src: 2001:db8::1, Dst: 2001:db8::fe2, NextHeader: 58 (ICMPv6), PayloadLen: 56)
            0x60, 0x00, 0x00, 0x00, 0x00, 0x38, 0x3a, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x20, 0x01, 0x0d, 0xb8,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0xe1,
            // ICMPv6 Packet Too Big (Type: 2, Code: 0, Checksum, MTU: 0x00000500)
            0x02, 0x00, 0x89, 0x43, 0x00, 0x00, 0x05, 0x00,
            // Original payload appended (48B)
            0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x11, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0xe1, 0x20, 0x01, 0x0d, 0xb8,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0xe2, 0x0b, 0xb8,
            0x0b, 0xb8, 0x00, 0x08, 0x00, 0x00,
        ];

        assert_eq!(buf.as_ref(), &expected[..]);
        assert_eq!(to_addr, IpAddr::from_str("2001:db8::fe1").unwrap());
    }

    #[test]
    fn test_ipv4_no_route() {
        let gateway = IcmpGateway::from_addr(IpAddr::from_str("8.8.4.4").unwrap());
        let mut buf = BytesMut::with_capacity(128);
        let to_addr = gateway
            .generate_reply(&mut buf, &MOCK_IPV4_PACKET, IcmpType::unreachable_net())
            .unwrap();

        // Expected output layout: 20B IP header + 8B ICMP header + 28B original packet
        let expected = [
            // IPv4 Header (Dst: 192.168.1.10, Src: 8.8.4.4, Proto: 1 (ICMP), Len: 56)
            0x45, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0xad, 0x07, 0x08, 0x08,
            0x04, 0x04, 0xc0, 0xa8, 0x01, 0x0a,
            // ICMPv4 Header (Type: 3 (Unreachable), Code: 6 (Network Unreachable), Checksum)
            0x03, 0x06, 0x96, 0x63, 0x00, 0x00, 0x00, 0x00, // Original payload appended
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x2d, 0xc0, 0xa8,
            0x01, 0x0a, 0x08, 0x08, 0x08, 0x08, 0x0b, 0xb8, 0x0b, 0xb8, 0x00, 0x08, 0x00, 0x00,
        ];

        assert_eq!(buf.as_ref(), &expected[..]);
        assert_eq!(to_addr, IpAddr::from_str("192.168.1.10").unwrap());
    }

    #[test]
    fn test_ipv6_no_route() {
        let gateway = IcmpGateway::from_addr(IpAddr::from_str("2001:db8::1").unwrap());
        let mut buf = BytesMut::with_capacity(128);
        let to_addr = gateway
            .generate_reply(&mut buf, &MOCK_IPV6_PACKET, IcmpType::unreachable_net())
            .unwrap();

        // Expected output layout: 40B IPv6 header + 8B ICMPv6 header + 48B original packet
        let expected = [
            // IPv6 Header (Src: 2001:db8::1, Dst: 2001:db8::fe2, NextHeader: 58 (ICMPv6), PayloadLen: 56)
            0x60, 0x00, 0x00, 0x00, 0x00, 0x38, 0x3a, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x20, 0x01, 0x0d, 0xb8,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0xe1,
            // ICMPv6 Header (Type: 1 (Unreachable), Code: 0 (No Route to Dest))
            0x01, 0x00, 0x8f, 0x43, 0x00, 0x00, 0x00, 0x00, // Original payload appended
            0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x11, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0xe1, 0x20, 0x01, 0x0d, 0xb8,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0xe2, 0x0b, 0xb8,
            0x0b, 0xb8, 0x00, 0x08, 0x00, 0x00,
        ];

        assert_eq!(buf.as_ref(), &expected[..]);
        assert_eq!(to_addr, IpAddr::from_str("2001:db8::fe1").unwrap());
    }
}
