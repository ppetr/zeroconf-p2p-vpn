use anyhow::{anyhow, Context, Result};
use bytes::{BufMut, Bytes};
use etherparse::{icmpv4, icmpv6, Icmpv4Type, Icmpv6Type, IpHeaders, Ipv4Header};
use etherparse::{InternetSlice, PacketBuilder, PacketHeaders, SlicedPacket};
use pretty_hex::PrettyHex;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Deref;
use std::time::Instant;

pub use crate::buffer_pool::PooledSlice;

fn format_packet(packet: &[u8], f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let mut builder = f.debug_struct("TxPacket");
    if let Ok(sliced) = PacketHeaders::from_ip_slice(packet) {
        builder.field("sliced", &sliced);
    }
    builder.field("payload", &packet.hex_dump()).finish()
}

pub fn elapsed_millis(since: Instant) -> f64 {
    let elapsed = since.elapsed();
    (elapsed.as_secs() as f64 * 1000.0) + (elapsed.subsec_nanos() as f64 / 1_000_000.0)
}

pub struct TxPacket {
    pub data: Bytes,
    pub populated_at: Instant,
}

impl TxPacket {
    pub fn new(data: Bytes) -> Self {
        Self {
            data,
            populated_at: Instant::now(),
        }
    }
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
    pub populated_at: std::time::Instant,
}

impl RxPacket {
    pub fn new(data: PooledSlice) -> Self {
        Self {
            data,
            populated_at: Instant::now(),
        }
    }
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

/// Extracts the destination IP address from a slice.
pub fn destination_ip(internet_slice: &InternetSlice) -> Option<IpAddr> {
    match internet_slice {
        InternetSlice::Ipv4(ipv4_slice) => Some(IpAddr::V4(ipv4_slice.header().destination_addr())),
        InternetSlice::Ipv6(ipv6_slice) => Some(IpAddr::V6(ipv6_slice.header().destination_addr())),
        InternetSlice::Arp(_) => None,
    }
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

    /// Host-unreachable (the peer is known, but there is currently no usable link to it) as
    /// opposed to the network-unknown [`Self::unreachable_net`]. Meant for the reconnect gap,
    /// when `PeerSession`'s link has dropped to `None`; not wired into `tun_rx_loop` yet.
    #[allow(dead_code)]
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

    #[test]
    fn empty_packet_is_rejected() {
        let gateway = IcmpGateway::from_addr(IpAddr::from_str("8.8.4.4").unwrap());
        let mut buf = BytesMut::with_capacity(64);
        let err = gateway
            .generate_reply(&mut buf, b"", IcmpType::unreachable_net())
            .unwrap_err();
        assert!(err.to_string().contains("Empty packet"));
    }

    #[test]
    fn unparseable_packet_is_rejected() {
        let gateway = IcmpGateway::from_addr(IpAddr::from_str("8.8.4.4").unwrap());
        let mut buf = BytesMut::with_capacity(64);
        assert!(gateway
            .generate_reply(
                &mut buf,
                &[0xde, 0xad, 0xbe, 0xef],
                IcmpType::unreachable_net()
            )
            .is_err());
    }

    #[test]
    fn ipv6_packet_without_an_ipv6_gateway_is_rejected() {
        let gateway = IcmpGateway::from_addr(IpAddr::from_str("8.8.4.4").unwrap());
        let mut buf = BytesMut::with_capacity(128);
        let err = gateway
            .generate_reply(&mut buf, &MOCK_IPV6_PACKET, IcmpType::unreachable_net())
            .unwrap_err();
        assert!(err.to_string().contains("No address configured"));
    }

    #[test]
    fn ipv4_packet_without_an_ipv4_gateway_is_rejected() {
        let gateway = IcmpGateway::from_addr(IpAddr::from_str("2001:db8::1").unwrap());
        let mut buf = BytesMut::with_capacity(128);
        let err = gateway
            .generate_reply(&mut buf, &MOCK_IPV4_PACKET, IcmpType::unreachable_net())
            .unwrap_err();
        assert!(err.to_string().contains("No address configured"));
    }

    #[test]
    fn reply_echoes_at_most_64_bytes_of_the_original_packet() {
        let mut header = Ipv4Header {
            total_len: (Ipv4Header::MIN_LEN + 80) as u16,
            time_to_live: 64,
            // Experimental protocol number: the parser keeps the rest as opaque payload
            // instead of trying to decode a transport header out of the filler bytes.
            protocol: etherparse::IpNumber(253),
            source: [192, 168, 1, 10],
            destination: [8, 8, 8, 8],
            ..Default::default()
        };
        header.header_checksum = header.calc_header_checksum();
        let mut input = header.to_bytes().to_vec();
        input.extend((0..80).map(|i| i as u8));
        assert_eq!(input.len(), 100);

        let gateway = IcmpGateway::from_addr(IpAddr::from_str("8.8.4.4").unwrap());
        let mut reply = BytesMut::with_capacity(256);
        let to_addr = gateway
            .generate_reply(&mut reply, &input, IcmpType::unreachable_net())
            .unwrap();

        // 20B IPv4 header + 8B ICMPv4 header + exactly 64 echoed bytes.
        assert_eq!(reply.len(), 20 + 8 + 64);
        assert_eq!(&reply[28..], &input[..64]);
        assert_eq!(to_addr, IpAddr::from_str("192.168.1.10").unwrap());
    }

    #[test]
    fn inet_slice_identifies_ipv4_ipv6_and_rejects_garbage() {
        assert!(matches!(
            inet_slice(&MOCK_IPV4_PACKET).unwrap(),
            InternetSlice::Ipv4(_)
        ));
        assert!(matches!(
            inet_slice(&MOCK_IPV6_PACKET).unwrap(),
            InternetSlice::Ipv6(_)
        ));
        assert!(inet_slice(&[0xde, 0xad, 0xbe, 0xef]).is_err());
    }

    #[test]
    fn destination_ip_reads_the_ipv4_destination() {
        let slice = inet_slice(&MOCK_IPV4_PACKET).unwrap();
        assert_eq!(
            destination_ip(&slice),
            Some(IpAddr::from_str("8.8.8.8").unwrap())
        );
    }

    #[test]
    fn destination_ip_reads_the_ipv6_destination() {
        let slice = inet_slice(&MOCK_IPV6_PACKET).unwrap();
        assert_eq!(
            destination_ip(&slice),
            Some(IpAddr::from_str("2001:db8::fe2").unwrap())
        );
    }

    #[test]
    fn destination_ip_is_none_for_arp() {
        // htype=Ethernet, ptype=IPv4, hlen=6, plen=4, oper=request, then the four addresses.
        const ARP: [u8; 28] = [
            0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x0a, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x02,
        ];
        let arp = etherparse::ArpPacketSlice::from_slice(&ARP).unwrap();
        assert_eq!(destination_ip(&InternetSlice::Arp(arp)), None);
    }

    #[test]
    fn from_addr_populates_only_the_matching_address_family() {
        let v4 = IcmpGateway::from_addr(IpAddr::from_str("10.1.2.3").unwrap());
        assert_eq!(v4.own_ipv4, Some(Ipv4Addr::new(10, 1, 2, 3)));
        assert_eq!(v4.own_ipv6, None);

        let v6 = IcmpGateway::from_addr(IpAddr::from_str("2001:db8::5").unwrap());
        assert_eq!(
            v6.own_ipv6,
            Some(Ipv6Addr::from_str("2001:db8::5").unwrap())
        );
        assert_eq!(v6.own_ipv4, None);
    }

    #[test]
    fn icmp_type_constructors_build_the_expected_variants() {
        assert_eq!(
            IcmpType::unreachable_net(),
            IcmpType {
                v4: Icmpv4Type::DestinationUnreachable(
                    icmpv4::DestUnreachableHeader::NetworkUnknown
                ),
                v6: Icmpv6Type::DestinationUnreachable(icmpv6::DestUnreachableCode::NoRoute),
            }
        );
        assert_eq!(
            IcmpType::unreachable_host(),
            IcmpType {
                v4: Icmpv4Type::DestinationUnreachable(icmpv4::DestUnreachableHeader::Host),
                v6: Icmpv6Type::DestinationUnreachable(icmpv6::DestUnreachableCode::Address),
            }
        );
        assert_eq!(
            IcmpType::packet_too_big(1400),
            IcmpType {
                v4: Icmpv4Type::DestinationUnreachable(
                    icmpv4::DestUnreachableHeader::FragmentationNeeded { next_hop_mtu: 1400 }
                ),
                v6: Icmpv6Type::PacketTooBig { mtu: 1400 },
            }
        );
        assert_ne!(IcmpType::unreachable_net(), IcmpType::unreachable_host());
    }

    #[test]
    fn tx_packet_derefs_to_its_bytes_and_debug_never_panics() {
        let valid = TxPacket::new(Bytes::copy_from_slice(&MOCK_IPV4_PACKET));
        assert_eq!(&valid[..], &MOCK_IPV4_PACKET[..]);
        assert!(format!("{valid:?}").contains("TxPacket"));

        // `format_packet` takes the `Err` branch for an unparseable payload.
        let garbage = TxPacket::new(Bytes::from_static(&[0xde, 0xad]));
        assert_eq!(&garbage[..], &[0xde, 0xad]);
        assert!(format!("{garbage:?}").contains("TxPacket"));
    }
}
