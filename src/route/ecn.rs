use etherparse::{IpEcn, IpHeaders};
use rand;

/// Packet routing outcome for the VPN engine
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketAction {
    Forward, // Packet (possibly updated with ECN info) and is ready to be forwarded.
    Drop,    // Endpoint lacks ECN support; drop to signal congestion via loss.
}

/// Evaluates a packet under congestion.
/// If ECN capable, marks it in-place and returns `PacketAction::Forward`.
/// If not ECN capable, returns `PacketAction::Drop`.
pub fn process_packet_congestion(packet_buffer: &mut [u8]) -> PacketAction {
    let Ok((mut ip_header, _remainder)) = IpHeaders::from_slice(packet_buffer) else {
        // Drop malformed packets that cannot be parsed
        // TODO: Add a metric for such packets.
        return PacketAction::Drop;
    };

    match &mut ip_header {
        IpHeaders::Ipv4(ipv4_header, _) => {
            match ipv4_header.ecn {
                IpEcn::Ect0 | IpEcn::Ect1 => {
                    ipv4_header.ecn = IpEcn::CongestionExperienced;
                    ipv4_header.header_checksum = ipv4_header.calc_header_checksum();
                    // Commit changes back to buffer.
                    packet_buffer[..ipv4_header.header_len()]
                        .copy_from_slice(&ipv4_header.to_bytes());
                    PacketAction::Forward
                }
                // Already marked downstream, keep forwarding
                IpEcn::CongestionExperienced => PacketAction::Forward,
                // Legacy endpoint. Must drop to trigger TCP backoff.
                IpEcn::NotEct => PacketAction::Drop,
            }
        }
        IpHeaders::Ipv6(ipv6_header, _) => {
            match ipv6_header.ecn() {
                IpEcn::Ect0 | IpEcn::Ect1 => {
                    ipv6_header.set_ecn(IpEcn::CongestionExperienced);
                    // Commit changes back to buffer (IPv6 headers are fixed length of 40 bytes).
                    packet_buffer[..40].copy_from_slice(&ipv6_header.to_bytes());
                    PacketAction::Forward
                }
                IpEcn::CongestionExperienced => PacketAction::Forward,
                IpEcn::NotEct => PacketAction::Drop,
            }
        }
    }
}

/// Simple Linear Advanced Queue Management logic: The more a queue gets full over `threshold`, the
/// more packet will be dropped in a random fashion.
///
/// Returns `true` iff an incoming packet should be queued.
pub fn linear_aqm(threshold: f32, fill_ratio: f32) -> bool {
    linear_aqm_rng(rand::rng(), threshold, fill_ratio)
}

/// Same as `linar_aqm`, but using a given `rand::Rng` implementation.
pub fn linear_aqm_rng(mut rng: impl rand::Rng, threshold: f32, fill_ratio: f32) -> bool {
    if fill_ratio < threshold {
        return true;
    }
    let r: f32 = rng.random();
    fill_ratio - threshold <= r * (1.0 - threshold)
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::{IpNumber, Ipv4Header, Ipv6Header};
    use rand::RngCore;

    const PAYLOAD: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];
    const V4_SRC: [u8; 4] = [10, 0, 0, 1];
    const V4_DST: [u8; 4] = [10, 0, 0, 2];
    const V6_SRC: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    const V6_DST: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

    /// Builds a serialized IPv4 packet carrying the given ECN codepoint, a valid header
    /// checksum, and a fixed 4-byte payload.
    fn ipv4_packet(ecn: IpEcn) -> Vec<u8> {
        let mut header = Ipv4Header {
            ecn,
            total_len: (Ipv4Header::MIN_LEN + PAYLOAD.len()) as u16,
            time_to_live: 64,
            protocol: IpNumber::UDP,
            source: V4_SRC,
            destination: V4_DST,
            ..Default::default()
        };
        header.header_checksum = header.calc_header_checksum();
        let mut buf = header.to_bytes().to_vec();
        buf.extend_from_slice(&PAYLOAD);
        buf
    }

    /// Builds a serialized IPv6 packet carrying the given ECN codepoint and a fixed 4-byte
    /// payload.
    fn ipv6_packet(ecn: IpEcn) -> Vec<u8> {
        let mut header = Ipv6Header {
            payload_length: PAYLOAD.len() as u16,
            next_header: IpNumber::UDP,
            hop_limit: 64,
            source: V6_SRC,
            destination: V6_DST,
            ..Default::default()
        };
        header.set_ecn(ecn);
        let mut buf = header.to_bytes().to_vec();
        buf.extend_from_slice(&PAYLOAD);
        buf
    }

    #[test]
    fn ipv4_ect0_is_marked_congestion_experienced_and_forwarded() {
        let mut packet = ipv4_packet(IpEcn::Ect0);

        let action = process_packet_congestion(&mut packet);

        assert_eq!(action, PacketAction::Forward);
        let (header, remainder) = Ipv4Header::from_slice(&packet).unwrap();
        assert_eq!(header.ecn, IpEcn::CongestionExperienced);
        // The in-place edit must leave the header checksum valid.
        assert_eq!(header.header_checksum, header.calc_header_checksum());
        // Nothing outside the ECN bits and checksum is touched.
        assert_eq!(remainder, &PAYLOAD[..]);
        assert_eq!(header.source, V4_SRC);
        assert_eq!(header.destination, V4_DST);
        assert_eq!(header.time_to_live, 64);
    }

    #[test]
    fn ipv4_ect1_is_marked_congestion_experienced_and_forwarded() {
        let mut packet = ipv4_packet(IpEcn::Ect1);

        let action = process_packet_congestion(&mut packet);

        assert_eq!(action, PacketAction::Forward);
        let (header, _) = Ipv4Header::from_slice(&packet).unwrap();
        assert_eq!(header.ecn, IpEcn::CongestionExperienced);
        assert_eq!(header.header_checksum, header.calc_header_checksum());
    }

    #[test]
    fn ipv4_already_congestion_experienced_is_forwarded_unchanged() {
        let mut packet = ipv4_packet(IpEcn::CongestionExperienced);
        let before = packet.clone();

        let action = process_packet_congestion(&mut packet);

        assert_eq!(action, PacketAction::Forward);
        assert_eq!(packet, before);
    }

    #[test]
    fn ipv4_not_ect_is_dropped_unchanged() {
        let mut packet = ipv4_packet(IpEcn::NotEct);
        let before = packet.clone();

        let action = process_packet_congestion(&mut packet);

        assert_eq!(action, PacketAction::Drop);
        assert_eq!(packet, before);
    }

    #[test]
    fn ipv6_ect0_is_marked_congestion_experienced_and_forwarded() {
        let mut packet = ipv6_packet(IpEcn::Ect0);

        let action = process_packet_congestion(&mut packet);

        assert_eq!(action, PacketAction::Forward);
        let (header, remainder) = Ipv6Header::from_slice(&packet).unwrap();
        assert_eq!(header.ecn(), IpEcn::CongestionExperienced);
        // Only the traffic-class ECN bits change; addresses and payload stay put.
        assert_eq!(remainder, &PAYLOAD[..]);
        assert_eq!(header.source, V6_SRC);
        assert_eq!(header.destination, V6_DST);
        assert_eq!(header.hop_limit, 64);
    }

    #[test]
    fn ipv6_ect1_is_marked_congestion_experienced_and_forwarded() {
        let mut packet = ipv6_packet(IpEcn::Ect1);

        let action = process_packet_congestion(&mut packet);

        assert_eq!(action, PacketAction::Forward);
        let (header, _) = Ipv6Header::from_slice(&packet).unwrap();
        assert_eq!(header.ecn(), IpEcn::CongestionExperienced);
    }

    #[test]
    fn ipv6_already_congestion_experienced_is_forwarded_unchanged() {
        let mut packet = ipv6_packet(IpEcn::CongestionExperienced);
        let before = packet.clone();

        let action = process_packet_congestion(&mut packet);

        assert_eq!(action, PacketAction::Forward);
        assert_eq!(packet, before);
    }

    #[test]
    fn ipv6_not_ect_is_dropped_unchanged() {
        let mut packet = ipv6_packet(IpEcn::NotEct);
        let before = packet.clone();

        let action = process_packet_congestion(&mut packet);

        assert_eq!(action, PacketAction::Drop);
        assert_eq!(packet, before);
    }

    #[test]
    fn unparseable_packets_are_dropped() {
        assert_eq!(process_packet_congestion(&mut []), PacketAction::Drop);
        // Garbage: IP version nibble 0xF is neither 4 nor 6.
        assert_eq!(
            process_packet_congestion(&mut [0xff, 0xff, 0xff, 0xff]),
            PacketAction::Drop
        );
        // A truncated IPv4 header (claims IHL 5 but only 3 bytes present).
        assert_eq!(
            process_packet_congestion(&mut [0x45, 0x00, 0x00]),
            PacketAction::Drop
        );
    }

    /// A deterministic RNG whose every output is a fixed value chosen so that
    /// `rng.random::<f32>()` equals `fraction`. `StandardUniform` for f32 keeps the top 24
    /// bits of one `next_u32()` and scales them by `2^-24`.
    struct FixedRng(u32);

    impl FixedRng {
        fn yielding(fraction: f32) -> Self {
            const SCALE: f32 = (1u32 << 24) as f32;
            let bits24 = ((fraction * SCALE) as u32).min((1 << 24) - 1);
            FixedRng(bits24 << 8)
        }
    }

    impl RngCore for FixedRng {
        fn next_u32(&mut self) -> u32 {
            self.0
        }
        fn next_u64(&mut self) -> u64 {
            u64::from(self.0)
        }
        fn fill_bytes(&mut self, dst: &mut [u8]) {
            dst.fill(self.0 as u8);
        }
    }

    #[test]
    fn linear_aqm_queues_below_threshold_regardless_of_rng() {
        // fill_ratio < threshold short-circuits before the RNG is consulted.
        assert!(linear_aqm_rng(FixedRng::yielding(0.0), 0.8, 0.1));
        assert!(linear_aqm_rng(FixedRng::yielding(1.0), 0.8, 0.1));
        assert!(linear_aqm(0.9, 0.1));
    }

    #[test]
    fn linear_aqm_drops_above_threshold_when_rng_is_low() {
        // fill_ratio - threshold = 0.6, r = 0.0  =>  0.6 <= 0.0 is false.
        assert!(!linear_aqm_rng(FixedRng::yielding(0.0), 0.2, 0.8));
    }

    #[test]
    fn linear_aqm_queues_exactly_at_threshold() {
        // fill_ratio == threshold  =>  0.0 <= r * (1.0 - threshold) holds for any r >= 0.
        assert!(linear_aqm_rng(FixedRng::yielding(0.0), 0.5, 0.5));
        assert!(linear_aqm_rng(FixedRng::yielding(1.0), 0.5, 0.5));
    }

    #[test]
    fn linear_aqm_probability_scales_with_fill() {
        // threshold 0: keep-probability is exactly `r`. r = 0.5 here.
        // fill 0.5  =>  0.5 <= 0.5  => queue.
        assert!(linear_aqm_rng(FixedRng::yielding(0.5), 0.0, 0.5));
        // fill 0.6  =>  0.6 <= 0.5  => drop.
        assert!(!linear_aqm_rng(FixedRng::yielding(0.5), 0.0, 0.6));
    }

    #[test]
    fn linear_aqm_full_queue_drops_below_full_threshold() {
        // fill_ratio 1.0, threshold 0.3, r = 0.0  =>  0.7 <= 0.0 is false.
        assert!(!linear_aqm_rng(FixedRng::yielding(0.0), 0.3, 1.0));
    }

    #[test]
    fn linear_aqm_threshold_one_always_queues() {
        // threshold == 1.0, fill_ratio == 1.0  =>  0.0 <= r * 0.0  => queue for any r.
        assert!(linear_aqm_rng(FixedRng::yielding(0.0), 1.0, 1.0));
        assert!(linear_aqm_rng(FixedRng::yielding(1.0), 1.0, 1.0));
    }
}
