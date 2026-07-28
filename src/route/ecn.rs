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
