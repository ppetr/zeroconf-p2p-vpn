use anyhow::{Context, Error, Result};
use ipnet::IpNet;
use iroh::{PublicKey, Signature};
use metrics::*;

use crate::addr;
use crate::error::ExtractedErrorCode;
use crate::proto;

/// Returns addresses that pass signature verification (`verify_signed_ipnet`) and that are also
/// subnets of (at least one of) the given `allowed_nets`.
/// Returns errors for networks that failed parsing/validation.
/// Peer networks that passed validation, but are outside `allowed_nets`, are silently skipped.
pub fn validate_addresses(
    allowed_nets: &[IpNet],
    advertise: &proto::v1::Advertise,
    key: &PublicKey,
) -> (Vec<IpNet>, Vec<Error>) {
    let mut valid = Vec::<IpNet>::with_capacity(advertise.own_addresses.len());
    let mut errors = Vec::<Error>::with_capacity(advertise.own_addresses.len());
    for host in &advertise.own_addresses {
        match validate_address(host, key) {
            Ok(net) if is_subnet_of_any(&net, allowed_nets) => valid.push(net),
            Ok(_) => (),
            Err(e) => {
                let e = e.context(format!("when validating network '{}'", host.peer_network));
                tracing::info!(error = e.to_string(), key = key.to_z32());
                counter!(description: "Validating peer addresses",
                         "p2p_vpn_peer_validate_addr_errors",
                         ExtractedErrorCode::from_anyhow(&e))
                .increment(1);
                errors.push(e);
            }
        }
    }
    (valid, errors)
}

/// Validates a `v1::HostAddress` against the host's public key.
fn validate_address(host: &proto::v1::HostAddress, key: &PublicKey) -> Result<IpNet> {
    let net: IpNet = host.peer_network.parse()?;
    let signature = Signature::try_from(host.peer_network_signature.as_slice())
        .context("Invalid cryptographic signature")?;
    addr::verify_signed_ipnet(host.peer_network.parse()?, key, &signature)?;
    Ok(net)
}

fn is_subnet_of_any(net: &IpNet, allowed: &[IpNet]) -> bool {
    allowed.into_iter().any(|a| a.contains(net))
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;
    use std::str::FromStr;

    // Helper to create a valid proto::v1::HostAddress for testing
    fn make_host_address(net: &IpNet, secret_key: &SecretKey) -> proto::v1::HostAddress {
        let (ipnet, signature) = addr::generate_signed_ipnet(net, secret_key);
        proto::v1::HostAddress {
            peer_network: ipnet.to_string(),
            peer_network_signature: signature.to_bytes().to_vec(),
        }
    }

    #[test]
    fn test_validate_addresses_all_valid() {
        let secret_key = SecretKey::generate();
        let public_key = secret_key.public();
        let allowed_nets = vec![
            IpNet::from_str("10.0.0.0/8").unwrap(),
            IpNet::from_str("2001:db8::/32").unwrap(),
        ];
        let advertise = proto::v1::Advertise {
            own_addresses: vec![
                make_host_address(&IpNet::from_str("10.1.2.3/24").unwrap(), &secret_key),
                make_host_address(
                    &IpNet::from_str("2001:db8:cafe::42/48").unwrap(),
                    &secret_key,
                ),
            ],
        };

        let (valid, errors) = validate_addresses(&allowed_nets, &advertise, &public_key);

        assert_eq!(valid.len(), 2, "{:?}", errors);
        assert!(errors.is_empty());
        // Verify that the parsed networks are matching the structural subnets
        assert!(valid.iter().any(|n| allowed_nets[0].contains(n)));
        assert!(valid.iter().any(|n| allowed_nets[1].contains(n)));
    }

    #[test]
    fn test_validate_addresses_silently_skips_outside_allowed() {
        let secret_key = SecretKey::generate();
        let public_key = secret_key.public();
        let allowed_nets = vec![IpNet::from_str("10.0.0.0/8").unwrap()];
        // This network is cryptographically valid but outside allowed_nets
        let advertise = proto::v1::Advertise {
            own_addresses: vec![make_host_address(
                &IpNet::from_str("192.168.1.0/24").unwrap(),
                &secret_key,
            )],
        };
        let (valid, errors) = validate_addresses(&allowed_nets, &advertise, &public_key);

        // Should be empty because it's not allowed, but NO error because signature is correct.
        assert!(valid.is_empty());
        assert!(errors.is_empty());
    }

    #[test]
    fn test_validate_addresses_error_invalid_ip_format() {
        let public_key = SecretKey::generate().public();
        let allowed_nets = vec![IpNet::from_str("10.0.0.0/8").unwrap()];

        let advertise = proto::v1::Advertise {
            own_addresses: vec![proto::v1::HostAddress {
                peer_network: "invalid-ip-format/24".to_string(),
                peer_network_signature: vec![0u8; 64],
            }],
        };

        let (valid, errors) = validate_addresses(&allowed_nets, &advertise, &public_key);

        assert!(valid.is_empty());
        assert_eq!(errors.len(), 1);

        let err_msg = format!("{:?}", errors[0]);
        assert!(err_msg.contains("when validating network 'invalid-ip-format/24'"));
    }

    #[test]
    fn test_validate_addresses_error_invalid_signature_length() {
        let public_key = SecretKey::generate().public();
        let allowed_nets = vec![IpNet::from_str("10.0.0.0/8").unwrap()];

        let advertise = proto::v1::Advertise {
            own_addresses: vec![proto::v1::HostAddress {
                peer_network: "10.1.1.42/24".to_string(),
                // Ed25519 signatures must be exactly 32 bytes
                peer_network_signature: vec![0u8; 32],
            }],
        };

        let (valid, errors) = validate_addresses(&allowed_nets, &advertise, &public_key);

        assert!(valid.is_empty());
        assert_eq!(errors.len(), 1);

        let err_msg = format!("{:?}", errors[0]);
        assert!(err_msg.contains("Invalid cryptographic signature"));
    }

    #[test]
    fn test_validate_addresses_error_signature_verification_failed() {
        let alice_key = SecretKey::generate();
        let charlie_key = SecretKey::generate(); // Wrong key

        let allowed_nets = vec![IpNet::from_str("10.0.0.0/8").unwrap()];
        let net = IpNet::from_str("10.1.1.0/24").unwrap();

        // Alice signs it, but Bob will check it against Charlie's public key
        let advertise = proto::v1::Advertise {
            own_addresses: vec![make_host_address(&net, &alice_key)],
        };

        let (valid, errors) = validate_addresses(&allowed_nets, &advertise, &charlie_key.public());

        assert!(valid.is_empty());
        assert_eq!(errors.len(), 1);

        let err_msg = format!("{:?}", errors[0]);
        assert!(err_msg.contains("signature"), "{}", err_msg);
    }

    #[test]
    fn test_validate_addresses_combined_matrix() {
        let secret_key = SecretKey::generate();
        let public_key = secret_key.public();
        let allowed_nets = vec![IpNet::from_str("10.0.0.0/8").unwrap()];

        let valid_net = IpNet::from_str("10.1.1.0/24").unwrap();
        let outside_net = IpNet::from_str("192.168.1.0/24").unwrap();

        let advertise = proto::v1::Advertise {
            own_addresses: vec![
                make_host_address(&valid_net, &secret_key), // 1. Valid and allowed
                make_host_address(&outside_net, &secret_key), // 2. Valid but skipped
                proto::v1::HostAddress {
                    // 3. Error: Malformed
                    peer_network: "parse-fail".to_string(),
                    peer_network_signature: vec![0u8; 64],
                },
            ],
        };

        let (valid, errors) = validate_addresses(&allowed_nets, &advertise, &public_key);

        assert_eq!(valid.len(), 1);
        assert_eq!(errors.len(), 1);

        assert!(
            valid_net.contains(&valid[0]),
            "{} should be in {}",
            valid[0],
            valid_net
        );
        assert!(format!("{:?}", errors[0]).contains("parse-fail"));
    }
}
