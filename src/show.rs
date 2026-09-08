//! `zeroconf-p2p-vpn show <config>` — prints this node's public key and its derived VPN address
//! (plus the configured peers), without starting the daemon or touching the network.
//!
//! Everything shown is a pure function of the config and the private key: the VPN address is
//! `addr::generate_signed_ipnet` over the node's subnet, exactly what the daemon puts into its
//! `Advertise`. No Iroh endpoint is involved.

use std::fmt::Write as _;

use anyhow::Result;
use iroh::SecretKey;
use secure_p2p_transport::load_key_from_disk;

use crate::addr;
use crate::config::Config;

/// Renders the report printed by `show`.
pub fn report(config: &Config, secret_key: &SecretKey) -> String {
    let (own_net, _sig) =
        addr::generate_signed_ipnet(&ipnet::IpNet::V6(addr::vpn_subnet(config.subnet)), secret_key);

    let mut out = String::new();
    let _ = writeln!(out, "public key:  {}", secret_key.public().to_z32());
    let _ = writeln!(out, "VPN address: {}", own_net.addr());

    let mut peers: Vec<_> = config.peers.iter().collect();
    peers.sort_by(|a, b| a.0.cmp(b.0));
    for (name, key) in peers {
        let _ = writeln!(out, "peer {name}: {}", key.to_z32());
    }
    out
}

/// Loads `config_path` and its private key and prints the report to stdout.
pub fn run(config_path: &str) -> Result<()> {
    let config = Config::load(config_path)?;
    let secret_key = load_key_from_disk(&config.private_key_path)?;
    print!("{}", report(&config, &secret_key));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_shows_key_and_derived_address_for_the_docker_alice_config() {
        let config = Config::parse(include_str!("../docker/data/alice-config.toml"))
            .expect("docker alice config should parse");
        let secret_key = SecretKey::from_bytes(include_bytes!("../docker/data/keys/alice.raw"));

        let report = report(&config, &secret_key);

        assert!(
            report.contains("public key:  ri5s1riaxztowkfasg645kdngnugembhsjwke5qfrktno9qjn8ty"),
            "report was:\n{report}"
        );
        // Deterministically derived from the key + subnet 0; this is also the address the Docker
        // integration test pings.
        assert!(
            report.contains("VPN address: fdbd:a6ce:654d:0:6f56:d923:de1e:5588"),
            "report was:\n{report}"
        );
        assert!(
            report.contains("peer bob: 18x6mrteyqw6oqga8418afrnamm3mpwftcojtre5j4crpeqzf66o"),
            "report was:\n{report}"
        );
        assert!(
            report.contains("peer charlie: u1kpy3s7ui7ao1jjf77k3fbpxb875xq1aqp1797ohrxio55f53ho"),
            "report was:\n{report}"
        );
    }
}
