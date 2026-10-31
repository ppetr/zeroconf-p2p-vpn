//! Parses the TOML configuration file, see `example-config.toml`.

use anyhow::{bail, Context, Result};
use iroh::PublicKey;
use secure_p2p_transport::NodeExtraConfig;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::addr::MAX_SUBNET;

/// Default interface description used when `[tun] description` is not set.
const DEFAULT_TUN_DESCRIPTION: &str = "zeroconf-p2p-vpn VPN interface";

/// A fully parsed and validated configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// The 15-bit subnet ID within `addr::VPN_IPV6_PREFIX`, from `[host] subnet`. Defaults to 0.
    pub subnet: u16,
    /// Path to this host's Ed25519 private key file, in the raw format, from
    /// `[host] private_key_path`.
    pub private_key_path: PathBuf,
    /// Allowed peers' public keys, keyed by their name (the `[peers]` table key).
    pub peers: HashMap<String, PublicKey>,
    /// TUN device settings, from `[tun]`.
    pub tun: TunConfig,
    /// Peer discovery settings, from `[discovery]`. Defaults to the n0.computer relay plus mDNS
    /// and the DHT (`NodeExtraConfig::default()`).
    pub discovery: NodeExtraConfig,
    /// DNS resolution of peer names, from `[dns]`. `None` (the default, no `[dns]` section)
    /// disables it entirely.
    pub dns: Option<DnsConfig>,
}

/// Settings for resolving peer names (the `[peers]` table keys) via DNS, from `[dns]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsConfig {
    /// The DNS suffix peer names are served under, e.g. a peer named `alice` becomes
    /// `alice.<suffix>`, from `[dns] suffix`.
    pub suffix: String,
}

/// Settings for the OS-level TUN network interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunConfig {
    /// The interface name, from `[tun] name`. `None` lets the OS/driver pick a unique name
    /// automatically.
    pub name: Option<String>,
    /// The interface's human-readable description (Windows only), from `[tun] description`.
    /// Defaults to [`DEFAULT_TUN_DESCRIPTION`] if unset.
    pub description: String,
}

impl Config {
    /// Parses a configuration from its TOML text representation.
    pub fn parse(toml: &str) -> Result<Self> {
        let raw: RawConfig = ::toml::from_str(toml).context("parsing configuration")?;
        raw.try_into()
    }

    /// Reads and parses a configuration file from `path`. A relative `private_key_path` is
    /// resolved relative to `path`'s directory.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("reading configuration file '{}'", path.display()))?;
        let mut config = Self::parse(&contents)
            .with_context(|| format!("in configuration file '{}'", path.display()))?;
        if let Some(config_dir) = path.parent() {
            config.private_key_path = config_dir.join(&config.private_key_path);
        }
        Ok(config)
    }
}

#[derive(Deserialize)]
struct RawConfig {
    host: RawHost,
    #[serde(default)]
    peers: HashMap<String, String>,
    #[serde(default)]
    tun: RawTun,
    #[serde(default)]
    discovery: NodeExtraConfig,
    #[serde(default)]
    dns: Option<RawDns>,
}

#[derive(Deserialize)]
struct RawDns {
    suffix: String,
}

#[derive(Deserialize)]
struct RawHost {
    #[serde(default)]
    subnet: u16,
    private_key_path: PathBuf,
}

#[derive(Deserialize, Default)]
struct RawTun {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    description: Option<String>,
}

impl TryFrom<RawConfig> for Config {
    type Error = anyhow::Error;

    fn try_from(raw: RawConfig) -> Result<Self> {
        if raw.host.subnet > MAX_SUBNET {
            bail!(
                "host.subnet 0x{:04x} is out of range: only 0x0000..=0x{:04x} is allowed",
                raw.host.subnet,
                MAX_SUBNET
            );
        }
        let peers = raw
            .peers
            .into_iter()
            .map(|(name, key)| {
                let key = PublicKey::from_z32(&key)
                    .with_context(|| format!("peer '{}': decoding public key '{}'", name, key))?;
                Ok((name, key))
            })
            .collect::<Result<_>>()?;
        Ok(Config {
            subnet: raw.host.subnet,
            private_key_path: raw.host.private_key_path,
            peers,
            tun: TunConfig {
                name: raw.tun.name,
                description: raw
                    .tun
                    .description
                    .unwrap_or_else(|| DEFAULT_TUN_DESCRIPTION.to_string()),
            },
            discovery: raw.discovery,
            dns: raw.dns.map(|raw_dns| DnsConfig { suffix: raw_dns.suffix }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;
    use secure_p2p_transport::N0Discovery;

    /// The real "alice" public key from `docker/docker-compose.yml`, kept as a string literal so
    /// these tests don't depend on other files in the repository.
    const ALICE_KEY_Z32: &str = "ri5s1riaxztowkfasg645kdngnugembhsjwke5qfrktno9qjn8ty";

    fn sample_key_z32() -> String {
        SecretKey::generate().public().to_z32()
    }

    #[test]
    fn test_parses_minimal_config() {
        let alice = sample_key_z32();
        let toml = format!(
            r#"
            [host]
            private_key_path = "/foo/bar"

            [peers]
            alice = "{alice}"
            "#
        );

        let config = Config::parse(&toml).expect("valid config should parse");

        assert_eq!(config.subnet, 0);
        assert_eq!(config.private_key_path, PathBuf::from("/foo/bar"));
        assert_eq!(config.peers.len(), 1);
        assert_eq!(config.peers["alice"], PublicKey::from_z32(&alice).unwrap());
        assert_eq!(
            config.tun.name, None,
            "a missing [tun] section must leave the interface name unset"
        );
        assert_eq!(config.tun.description, DEFAULT_TUN_DESCRIPTION);
        assert_eq!(
            config.discovery,
            NodeExtraConfig::default(),
            "a missing [discovery] section must default to the n0.computer relay plus mDNS and the DHT"
        );
    }

    #[test]
    fn test_parses_discovery_section() {
        let toml = r#"
            [host]
            private_key_path = "/foo/bar"

            [discovery]
            n0_discovery = "NoN0"
            use_mdns = true
            use_dht = false
        "#;

        let config = Config::parse(toml).expect("valid config should parse");

        assert_eq!(
            config.discovery,
            NodeExtraConfig { n0_discovery: N0Discovery::NoN0, use_mdns: true, use_dht: false }
        );
    }

    #[test]
    fn test_discovery_section_allows_partial_overrides() {
        let toml = r#"
            [host]
            private_key_path = "/foo/bar"

            [discovery]
            use_dht = false
        "#;

        let config = Config::parse(toml).expect("a [discovery] section may set only some fields");

        assert_eq!(
            config.discovery,
            NodeExtraConfig { use_dht: false, ..NodeExtraConfig::default() },
            "unset fields must fall back to NodeExtraConfig::default()"
        );
    }

    #[test]
    fn test_parses_tun_section() {
        let toml = r#"
            [host]
            private_key_path = "/foo/bar"

            [tun]
            name = "zeroconf-p2p-vpn"
            description = "My VPN interface"
        "#;

        let config = Config::parse(toml).expect("valid config should parse");

        assert_eq!(config.tun.name, Some("zeroconf-p2p-vpn".to_string()));
        assert_eq!(config.tun.description, "My VPN interface");
    }

    #[test]
    fn test_tun_description_defaults_when_only_name_is_set() {
        let toml = r#"
            [host]
            private_key_path = "/foo/bar"

            [tun]
            name = "zeroconf-p2p-vpn"
        "#;

        let config = Config::parse(toml).expect("valid config should parse");

        assert_eq!(config.tun.name, Some("zeroconf-p2p-vpn".to_string()));
        assert_eq!(config.tun.description, DEFAULT_TUN_DESCRIPTION);
    }

    #[test]
    fn test_decodes_real_docker_compose_peer_key() {
        let toml = format!(
            r#"
            [host]
            subnet = 0x0000
            private_key_path = "/foo/bar"

            [peers]
            alice = "{ALICE_KEY_Z32}"
            "#
        );

        let config = Config::parse(&toml).expect("real docker-compose peer key should decode");

        assert_eq!(config.peers["alice"], PublicKey::from_z32(ALICE_KEY_Z32).unwrap());
    }

    #[test]
    fn test_parses_config_with_multiple_peers() {
        let alice = sample_key_z32();
        let bob = sample_key_z32();
        let toml = format!(
            r#"
            [host]
            subnet = 0x7ffF
            private_key_path = "/foo/bar"

            [peers]
            alice = "{alice}"
            bob = "{bob}"
            "#
        );

        let config = Config::parse(&toml).expect("valid config should parse");

        assert_eq!(config.subnet, 0x7fff);
        assert_eq!(config.peers.len(), 2);
        assert_eq!(config.peers["alice"], PublicKey::from_z32(&alice).unwrap());
        assert_eq!(config.peers["bob"], PublicKey::from_z32(&bob).unwrap());
    }

    #[test]
    fn test_parses_config_without_peers() {
        let toml = r#"
            [host]
            subnet = 0x0000
            private_key_path = "/foo/bar"
        "#;

        let config = Config::parse(toml).expect("config without peers should parse");
        assert!(config.peers.is_empty());
    }

    #[test]
    fn test_subnet_defaults_to_zero_when_missing() {
        let toml = r#"
            [host]
            private_key_path = "/foo/bar"
        "#;

        let config = Config::parse(toml).expect("subnet should be optional");
        assert_eq!(config.subnet, 0);
    }

    #[test]
    fn test_dns_defaults_to_disabled_when_missing() {
        let toml = r#"
            [host]
            private_key_path = "/foo/bar"
        "#;

        let config = Config::parse(toml).expect("a missing [dns] section must be allowed");
        assert_eq!(config.dns, None);
    }

    #[test]
    fn test_parses_dns_section() {
        let toml = r#"
            [host]
            private_key_path = "/foo/bar"

            [dns]
            suffix = "p2p"
        "#;

        let config = Config::parse(toml).expect("valid config should parse");
        assert_eq!(config.dns, Some(DnsConfig { suffix: "p2p".to_string() }));
    }

    #[test]
    fn test_rejects_subnet_out_of_range() {
        let toml = r#"
            [host]
            subnet = 0x8000
            private_key_path = "/foo/bar"
        "#;

        let err = Config::parse(toml).expect_err("subnet 0x8000 must be rejected");
        assert!(format!("{err:#}").contains("0x8000"));
    }

    #[test]
    fn test_rejects_invalid_peer_key() {
        let toml = r#"
            [host]
            subnet = 0x0000
            private_key_path = "/foo/bar"

            [peers]
            alice = "not-a-valid-z32-key"
        "#;

        let err = Config::parse(toml).expect_err("invalid peer key must be rejected");
        let message = format!("{err:#}");
        assert!(message.contains("alice"), "error was: {message}");
    }

    #[test]
    fn test_rejects_missing_host_section() {
        let toml = r#"
            [peers]
            alice = "irrelevant"
        "#;

        Config::parse(toml).expect_err("missing [host] section must be rejected");
    }

    #[test]
    fn test_rejects_missing_private_key_path() {
        let toml = r#"
            [host]
            subnet = 0x0000
        "#;

        Config::parse(toml).expect_err("missing private_key_path must be rejected");
    }

    #[test]
    fn test_load_reads_config_from_disk() {
        let alice = sample_key_z32();
        let toml = format!(
            r#"
            [host]
            subnet = 0x0000
            private_key_path = "/foo/bar"

            [peers]
            alice = "{alice}"
            "#
        );

        let mut path = std::env::temp_dir();
        path.push(format!("zeroconf-p2p-vpn-config-test-{}.toml", std::process::id()));
        std::fs::write(&path, toml).unwrap();

        let config = Config::load(&path).expect("config file should load");
        std::fs::remove_file(&path).unwrap();

        assert_eq!(config.subnet, 0);
        assert_eq!(config.peers.len(), 1);
        assert_eq!(
            config.private_key_path,
            PathBuf::from("/foo/bar"),
            "an absolute private_key_path must be kept as-is"
        );
    }

    #[test]
    fn test_load_resolves_relative_private_key_path_against_config_dir() {
        let toml = r#"
            [host]
            private_key_path = "keys/host.raw"
        "#;

        let dir = std::env::temp_dir()
            .join(format!("zeroconf-p2p-vpn-config-test-dir-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(&path, toml).unwrap();

        let config = Config::load(&path).expect("config file should load");
        std::fs::remove_dir_all(&dir).unwrap();

        assert_eq!(config.private_key_path, dir.join("keys/host.raw"));
    }

    /// This matches how `docker/docker-compose.yml` invokes the binary: with a bare filename
    /// (`config.toml`, no directory component), so `private_key_path` must stay relative to the
    /// process's current directory, unchanged.
    #[test]
    fn test_load_keeps_relative_private_key_path_when_config_path_has_no_directory() {
        let toml = r#"
            [host]
            private_key_path = "keys/host.raw"
        "#;

        let path =
            PathBuf::from(format!("zeroconf-p2p-vpn-config-test-bare-{}.toml", std::process::id()));
        std::fs::write(&path, toml).unwrap();

        let config = Config::load(&path).expect("config file should load");
        std::fs::remove_file(&path).unwrap();

        assert_eq!(config.private_key_path, PathBuf::from("keys/host.raw"));
    }

    /// Regression test for the config files actually used by `docker/docker-compose.yml` (part
    /// of the integration test), so a config-format change here can't silently break it.
    ///
    /// Topology: Alice peers with both Bob and Charlie; Bob and Charlie each peer only with Alice.
    #[test]
    fn test_docker_compose_configs_parse() {
        let alice = Config::parse(include_str!("../docker/data/alice-config.toml"))
            .expect("docker/data/alice-config.toml should parse");
        assert_eq!(alice.private_key_path, PathBuf::from("keys/alice.raw"));
        assert_eq!(alice.peers.len(), 2);
        assert!(alice.peers.contains_key("bob"));
        assert!(alice.peers.contains_key("charlie"));

        let bob = Config::parse(include_str!("../docker/data/bob-config.toml"))
            .expect("docker/data/bob-config.toml should parse");
        assert_eq!(bob.private_key_path, PathBuf::from("keys/bob.raw"));
        assert_eq!(bob.peers.len(), 1);
        assert!(bob.peers.contains_key("alice"));

        let charlie = Config::parse(include_str!("../docker/data/charlie-config.toml"))
            .expect("docker/data/charlie-config.toml should parse");
        assert_eq!(charlie.private_key_path, PathBuf::from("keys/charlie.raw"));
        assert_eq!(charlie.peers.len(), 1);
        assert!(charlie.peers.contains_key("alice"));

        // Each config must name the right peer by its actual public key.
        let alice_secret = SecretKey::from_bytes(include_bytes!("../docker/data/keys/alice.raw"));
        let bob_secret = SecretKey::from_bytes(include_bytes!("../docker/data/keys/bob.raw"));
        let charlie_secret =
            SecretKey::from_bytes(include_bytes!("../docker/data/keys/charlie.raw"));
        assert_eq!(alice.peers["bob"], bob_secret.public());
        assert_eq!(alice.peers["charlie"], charlie_secret.public());
        assert_eq!(bob.peers["alice"], alice_secret.public());
        assert_eq!(charlie.peers["alice"], alice_secret.public());

        // The integration test must stay local-network-only: no n0.computer relay, no DHT.
        let local_only =
            NodeExtraConfig { n0_discovery: N0Discovery::NoN0, use_mdns: true, use_dht: false };
        assert_eq!(alice.discovery, local_only);
        assert_eq!(bob.discovery, local_only);
        assert_eq!(charlie.discovery, local_only);

        // All three resolve peer names under the same DNS suffix.
        let dns_p2p = Some(DnsConfig { suffix: "p2p".to_string() });
        assert_eq!(alice.dns, dns_p2p);
        assert_eq!(bob.dns, dns_p2p);
        assert_eq!(charlie.dns, dns_p2p);
    }
}
