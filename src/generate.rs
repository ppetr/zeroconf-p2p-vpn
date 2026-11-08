//! `zeroconf-p2p-vpn generate <config>` — bootstraps a node's on-disk state (a config file and a
//! private key) without starting the daemon or touching the network.
//!
//! * If `<config>` does not exist, a minimal template config is written next to it, pointing at a
//!   private key file named [`DEFAULT_KEY_FILE_NAME`] in the same directory. The user only has to
//!   fill in the `[peers]` table.
//! * If `<config>` already exists, it is left untouched and its `private_key_path` is used.
//! * The private key file is created (a fresh Ed25519 key) only when it does not already exist; an
//!   existing key is always kept as-is.
//!
//! Either way, the node's public key is printed at the end, ready to hand to a peer.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use iroh::SecretKey;
use secure_p2p_transport::{load_key_from_disk, save_key_to_disk};

use crate::config::Config;

/// File name of the private key referenced by a freshly generated template config.
const DEFAULT_KEY_FILE_NAME: &str = "zeroconf-p2p-vpn_private.key";

/// Contents of the template config written when the target file does not yet exist.
fn default_config_toml() -> String {
    format!(
        r#"# zeroconf-p2p-vpn configuration, created by `zeroconf-p2p-vpn generate`.
# Fill in the [peers] table below, then run `zeroconf-p2p-vpn <this-file>`.
# See example-config.toml for the optional [host] subnet, [tun] and [discovery] settings.

[host]
# This host's Ed25519 private key (raw 32-byte format). A relative path is
# resolved next to this config file; `generate` created the key file for you.
private_key_path = "{DEFAULT_KEY_FILE_NAME}"

[peers]
# z-base-32-encoded Ed25519 public keys of allowed peers, each keyed by a name of
# your choosing. A peer's key is the "public key" line printed by
# `zeroconf-p2p-vpn generate` or `zeroconf-p2p-vpn show` on that peer's machine.
# alice = "ri5s1riaxztowkfasg645kdngnugembhsjwke5qfrktno9qjn8ty"
"#
    )
}

/// Ensures a config file exists at `config_path`, writing a template if it does not, and returns
/// the path to the private key it references (resolved the same way [`Config::load`] does).
fn ensure_config(config_path: &Path) -> Result<PathBuf> {
    if config_path.exists() {
        let config = Config::load(config_path)?;
        println!("Keeping existing config '{}'.", config_path.display());
        return Ok(config.private_key_path);
    }
    std::fs::write(config_path, default_config_toml())
        .with_context(|| format!("writing config file '{}'", config_path.display()))?;
    println!("Wrote template config '{}'.", config_path.display());
    let key_path = match config_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        Some(dir) => dir.join(DEFAULT_KEY_FILE_NAME),
        None => PathBuf::from(DEFAULT_KEY_FILE_NAME),
    };
    Ok(key_path)
}

/// Loads the key at `key_path`, or generates a fresh one and writes it there if the file is
/// absent. A newly written key file is restricted to owner-only permissions on Unix.
fn ensure_key(key_path: &Path) -> Result<SecretKey> {
    if key_path.exists() {
        let key = load_key_from_disk(key_path)
            .with_context(|| format!("reading private key '{}'", key_path.display()))?;
        println!("Keeping existing private key '{}'.", key_path.display());
        return Ok(key);
    }
    let key = SecretKey::generate();
    save_key_to_disk(key_path, &key)
        .with_context(|| format!("writing private key '{}'", key_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("restricting permissions on '{}'", key_path.display()))?;
    }
    println!("Wrote new private key '{}'.", key_path.display());
    Ok(key)
}

/// Creates any missing config/key files for `config_path` and returns the node's secret key.
pub fn generate(config_path: &Path) -> Result<SecretKey> {
    let key_path = ensure_config(config_path)?;
    ensure_key(&key_path)
}

/// Polkit rule needed for the optional `[dns]` config section on a host running
/// systemd-resolved -- see `systemd/zeroconf-p2p-vpn.service`'s install instructions. Printed
/// here too, not just there, so it stays visible at the point someone actually sets a node up.
const POLKIT_RULES_HINT: &str = concat!(
    "If you enable the optional [dns] config section on a host running systemd-resolved, also \
     install a polkit rule -- otherwise systemd-resolved refuses the unprivileged, session-less \
     service user with \"InteractiveAuthorizationRequired\". Install whichever of the two your \
     polkit version understands (installing both is harmless):\n\n",
    "polkit >= 0.106, i.e. effectively every current distro -- systemd/zeroconf-p2p-vpn.polkit.rules:\n",
    include_str!("../systemd/zeroconf-p2p-vpn.polkit.rules"),
    "\npolkit <= 0.105, or newer with polkit-pkla-compat / polkitd-pkla installed -- systemd/zeroconf-p2p-vpn.pkla:\n",
    include_str!("../systemd/zeroconf-p2p-vpn.pkla"),
);

/// Entry point for the `generate` subcommand: bootstraps the files and prints the public key.
pub fn run(config_path: &str) -> Result<()> {
    let key = generate(Path::new(config_path))?;
    println!("public key: {}", key.public().to_z32());
    println!("\n{POLKIT_RULES_HINT}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh, empty temp directory unique to this test process and `tag`.
    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "zeroconf-p2p-vpn-generate-test-{}-{}",
            std::process::id(),
            tag
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn creates_template_config_and_key_when_neither_exists() {
        let dir = temp_dir("fresh");
        let config_path = dir.join("myconfig.toml");

        let key = generate(&config_path).expect("generate should succeed");

        let key_path = dir.join(DEFAULT_KEY_FILE_NAME);
        assert!(config_path.exists(), "config file must be created");
        assert!(key_path.exists(), "key file must be created");
        assert_eq!(
            std::fs::read(&key_path).unwrap().len(),
            32,
            "key file must be a raw 32-byte Ed25519 key"
        );

        // The template must be a valid config pointing at the generated key.
        let config = Config::load(&config_path).expect("template config must parse");
        assert_eq!(config.private_key_path, key_path);
        assert!(config.peers.is_empty());

        // The returned key is exactly the one persisted to disk.
        let loaded = load_key_from_disk(&key_path).unwrap();
        assert_eq!(key.to_bytes(), loaded.to_bytes());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn new_key_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_dir("perms");
        let config_path = dir.join("myconfig.toml");

        generate(&config_path).expect("generate should succeed");

        let mode = std::fs::metadata(dir.join(DEFAULT_KEY_FILE_NAME)).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "private key must not be group/world readable");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn is_idempotent_and_keeps_existing_files() {
        let dir = temp_dir("idempotent");
        let config_path = dir.join("myconfig.toml");

        let first = generate(&config_path).expect("first run should succeed");
        let config_bytes = std::fs::read(&config_path).unwrap();

        let second = generate(&config_path).expect("second run should succeed");

        assert_eq!(first.to_bytes(), second.to_bytes(), "a second run must keep the existing key");
        assert_eq!(
            config_bytes,
            std::fs::read(&config_path).unwrap(),
            "a second run must not rewrite the existing config"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn creates_only_the_key_when_config_already_exists() {
        let dir = temp_dir("config-only");
        let config_path = dir.join("myconfig.toml");
        std::fs::write(&config_path, "[host]\nprivate_key_path = \"host.key\"\n").unwrap();

        let key = generate(&config_path).expect("generate should succeed");

        let key_path = dir.join("host.key");
        assert!(key_path.exists(), "the key named by the existing config must be created");
        let loaded = load_key_from_disk(&key_path).unwrap();
        assert_eq!(key.to_bytes(), loaded.to_bytes());

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
