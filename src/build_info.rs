//! Build-time identification of this binary (version, git revision, target).

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const GIT_REV: &str = env!("BUILD_GIT_REV");
pub const GIT_DESCRIBE: &str = env!("BUILD_GIT_DESCRIBE");
pub const TARGET: &str = env!("BUILD_TARGET");
pub const PROFILE: &str = env!("BUILD_PROFILE");

/// True if the working tree had uncommitted changes at build time.
pub fn is_dirty() -> bool {
    GIT_DESCRIBE.ends_with("-modified")
}

/// One-line human-readable description, e.g. `0.1.4 (v0.1.4-0-gca1f59d, x86_64-unknown-linux-gnu)`.
pub fn summary() -> String {
    format!("{VERSION} ({GIT_DESCRIBE}, {TARGET})")
}

/// Registers the `p2p_vpn_build_info` and `p2p_vpn_start_time_seconds` metrics.
pub fn register_metrics() {
    metrics::gauge!(
        "p2p_vpn_build_info",
        "version" => VERSION,
        "revision" => GIT_REV,
        "describe" => GIT_DESCRIBE,
        "dirty" => if is_dirty() { "true" } else { "false" },
        "target" => TARGET,
        "profile" => PROFILE,
    )
    .set(1.0);
    let start = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64());
    metrics::gauge!("p2p_vpn_start_time_seconds").set(start);
}
