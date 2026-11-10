use std::io::Result;
use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_owned();
    (!s.is_empty()).then_some(s)
}

/// Resolves a value from an environment override, falling back to a git command, then "unknown".
fn resolve(var: &str, git_args: &[&str]) -> String {
    println!("cargo:rerun-if-env-changed={var}");
    std::env::var(var)
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| git(git_args))
        .unwrap_or_else(|| "unknown".into())
}

fn main() -> Result<()> {
    prost_build::compile_protos(&["proto/p2p_vpn/control/v1/control.proto"], &["proto/"])?;

    let rev = resolve("ZEROCONF_GIT_REV", &["rev-parse", "HEAD"]);
    let describe = resolve(
        "ZEROCONF_GIT_DESCRIBE",
        &["describe", "--tags", "--always", "--long", "--dirty=-modified"],
    );
    println!("cargo:rustc-env=BUILD_GIT_REV={rev}");
    println!("cargo:rustc-env=BUILD_GIT_DESCRIBE={describe}");
    println!("cargo:rustc-env=BUILD_TARGET={}", std::env::var("TARGET").unwrap_or_default());
    println!("cargo:rustc-env=BUILD_PROFILE={}", std::env::var("PROFILE").unwrap_or_default());

    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs");
    println!("cargo:rerun-if-changed=.git/packed-refs");
    Ok(())
}
