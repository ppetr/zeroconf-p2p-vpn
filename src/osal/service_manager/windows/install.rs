//! `service install` / `service uninstall`: registering the daemon with the service control
//! manager, or printing the equivalent PowerShell commands instead.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{bail, Context};
use windows_service::service::{
    Service, ServiceAccess, ServiceAction, ServiceActionType, ServiceDependency,
    ServiceErrorControl, ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo,
    ServiceStartType, ServiceState, ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use super::SERVICE_NAME;

const DISPLAY_NAME: &str = "zeroconf-p2p-vpn";
const DESCRIPTION: &str = "Zero-config peer-to-peer VPN daemon";
const DEPENDENCIES: [&str; 2] = ["Tcpip", "Dnscache"];
const RESTART_DELAYS: [Duration; 3] =
    [Duration::from_secs(5), Duration::from_secs(5), Duration::from_secs(30)];
const FAILURE_RESET_PERIOD: Duration = Duration::from_secs(24 * 3600);
/// SIDs of LocalSystem and the Administrators group (names are localized, SIDs are not).
const KEY_FILE_OWNERS: [&str; 2] = ["*S-1-5-18:F", "*S-1-5-32-544:F"];
const STOP_TIMEOUT: Duration = Duration::from_secs(30);

pub const INSTALL_USAGE: &str =
    "Usage: zeroconf-p2p-vpn service install --config <config-file-path> [--print]\n       \
     zeroconf-p2p-vpn service uninstall";

/// Parses the arguments of `service install`: the mandatory `--config <path>` and `--print`.
pub fn parse_install_args(args: &[&str]) -> anyhow::Result<(PathBuf, bool)> {
    let (mut config, mut print) = (None, false);
    let mut args = args.iter();
    while let Some(&arg) = args.next() {
        match arg {
            "--config" => {
                let path = args
                    .next()
                    .with_context(|| format!("--config needs a path\n{INSTALL_USAGE}"))?;
                config = Some(PathBuf::from(path));
            }
            "--print" => print = true,
            _ => bail!("unexpected argument '{arg}'\n{INSTALL_USAGE}"),
        }
    }
    let config = config.with_context(|| format!("--config is required\n{INSTALL_USAGE}"))?;
    Ok((config, print))
}

/// What gets registered: the executable, the config it will run with and the config's key file.
struct Plan {
    exe: PathBuf,
    config: PathBuf,
    key: PathBuf,
}

impl Plan {
    fn new(config: &Path) -> anyhow::Result<Plan> {
        let config = std::path::absolute(config)
            .with_context(|| format!("resolving config path '{}'", config.display()))?;
        let key = crate::config::Config::load(&config)?.private_key_path;
        let exe = std::env::current_exe().context("locating the executable")?;
        Ok(Plan { exe, config, key })
    }

    fn launch_arguments(&self) -> Vec<OsString> {
        vec!["service".into(), "run".into(), self.config.clone().into()]
    }
}

pub fn install(config: &Path, print_only: bool) -> anyhow::Result<()> {
    let plan = Plan::new(config)?;
    if print_only {
        print!("{}", powershell_script(&plan));
        return Ok(());
    }
    if !plan.key.exists() {
        bail!(
            "private key '{}' does not exist; create it with `zeroconf-p2p-vpn generate`",
            plan.key.display()
        );
    }
    restrict_key_file(&plan.key)?;

    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .context("cannot open the service control manager (run from an elevated PowerShell)")?;
    let info = ServiceInfo {
        name: SERVICE_NAME.into(),
        display_name: DISPLAY_NAME.into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: plan.exe.clone(),
        launch_arguments: plan.launch_arguments(),
        dependencies: DEPENDENCIES
            .iter()
            .map(|d| ServiceDependency::Service((*d).into()))
            .collect(),
        account_name: None,
        account_password: None,
    };
    // `Restart` failure actions require `START` access in addition to `CHANGE_CONFIG`.
    let service = manager
        .create_service(
            &info,
            ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::DELETE,
        )
        .with_context(|| format!("creating service '{SERVICE_NAME}' (already installed?)"))?;
    if let Err(err) = configure(&service) {
        let _ = service.delete();
        return Err(err.context("configuring the new service; it was removed again"));
    }

    println!("Installed service '{SERVICE_NAME}'. Start it with: Start-Service {SERVICE_NAME}");
    Ok(())
}

/// Applies the settings that cannot be given at creation time.
fn configure(service: &Service) -> anyhow::Result<()> {
    service.set_description(DESCRIPTION)?;
    service.set_delayed_auto_start(true)?;
    service.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(FAILURE_RESET_PERIOD),
        reboot_msg: None,
        command: None,
        actions: Some(
            RESTART_DELAYS
                .iter()
                .map(|&delay| ServiceAction { action_type: ServiceActionType::Restart, delay })
                .collect(),
        ),
    })?;
    // Also restart after a clean-looking exit with a nonzero exit code, not only after a crash.
    service.set_failure_actions_on_non_crash_failures(true)?;
    Ok(())
}

pub fn uninstall() -> anyhow::Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("cannot open the service control manager (run from an elevated PowerShell)")?;
    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        )
        .with_context(|| format!("opening service '{SERVICE_NAME}' (not installed?)"))?;
    if service.query_status()?.current_state != ServiceState::Stopped {
        println!("Stopping service '{SERVICE_NAME}'...");
        service.stop()?;
        let deadline = std::time::Instant::now() + STOP_TIMEOUT;
        while service.query_status()?.current_state != ServiceState::Stopped {
            if std::time::Instant::now() > deadline {
                bail!("service '{SERVICE_NAME}' did not stop within {STOP_TIMEOUT:?}");
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }
    service.delete()?;
    println!("Removed service '{SERVICE_NAME}'.");
    Ok(())
}

/// Leaves only LocalSystem and Administrators with access to the private key file.
fn restrict_key_file(key: &Path) -> anyhow::Result<()> {
    let status = Command::new("icacls")
        .arg(key)
        .args(["/inheritance:r", "/grant:r"])
        .args(KEY_FILE_OWNERS)
        .status()
        .context("running icacls")?;
    if !status.success() {
        bail!("icacls failed to restrict access to '{}' ({status})", key.display());
    }
    println!("Restricted access to '{}' to SYSTEM and Administrators.", key.display());
    Ok(())
}

fn ps_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// The PowerShell commands doing what [`install`] does.
fn powershell_script(plan: &Plan) -> String {
    let key = ps_quote(&plan.key.to_string_lossy());
    let command_line =
        format!("\"{}\" service run \"{}\"", plan.exe.display(), plan.config.display());
    let name = ps_quote(SERVICE_NAME);
    let owners = KEY_FILE_OWNERS.map(|o| format!("'{o}'")).join(" ");
    let deps = DEPENDENCIES.join(",");
    let actions = RESTART_DELAYS
        .iter()
        .map(|d| format!("restart/{}", d.as_millis()))
        .collect::<Vec<_>>()
        .join("/");
    format!(
        "# Run from an elevated PowerShell.\n\
         icacls {key} /inheritance:r /grant:r {owners}\n\
         New-Service -Name {name} -DisplayName {display} -Description {description} `\n    \
         -BinaryPathName {binary} -StartupType Automatic -DependsOn {deps}\n\
         sc.exe config {name} start= delayed-auto\n\
         sc.exe failure {name} reset= {reset} actions= {actions}\n\
         sc.exe failureflag {name} 1\n\
         Start-Service {name}\n",
        display = ps_quote(DISPLAY_NAME),
        description = ps_quote(DESCRIPTION),
        binary = ps_quote(&command_line),
        reset = FAILURE_RESET_PERIOD.as_secs(),
    )
}
