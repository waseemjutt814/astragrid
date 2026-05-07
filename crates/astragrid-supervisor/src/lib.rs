use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerWorkerSupervisorSpec {
    pub binary: PathBuf,
    pub working_directory: PathBuf,
    pub ledger: PathBuf,
    pub queue: PathBuf,
    pub shared_key_file: PathBuf,
    pub identity: Option<PathBuf>,
    pub identity_passphrase_file: Option<PathBuf>,
    pub limit: u32,
    pub retry_delay_seconds: i64,
    pub interval_seconds: u64,
    pub health_file: Option<PathBuf>,
    pub audit_log: Option<PathBuf>,
    pub stale_after_seconds: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FederationDaemonSupervisorSpec {
    pub binary: PathBuf,
    pub working_directory: PathBuf,
    pub bind: String,
    pub ledger: PathBuf,
    pub shared_key_file: PathBuf,
    pub peer_registry: Option<PathBuf>,
    pub health_file: PathBuf,
    pub audit_log: PathBuf,
    pub max_requests: Option<u32>,
    pub idle_timeout_seconds: u64,
}

impl PeerWorkerSupervisorSpec {
    pub fn validate(&self) -> Result<(), SupervisorError> {
        validate_path("binary", &self.binary)?;
        validate_path("working_directory", &self.working_directory)?;
        validate_path("ledger", &self.ledger)?;
        validate_path("queue", &self.queue)?;
        validate_path("shared_key_file", &self.shared_key_file)?;
        if let Some(identity) = &self.identity {
            validate_path("identity", identity)?;
        }
        if let Some(identity_passphrase_file) = &self.identity_passphrase_file {
            validate_path("identity_passphrase_file", identity_passphrase_file)?;
        }
        if self.identity.is_none() && self.identity_passphrase_file.is_some() {
            return Err(SupervisorError::InvalidValue(
                "identity_passphrase_file requires identity".to_owned(),
            ));
        }
        if self.limit == 0 {
            return Err(SupervisorError::InvalidValue(
                "limit must be greater than zero".to_owned(),
            ));
        }
        if self.retry_delay_seconds < 0 {
            return Err(SupervisorError::InvalidValue(
                "retry_delay_seconds cannot be negative".to_owned(),
            ));
        }
        if self.stale_after_seconds < 0 {
            return Err(SupervisorError::InvalidValue(
                "stale_after_seconds cannot be negative".to_owned(),
            ));
        }
        if self.interval_seconds == 0 {
            return Err(SupervisorError::InvalidValue(
                "interval_seconds must be greater than zero".to_owned(),
            ));
        }
        if let Some(health_file) = &self.health_file {
            validate_path("health_file", health_file)?;
        }
        if let Some(audit_log) = &self.audit_log {
            validate_path("audit_log", audit_log)?;
        }
        Ok(())
    }

    pub fn worker_args(&self) -> Result<Vec<String>, SupervisorError> {
        self.validate()?;
        let mut args = vec![
            "peer-queue".to_owned(),
            "worker".to_owned(),
            "--queue".to_owned(),
            self.queue.to_string_lossy().into_owned(),
            "--ledger".to_owned(),
            self.ledger.to_string_lossy().into_owned(),
            "--shared-key-file".to_owned(),
            self.shared_key_file.to_string_lossy().into_owned(),
        ];
        if let Some(identity) = &self.identity {
            args.extend([
                "--identity".to_owned(),
                identity.to_string_lossy().into_owned(),
            ]);
        }
        if let Some(identity_passphrase_file) = &self.identity_passphrase_file {
            args.extend([
                "--passphrase-file".to_owned(),
                identity_passphrase_file.to_string_lossy().into_owned(),
            ]);
        }
        if let Some(health_file) = &self.health_file {
            args.extend([
                "--health-file".to_owned(),
                health_file.to_string_lossy().into_owned(),
            ]);
        }
        if let Some(audit_log) = &self.audit_log {
            args.extend([
                "--audit-log".to_owned(),
                audit_log.to_string_lossy().into_owned(),
            ]);
        }
        args.extend([
            "--limit".to_owned(),
            self.limit.to_string(),
            "--retry-delay-seconds".to_owned(),
            self.retry_delay_seconds.to_string(),
            "--interval-seconds".to_owned(),
            self.interval_seconds.to_string(),
            "--stale-after-seconds".to_owned(),
            self.stale_after_seconds.to_string(),
        ]);
        Ok(args)
    }
}

impl FederationDaemonSupervisorSpec {
    pub fn validate(&self) -> Result<(), SupervisorError> {
        validate_path("binary", &self.binary)?;
        validate_path("working_directory", &self.working_directory)?;
        validate_text("bind", &self.bind)?;
        if self.bind.trim().is_empty() {
            return Err(SupervisorError::InvalidValue(
                "bind cannot be empty".to_owned(),
            ));
        }
        validate_path("ledger", &self.ledger)?;
        validate_path("shared_key_file", &self.shared_key_file)?;
        if let Some(peer_registry) = &self.peer_registry {
            validate_path("peer_registry", peer_registry)?;
        }
        validate_path("health_file", &self.health_file)?;
        validate_path("audit_log", &self.audit_log)?;
        if self.max_requests == Some(0) {
            return Err(SupervisorError::InvalidValue(
                "max_requests must be greater than zero when set".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn daemon_args(&self) -> Result<Vec<String>, SupervisorError> {
        self.validate()?;
        let mut args = vec![
            "net".to_owned(),
            "serve-daemon".to_owned(),
            "--bind".to_owned(),
            self.bind.clone(),
            "--ledger".to_owned(),
            self.ledger.to_string_lossy().into_owned(),
            "--shared-key-file".to_owned(),
            self.shared_key_file.to_string_lossy().into_owned(),
        ];
        if let Some(peer_registry) = &self.peer_registry {
            args.extend([
                "--peer-registry".to_owned(),
                peer_registry.to_string_lossy().into_owned(),
            ]);
        }
        args.extend([
            "--health-file".to_owned(),
            self.health_file.to_string_lossy().into_owned(),
            "--audit-log".to_owned(),
            self.audit_log.to_string_lossy().into_owned(),
            "--idle-timeout-seconds".to_owned(),
            self.idle_timeout_seconds.to_string(),
        ]);
        if let Some(max_requests) = self.max_requests {
            args.extend(["--max-requests".to_owned(), max_requests.to_string()]);
        }
        Ok(args)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemdPeerWorkerUnit {
    pub unit_name: String,
    pub description: String,
    pub user: Option<String>,
    pub restart_seconds: u32,
    pub spec: PeerWorkerSupervisorSpec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemdFederationDaemonUnit {
    pub unit_name: String,
    pub description: String,
    pub user: Option<String>,
    pub restart_seconds: u32,
    pub spec: FederationDaemonSupervisorSpec,
}

impl SystemdPeerWorkerUnit {
    pub fn render(&self) -> Result<String, SupervisorError> {
        validate_name("unit_name", &self.unit_name)?;
        validate_text("description", &self.description)?;
        if let Some(user) = &self.user {
            validate_name("user", user)?;
        }
        if self.restart_seconds == 0 {
            return Err(SupervisorError::InvalidValue(
                "restart_seconds must be greater than zero".to_owned(),
            ));
        }

        let mut args = vec![self.spec.binary.to_string_lossy().into_owned()];
        args.extend(self.spec.worker_args()?);
        let exec_start = args
            .iter()
            .map(|arg| systemd_quote(arg))
            .collect::<Vec<_>>()
            .join(" ");
        let mut lines = vec![
            "[Unit]".to_owned(),
            format!("Description={}", self.description),
            "After=network-online.target".to_owned(),
            "Wants=network-online.target".to_owned(),
            String::new(),
            "[Service]".to_owned(),
            "Type=simple".to_owned(),
            format!(
                "WorkingDirectory={}",
                systemd_quote(&self.spec.working_directory.to_string_lossy())
            ),
            format!("ExecStart={exec_start}"),
            "Restart=always".to_owned(),
            format!("RestartSec={}", self.restart_seconds),
        ];
        if let Some(user) = &self.user {
            lines.push(format!("User={user}"));
        }
        lines.extend([
            String::new(),
            "[Install]".to_owned(),
            "WantedBy=multi-user.target".to_owned(),
            String::new(),
        ]);
        Ok(lines.join("\n"))
    }

    pub fn render_install_script(&self) -> Result<String, SupervisorError> {
        validate_name("unit_name", &self.unit_name)?;
        self.spec.validate()?;
        Ok(format!(
            concat!(
                "#!/usr/bin/env bash\n",
                "set -euo pipefail\n",
                "SCRIPT_DIR=\"$(cd \"$(dirname \"${{BASH_SOURCE[0]}}\")\" && pwd)\"\n",
                "UNIT_NAME={unit_name}\n",
                "install -m 0644 \"$SCRIPT_DIR/$UNIT_NAME\" \"/etc/systemd/system/$UNIT_NAME\"\n",
                "systemctl daemon-reload\n",
                "systemctl enable --now \"$UNIT_NAME\"\n",
                "systemctl status --no-pager \"$UNIT_NAME\"\n"
            ),
            unit_name = shell_quote(&self.unit_name),
        ))
    }

    pub fn render_uninstall_script(&self) -> Result<String, SupervisorError> {
        validate_name("unit_name", &self.unit_name)?;
        Ok(format!(
            concat!(
                "#!/usr/bin/env bash\n",
                "set -euo pipefail\n",
                "UNIT_NAME={unit_name}\n",
                "systemctl disable --now \"$UNIT_NAME\" || true\n",
                "rm -f \"/etc/systemd/system/$UNIT_NAME\"\n",
                "systemctl daemon-reload\n",
                "systemctl reset-failed \"$UNIT_NAME\" || true\n"
            ),
            unit_name = shell_quote(&self.unit_name),
        ))
    }
}

impl SystemdFederationDaemonUnit {
    pub fn render(&self) -> Result<String, SupervisorError> {
        validate_name("unit_name", &self.unit_name)?;
        validate_text("description", &self.description)?;
        if let Some(user) = &self.user {
            validate_name("user", user)?;
        }
        if self.restart_seconds == 0 {
            return Err(SupervisorError::InvalidValue(
                "restart_seconds must be greater than zero".to_owned(),
            ));
        }

        let mut args = vec![self.spec.binary.to_string_lossy().into_owned()];
        args.extend(self.spec.daemon_args()?);
        let exec_start = args
            .iter()
            .map(|arg| systemd_quote(arg))
            .collect::<Vec<_>>()
            .join(" ");
        let mut lines = vec![
            "[Unit]".to_owned(),
            format!("Description={}", self.description),
            "After=network-online.target".to_owned(),
            "Wants=network-online.target".to_owned(),
            String::new(),
            "[Service]".to_owned(),
            "Type=simple".to_owned(),
            format!(
                "WorkingDirectory={}",
                systemd_quote(&self.spec.working_directory.to_string_lossy())
            ),
            format!("ExecStart={exec_start}"),
            "Restart=always".to_owned(),
            format!("RestartSec={}", self.restart_seconds),
        ];
        if let Some(user) = &self.user {
            lines.push(format!("User={user}"));
        }
        lines.extend([
            String::new(),
            "[Install]".to_owned(),
            "WantedBy=multi-user.target".to_owned(),
            String::new(),
        ]);
        Ok(lines.join("\n"))
    }

    pub fn render_install_script(&self) -> Result<String, SupervisorError> {
        validate_name("unit_name", &self.unit_name)?;
        self.spec.validate()?;
        Ok(format!(
            concat!(
                "#!/usr/bin/env bash\n",
                "set -euo pipefail\n",
                "SCRIPT_DIR=\"$(cd \"$(dirname \"${{BASH_SOURCE[0]}}\")\" && pwd)\"\n",
                "UNIT_NAME={unit_name}\n",
                "install -m 0644 \"$SCRIPT_DIR/$UNIT_NAME\" \"/etc/systemd/system/$UNIT_NAME\"\n",
                "systemctl daemon-reload\n",
                "systemctl enable --now \"$UNIT_NAME\"\n",
                "systemctl status --no-pager \"$UNIT_NAME\"\n"
            ),
            unit_name = shell_quote(&self.unit_name),
        ))
    }

    pub fn render_uninstall_script(&self) -> Result<String, SupervisorError> {
        validate_name("unit_name", &self.unit_name)?;
        Ok(format!(
            concat!(
                "#!/usr/bin/env bash\n",
                "set -euo pipefail\n",
                "UNIT_NAME={unit_name}\n",
                "systemctl disable --now \"$UNIT_NAME\" || true\n",
                "rm -f \"/etc/systemd/system/$UNIT_NAME\"\n",
                "systemctl daemon-reload\n",
                "systemctl reset-failed \"$UNIT_NAME\" || true\n"
            ),
            unit_name = shell_quote(&self.unit_name),
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsPeerWorkerTask {
    pub task_name: String,
    pub spec: PeerWorkerSupervisorSpec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsFederationDaemonTask {
    pub task_name: String,
    pub spec: FederationDaemonSupervisorSpec,
}

impl WindowsPeerWorkerTask {
    pub fn render(&self) -> Result<String, SupervisorError> {
        validate_name("task_name", &self.task_name)?;
        let args = self.spec.worker_args()?;
        let argument = args
            .iter()
            .map(|arg| windows_arg_quote(arg))
            .collect::<Vec<_>>()
            .join(" ");
        Ok(format!(
            concat!(
                "$ErrorActionPreference = 'Stop'\n",
                "$action = New-ScheduledTaskAction -Execute {binary} -Argument {argument} -WorkingDirectory {working_directory}\n",
                "$trigger = New-ScheduledTaskTrigger -AtStartup\n",
                "$settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Days 365)\n",
                "Register-ScheduledTask -TaskName {task_name} -Action $action -Trigger $trigger -Settings $settings -RunLevel Highest -Force\n"
            ),
            binary = powershell_quote(&self.spec.binary.to_string_lossy()),
            argument = powershell_quote(&argument),
            working_directory = powershell_quote(&self.spec.working_directory.to_string_lossy()),
            task_name = powershell_quote(&self.task_name),
        ))
    }

    pub fn render_uninstall_script(&self) -> Result<String, SupervisorError> {
        validate_name("task_name", &self.task_name)?;
        Ok(format!(
            concat!(
                "$ErrorActionPreference = 'Stop'\n",
                "$taskName = {task_name}\n",
                "if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {{\n",
                "    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false\n",
                "}}\n"
            ),
            task_name = powershell_quote(&self.task_name),
        ))
    }
}

impl WindowsFederationDaemonTask {
    pub fn render(&self) -> Result<String, SupervisorError> {
        validate_name("task_name", &self.task_name)?;
        let args = self.spec.daemon_args()?;
        let argument = args
            .iter()
            .map(|arg| windows_arg_quote(arg))
            .collect::<Vec<_>>()
            .join(" ");
        Ok(format!(
            concat!(
                "$ErrorActionPreference = 'Stop'\n",
                "$action = New-ScheduledTaskAction -Execute {binary} -Argument {argument} -WorkingDirectory {working_directory}\n",
                "$trigger = New-ScheduledTaskTrigger -AtStartup\n",
                "$settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Days 365)\n",
                "Register-ScheduledTask -TaskName {task_name} -Action $action -Trigger $trigger -Settings $settings -RunLevel Highest -Force\n"
            ),
            binary = powershell_quote(&self.spec.binary.to_string_lossy()),
            argument = powershell_quote(&argument),
            working_directory = powershell_quote(&self.spec.working_directory.to_string_lossy()),
            task_name = powershell_quote(&self.task_name),
        ))
    }

    pub fn render_uninstall_script(&self) -> Result<String, SupervisorError> {
        validate_name("task_name", &self.task_name)?;
        Ok(format!(
            concat!(
                "$ErrorActionPreference = 'Stop'\n",
                "$taskName = {task_name}\n",
                "if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {{\n",
                "    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false\n",
                "}}\n"
            ),
            task_name = powershell_quote(&self.task_name),
        ))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SupervisorError {
    #[error("{field} cannot contain a newline, carriage return, or NUL byte")]
    UnsafeText { field: &'static str },
    #[error("invalid supervisor value: {0}")]
    InvalidValue(String),
}

fn validate_path(field: &'static str, path: &Path) -> Result<(), SupervisorError> {
    let value = path.to_string_lossy();
    if value.trim().is_empty() {
        return Err(SupervisorError::InvalidValue(format!(
            "{field} cannot be empty"
        )));
    }
    validate_text(field, &value)
}

fn validate_name(field: &'static str, value: &str) -> Result<(), SupervisorError> {
    if value.trim().is_empty() {
        return Err(SupervisorError::InvalidValue(format!(
            "{field} cannot be empty"
        )));
    }
    validate_text(field, value)
}

fn validate_text(field: &'static str, value: &str) -> Result<(), SupervisorError> {
    if value.chars().any(|char| matches!(char, '\n' | '\r' | '\0')) {
        return Err(SupervisorError::UnsafeText { field });
    }
    Ok(())
}

fn systemd_quote(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

fn powershell_quote(value: &str) -> String {
    let escaped = value.replace('\'', "''");
    format!("'{escaped}'")
}

fn windows_arg_quote(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

fn shell_quote(value: &str) -> String {
    let escaped = value.replace('\'', "'\"'\"'");
    format!("'{escaped}'")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> PeerWorkerSupervisorSpec {
        PeerWorkerSupervisorSpec {
            binary: PathBuf::from("/usr/local/bin/astragrid"),
            working_directory: PathBuf::from("/srv/astragrid"),
            ledger: PathBuf::from("data/mission.agl"),
            queue: PathBuf::from("data/peer-sync.db"),
            shared_key_file: PathBuf::from("secrets/peer.key"),
            identity: None,
            identity_passphrase_file: None,
            limit: 10,
            retry_delay_seconds: 300,
            interval_seconds: 30,
            health_file: Some(PathBuf::from("data/peer-worker-health.json")),
            audit_log: Some(PathBuf::from("data/peer-worker-audit.jsonl")),
            stale_after_seconds: 600,
        }
    }

    fn daemon_spec() -> FederationDaemonSupervisorSpec {
        FederationDaemonSupervisorSpec {
            binary: PathBuf::from("/usr/local/bin/astragrid"),
            working_directory: PathBuf::from("/srv/astragrid"),
            bind: "127.0.0.1:17655".to_owned(),
            ledger: PathBuf::from("data/mission.agl"),
            shared_key_file: PathBuf::from("secrets/peer.key"),
            peer_registry: Some(PathBuf::from("data/operators.agregistry")),
            health_file: PathBuf::from("data/federation-health.json"),
            audit_log: PathBuf::from("data/federation-audit.jsonl"),
            max_requests: None,
            idle_timeout_seconds: 0,
        }
    }

    #[test]
    fn renders_systemd_peer_worker_unit() {
        let unit = SystemdPeerWorkerUnit {
            unit_name: "astragrid-peer-worker.service".to_owned(),
            description: "AstraGrid peer sync worker".to_owned(),
            user: Some("astragrid".to_owned()),
            restart_seconds: 5,
            spec: spec(),
        };

        let rendered = unit.render().unwrap();

        assert!(rendered.contains("[Service]"));
        assert!(rendered.contains("Restart=always"));
        assert!(rendered.contains("\"/usr/local/bin/astragrid\" \"peer-queue\" \"worker\""));
        assert!(rendered.contains("\"--health-file\" \"data/peer-worker-health.json\""));
        assert!(rendered.contains("\"--audit-log\" \"data/peer-worker-audit.jsonl\""));
        assert!(rendered.contains("\"--stale-after-seconds\" \"600\""));
        assert!(rendered.contains("User=astragrid"));
    }

    #[test]
    fn renders_systemd_federation_daemon_unit() {
        let unit = SystemdFederationDaemonUnit {
            unit_name: "astragrid-federation-daemon.service".to_owned(),
            description: "AstraGrid federation daemon".to_owned(),
            user: Some("astragrid".to_owned()),
            restart_seconds: 5,
            spec: daemon_spec(),
        };

        let rendered = unit.render().unwrap();

        assert!(rendered.contains("[Service]"));
        assert!(rendered.contains("\"/usr/local/bin/astragrid\" \"net\" \"serve-daemon\""));
        assert!(rendered.contains("\"--peer-registry\" \"data/operators.agregistry\""));
        assert!(rendered.contains("\"--health-file\" \"data/federation-health.json\""));
        assert!(rendered.contains("User=astragrid"));
    }

    #[test]
    fn renders_windows_peer_worker_task() {
        let mut spec = spec();
        spec.binary = PathBuf::from("D:\\astragrid\\target\\release\\astragrid.exe");
        spec.working_directory = PathBuf::from("D:\\astragrid");
        spec.identity = Some(PathBuf::from("D:\\astragrid\\peer.agkey"));
        spec.identity_passphrase_file = Some(PathBuf::from("D:\\astragrid\\peer.pass"));
        let task = WindowsPeerWorkerTask {
            task_name: "AstraGrid Peer Worker".to_owned(),
            spec,
        };

        let rendered = task.render().unwrap();

        assert!(rendered.contains("New-ScheduledTaskAction"));
        assert!(rendered.contains("'D:\\astragrid\\target\\release\\astragrid.exe'"));
        assert!(rendered.contains("--identity"));
        assert!(rendered.contains("--passphrase-file"));
        assert!(rendered.contains("--health-file"));
        assert!(rendered.contains("--audit-log"));
        assert!(rendered.contains("Register-ScheduledTask"));
    }

    #[test]
    fn renders_windows_federation_daemon_task() {
        let mut spec = daemon_spec();
        spec.binary = PathBuf::from("D:\\astragrid\\target\\release\\astragrid.exe");
        spec.working_directory = PathBuf::from("D:\\astragrid");
        spec.max_requests = Some(1);
        let task = WindowsFederationDaemonTask {
            task_name: "AstraGrid Federation Daemon".to_owned(),
            spec,
        };

        let rendered = task.render().unwrap();

        assert!(rendered.contains("New-ScheduledTaskAction"));
        assert!(rendered.contains("serve-daemon"));
        assert!(rendered.contains("peer-registry"));
        assert!(rendered.contains("--max-requests"));
        assert!(rendered.contains("Register-ScheduledTask"));
    }

    #[test]
    fn renders_systemd_install_uninstall_scripts() {
        let unit = SystemdPeerWorkerUnit {
            unit_name: "astragrid-peer-worker.service".to_owned(),
            description: "AstraGrid peer sync worker".to_owned(),
            user: Some("astragrid".to_owned()),
            restart_seconds: 5,
            spec: spec(),
        };

        let install = unit.render_install_script().unwrap();
        let uninstall = unit.render_uninstall_script().unwrap();

        assert!(install.contains("systemctl enable --now"));
        assert!(install.contains("/etc/systemd/system/$UNIT_NAME"));
        assert!(uninstall.contains("systemctl disable --now"));
    }

    #[test]
    fn renders_federation_daemon_install_uninstall_scripts() {
        let unit = SystemdFederationDaemonUnit {
            unit_name: "astragrid-federation-daemon.service".to_owned(),
            description: "AstraGrid federation daemon".to_owned(),
            user: Some("astragrid".to_owned()),
            restart_seconds: 5,
            spec: daemon_spec(),
        };
        let task = WindowsFederationDaemonTask {
            task_name: "AstraGrid Federation Daemon".to_owned(),
            spec: daemon_spec(),
        };

        let systemd_install = unit.render_install_script().unwrap();
        let systemd_uninstall = unit.render_uninstall_script().unwrap();
        let windows_uninstall = task.render_uninstall_script().unwrap();

        assert!(systemd_install.contains("systemctl enable --now"));
        assert!(systemd_uninstall.contains("systemctl disable --now"));
        assert!(windows_uninstall.contains("Unregister-ScheduledTask"));
    }

    #[test]
    fn renders_windows_uninstall_script() {
        let task = WindowsPeerWorkerTask {
            task_name: "AstraGrid Peer Worker".to_owned(),
            spec: spec(),
        };

        let rendered = task.render_uninstall_script().unwrap();

        assert!(rendered.contains("Unregister-ScheduledTask"));
        assert!(rendered.contains("$taskName"));
    }

    #[test]
    fn rejects_newline_in_supervisor_paths() {
        let mut unsafe_path_spec = spec();
        unsafe_path_spec.queue = PathBuf::from("data\nbad.db");

        assert!(matches!(
            unsafe_path_spec.worker_args(),
            Err(SupervisorError::UnsafeText { field: "queue" })
        ));

        let mut missing_identity_spec = spec();
        missing_identity_spec.identity_passphrase_file = Some(PathBuf::from("peer.pass"));
        assert!(matches!(
            missing_identity_spec.worker_args(),
            Err(SupervisorError::InvalidValue(_))
        ));

        let mut invalid_stale_spec = spec();
        invalid_stale_spec.stale_after_seconds = -1;
        assert!(matches!(
            invalid_stale_spec.worker_args(),
            Err(SupervisorError::InvalidValue(_))
        ));
    }

    #[test]
    fn rejects_invalid_federation_daemon_values() {
        let mut spec = daemon_spec();
        spec.bind = "127.0.0.1:17655\nbad".to_owned();

        assert!(matches!(
            spec.daemon_args(),
            Err(SupervisorError::UnsafeText { field: "bind" })
        ));

        let mut spec = daemon_spec();
        spec.max_requests = Some(0);

        assert!(matches!(
            spec.daemon_args(),
            Err(SupervisorError::InvalidValue(_))
        ));
    }
}
