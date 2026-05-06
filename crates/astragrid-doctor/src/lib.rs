use std::path::PathBuf;

use astragrid_approvals::ApprovalLog;
use astragrid_core::{MissionLedger, OperatorKeypair};
use astragrid_state::MissionState;
use astragrid_store::MissionStore;
use astragrid_sync_queue::PeerSyncQueue;
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorInput {
    pub ledger: PathBuf,
    pub db: Option<PathBuf>,
    pub identities: Vec<PathBuf>,
    pub approvals: Option<PathBuf>,
    pub peer_queue: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DoctorReport {
    pub status: DoctorStatus,
    pub ok: usize,
    pub warnings: usize,
    pub failures: usize,
    pub checks: Vec<DoctorCheck>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DoctorStatus {
    Healthy,
    Warning,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DoctorCheck {
    pub name: String,
    pub status: CheckStatus,
    pub detail: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Ok,
    Warning,
    Failed,
}

pub fn run_doctor(input: DoctorInput) -> DoctorReport {
    let mut checks = Vec::new();
    check_ledger_and_state(&input.ledger, &mut checks);
    if let Some(db) = input.db {
        check_store(db, &mut checks);
    }
    for identity in input.identities {
        check_identity(identity, &mut checks);
    }
    if let Some(approvals) = input.approvals {
        check_approvals(approvals, &mut checks);
    }
    if let Some(peer_queue) = input.peer_queue {
        check_peer_queue(peer_queue, &mut checks);
    }
    summarize(checks)
}

fn check_ledger_and_state(ledger_path: &PathBuf, checks: &mut Vec<DoctorCheck>) {
    if !ledger_path.exists() {
        checks.push(DoctorCheck::failed(
            "ledger",
            json!({"path": ledger_path, "error": "ledger file does not exist"}),
        ));
        return;
    }

    let ledger = MissionLedger::open(ledger_path);
    match ledger.verify() {
        Ok(verification) if verification.valid => {
            checks.push(DoctorCheck::ok(
                "ledger",
                json!({
                    "path": ledger_path,
                    "events": verification.events,
                    "last_hash": verification.last_hash,
                }),
            ));
        }
        Ok(verification) => {
            checks.push(DoctorCheck::failed(
                "ledger",
                json!({
                    "path": ledger_path,
                    "failures": verification.failures,
                }),
            ));
            return;
        }
        Err(error) => {
            checks.push(DoctorCheck::failed(
                "ledger",
                json!({"path": ledger_path, "error": error.to_string()}),
            ));
            return;
        }
    }

    match MissionState::from_ledger(&ledger) {
        Ok(state) => checks.push(DoctorCheck::ok("state", json!(state.summary()))),
        Err(error) => checks.push(DoctorCheck::failed(
            "state",
            json!({"path": ledger_path, "error": error.to_string()}),
        )),
    }
}

fn check_store(db: PathBuf, checks: &mut Vec<DoctorCheck>) {
    if !db.exists() {
        checks.push(DoctorCheck::warning(
            "store",
            json!({"path": db, "warning": "store DB does not exist"}),
        ));
        return;
    }
    match MissionStore::open(&db).and_then(|store| store.summary()) {
        Ok(summary) => checks.push(DoctorCheck::ok(
            "store",
            json!({"path": db, "summary": summary}),
        )),
        Err(error) => checks.push(DoctorCheck::failed(
            "store",
            json!({"path": db, "error": error.to_string()}),
        )),
    }
}

fn check_identity(identity: PathBuf, checks: &mut Vec<DoctorCheck>) {
    if !identity.exists() {
        checks.push(DoctorCheck::failed(
            "identity",
            json!({"path": identity, "error": "identity file does not exist"}),
        ));
        return;
    }
    match OperatorKeypair::inspect_key_file(&identity) {
        Ok(security) if security.warnings.is_empty() => {
            checks.push(DoctorCheck::ok("identity", json!(security)));
        }
        Ok(security) => {
            checks.push(DoctorCheck::warning("identity", json!(security)));
        }
        Err(error) => checks.push(DoctorCheck::failed(
            "identity",
            json!({"path": identity, "error": error.to_string()}),
        )),
    }
}

fn check_approvals(approvals: PathBuf, checks: &mut Vec<DoctorCheck>) {
    if !approvals.exists() {
        checks.push(DoctorCheck::warning(
            "approvals",
            json!({"path": approvals, "warning": "approval log does not exist"}),
        ));
        return;
    }
    match ApprovalLog::open(&approvals).verify() {
        Ok(verification) if verification.valid => {
            checks.push(DoctorCheck::ok(
                "approvals",
                json!({"path": approvals, "verification": verification}),
            ));
        }
        Ok(verification) => checks.push(DoctorCheck::failed(
            "approvals",
            json!({"path": approvals, "verification": verification}),
        )),
        Err(error) => checks.push(DoctorCheck::failed(
            "approvals",
            json!({"path": approvals, "error": error.to_string()}),
        )),
    }
}

fn check_peer_queue(peer_queue: PathBuf, checks: &mut Vec<DoctorCheck>) {
    if !peer_queue.exists() {
        checks.push(DoctorCheck::warning(
            "peer_queue",
            json!({"path": peer_queue, "warning": "peer queue DB does not exist"}),
        ));
        return;
    }
    match PeerSyncQueue::open(&peer_queue).and_then(|queue| queue.summary()) {
        Ok(summary) => {
            let status = if summary.failed > 0 {
                CheckStatus::Warning
            } else {
                CheckStatus::Ok
            };
            checks.push(DoctorCheck {
                name: "peer_queue".to_owned(),
                status,
                detail: json!({"path": peer_queue, "summary": summary}),
            });
        }
        Err(error) => checks.push(DoctorCheck::failed(
            "peer_queue",
            json!({"path": peer_queue, "error": error.to_string()}),
        )),
    }
}

fn summarize(checks: Vec<DoctorCheck>) -> DoctorReport {
    let ok = checks
        .iter()
        .filter(|check| check.status == CheckStatus::Ok)
        .count();
    let warnings = checks
        .iter()
        .filter(|check| check.status == CheckStatus::Warning)
        .count();
    let failures = checks
        .iter()
        .filter(|check| check.status == CheckStatus::Failed)
        .count();
    let status = if failures > 0 {
        DoctorStatus::Failed
    } else if warnings > 0 {
        DoctorStatus::Warning
    } else {
        DoctorStatus::Healthy
    };
    DoctorReport {
        status,
        ok,
        warnings,
        failures,
        checks,
    }
}

impl DoctorCheck {
    fn ok(name: impl Into<String>, detail: serde_json::Value) -> Self {
        Self {
            name: name.into(),
            status: CheckStatus::Ok,
            detail,
        }
    }

    fn warning(name: impl Into<String>, detail: serde_json::Value) -> Self {
        Self {
            name: name.into(),
            status: CheckStatus::Warning,
            detail,
        }
    }

    fn failed(name: impl Into<String>, detail: serde_json::Value) -> Self {
        Self {
            name: name.into(),
            status: CheckStatus::Failed,
            detail,
        }
    }
}

#[cfg(test)]
mod tests {
    use astragrid_core::{Action, Actor, CommandRequest, MissionLedger, Priority, Role};
    use serde_json::json;
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn reports_healthy_ledger_and_state() {
        let dir = tempdir().unwrap();
        let ledger_path = dir.path().join("mission.agl");
        let ledger = MissionLedger::open(&ledger_path);
        ledger
            .append(CommandRequest::new(
                Actor::new("kernel", Role::System),
                Action::OpenMission,
                "mission-a",
                Priority::Elevated,
                json!({"mission": "mission-a"}),
            ))
            .unwrap();

        let report = run_doctor(DoctorInput {
            ledger: ledger_path,
            db: None,
            identities: Vec::new(),
            approvals: None,
            peer_queue: None,
        });

        assert_eq!(report.status, DoctorStatus::Healthy);
        assert_eq!(report.failures, 0);
        assert!(report.checks.iter().any(|check| check.name == "ledger"));
        assert!(report.checks.iter().any(|check| check.name == "state"));
    }

    #[test]
    fn reports_missing_ledger_failure() {
        let dir = tempdir().unwrap();
        let report = run_doctor(DoctorInput {
            ledger: dir.path().join("missing.agl"),
            db: None,
            identities: Vec::new(),
            approvals: None,
            peer_queue: None,
        });

        assert_eq!(report.status, DoctorStatus::Failed);
        assert_eq!(report.failures, 1);
    }
}
