use std::path::PathBuf;

use astragrid_approvals::ApprovalLog;
use astragrid_core::{MissionLedger, OperatorKeypair};
use astragrid_provenance::{
    PackageProvenance, ProvenanceQuorumEnvelope, ProvenanceSignatureEnvelope,
};
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseDoctorInput {
    pub provenance: PathBuf,
    pub signatures: Vec<PathBuf>,
    pub quorum: Option<PathBuf>,
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

pub fn run_release_doctor(input: ReleaseDoctorInput) -> DoctorReport {
    let mut checks = Vec::new();
    check_package_provenance(input.provenance, &mut checks);
    if input.signatures.is_empty() && input.quorum.is_none() {
        checks.push(DoctorCheck::warning(
            "release_custody",
            json!({"warning": "no provenance signature or quorum was supplied"}),
        ));
    }
    for signature in input.signatures {
        check_provenance_signature(signature, &mut checks);
    }
    if let Some(quorum) = input.quorum {
        check_provenance_quorum(quorum, &mut checks);
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

fn check_package_provenance(provenance: PathBuf, checks: &mut Vec<DoctorCheck>) {
    if !provenance.exists() {
        checks.push(DoctorCheck::failed(
            "release_provenance",
            json!({"path": provenance, "error": "provenance file does not exist"}),
        ));
        return;
    }
    match PackageProvenance::load(&provenance)
        .and_then(|package| package.verify_hashes(&provenance))
    {
        Ok(report) if report.valid => checks.push(DoctorCheck::ok(
            "release_provenance",
            json!({"path": provenance, "verification": report}),
        )),
        Ok(report) => checks.push(DoctorCheck::failed(
            "release_provenance",
            json!({"path": provenance, "verification": report}),
        )),
        Err(error) => checks.push(DoctorCheck::failed(
            "release_provenance",
            json!({"path": provenance, "error": error.to_string()}),
        )),
    }
}

fn check_provenance_signature(signature: PathBuf, checks: &mut Vec<DoctorCheck>) {
    if !signature.exists() {
        checks.push(DoctorCheck::failed(
            "release_signature",
            json!({"path": signature, "error": "signature file does not exist"}),
        ));
        return;
    }
    match ProvenanceSignatureEnvelope::load(&signature)
        .and_then(|envelope| envelope.verify(&signature))
    {
        Ok(report) if report.valid => checks.push(DoctorCheck::ok(
            "release_signature",
            json!({"path": signature, "verification": report}),
        )),
        Ok(report) => checks.push(DoctorCheck::failed(
            "release_signature",
            json!({"path": signature, "verification": report}),
        )),
        Err(error) => checks.push(DoctorCheck::failed(
            "release_signature",
            json!({"path": signature, "error": error.to_string()}),
        )),
    }
}

fn check_provenance_quorum(quorum: PathBuf, checks: &mut Vec<DoctorCheck>) {
    if !quorum.exists() {
        checks.push(DoctorCheck::failed(
            "release_quorum",
            json!({"path": quorum, "error": "quorum file does not exist"}),
        ));
        return;
    }
    match ProvenanceQuorumEnvelope::load(&quorum).and_then(|envelope| envelope.verify(&quorum)) {
        Ok(report) if report.valid => checks.push(DoctorCheck::ok(
            "release_quorum",
            json!({"path": quorum, "verification": report}),
        )),
        Ok(report) => checks.push(DoctorCheck::failed(
            "release_quorum",
            json!({"path": quorum, "verification": report}),
        )),
        Err(error) => checks.push(DoctorCheck::failed(
            "release_quorum",
            json!({"path": quorum, "error": error.to_string()}),
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
    use astragrid_provenance::ProvenanceFile;
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

    #[test]
    fn reports_release_provenance_health_with_unsigned_warning() {
        let dir = tempdir().unwrap();
        let artifact = dir.path().join("artifact.zip");
        std::fs::write(&artifact, b"release artifact").unwrap();
        let provenance = PackageProvenance {
            schema: 1,
            package: "astragrid".to_owned(),
            version: "0.1.0".to_owned(),
            target: "test".to_owned(),
            generated_at: "2026-05-07T00:00:00Z".to_owned(),
            artifact: Some(ProvenanceFile {
                path: PathBuf::from("artifact.zip"),
                sha256: sha256_bytes(b"release artifact"),
            }),
            binary: None,
            included_files: Vec::new(),
            toolchain: serde_json::Value::Null,
            git: serde_json::Value::Null,
        };
        let provenance_path = dir.path().join("artifact.provenance.json");
        std::fs::write(&provenance_path, serde_json::to_vec(&provenance).unwrap()).unwrap();

        let report = run_release_doctor(ReleaseDoctorInput {
            provenance: provenance_path,
            signatures: Vec::new(),
            quorum: None,
        });

        assert_eq!(report.status, DoctorStatus::Warning);
        assert_eq!(report.failures, 0);
        assert!(
            report
                .checks
                .iter()
                .any(|check| check.name == "release_provenance")
        );
        assert!(
            report
                .checks
                .iter()
                .any(|check| check.name == "release_custody")
        );
    }

    fn sha256_bytes(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};

        hex::encode(Sha256::digest(bytes))
    }
}
