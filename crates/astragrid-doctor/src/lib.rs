use std::path::PathBuf;

use astragrid_approvals::ApprovalLog;
use astragrid_core::{MissionLedger, OperatorKeypair};
use astragrid_provenance::{
    PackageProvenance, ProvenanceQuorumEnvelope, ProvenanceSignatureEnvelope, ReleaseCustodyPolicy,
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
    pub policy: Option<PathBuf>,
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
    let package = check_package_provenance(input.provenance, &mut checks);
    if input.signatures.is_empty() && input.quorum.is_none() {
        checks.push(DoctorCheck::warning(
            "release_custody",
            json!({"warning": "no provenance signature or quorum was supplied"}),
        ));
    }
    for signature in input.signatures {
        check_provenance_signature(signature, &mut checks);
    }
    let quorum_report = input
        .quorum
        .and_then(|quorum| check_provenance_quorum(quorum, &mut checks));
    if let Some(policy) = input.policy {
        if let (Some(package), Some(quorum_report)) = (package, quorum_report) {
            check_release_policy(policy, &package, &quorum_report, &mut checks);
        } else {
            checks.push(DoctorCheck::failed(
                "release_policy",
                json!({"path": policy, "error": "policy requires valid provenance and quorum inputs"}),
            ));
        }
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

fn check_package_provenance(
    provenance: PathBuf,
    checks: &mut Vec<DoctorCheck>,
) -> Option<PackageProvenance> {
    if !provenance.exists() {
        checks.push(DoctorCheck::failed(
            "release_provenance",
            json!({"path": provenance, "error": "provenance file does not exist"}),
        ));
        return None;
    }
    match PackageProvenance::load(&provenance) {
        Ok(package) => match package.verify_hashes(&provenance) {
            Ok(report) if report.valid => {
                checks.push(DoctorCheck::ok(
                    "release_provenance",
                    json!({"path": provenance, "verification": report}),
                ));
                Some(package)
            }
            Ok(report) => {
                checks.push(DoctorCheck::failed(
                    "release_provenance",
                    json!({"path": provenance, "verification": report}),
                ));
                None
            }
            Err(error) => {
                checks.push(DoctorCheck::failed(
                    "release_provenance",
                    json!({"path": provenance, "error": error.to_string()}),
                ));
                None
            }
        },
        Err(error) => {
            checks.push(DoctorCheck::failed(
                "release_provenance",
                json!({"path": provenance, "error": error.to_string()}),
            ));
            None
        }
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

fn check_provenance_quorum(
    quorum: PathBuf,
    checks: &mut Vec<DoctorCheck>,
) -> Option<astragrid_provenance::ProvenanceQuorumVerificationReport> {
    if !quorum.exists() {
        checks.push(DoctorCheck::failed(
            "release_quorum",
            json!({"path": quorum, "error": "quorum file does not exist"}),
        ));
        return None;
    }
    match ProvenanceQuorumEnvelope::load(&quorum).and_then(|envelope| envelope.verify(&quorum)) {
        Ok(report) if report.valid => {
            checks.push(DoctorCheck::ok(
                "release_quorum",
                json!({"path": quorum, "verification": report}),
            ));
            Some(report)
        }
        Ok(report) => {
            checks.push(DoctorCheck::failed(
                "release_quorum",
                json!({"path": quorum, "verification": report}),
            ));
            None
        }
        Err(error) => {
            checks.push(DoctorCheck::failed(
                "release_quorum",
                json!({"path": quorum, "error": error.to_string()}),
            ));
            None
        }
    }
}

fn check_release_policy(
    policy: PathBuf,
    package: &PackageProvenance,
    quorum: &astragrid_provenance::ProvenanceQuorumVerificationReport,
    checks: &mut Vec<DoctorCheck>,
) {
    if !policy.exists() {
        checks.push(DoctorCheck::failed(
            "release_policy",
            json!({"path": policy, "error": "policy file does not exist"}),
        ));
        return;
    }
    match ReleaseCustodyPolicy::load(&policy)
        .and_then(|policy_doc| policy_doc.verify(package, quorum))
    {
        Ok(report) if report.valid => checks.push(DoctorCheck::ok(
            "release_policy",
            json!({"path": policy, "verification": report}),
        )),
        Ok(report) => checks.push(DoctorCheck::failed(
            "release_policy",
            json!({"path": policy, "verification": report}),
        )),
        Err(error) => checks.push(DoctorCheck::failed(
            "release_policy",
            json!({"path": policy, "error": error.to_string()}),
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
    use astragrid_core::{
        Action, Actor, CommandRequest, MissionLedger, OperatorKeypair, Priority, Role,
    };
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
            policy: None,
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

    #[test]
    fn reports_release_policy_health() {
        let dir = tempdir().unwrap();
        let artifact = dir.path().join("artifact.zip");
        std::fs::write(&artifact, b"release artifact").unwrap();
        let provenance = PackageProvenance {
            schema: 1,
            package: "astragrid".to_owned(),
            version: "0.1.0".to_owned(),
            target: "windows-x64".to_owned(),
            generated_at: "2026-05-07T00:00:00Z".to_owned(),
            artifact: Some(ProvenanceFile {
                path: PathBuf::from("artifact.zip"),
                sha256: sha256_bytes(b"release artifact"),
            }),
            binary: None,
            included_files: Vec::new(),
            toolchain: serde_json::Value::Null,
            git: json!({"dirty": false}),
        };
        let provenance_path = dir.path().join("artifact.provenance.json");
        std::fs::write(&provenance_path, serde_json::to_vec(&provenance).unwrap()).unwrap();
        let signer = OperatorKeypair::generate("release-one", Role::Operator);
        let quorum = ProvenanceQuorumEnvelope::new(
            1,
            vec![ProvenanceSignatureEnvelope::sign_file(&provenance_path, &signer).unwrap()],
        )
        .unwrap();
        let quorum_path = dir.path().join("artifact.provenance.quorum.json");
        std::fs::write(&quorum_path, serde_json::to_vec(&quorum).unwrap()).unwrap();
        let policy = ReleaseCustodyPolicy {
            schema: 1,
            package: Some("astragrid".to_owned()),
            version: Some("0.1.0".to_owned()),
            target: Some("windows-x64".to_owned()),
            min_distinct_valid_signers: 1,
            required_signer_ids: vec![signer.identity().id.clone()],
            allowed_signer_ids: vec![signer.identity().id.clone()],
            require_clean_git: true,
        };
        let policy_path = dir.path().join("release-policy.json");
        std::fs::write(&policy_path, serde_json::to_vec(&policy).unwrap()).unwrap();

        let report = run_release_doctor(ReleaseDoctorInput {
            provenance: provenance_path,
            signatures: Vec::new(),
            quorum: Some(quorum_path),
            policy: Some(policy_path),
        });

        assert_eq!(report.status, DoctorStatus::Healthy);
        assert!(
            report
                .checks
                .iter()
                .any(|check| check.name == "release_policy")
        );
    }

    fn sha256_bytes(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};

        hex::encode(Sha256::digest(bytes))
    }
}
