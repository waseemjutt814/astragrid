use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{
    event::{EventHashError, MissionEvent},
    identity::{CommandAttestation, IdentityError, OperatorRegistry, RegistryError, SignedCommand},
    policy::{AdmissionPolicy, CommandRequest, PolicyDecision},
};

pub const PAYLOAD_LIMIT_BYTES: usize = 128 * 1024;

#[derive(Debug, Clone)]
pub struct MissionLedger {
    path: PathBuf,
    policy: AdmissionPolicy,
}

impl MissionLedger {
    pub fn open(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            policy: AdmissionPolicy,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn append(&self, request: CommandRequest) -> Result<MissionEvent, LedgerError> {
        self.append_admitted(request, None)
    }

    pub fn append_signed(&self, command: SignedCommand) -> Result<MissionEvent, LedgerError> {
        command.verify()?;
        let attestation = Some(command.attestation);
        self.append_admitted(command.request, attestation)
    }

    pub fn append_signed_with_registry(
        &self,
        command: SignedCommand,
        registry: &OperatorRegistry,
    ) -> Result<MissionEvent, LedgerError> {
        registry.authorize_signed_command(&command)?;
        let attestation = Some(command.attestation);
        self.append_admitted(command.request, attestation)
    }

    fn append_admitted(
        &self,
        request: CommandRequest,
        attestation: Option<CommandAttestation>,
    ) -> Result<MissionEvent, LedgerError> {
        let payload_size = serde_json::to_vec(&request.payload)?.len();
        if payload_size > PAYLOAD_LIMIT_BYTES {
            return Err(LedgerError::PayloadTooLarge {
                actual: payload_size,
                limit: PAYLOAD_LIMIT_BYTES,
            });
        }

        let decision = self.policy.evaluate(&request);
        if !decision.allowed {
            return Err(LedgerError::PolicyDenied(decision));
        }

        let verification = self.verify()?;
        if !verification.valid {
            return Err(LedgerError::LedgerCorrupt(verification));
        }

        let (sequence, previous_hash) = match self.load_events()?.last() {
            Some(last) => (last.sequence + 1, Some(last.hash.clone())),
            None => (0, None),
        };

        let event = MissionEvent::new_attested(
            sequence,
            request.actor,
            request.action,
            request.subject,
            request.priority,
            request.payload,
            attestation,
            previous_hash,
        )?;
        self.append_event_line(&event)?;
        Ok(event)
    }

    pub fn load_events(&self) -> Result<Vec<MissionEvent>, LedgerError> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }

        let file = File::open(&self.path)?;
        let reader = BufReader::new(file);
        let mut events = Vec::new();
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            events.push(serde_json::from_str(&line)?);
        }
        Ok(events)
    }

    pub fn append_verified_events(
        &self,
        incoming: &[MissionEvent],
    ) -> Result<AppendVerifiedReport, LedgerError> {
        if incoming.is_empty() {
            let verification = self.verify()?;
            if !verification.valid {
                return Err(LedgerError::LedgerCorrupt(verification));
            }
            return Ok(AppendVerifiedReport {
                appended: 0,
                last_hash: verification.last_hash,
            });
        }

        let verification = self.verify()?;
        if !verification.valid {
            return Err(LedgerError::LedgerCorrupt(verification));
        }
        let existing = self.load_events()?;
        let mut expected_sequence = existing
            .last()
            .map(|event| event.sequence.saturating_add(1))
            .unwrap_or(0);
        let mut previous_hash = existing.last().map(|event| event.hash.clone());

        for event in incoming {
            validate_import_event(event, expected_sequence, &previous_hash, &self.policy)?;
            expected_sequence = event.sequence.saturating_add(1);
            previous_hash = Some(event.hash.clone());
        }

        self.append_event_lines(incoming)?;
        Ok(AppendVerifiedReport {
            appended: incoming.len(),
            last_hash: previous_hash,
        })
    }

    pub fn verify(&self) -> Result<LedgerVerification, LedgerError> {
        if !self.path.exists() {
            return Ok(LedgerVerification {
                valid: true,
                events: 0,
                last_hash: None,
                failures: Vec::new(),
            });
        }

        let file = File::open(&self.path)?;
        let reader = BufReader::new(file);
        let mut expected_sequence = 0_u64;
        let mut previous_hash: Option<String> = None;
        let mut failures = Vec::new();
        let mut events = 0_usize;
        let mut last_hash = None;

        for (index, line) in reader.lines().enumerate() {
            let line_number = index + 1;
            let line = line?;
            if line.trim().is_empty() {
                failures.push(LedgerFailure::new(
                    line_number,
                    "blank_line",
                    "blank lines are not allowed inside the ledger",
                ));
                break;
            }

            let event = match serde_json::from_str::<MissionEvent>(&line) {
                Ok(event) => event,
                Err(error) => {
                    failures.push(LedgerFailure::new(
                        line_number,
                        "invalid_json",
                        error.to_string(),
                    ));
                    break;
                }
            };

            if event.sequence != expected_sequence {
                failures.push(LedgerFailure::new(
                    line_number,
                    "sequence_gap",
                    format!(
                        "expected sequence {}, found {}",
                        expected_sequence, event.sequence
                    ),
                ));
            }

            if event.previous_hash != previous_hash {
                failures.push(LedgerFailure::new(
                    line_number,
                    "previous_hash_mismatch",
                    "event does not point to the previous ledger hash",
                ));
            }

            if !event.has_valid_hash()? {
                failures.push(LedgerFailure::new(
                    line_number,
                    "hash_mismatch",
                    "event content does not match its stored hash",
                ));
            }

            expected_sequence = event.sequence.saturating_add(1);
            previous_hash = Some(event.hash.clone());
            last_hash = Some(event.hash);
            events += 1;

            if !failures.is_empty() {
                break;
            }
        }

        Ok(LedgerVerification {
            valid: failures.is_empty(),
            events,
            last_hash,
            failures,
        })
    }

    fn append_event_line(&self, event: &MissionEvent) -> Result<(), LedgerError> {
        self.append_event_lines(std::slice::from_ref(event))
    }

    fn append_event_lines(&self, events: &[MissionEvent]) -> Result<(), LedgerError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(&self.path)?;
        for event in events {
            serde_json::to_writer(&mut file, event)?;
            file.write_all(b"\n")?;
        }
        file.sync_data()?;
        Ok(())
    }
}

fn validate_import_event(
    event: &MissionEvent,
    expected_sequence: u64,
    previous_hash: &Option<String>,
    policy: &AdmissionPolicy,
) -> Result<(), LedgerError> {
    if event.sequence != expected_sequence {
        return Err(LedgerError::InvalidImportedEvent(format!(
            "expected sequence {}, found {}",
            expected_sequence, event.sequence
        )));
    }
    if &event.previous_hash != previous_hash {
        return Err(LedgerError::InvalidImportedEvent(format!(
            "event {} previous hash does not match target ledger",
            event.sequence
        )));
    }
    if !event.has_valid_hash()? {
        return Err(LedgerError::InvalidImportedEvent(format!(
            "event {} hash does not match content",
            event.sequence
        )));
    }

    let request = CommandRequest::new(
        event.actor.clone(),
        event.action,
        event.subject.clone(),
        event.priority,
        event.payload.clone(),
    );
    if let Some(attestation) = &event.attestation {
        SignedCommand {
            schema: attestation.schema,
            request: request.clone(),
            attestation: attestation.clone(),
        }
        .verify()?;
    }
    let decision = policy.evaluate(&request);
    if !decision.allowed {
        return Err(LedgerError::PolicyDenied(decision));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerVerification {
    pub valid: bool,
    pub events: usize,
    pub last_hash: Option<String>,
    pub failures: Vec<LedgerFailure>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerFailure {
    pub line: usize,
    pub code: String,
    pub detail: String,
}

impl LedgerFailure {
    fn new(line: usize, code: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            line,
            code: code.into(),
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppendVerifiedReport {
    pub appended: usize,
    pub last_hash: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error("ledger I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("ledger JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("event hash failed: {0}")]
    EventHash(#[from] EventHashError),
    #[error("identity verification failed: {0}")]
    Identity(#[from] IdentityError),
    #[error("operator registry authorization failed: {0}")]
    Registry(#[from] RegistryError),
    #[error("mission policy denied command: {0:?}")]
    PolicyDenied(PolicyDecision),
    #[error("ledger is corrupt: {0:?}")]
    LedgerCorrupt(LedgerVerification),
    #[error("imported event is invalid: {0}")]
    InvalidImportedEvent(String),
    #[error("payload is too large: {actual} bytes exceeds {limit} bytes")]
    PayloadTooLarge { actual: usize, limit: usize },
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::json;
    use tempfile::tempdir;

    use crate::event::{Action, Actor, Priority, Role};

    use super::*;

    #[test]
    fn appends_and_verifies_hash_chain() {
        let dir = tempdir().unwrap();
        let ledger = MissionLedger::open(dir.path().join("mission.agl"));

        let first = ledger
            .append(CommandRequest::new(
                Actor::new("kernel", Role::System),
                Action::OpenMission,
                "flood-watch",
                Priority::Elevated,
                json!({"mission": "flood-watch"}),
            ))
            .unwrap();
        let second = ledger
            .append(CommandRequest::new(
                Actor::new("lead", Role::IncidentCommander),
                Action::DeclareIncident,
                "river-east",
                Priority::Critical,
                json!({"water_level_m": 5.2}),
            ))
            .unwrap();

        assert_eq!(first.sequence, 0);
        assert_eq!(second.sequence, 1);
        assert_eq!(second.previous_hash.as_deref(), Some(first.hash.as_str()));
        assert!(ledger.verify().unwrap().valid);
    }

    #[test]
    fn detects_tampered_event_content() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("mission.agl");
        let ledger = MissionLedger::open(&path);
        ledger
            .append(CommandRequest::new(
                Actor::new("kernel", Role::System),
                Action::OpenMission,
                "mission-a",
                Priority::Elevated,
                json!({"mission": "mission-a"}),
            ))
            .unwrap();

        let original = fs::read_to_string(&path).unwrap();
        fs::write(&path, original.replace("mission-a", "mission-b")).unwrap();

        let verification = ledger.verify().unwrap();
        assert!(!verification.valid);
        assert_eq!(verification.failures[0].code, "hash_mismatch");
    }

    #[test]
    fn refuses_policy_denied_append() {
        let dir = tempdir().unwrap();
        let ledger = MissionLedger::open(dir.path().join("mission.agl"));
        let error = ledger
            .append(CommandRequest::new(
                Actor::new("observer", Role::Observer),
                Action::DispatchTeam,
                "sector-7",
                Priority::Elevated,
                json!({"team": "alpha"}),
            ))
            .unwrap_err();

        assert!(matches!(error, LedgerError::PolicyDenied(_)));
        assert_eq!(ledger.load_events().unwrap().len(), 0);
    }

    #[test]
    fn appends_signed_command_with_attestation() {
        let dir = tempdir().unwrap();
        let ledger = MissionLedger::open(dir.path().join("mission.agl"));
        let keypair = crate::identity::OperatorKeypair::generate("lead", Role::IncidentCommander);
        let request = CommandRequest::new(
            Actor::from(keypair.identity()),
            Action::DeclareIncident,
            "river-east",
            Priority::Critical,
            json!({"water_level_m": 5.2}),
        );

        let event = ledger
            .append_signed(keypair.sign_request(request).unwrap())
            .unwrap();

        assert!(event.attestation.is_some());
        assert!(ledger.verify().unwrap().valid);
    }

    #[test]
    fn appends_signed_command_with_registry_authorization() {
        let dir = tempdir().unwrap();
        let ledger = MissionLedger::open(dir.path().join("mission.agl"));
        let keypair = crate::identity::OperatorKeypair::generate("lead", Role::IncidentCommander);
        let mut registry = crate::identity::OperatorRegistry::new("local");
        registry.enroll(keypair.identity().clone(), "root").unwrap();
        let request = CommandRequest::new(
            Actor::from(keypair.identity()),
            Action::DeclareIncident,
            "river-east",
            Priority::Critical,
            json!({"water_level_m": 5.2}),
        );

        let event = ledger
            .append_signed_with_registry(keypair.sign_request(request).unwrap(), &registry)
            .unwrap();

        assert!(event.attestation.is_some());
        assert!(ledger.verify().unwrap().valid);
    }

    #[test]
    fn appends_verified_imported_events_without_rehashing() {
        let dir = tempdir().unwrap();
        let source = MissionLedger::open(dir.path().join("source.agl"));
        let target = MissionLedger::open(dir.path().join("target.agl"));
        let first = source
            .append(CommandRequest::new(
                Actor::new("kernel", Role::System),
                Action::OpenMission,
                "mission-a",
                Priority::Elevated,
                json!({"mission": "mission-a"}),
            ))
            .unwrap();
        source
            .append(CommandRequest::new(
                Actor::new("operator", Role::Operator),
                Action::AnnotateSituation,
                "sector-7",
                Priority::Elevated,
                json!({"note": "field check"}),
            ))
            .unwrap();
        std::fs::copy(source.path(), target.path()).unwrap();
        let third = source
            .append(CommandRequest::new(
                Actor::new("operator", Role::Operator),
                Action::RecordObservation,
                "sector-7",
                Priority::Routine,
                json!({"water_level_m": 5.1}),
            ))
            .unwrap();
        let incoming = source.load_events().unwrap()[2..].to_vec();

        let report = target.append_verified_events(&incoming).unwrap();

        let target_events = target.load_events().unwrap();
        assert_eq!(first.hash, target_events[0].hash);
        assert_eq!(third.hash, target_events[2].hash);
        assert_eq!(report.appended, 1);
        assert!(target.verify().unwrap().valid);
    }

    #[test]
    fn registry_authorization_blocks_unenrolled_signed_append() {
        let dir = tempdir().unwrap();
        let ledger = MissionLedger::open(dir.path().join("mission.agl"));
        let keypair = crate::identity::OperatorKeypair::generate("lead", Role::IncidentCommander);
        let registry = crate::identity::OperatorRegistry::new("local");
        let request = CommandRequest::new(
            Actor::from(keypair.identity()),
            Action::DeclareIncident,
            "river-east",
            Priority::Critical,
            json!({"water_level_m": 5.2}),
        );

        let error = ledger
            .append_signed_with_registry(keypair.sign_request(request).unwrap(), &registry)
            .unwrap_err();

        assert!(matches!(error, LedgerError::Registry(_)));
        assert_eq!(ledger.load_events().unwrap().len(), 0);
    }
}
