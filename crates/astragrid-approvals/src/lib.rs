use std::{
    collections::BTreeMap,
    fmt, fs,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    str::FromStr,
};

use astragrid_core::CommandRequest;
use astragrid_workflow::{CommandDraft, DraftStatus};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

const APPROVAL_SCHEMA: u16 = 1;

#[derive(Debug, Clone)]
pub struct ApprovalLog {
    path: PathBuf,
}

impl ApprovalLog {
    pub fn open(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn submit_draft(
        &self,
        draft: CommandDraft,
        requested_by: impl Into<String>,
    ) -> Result<ApprovalItem, ApprovalError> {
        validate_ready_draft(&draft)?;
        let requested_by = normalize_actor(requested_by)?;
        let draft_hash = draft_hash(&draft)?;
        let draft_id = format!("agdr_{}", Uuid::now_v7().simple());
        self.append_record(ApprovalRecordInput {
            actor: requested_by,
            action: ApprovalAction::SubmitDraft,
            draft_id: draft_id.clone(),
            draft_hash,
            draft: Some(draft),
            reason: None,
            ledger_event_hash: None,
        })?;
        self.get_item(&draft_id)
    }

    pub fn approve(
        &self,
        draft_id: &str,
        reviewed_by: impl Into<String>,
        reason: Option<String>,
    ) -> Result<ApprovalItem, ApprovalError> {
        let item = self.get_item(draft_id)?;
        require_status(&item, ApprovalStatus::Pending)?;
        self.append_record(ApprovalRecordInput {
            actor: normalize_actor(reviewed_by)?,
            action: ApprovalAction::ApproveDraft,
            draft_id: draft_id.to_owned(),
            draft_hash: item.draft_hash,
            draft: None,
            reason: clean_optional_reason(reason),
            ledger_event_hash: None,
        })?;
        self.get_item(draft_id)
    }

    pub fn reject(
        &self,
        draft_id: &str,
        reviewed_by: impl Into<String>,
        reason: Option<String>,
    ) -> Result<ApprovalItem, ApprovalError> {
        let item = self.get_item(draft_id)?;
        require_status(&item, ApprovalStatus::Pending)?;
        self.append_record(ApprovalRecordInput {
            actor: normalize_actor(reviewed_by)?,
            action: ApprovalAction::RejectDraft,
            draft_id: draft_id.to_owned(),
            draft_hash: item.draft_hash,
            draft: None,
            reason: clean_optional_reason(reason),
            ledger_event_hash: None,
        })?;
        self.get_item(draft_id)
    }

    pub fn mark_executed(
        &self,
        draft_id: &str,
        executed_by: impl Into<String>,
        ledger_event_hash: impl Into<String>,
    ) -> Result<ApprovalItem, ApprovalError> {
        let item = self.get_item(draft_id)?;
        require_status(&item, ApprovalStatus::Approved)?;
        let ledger_event_hash = ledger_event_hash.into();
        if ledger_event_hash.trim().is_empty() {
            return Err(ApprovalError::EmptyLedgerEventHash);
        }
        self.append_record(ApprovalRecordInput {
            actor: normalize_actor(executed_by)?,
            action: ApprovalAction::MarkExecuted,
            draft_id: draft_id.to_owned(),
            draft_hash: item.draft_hash,
            draft: None,
            reason: None,
            ledger_event_hash: Some(ledger_event_hash),
        })?;
        self.get_item(draft_id)
    }

    pub fn approved_request(&self, draft_id: &str) -> Result<CommandRequest, ApprovalError> {
        let item = self.get_item(draft_id)?;
        require_status(&item, ApprovalStatus::Approved)?;
        item.draft
            .request
            .clone()
            .ok_or(ApprovalError::MissingDraftRequest)
    }

    pub fn get_item(&self, draft_id: &str) -> Result<ApprovalItem, ApprovalError> {
        self.list_items()?
            .into_iter()
            .find(|item| item.id == draft_id)
            .ok_or_else(|| ApprovalError::NotFound(draft_id.to_owned()))
    }

    pub fn list_items(&self) -> Result<Vec<ApprovalItem>, ApprovalError> {
        let verification = self.verify()?;
        if !verification.valid {
            return Err(ApprovalError::Corrupt(verification));
        }
        materialize(self.load_records()?)
    }

    pub fn verify(&self) -> Result<ApprovalVerification, ApprovalError> {
        if !self.path.exists() {
            return Ok(ApprovalVerification {
                valid: true,
                records: 0,
                last_hash: None,
                failures: Vec::new(),
            });
        }

        let file = File::open(&self.path)?;
        let reader = BufReader::new(file);
        let mut expected_sequence = 0_u64;
        let mut previous_hash: Option<String> = None;
        let mut records = 0_usize;
        let mut last_hash = None;
        let mut failures = Vec::new();

        for (index, line) in reader.lines().enumerate() {
            let line_number = index + 1;
            let line = line?;
            if line.trim().is_empty() {
                failures.push(ApprovalFailure::new(
                    line_number,
                    "blank_line",
                    "blank lines are not allowed inside the approval log",
                ));
                break;
            }

            let record = match serde_json::from_str::<ApprovalRecord>(&line) {
                Ok(record) => record,
                Err(error) => {
                    failures.push(ApprovalFailure::new(
                        line_number,
                        "invalid_json",
                        error.to_string(),
                    ));
                    break;
                }
            };

            if record.schema != APPROVAL_SCHEMA {
                failures.push(ApprovalFailure::new(
                    line_number,
                    "unsupported_schema",
                    format!("unsupported approval schema {}", record.schema),
                ));
            }
            if record.sequence != expected_sequence {
                failures.push(ApprovalFailure::new(
                    line_number,
                    "sequence_gap",
                    format!(
                        "expected sequence {}, found {}",
                        expected_sequence, record.sequence
                    ),
                ));
            }
            if record.previous_hash != previous_hash {
                failures.push(ApprovalFailure::new(
                    line_number,
                    "previous_hash_mismatch",
                    "record does not point to the previous approval hash",
                ));
            }
            if !record.has_valid_hash()? {
                failures.push(ApprovalFailure::new(
                    line_number,
                    "hash_mismatch",
                    "record content does not match its stored hash",
                ));
            }
            if let Some(draft) = &record.draft
                && draft_hash(draft)? != record.draft_hash
            {
                failures.push(ApprovalFailure::new(
                    line_number,
                    "draft_hash_mismatch",
                    "embedded draft does not match the recorded draft hash",
                ));
            }

            expected_sequence = record.sequence.saturating_add(1);
            previous_hash = Some(record.hash.clone());
            last_hash = Some(record.hash);
            records += 1;

            if !failures.is_empty() {
                break;
            }
        }

        Ok(ApprovalVerification {
            valid: failures.is_empty(),
            records,
            last_hash,
            failures,
        })
    }

    fn append_record(&self, input: ApprovalRecordInput) -> Result<ApprovalRecord, ApprovalError> {
        let verification = self.verify()?;
        if !verification.valid {
            return Err(ApprovalError::Corrupt(verification));
        }
        let records = self.load_records()?;
        materialize(records.clone())?;

        let (sequence, previous_hash) = match records.last() {
            Some(last) => (last.sequence + 1, Some(last.hash.clone())),
            None => (0, None),
        };
        let record = ApprovalRecord::new(sequence, previous_hash, input)?;
        self.append_record_line(&record)?;
        Ok(record)
    }

    fn load_records(&self) -> Result<Vec<ApprovalRecord>, ApprovalError> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let file = File::open(&self.path)?;
        let reader = BufReader::new(file);
        let mut records = Vec::new();
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            records.push(serde_json::from_str(&line)?);
        }
        Ok(records)
    }

    fn append_record_line(&self, record: &ApprovalRecord) -> Result<(), ApprovalError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(&self.path)?;
        serde_json::to_writer(&mut file, record)?;
        file.write_all(b"\n")?;
        file.sync_data()?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalRecord {
    pub schema: u16,
    pub sequence: u64,
    pub id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    pub occurred_at: OffsetDateTime,
    pub actor: String,
    pub action: ApprovalAction,
    pub draft_id: String,
    pub draft_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draft: Option<CommandDraft>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ledger_event_hash: Option<String>,
    pub previous_hash: Option<String>,
    pub hash: String,
}

impl ApprovalRecord {
    fn new(
        sequence: u64,
        previous_hash: Option<String>,
        input: ApprovalRecordInput,
    ) -> Result<Self, ApprovalError> {
        let mut record = Self {
            schema: APPROVAL_SCHEMA,
            sequence,
            id: Uuid::now_v7(),
            occurred_at: OffsetDateTime::now_utc(),
            actor: input.actor,
            action: input.action,
            draft_id: input.draft_id,
            draft_hash: input.draft_hash,
            draft: input.draft,
            reason: input.reason,
            ledger_event_hash: input.ledger_event_hash,
            previous_hash,
            hash: String::new(),
        };
        record.hash = record.compute_hash()?;
        Ok(record)
    }

    pub fn compute_hash(&self) -> Result<String, ApprovalError> {
        #[derive(Serialize)]
        struct HashInput<'a> {
            schema: u16,
            sequence: u64,
            id: Uuid,
            occurred_at: String,
            actor: &'a str,
            action: ApprovalAction,
            draft_id: &'a str,
            draft_hash: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            draft: Option<Value>,
            #[serde(skip_serializing_if = "Option::is_none")]
            reason: &'a Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            ledger_event_hash: &'a Option<String>,
            previous_hash: &'a Option<String>,
        }

        let draft = self.draft.as_ref().map(canonical_json_value).transpose()?;
        let input = HashInput {
            schema: self.schema,
            sequence: self.sequence,
            id: self.id,
            occurred_at: self.occurred_at.format(&Rfc3339)?,
            actor: &self.actor,
            action: self.action,
            draft_id: &self.draft_id,
            draft_hash: &self.draft_hash,
            draft,
            reason: &self.reason,
            ledger_event_hash: &self.ledger_event_hash,
            previous_hash: &self.previous_hash,
        };
        Ok(blake3::hash(&serde_json::to_vec(&input)?)
            .to_hex()
            .to_string())
    }

    pub fn has_valid_hash(&self) -> Result<bool, ApprovalError> {
        Ok(self.compute_hash()? == self.hash)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalAction {
    SubmitDraft,
    ApproveDraft,
    RejectDraft,
    MarkExecuted,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalItem {
    pub id: String,
    pub draft_hash: String,
    pub status: ApprovalStatus,
    pub draft: CommandDraft,
    pub submitted_by: String,
    #[serde(with = "time::serde::rfc3339")]
    pub submitted_at: OffsetDateTime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewed_by: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub reviewed_at: Option<OffsetDateTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executed_by: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub executed_at: Option<OffsetDateTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ledger_event_hash: Option<String>,
    pub last_record_hash: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Rejected,
    Executed,
}

impl fmt::Display for ApprovalStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ApprovalStatus::Pending => "pending",
            ApprovalStatus::Approved => "approved",
            ApprovalStatus::Rejected => "rejected",
            ApprovalStatus::Executed => "executed",
        })
    }
}

impl FromStr for ApprovalStatus {
    type Err = ApprovalStatusParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input.trim().to_ascii_lowercase().as_str() {
            "pending" => Ok(Self::Pending),
            "approved" => Ok(Self::Approved),
            "rejected" => Ok(Self::Rejected),
            "executed" => Ok(Self::Executed),
            _ => Err(ApprovalStatusParseError(input.to_owned())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalStatusParseError(String);

impl fmt::Display for ApprovalStatusParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown approval status '{}'", self.0)
    }
}

impl std::error::Error for ApprovalStatusParseError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalVerification {
    pub valid: bool,
    pub records: usize,
    pub last_hash: Option<String>,
    pub failures: Vec<ApprovalFailure>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalFailure {
    pub line: usize,
    pub code: String,
    pub detail: String,
}

impl ApprovalFailure {
    fn new(line: usize, code: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            line,
            code: code.into(),
            detail: detail.into(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ApprovalError {
    #[error("approval log I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("approval log JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("approval timestamp formatting failed: {0}")]
    TimeFormat(#[from] time::error::Format),
    #[error("approval log is corrupt: {0:?}")]
    Corrupt(ApprovalVerification),
    #[error("draft {0} was not found")]
    NotFound(String),
    #[error("draft status must be ready before approval submission")]
    DraftNotReady,
    #[error("draft has no command request")]
    MissingDraftRequest,
    #[error("approval actor is required")]
    EmptyActor,
    #[error("ledger event hash is required")]
    EmptyLedgerEventHash,
    #[error("draft {id} is {actual}, expected {expected}")]
    InvalidTransition {
        id: String,
        actual: ApprovalStatus,
        expected: ApprovalStatus,
    },
    #[error("approval log semantic integrity failed: {0}")]
    Integrity(String),
}

struct ApprovalRecordInput {
    actor: String,
    action: ApprovalAction,
    draft_id: String,
    draft_hash: String,
    draft: Option<CommandDraft>,
    reason: Option<String>,
    ledger_event_hash: Option<String>,
}

fn materialize(records: Vec<ApprovalRecord>) -> Result<Vec<ApprovalItem>, ApprovalError> {
    let mut items = BTreeMap::<String, ApprovalItem>::new();
    for record in records {
        match record.action {
            ApprovalAction::SubmitDraft => {
                if items.contains_key(&record.draft_id) {
                    return Err(ApprovalError::Integrity(format!(
                        "draft {} was submitted more than once",
                        record.draft_id
                    )));
                }
                let draft = record
                    .draft
                    .clone()
                    .ok_or_else(|| ApprovalError::Integrity("submit record has no draft".into()))?;
                validate_ready_draft(&draft)?;
                if draft_hash(&draft)? != record.draft_hash {
                    return Err(ApprovalError::Integrity(format!(
                        "draft {} hash does not match submit record",
                        record.draft_id
                    )));
                }
                items.insert(
                    record.draft_id.clone(),
                    ApprovalItem {
                        id: record.draft_id,
                        draft_hash: record.draft_hash,
                        status: ApprovalStatus::Pending,
                        draft,
                        submitted_by: record.actor,
                        submitted_at: record.occurred_at,
                        reviewed_by: None,
                        reviewed_at: None,
                        review_reason: None,
                        executed_by: None,
                        executed_at: None,
                        ledger_event_hash: None,
                        last_record_hash: record.hash,
                    },
                );
            }
            ApprovalAction::ApproveDraft => {
                let item = item_for_transition(&mut items, &record, ApprovalStatus::Pending)?;
                item.status = ApprovalStatus::Approved;
                item.reviewed_by = Some(record.actor);
                item.reviewed_at = Some(record.occurred_at);
                item.review_reason = record.reason;
                item.last_record_hash = record.hash;
            }
            ApprovalAction::RejectDraft => {
                let item = item_for_transition(&mut items, &record, ApprovalStatus::Pending)?;
                item.status = ApprovalStatus::Rejected;
                item.reviewed_by = Some(record.actor);
                item.reviewed_at = Some(record.occurred_at);
                item.review_reason = record.reason;
                item.last_record_hash = record.hash;
            }
            ApprovalAction::MarkExecuted => {
                let item = item_for_transition(&mut items, &record, ApprovalStatus::Approved)?;
                item.status = ApprovalStatus::Executed;
                item.executed_by = Some(record.actor);
                item.executed_at = Some(record.occurred_at);
                item.ledger_event_hash = record.ledger_event_hash;
                item.last_record_hash = record.hash;
            }
        }
    }
    Ok(items.into_values().collect())
}

fn item_for_transition<'a>(
    items: &'a mut BTreeMap<String, ApprovalItem>,
    record: &ApprovalRecord,
    expected: ApprovalStatus,
) -> Result<&'a mut ApprovalItem, ApprovalError> {
    let item = items.get_mut(&record.draft_id).ok_or_else(|| {
        ApprovalError::Integrity(format!("draft {} has no submit record", record.draft_id))
    })?;
    require_status(item, expected)?;
    if item.draft_hash != record.draft_hash {
        return Err(ApprovalError::Integrity(format!(
            "draft {} transition hash does not match submit hash",
            record.draft_id
        )));
    }
    Ok(item)
}

fn require_status(item: &ApprovalItem, expected: ApprovalStatus) -> Result<(), ApprovalError> {
    if item.status != expected {
        return Err(ApprovalError::InvalidTransition {
            id: item.id.clone(),
            actual: item.status,
            expected,
        });
    }
    Ok(())
}

fn validate_ready_draft(draft: &CommandDraft) -> Result<(), ApprovalError> {
    if draft.status != DraftStatus::Ready {
        return Err(ApprovalError::DraftNotReady);
    }
    if draft.request.is_none() {
        return Err(ApprovalError::MissingDraftRequest);
    }
    Ok(())
}

fn draft_hash(draft: &CommandDraft) -> Result<String, ApprovalError> {
    let value = canonical_json_value(draft)?;
    Ok(blake3::hash(&serde_json::to_vec(&value)?)
        .to_hex()
        .to_string())
}

fn canonical_json_value<T: Serialize>(value: &T) -> Result<Value, ApprovalError> {
    Ok(canonicalize_value(&serde_json::to_value(value)?))
}

fn canonicalize_value(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(canonicalize_value).collect()),
        Value::Object(object) => {
            let mut keys = object.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            let mut normalized = Map::new();
            for key in keys {
                if let Some(value) = object.get(key) {
                    normalized.insert(key.clone(), canonicalize_value(value));
                }
            }
            Value::Object(normalized)
        }
        primitive => primitive.clone(),
    }
}

fn normalize_actor(actor: impl Into<String>) -> Result<String, ApprovalError> {
    let actor = actor.into();
    if actor.trim().is_empty() {
        return Err(ApprovalError::EmptyActor);
    }
    Ok(actor)
}

fn clean_optional_reason(reason: Option<String>) -> Option<String> {
    reason.and_then(|value| {
        let value = value.trim().to_owned();
        (!value.is_empty()).then_some(value)
    })
}

#[cfg(test)]
mod tests {
    use astragrid_core::{Action, Actor, CommandRequest, PolicyDecision, Priority, Role};
    use serde_json::json;
    use tempfile::tempdir;

    use super::*;

    fn ready_draft() -> CommandDraft {
        let request = CommandRequest::new(
            Actor::new("lead", Role::IncidentCommander),
            Action::DeclareIncident,
            "river-east",
            Priority::Critical,
            json!({"evidence_bundle": "abc"}),
        );
        CommandDraft {
            status: DraftStatus::Ready,
            reason: "verified".to_owned(),
            request: Some(request),
            policy: Some(PolicyDecision {
                allowed: true,
                reason: "allowed".to_owned(),
                required_role: Role::IncidentCommander,
            }),
        }
    }

    #[test]
    fn records_approval_lifecycle_as_hash_chain() {
        let dir = tempdir().unwrap();
        let log = ApprovalLog::open(dir.path().join("approvals.agl"));

        let submitted = log.submit_draft(ready_draft(), "planner").unwrap();
        let approved = log
            .approve(
                &submitted.id,
                "commander",
                Some("field check passed".to_owned()),
            )
            .unwrap();
        let executed = log
            .mark_executed(&submitted.id, "commander", "event-hash-1")
            .unwrap();
        let verification = log.verify().unwrap();

        assert_eq!(submitted.status, ApprovalStatus::Pending);
        assert_eq!(approved.status, ApprovalStatus::Approved);
        assert_eq!(executed.status, ApprovalStatus::Executed);
        assert!(verification.valid);
        assert_eq!(verification.records, 3);
        assert_eq!(
            log.approved_request(&submitted.id).unwrap_err().to_string(),
            format!("draft {} is executed, expected approved", submitted.id)
        );
    }

    #[test]
    fn rejects_blocked_draft_submission() {
        let dir = tempdir().unwrap();
        let log = ApprovalLog::open(dir.path().join("approvals.agl"));
        let draft = CommandDraft {
            status: DraftStatus::Blocked,
            reason: "low confidence".to_owned(),
            request: None,
            policy: None,
        };

        assert!(matches!(
            log.submit_draft(draft, "planner"),
            Err(ApprovalError::DraftNotReady)
        ));
    }

    #[test]
    fn rejects_invalid_status_transition() {
        let dir = tempdir().unwrap();
        let log = ApprovalLog::open(dir.path().join("approvals.agl"));
        let submitted = log.submit_draft(ready_draft(), "planner").unwrap();
        log.reject(&submitted.id, "commander", None).unwrap();

        assert!(matches!(
            log.approve(&submitted.id, "commander", None),
            Err(ApprovalError::InvalidTransition {
                actual: ApprovalStatus::Rejected,
                expected: ApprovalStatus::Pending,
                ..
            })
        ));
    }
}
