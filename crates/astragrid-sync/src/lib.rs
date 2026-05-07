use std::{
    cmp::Ordering,
    fs,
    path::{Path, PathBuf},
    process,
};

use astragrid_core::{AppendVerifiedReport, LedgerVerification, MissionEvent, MissionLedger};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncStatus {
    Identical,
    LeftAhead,
    RightAhead,
    Diverged,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncConflict {
    pub sequence: u64,
    pub left_hash: Option<String>,
    pub right_hash: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncPlan {
    pub status: SyncStatus,
    pub common_prefix_events: usize,
    pub left_events: usize,
    pub right_events: usize,
    pub left_missing_from_right: Vec<String>,
    pub right_missing_from_left: Vec<String>,
    pub conflicts: Vec<SyncConflict>,
}

impl SyncPlan {
    pub fn from_ledgers(left: &MissionLedger, right: &MissionLedger) -> Result<Self, SyncError> {
        let left_verification = left.verify()?;
        if !left_verification.valid {
            return Err(SyncError::InvalidLeft(left_verification));
        }
        let right_verification = right.verify()?;
        if !right_verification.valid {
            return Err(SyncError::InvalidRight(right_verification));
        }
        Self::from_events(&left.load_events()?, &right.load_events()?)
    }

    pub fn from_events(left: &[MissionEvent], right: &[MissionEvent]) -> Result<Self, SyncError> {
        let common_prefix_events = left
            .iter()
            .zip(right.iter())
            .take_while(|(left, right)| left.hash == right.hash)
            .count();

        let status = if left.len() == right.len() && common_prefix_events == left.len() {
            SyncStatus::Identical
        } else if common_prefix_events == right.len() {
            SyncStatus::LeftAhead
        } else if common_prefix_events == left.len() {
            SyncStatus::RightAhead
        } else {
            SyncStatus::Diverged
        };

        let mut conflicts = Vec::new();
        if status == SyncStatus::Diverged {
            let left_event = left.get(common_prefix_events);
            let right_event = right.get(common_prefix_events);
            conflicts.push(SyncConflict {
                sequence: u64::try_from(common_prefix_events)
                    .map_err(|_| SyncError::SequenceOverflow)?,
                left_hash: left_event.map(|event| event.hash.clone()),
                right_hash: right_event.map(|event| event.hash.clone()),
                detail: "ledgers have different events at the first non-shared sequence".to_owned(),
            });
        }

        Ok(Self {
            status,
            common_prefix_events,
            left_events: left.len(),
            right_events: right.len(),
            left_missing_from_right: left
                .iter()
                .skip(common_prefix_events)
                .map(|event| event.hash.clone())
                .collect(),
            right_missing_from_left: right
                .iter()
                .skip(common_prefix_events)
                .map(|event| event.hash.clone())
                .collect(),
            conflicts,
        })
    }
}

pub fn apply_append_only(
    target: &MissionLedger,
    source: &MissionLedger,
) -> Result<SyncApplyReport, SyncError> {
    let target_verification = target.verify()?;
    if !target_verification.valid {
        return Err(SyncError::InvalidLeft(target_verification));
    }
    let source_verification = source.verify()?;
    if !source_verification.valid {
        return Err(SyncError::InvalidRight(source_verification));
    }
    let target_events = target.load_events()?;
    let source_events = source.load_events()?;
    apply_append_only_events(target, &target_events, &source_events)
}

pub fn apply_append_only_events(
    target: &MissionLedger,
    target_events: &[MissionEvent],
    source_events: &[MissionEvent],
) -> Result<SyncApplyReport, SyncError> {
    let plan = SyncPlan::from_events(target_events, source_events)?;
    match plan.status {
        SyncStatus::Identical | SyncStatus::LeftAhead => Ok(SyncApplyReport {
            plan,
            append: AppendVerifiedReport {
                appended: 0,
                last_hash: target_events.last().map(|event| event.hash.clone()),
            },
        }),
        SyncStatus::RightAhead => {
            let missing = &source_events[plan.common_prefix_events..];
            let append = target.append_verified_events(missing)?;
            Ok(SyncApplyReport { plan, append })
        }
        SyncStatus::Diverged => Err(SyncError::Diverged(plan)),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncApplyReport {
    pub plan: SyncPlan,
    pub append: AppendVerifiedReport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MergeSource {
    Both,
    Left,
    Right,
}

impl MergeSource {
    fn sort_label(self) -> &'static str {
        match self {
            Self::Both => "both",
            Self::Left => "left",
            Self::Right => "right",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerMergeOptions {
    pub overwrite: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerMergeReport {
    pub schema_version: u16,
    pub status: SyncStatus,
    pub policy: String,
    pub common_prefix_events: usize,
    pub left_events: usize,
    pub right_events: usize,
    pub merged_events: usize,
    pub preserved_events: usize,
    pub replayed_events: usize,
    pub output_valid: bool,
    pub output_last_hash: Option<String>,
    pub conflicts: Vec<SyncConflict>,
    pub proof: Vec<MergedEventProof>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergedEventProof {
    pub source: MergeSource,
    pub source_sequence: u64,
    pub source_hash: String,
    pub merged_sequence: u64,
    pub merged_hash: String,
    pub replayed: bool,
    pub signed: bool,
    pub action: String,
    pub subject: String,
}

pub fn merge_ledgers_to_output(
    left: &MissionLedger,
    right: &MissionLedger,
    output: &MissionLedger,
    options: LedgerMergeOptions,
) -> Result<LedgerMergeReport, SyncError> {
    if same_existing_path(output.path(), left.path())
        || same_existing_path(output.path(), right.path())
    {
        return Err(SyncError::OutputMatchesInput(output.path().to_path_buf()));
    }
    prepare_output_path(output.path(), options.overwrite)?;

    let left_verification = left.verify()?;
    if !left_verification.valid {
        return Err(SyncError::InvalidLeft(left_verification));
    }
    let right_verification = right.verify()?;
    if !right_verification.valid {
        return Err(SyncError::InvalidRight(right_verification));
    }

    let left_events = left.load_events()?;
    let right_events = right.load_events()?;
    let plan = SyncPlan::from_events(&left_events, &right_events)?;
    let temp_path = temporary_merge_path(output.path())?;
    let temp_output = MissionLedger::open(&temp_path);
    let merge_result = build_merged_ledger(&plan, &left_events, &right_events, &temp_output);

    match merge_result {
        Ok(report) => {
            if report.merged_events == 0 {
                fs::write(&temp_path, b"")?;
            }
            if let Err(error) = finalize_output_path(&temp_path, output.path()) {
                let _ = fs::remove_file(&temp_path);
                return Err(error);
            }
            Ok(report)
        }
        Err(error) => {
            let _ = fs::remove_file(&temp_path);
            Err(error)
        }
    }
}

fn build_merged_ledger(
    plan: &SyncPlan,
    left_events: &[MissionEvent],
    right_events: &[MissionEvent],
    output: &MissionLedger,
) -> Result<LedgerMergeReport, SyncError> {
    let mut proof = Vec::new();
    let common = &left_events[..plan.common_prefix_events];
    if !common.is_empty() {
        output.append_verified_events(common)?;
        proof.extend(
            common
                .iter()
                .map(|event| proof_for_preserved_event(MergeSource::Both, event)),
        );
    }

    let mut preserved_events = common.len();
    let mut replayed_events = 0_usize;

    match plan.status {
        SyncStatus::Identical => {}
        SyncStatus::LeftAhead => {
            let suffix = &left_events[plan.common_prefix_events..];
            output.append_verified_events(suffix)?;
            preserved_events += suffix.len();
            proof.extend(
                suffix
                    .iter()
                    .map(|event| proof_for_preserved_event(MergeSource::Left, event)),
            );
        }
        SyncStatus::RightAhead => {
            let suffix = &right_events[plan.common_prefix_events..];
            output.append_verified_events(suffix)?;
            preserved_events += suffix.len();
            proof.extend(
                suffix
                    .iter()
                    .map(|event| proof_for_preserved_event(MergeSource::Right, event)),
            );
        }
        SyncStatus::Diverged => {
            let mut left_index = plan.common_prefix_events;
            let mut right_index = plan.common_prefix_events;
            let mut next_sequence =
                u64::try_from(common.len()).map_err(|_| SyncError::SequenceOverflow)?;
            let mut previous_hash = common.last().map(|event| event.hash.clone());

            while left_index < left_events.len() || right_index < right_events.len() {
                let (source, event) =
                    next_replay_source(left_events, right_events, left_index, right_index);
                match source {
                    MergeSource::Left => left_index += 1,
                    MergeSource::Right => right_index += 1,
                    MergeSource::Both => {
                        unreachable!("divergent replay never emits both-source events")
                    }
                }

                let merged = replay_event(event, next_sequence, previous_hash.clone())?;
                output.append_verified_events(std::slice::from_ref(&merged))?;
                proof.push(MergedEventProof {
                    source,
                    source_sequence: event.sequence,
                    source_hash: event.hash.clone(),
                    merged_sequence: merged.sequence,
                    merged_hash: merged.hash.clone(),
                    replayed: true,
                    signed: merged.attestation.is_some(),
                    action: merged.action.to_string(),
                    subject: merged.subject.clone(),
                });
                next_sequence = next_sequence.saturating_add(1);
                previous_hash = Some(merged.hash);
                replayed_events += 1;
            }
        }
    }

    let verification = output.verify()?;
    if !verification.valid {
        return Err(SyncError::MergedOutputInvalid(verification));
    }

    Ok(LedgerMergeReport {
        schema_version: 1,
        status: plan.status,
        policy: "common_prefix_preserved_then_branch_ordered_chronological_replay".to_owned(),
        common_prefix_events: plan.common_prefix_events,
        left_events: plan.left_events,
        right_events: plan.right_events,
        merged_events: verification.events,
        preserved_events,
        replayed_events,
        output_valid: verification.valid,
        output_last_hash: verification.last_hash,
        conflicts: plan.conflicts.clone(),
        proof,
    })
}

fn proof_for_preserved_event(source: MergeSource, event: &MissionEvent) -> MergedEventProof {
    MergedEventProof {
        source,
        source_sequence: event.sequence,
        source_hash: event.hash.clone(),
        merged_sequence: event.sequence,
        merged_hash: event.hash.clone(),
        replayed: false,
        signed: event.attestation.is_some(),
        action: event.action.to_string(),
        subject: event.subject.clone(),
    }
}

fn next_replay_source<'a>(
    left: &'a [MissionEvent],
    right: &'a [MissionEvent],
    left_index: usize,
    right_index: usize,
) -> (MergeSource, &'a MissionEvent) {
    match (left.get(left_index), right.get(right_index)) {
        (Some(left_event), Some(right_event)) => {
            if compare_replay_heads(left_event, right_event) != Ordering::Greater {
                (MergeSource::Left, left_event)
            } else {
                (MergeSource::Right, right_event)
            }
        }
        (Some(left_event), None) => (MergeSource::Left, left_event),
        (None, Some(right_event)) => (MergeSource::Right, right_event),
        (None, None) => unreachable!("caller guarantees at least one pending replay event"),
    }
}

fn compare_replay_heads(left: &MissionEvent, right: &MissionEvent) -> Ordering {
    left.occurred_at
        .cmp(&right.occurred_at)
        .then_with(|| left.sequence.cmp(&right.sequence))
        .then_with(|| left.hash.cmp(&right.hash))
        .then_with(|| {
            MergeSource::Left
                .sort_label()
                .cmp(MergeSource::Right.sort_label())
        })
}

fn replay_event(
    original: &MissionEvent,
    sequence: u64,
    previous_hash: Option<String>,
) -> Result<MissionEvent, SyncError> {
    let mut event = MissionEvent {
        sequence,
        id: original.id,
        occurred_at: original.occurred_at,
        actor: original.actor.clone(),
        action: original.action,
        subject: original.subject.clone(),
        priority: original.priority,
        payload: original.payload.clone(),
        attestation: original.attestation.clone(),
        previous_hash,
        hash: String::new(),
    };
    event.hash = event.compute_hash()?;
    Ok(event)
}

fn prepare_output_path(path: &Path, overwrite: bool) -> Result<(), SyncError> {
    if path.is_dir() {
        return Err(SyncError::OutputIsDirectory(path.to_path_buf()));
    }
    if path.exists() {
        let metadata = fs::metadata(path)?;
        if metadata.len() > 0 && !overwrite {
            return Err(SyncError::OutputExists(path.to_path_buf()));
        }
    }
    Ok(())
}

fn finalize_output_path(temp_path: &Path, output_path: &Path) -> Result<(), SyncError> {
    if output_path.exists() {
        fs::remove_file(output_path)?;
    }
    fs::rename(temp_path, output_path)?;
    Ok(())
}

fn temporary_merge_path(output_path: &Path) -> Result<PathBuf, SyncError> {
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let file_name = output_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("ledger");
    let parent = output_path.parent().unwrap_or_else(|| Path::new("."));
    for attempt in 0..1000_u16 {
        let candidate = parent.join(format!(
            ".{file_name}.merge-{}-{attempt}.tmp",
            process::id()
        ));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(SyncError::TemporaryPathExhausted(output_path.to_path_buf()))
}

fn same_existing_path(left: &Path, right: &Path) -> bool {
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => left == right,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("left ledger is invalid: {0:?}")]
    InvalidLeft(LedgerVerification),
    #[error("right ledger is invalid: {0:?}")]
    InvalidRight(LedgerVerification),
    #[error("ledger failed: {0}")]
    Ledger(#[from] astragrid_core::LedgerError),
    #[error("event hash failed: {0}")]
    EventHash(#[from] astragrid_core::event::EventHashError),
    #[error("ledgers diverged and cannot be applied automatically: {0:?}")]
    Diverged(SyncPlan),
    #[error("merge output path matches an input ledger: {0}")]
    OutputMatchesInput(PathBuf),
    #[error("merge output already exists and is not empty: {0}")]
    OutputExists(PathBuf),
    #[error("merge output path is a directory: {0}")]
    OutputIsDirectory(PathBuf),
    #[error("merged output ledger is invalid: {0:?}")]
    MergedOutputInvalid(LedgerVerification),
    #[error("could not allocate a temporary merge path near {0}")]
    TemporaryPathExhausted(PathBuf),
    #[error("sequence index exceeds u64")]
    SequenceOverflow,
    #[error("merge I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use astragrid_core::{Action, Actor, CommandRequest, MissionLedger, Priority, Role};
    use serde_json::json;
    use tempfile::tempdir;

    use super::*;

    fn append_open(ledger: &MissionLedger, mission: &str) {
        ledger
            .append(CommandRequest::new(
                Actor::new("kernel", Role::System),
                Action::OpenMission,
                mission,
                Priority::Elevated,
                json!({"mission": mission}),
            ))
            .unwrap();
    }

    #[test]
    fn detects_right_ahead_append_only_plan() {
        let dir = tempdir().unwrap();
        let left = MissionLedger::open(dir.path().join("left.agl"));
        let right = MissionLedger::open(dir.path().join("right.agl"));
        append_open(&left, "mission-a");
        std::fs::copy(left.path(), right.path()).unwrap();
        right
            .append(CommandRequest::new(
                Actor::new("operator", Role::Operator),
                Action::AnnotateSituation,
                "sector-7",
                Priority::Elevated,
                json!({"note": "field check"}),
            ))
            .unwrap();

        let plan = SyncPlan::from_ledgers(&left, &right).unwrap();

        assert_eq!(plan.status, SyncStatus::RightAhead);
        assert_eq!(plan.right_missing_from_left.len(), 1);
        assert!(plan.conflicts.is_empty());
    }

    #[test]
    fn detects_diverged_ledgers() {
        let dir = tempdir().unwrap();
        let left = MissionLedger::open(dir.path().join("left.agl"));
        let right = MissionLedger::open(dir.path().join("right.agl"));
        append_open(&left, "mission-a");
        std::fs::copy(left.path(), right.path()).unwrap();
        left.append(CommandRequest::new(
            Actor::new("operator", Role::Operator),
            Action::AnnotateSituation,
            "sector-left",
            Priority::Elevated,
            json!({"note": "left"}),
        ))
        .unwrap();
        right
            .append(CommandRequest::new(
                Actor::new("operator", Role::Operator),
                Action::AnnotateSituation,
                "sector-right",
                Priority::Elevated,
                json!({"note": "right"}),
            ))
            .unwrap();

        let plan = SyncPlan::from_ledgers(&left, &right).unwrap();

        assert_eq!(plan.status, SyncStatus::Diverged);
        assert_eq!(plan.conflicts.len(), 1);
    }

    #[test]
    fn applies_right_ahead_events_to_left_ledger() {
        let dir = tempdir().unwrap();
        let left = MissionLedger::open(dir.path().join("left.agl"));
        let right = MissionLedger::open(dir.path().join("right.agl"));
        append_open(&left, "mission-a");
        std::fs::copy(left.path(), right.path()).unwrap();
        let imported = right
            .append(CommandRequest::new(
                Actor::new("operator", Role::Operator),
                Action::AnnotateSituation,
                "sector-7",
                Priority::Elevated,
                json!({"note": "right"}),
            ))
            .unwrap();

        let report = apply_append_only(&left, &right).unwrap();
        let left_events = left.load_events().unwrap();

        assert_eq!(report.plan.status, SyncStatus::RightAhead);
        assert_eq!(report.append.appended, 1);
        assert_eq!(left_events.last().unwrap().hash, imported.hash);
        assert!(left.verify().unwrap().valid);
    }

    #[test]
    fn refuses_to_apply_diverged_ledgers() {
        let dir = tempdir().unwrap();
        let left = MissionLedger::open(dir.path().join("left.agl"));
        let right = MissionLedger::open(dir.path().join("right.agl"));
        append_open(&left, "mission-a");
        std::fs::copy(left.path(), right.path()).unwrap();
        left.append(CommandRequest::new(
            Actor::new("operator", Role::Operator),
            Action::AnnotateSituation,
            "sector-left",
            Priority::Elevated,
            json!({"note": "left"}),
        ))
        .unwrap();
        right
            .append(CommandRequest::new(
                Actor::new("operator", Role::Operator),
                Action::AnnotateSituation,
                "sector-right",
                Priority::Elevated,
                json!({"note": "right"}),
            ))
            .unwrap();

        assert!(matches!(
            apply_append_only(&left, &right),
            Err(SyncError::Diverged(plan)) if plan.status == SyncStatus::Diverged
        ));
    }

    #[test]
    fn merges_diverged_ledgers_with_replay_proof() {
        let dir = tempdir().unwrap();
        let left = MissionLedger::open(dir.path().join("left.agl"));
        let right = MissionLedger::open(dir.path().join("right.agl"));
        let output = MissionLedger::open(dir.path().join("merged.agl"));
        append_open(&left, "mission-a");
        std::fs::copy(left.path(), right.path()).unwrap();
        let left_event = left
            .append(CommandRequest::new(
                Actor::new("operator", Role::Operator),
                Action::AnnotateSituation,
                "sector-left",
                Priority::Elevated,
                json!({"note": "left"}),
            ))
            .unwrap();
        let right_event = right
            .append(CommandRequest::new(
                Actor::new("operator", Role::Operator),
                Action::RecordObservation,
                "sector-right",
                Priority::Routine,
                json!({"note": "right"}),
            ))
            .unwrap();

        let report =
            merge_ledgers_to_output(&left, &right, &output, LedgerMergeOptions::default()).unwrap();

        assert_eq!(report.status, SyncStatus::Diverged);
        assert_eq!(report.common_prefix_events, 1);
        assert_eq!(report.merged_events, 3);
        assert_eq!(report.preserved_events, 1);
        assert_eq!(report.replayed_events, 2);
        assert!(report.output_valid);
        assert_eq!(report.proof.len(), 3);
        assert!(!report.proof[0].replayed);
        assert_eq!(report.proof[0].source, MergeSource::Both);
        assert!(report.proof.iter().any(|proof| {
            proof.source == MergeSource::Left && proof.source_hash == left_event.hash
        }));
        assert!(report.proof.iter().any(|proof| {
            proof.source == MergeSource::Right && proof.source_hash == right_event.hash
        }));
        assert!(
            report
                .proof
                .iter()
                .any(|proof| { proof.replayed && proof.source_hash != proof.merged_hash })
        );
        assert!(output.verify().unwrap().valid);
    }

    #[test]
    fn merge_preserves_append_only_suffix_hashes() {
        let dir = tempdir().unwrap();
        let left = MissionLedger::open(dir.path().join("left.agl"));
        let right = MissionLedger::open(dir.path().join("right.agl"));
        let output = MissionLedger::open(dir.path().join("merged.agl"));
        append_open(&left, "mission-a");
        std::fs::copy(left.path(), right.path()).unwrap();
        let right_event = right
            .append(CommandRequest::new(
                Actor::new("operator", Role::Operator),
                Action::AnnotateSituation,
                "sector-right",
                Priority::Elevated,
                json!({"note": "right"}),
            ))
            .unwrap();

        let report =
            merge_ledgers_to_output(&left, &right, &output, LedgerMergeOptions::default()).unwrap();

        assert_eq!(report.status, SyncStatus::RightAhead);
        assert_eq!(report.merged_events, 2);
        assert_eq!(report.preserved_events, 2);
        assert_eq!(report.replayed_events, 0);
        assert_eq!(
            report.output_last_hash.as_deref(),
            Some(right_event.hash.as_str())
        );
        assert!(
            report
                .proof
                .iter()
                .any(|proof| proof.source == MergeSource::Right
                    && proof.source_hash == right_event.hash
                    && proof.merged_hash == right_event.hash
                    && !proof.replayed)
        );
    }

    #[test]
    fn merge_refuses_nonempty_output_without_overwrite() {
        let dir = tempdir().unwrap();
        let left = MissionLedger::open(dir.path().join("left.agl"));
        let right = MissionLedger::open(dir.path().join("right.agl"));
        let output_path = dir.path().join("merged.agl");
        let output = MissionLedger::open(&output_path);
        append_open(&left, "mission-a");
        std::fs::copy(left.path(), right.path()).unwrap();
        std::fs::write(&output_path, b"existing").unwrap();

        let error = merge_ledgers_to_output(&left, &right, &output, LedgerMergeOptions::default())
            .unwrap_err();

        assert!(matches!(error, SyncError::OutputExists(path) if path == output_path));
    }
}
