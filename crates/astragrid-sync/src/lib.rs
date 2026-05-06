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

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("left ledger is invalid: {0:?}")]
    InvalidLeft(LedgerVerification),
    #[error("right ledger is invalid: {0:?}")]
    InvalidRight(LedgerVerification),
    #[error("ledger failed: {0}")]
    Ledger(#[from] astragrid_core::LedgerError),
    #[error("ledgers diverged and cannot be applied automatically: {0:?}")]
    Diverged(SyncPlan),
    #[error("sequence index exceeds u64")]
    SequenceOverflow,
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
}
