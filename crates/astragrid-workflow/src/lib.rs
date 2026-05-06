use std::str::FromStr;

use astragrid_core::{
    Action, Actor, AdmissionPolicy, CommandRequest, PolicyDecision, Priority, Role,
};
use astragrid_evidence::EvidenceBundle;
use astragrid_state::{IncidentStatus, MissionState};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkflowPlanner {
    pub min_confidence: f64,
}

impl Default for WorkflowPlanner {
    fn default() -> Self {
        Self {
            min_confidence: 0.75,
        }
    }
}

impl WorkflowPlanner {
    pub fn draft_command(
        &self,
        state: &MissionState,
        bundle: &EvidenceBundle,
        actor: Actor,
    ) -> Result<CommandDraft, WorkflowError> {
        bundle.verify()?;
        if !(0.0..=1.0).contains(&self.min_confidence) {
            return Err(WorkflowError::InvalidMinimumConfidence(self.min_confidence));
        }
        if bundle.recommendation.confidence < self.min_confidence {
            return Ok(CommandDraft::blocked(
                "recommendation confidence is below workflow threshold",
                None,
                None,
            ));
        }

        let action = Action::from_str(&bundle.recommendation.action)
            .map_err(|_| WorkflowError::UnknownAction(bundle.recommendation.action.clone()))?;
        let priority = priority_from_confidence(bundle.recommendation.confidence);
        let payload = serde_json::json!({
            "rationale": bundle.recommendation.rationale,
            "confidence": bundle.recommendation.confidence,
            "evidence_bundle": bundle.bundle_hash,
            "evidence_ids": bundle.recommendation.evidence_ids,
        });
        let request = CommandRequest::new(
            actor,
            action,
            bundle.recommendation.subject.clone(),
            priority,
            payload,
        );

        if let Some(reason) = state_guard(state, &request) {
            return Ok(CommandDraft::blocked(reason, Some(request), None));
        }

        let decision = AdmissionPolicy.evaluate(&request);
        if !decision.allowed {
            return Ok(CommandDraft::blocked(
                decision.reason.clone(),
                Some(request),
                Some(decision),
            ));
        }

        Ok(CommandDraft {
            status: DraftStatus::Ready,
            reason: "draft passed evidence, state, and policy checks".to_owned(),
            request: Some(request),
            policy: Some(decision),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommandDraft {
    pub status: DraftStatus,
    pub reason: String,
    pub request: Option<CommandRequest>,
    pub policy: Option<PolicyDecision>,
}

impl CommandDraft {
    fn blocked(
        reason: impl Into<String>,
        request: Option<CommandRequest>,
        policy: Option<PolicyDecision>,
    ) -> Self {
        Self {
            status: DraftStatus::Blocked,
            reason: reason.into(),
            request,
            policy,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DraftStatus {
    Ready,
    Blocked,
}

fn priority_from_confidence(confidence: f64) -> Priority {
    if confidence >= 0.9 {
        Priority::Critical
    } else if confidence >= 0.7 {
        Priority::Elevated
    } else {
        Priority::Routine
    }
}

fn state_guard(state: &MissionState, request: &CommandRequest) -> Option<String> {
    match request.action {
        Action::DeclareIncident => {
            if state
                .incidents
                .get(&request.subject)
                .is_some_and(|incident| incident.status == IncidentStatus::Open)
            {
                return Some(format!("incident {} is already open", request.subject));
            }
        }
        Action::CloseIncident | Action::ChangePriority => {
            if !state
                .incidents
                .get(&request.subject)
                .is_some_and(|incident| incident.status == IncidentStatus::Open)
            {
                return Some(format!("incident {} is not open", request.subject));
            }
        }
        _ => {}
    }
    None
}

#[derive(Debug, thiserror::Error)]
pub enum WorkflowError {
    #[error("evidence failed: {0}")]
    Evidence(#[from] astragrid_evidence::EvidenceError),
    #[error("unknown workflow action {0}")]
    UnknownAction(String),
    #[error("invalid minimum confidence {0}")]
    InvalidMinimumConfidence(f64),
}

pub fn actor_from_parts(name: impl Into<String>, role: Role) -> Actor {
    Actor::new(name, role)
}

#[cfg(test)]
mod tests {
    use astragrid_core::{CommandRequest, MissionLedger};
    use astragrid_evidence::{
        EvidenceBundle, EvidenceItem, EvidenceKind, Recommendation, digest_bytes,
    };
    use serde_json::json;
    use tempfile::tempdir;

    use super::*;

    fn bundle(action: &str, confidence: f64) -> EvidenceBundle {
        EvidenceBundle::new(
            "flood-watch",
            vec![EvidenceItem {
                id: "sensor-1".to_owned(),
                source: "river-gauge".to_owned(),
                kind: EvidenceKind::Sensor,
                confidence: 0.95,
                digest: digest_bytes(b"water=5.2"),
                excerpt: Some("water=5.2".to_owned()),
            }],
            Recommendation {
                action: action.to_owned(),
                subject: "river-east".to_owned(),
                rationale: "Gauge exceeded threshold.".to_owned(),
                confidence,
                evidence_ids: vec!["sensor-1".to_owned()],
            },
        )
        .unwrap()
    }

    #[test]
    fn drafts_ready_command_from_verified_bundle() {
        let state = MissionState::from_events(Vec::new()).unwrap();
        let draft = WorkflowPlanner::default()
            .draft_command(
                &state,
                &bundle("declare_incident", 0.92),
                Actor::new("lead", Role::IncidentCommander),
            )
            .unwrap();

        assert_eq!(draft.status, DraftStatus::Ready);
        assert_eq!(draft.request.unwrap().priority, Priority::Critical);
    }

    #[test]
    fn blocks_low_confidence_recommendation() {
        let state = MissionState::from_events(Vec::new()).unwrap();
        let draft = WorkflowPlanner::default()
            .draft_command(
                &state,
                &bundle("declare_incident", 0.5),
                Actor::new("lead", Role::IncidentCommander),
            )
            .unwrap();

        assert_eq!(draft.status, DraftStatus::Blocked);
    }

    #[test]
    fn blocks_duplicate_open_incident() {
        let dir = tempdir().unwrap();
        let ledger = MissionLedger::open(dir.path().join("mission.agl"));
        ledger
            .append(CommandRequest::new(
                Actor::new("lead", Role::IncidentCommander),
                Action::DeclareIncident,
                "river-east",
                Priority::Critical,
                json!({"water_level_m": 5.2}),
            ))
            .unwrap();
        let state = MissionState::from_ledger(&ledger).unwrap();
        let draft = WorkflowPlanner::default()
            .draft_command(
                &state,
                &bundle("declare_incident", 0.92),
                Actor::new("lead", Role::IncidentCommander),
            )
            .unwrap();

        assert_eq!(draft.status, DraftStatus::Blocked);
        assert!(draft.reason.contains("already open"));
    }
}
