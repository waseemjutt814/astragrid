use std::{collections::BTreeMap, path::PathBuf};

use astragrid_core::{Action, LedgerVerification, MissionEvent, MissionLedger, Priority};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MissionState {
    pub mission: Option<String>,
    pub events: usize,
    pub last_hash: Option<String>,
    pub incidents: BTreeMap<String, IncidentState>,
    pub observations: Vec<ObservationRecord>,
    pub dispatches: Vec<DispatchRecord>,
    pub annotations: Vec<AnnotationRecord>,
}

impl MissionState {
    pub fn from_ledger(ledger: &MissionLedger) -> Result<Self, StateError> {
        let verification = ledger.verify()?;
        if !verification.valid {
            return Err(StateError::LedgerCorrupt(verification));
        }
        Self::from_events(ledger.load_events()?)
    }

    pub fn from_events(events: Vec<MissionEvent>) -> Result<Self, StateError> {
        let mut state = Self {
            mission: None,
            events: events.len(),
            last_hash: events.last().map(|event| event.hash.clone()),
            incidents: BTreeMap::new(),
            observations: Vec::new(),
            dispatches: Vec::new(),
            annotations: Vec::new(),
        };

        for event in events {
            state.apply(event)?;
        }

        Ok(state)
    }

    pub fn summary(&self) -> MissionStateSummary {
        MissionStateSummary {
            mission: self.mission.clone(),
            events: self.events,
            open_incidents: self
                .incidents
                .values()
                .filter(|incident| incident.status == IncidentStatus::Open)
                .count(),
            closed_incidents: self
                .incidents
                .values()
                .filter(|incident| incident.status == IncidentStatus::Closed)
                .count(),
            observations: self.observations.len(),
            dispatches: self.dispatches.len(),
            annotations: self.annotations.len(),
            last_hash: self.last_hash.clone(),
        }
    }

    fn apply(&mut self, event: MissionEvent) -> Result<(), StateError> {
        match event.action {
            Action::OpenMission => {
                self.mission = Some(event.subject.clone());
            }
            Action::RecordObservation => {
                self.observations
                    .push(ObservationRecord::from_event(&event));
            }
            Action::DispatchTeam => {
                self.dispatches.push(DispatchRecord::from_event(&event));
            }
            Action::AnnotateSituation => {
                self.annotations.push(AnnotationRecord::from_event(&event));
            }
            Action::DeclareIncident => {
                let incident = self
                    .incidents
                    .entry(event.subject.clone())
                    .or_insert_with(|| IncidentState::new(&event));
                incident.status = IncidentStatus::Open;
                incident.priority = event.priority;
                incident.updated_at = event.occurred_at;
                incident.last_event_hash = event.hash.clone();
                incident.declared_by = event.actor.name.clone();
                incident.payload = event.payload.clone();
            }
            Action::CloseIncident => {
                let incident = self
                    .incidents
                    .get_mut(&event.subject)
                    .ok_or_else(|| StateError::CloseUnknownIncident(event.subject.clone()))?;
                incident.status = IncidentStatus::Closed;
                incident.updated_at = event.occurred_at;
                incident.closed_at = Some(event.occurred_at);
                incident.closed_by = Some(event.actor.name.clone());
                incident.last_event_hash = event.hash.clone();
                incident.payload = event.payload.clone();
            }
            Action::ChangePriority => {
                let incident = self
                    .incidents
                    .get_mut(&event.subject)
                    .ok_or_else(|| StateError::ChangeUnknownIncident(event.subject.clone()))?;
                incident.priority = event.priority;
                incident.updated_at = event.occurred_at;
                incident.last_event_hash = event.hash.clone();
                incident.payload = event.payload.clone();
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MissionStateSummary {
    pub mission: Option<String>,
    pub events: usize,
    pub open_incidents: usize,
    pub closed_incidents: usize,
    pub observations: usize,
    pub dispatches: usize,
    pub annotations: usize,
    pub last_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IncidentState {
    pub subject: String,
    pub status: IncidentStatus,
    pub priority: Priority,
    #[serde(with = "time::serde::rfc3339")]
    pub declared_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::rfc3339::option"
    )]
    pub closed_at: Option<OffsetDateTime>,
    pub declared_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closed_by: Option<String>,
    pub last_event_hash: String,
    pub payload: Value,
}

impl IncidentState {
    fn new(event: &MissionEvent) -> Self {
        Self {
            subject: event.subject.clone(),
            status: IncidentStatus::Open,
            priority: event.priority,
            declared_at: event.occurred_at,
            updated_at: event.occurred_at,
            closed_at: None,
            declared_by: event.actor.name.clone(),
            closed_by: None,
            last_event_hash: event.hash.clone(),
            payload: event.payload.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentStatus {
    Open,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObservationRecord {
    pub sequence: u64,
    pub subject: String,
    pub priority: Priority,
    pub actor: String,
    #[serde(with = "time::serde::rfc3339")]
    pub observed_at: OffsetDateTime,
    pub payload: Value,
    pub event_hash: String,
}

impl ObservationRecord {
    fn from_event(event: &MissionEvent) -> Self {
        Self {
            sequence: event.sequence,
            subject: event.subject.clone(),
            priority: event.priority,
            actor: event.actor.name.clone(),
            observed_at: event.occurred_at,
            payload: event.payload.clone(),
            event_hash: event.hash.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DispatchRecord {
    pub sequence: u64,
    pub subject: String,
    pub priority: Priority,
    pub actor: String,
    #[serde(with = "time::serde::rfc3339")]
    pub dispatched_at: OffsetDateTime,
    pub payload: Value,
    pub event_hash: String,
}

impl DispatchRecord {
    fn from_event(event: &MissionEvent) -> Self {
        Self {
            sequence: event.sequence,
            subject: event.subject.clone(),
            priority: event.priority,
            actor: event.actor.name.clone(),
            dispatched_at: event.occurred_at,
            payload: event.payload.clone(),
            event_hash: event.hash.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnnotationRecord {
    pub sequence: u64,
    pub subject: String,
    pub actor: String,
    #[serde(with = "time::serde::rfc3339")]
    pub annotated_at: OffsetDateTime,
    pub payload: Value,
    pub event_hash: String,
}

impl AnnotationRecord {
    fn from_event(event: &MissionEvent) -> Self {
        Self {
            sequence: event.sequence,
            subject: event.subject.clone(),
            actor: event.actor.name.clone(),
            annotated_at: event.occurred_at,
            payload: event.payload.clone(),
            event_hash: event.hash.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StateExport {
    pub source_ledger: PathBuf,
    pub state: MissionState,
}

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("ledger failed: {0}")]
    Ledger(#[from] astragrid_core::LedgerError),
    #[error("ledger is corrupt: {0:?}")]
    LedgerCorrupt(LedgerVerification),
    #[error("cannot close unknown incident {0}")]
    CloseUnknownIncident(String),
    #[error("cannot change priority for unknown incident {0}")]
    ChangeUnknownIncident(String),
}

#[cfg(test)]
mod tests {
    use astragrid_core::{Action, Actor, CommandRequest, MissionLedger, Priority, Role};
    use serde_json::json;
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn materializes_open_and_closed_incidents() {
        let dir = tempdir().unwrap();
        let ledger = MissionLedger::open(dir.path().join("mission.agl"));
        ledger
            .append(CommandRequest::new(
                Actor::new("kernel", Role::System),
                Action::OpenMission,
                "flood-watch",
                Priority::Elevated,
                json!({"mission": "flood-watch"}),
            ))
            .unwrap();
        ledger
            .append(CommandRequest::new(
                Actor::new("lead", Role::IncidentCommander),
                Action::DeclareIncident,
                "river-east",
                Priority::Critical,
                json!({"water_level_m": 5.2}),
            ))
            .unwrap();
        ledger
            .append(CommandRequest::new(
                Actor::new("lead", Role::IncidentCommander),
                Action::CloseIncident,
                "river-east",
                Priority::Elevated,
                json!({"reason": "water receded"}),
            ))
            .unwrap();

        let state = MissionState::from_ledger(&ledger).unwrap();
        let summary = state.summary();

        assert_eq!(summary.mission.as_deref(), Some("flood-watch"));
        assert_eq!(summary.open_incidents, 0);
        assert_eq!(summary.closed_incidents, 1);
        assert_eq!(state.incidents["river-east"].status, IncidentStatus::Closed);
    }

    #[test]
    fn rejects_closing_unknown_incident() {
        let event = MissionEvent::new(
            0,
            Actor::new("lead", Role::IncidentCommander),
            Action::CloseIncident,
            "river-east",
            Priority::Elevated,
            json!({"reason": "missing"}),
            None,
        )
        .unwrap();

        assert!(matches!(
            MissionState::from_events(vec![event]),
            Err(StateError::CloseUnknownIncident(subject)) if subject == "river-east"
        ));
    }
}
