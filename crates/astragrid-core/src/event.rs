use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::identity::CommandAttestation;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Observer,
    Operator,
    IncidentCommander,
    System,
}

impl Role {
    pub fn allows(self, required: Role) -> bool {
        self >= required
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Role::Observer => "observer",
            Role::Operator => "operator",
            Role::IncidentCommander => "incident_commander",
            Role::System => "system",
        })
    }
}

impl FromStr for Role {
    type Err = ParseEnumError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match normalize_token(input).as_str() {
            "observer" => Ok(Role::Observer),
            "operator" => Ok(Role::Operator),
            "incidentcommander" | "commander" | "incidentlead" => Ok(Role::IncidentCommander),
            "system" => Ok(Role::System),
            _ => Err(ParseEnumError::new("role", input)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Actor {
    pub name: String,
    pub role: Role,
}

impl Actor {
    pub fn new(name: impl Into<String>, role: Role) -> Self {
        Self {
            name: name.into(),
            role,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    OpenMission,
    RecordObservation,
    DispatchTeam,
    AnnotateSituation,
    DeclareIncident,
    CloseIncident,
    ChangePriority,
}

impl Action {
    pub fn required_role(self) -> Role {
        match self {
            Action::RecordObservation => Role::Observer,
            Action::AnnotateSituation | Action::DispatchTeam => Role::Operator,
            Action::DeclareIncident | Action::CloseIncident | Action::ChangePriority => {
                Role::IncidentCommander
            }
            Action::OpenMission => Role::System,
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Action::OpenMission => "open_mission",
            Action::RecordObservation => "record_observation",
            Action::DispatchTeam => "dispatch_team",
            Action::AnnotateSituation => "annotate_situation",
            Action::DeclareIncident => "declare_incident",
            Action::CloseIncident => "close_incident",
            Action::ChangePriority => "change_priority",
        })
    }
}

impl FromStr for Action {
    type Err = ParseEnumError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match normalize_token(input).as_str() {
            "openmission" | "open" => Ok(Action::OpenMission),
            "recordobservation" | "observe" | "observation" => Ok(Action::RecordObservation),
            "dispatchteam" | "dispatch" => Ok(Action::DispatchTeam),
            "annotatesituation" | "annotate" | "note" => Ok(Action::AnnotateSituation),
            "declareincident" | "declare" => Ok(Action::DeclareIncident),
            "closeincident" | "close" => Ok(Action::CloseIncident),
            "changepriority" | "priority" => Ok(Action::ChangePriority),
            _ => Err(ParseEnumError::new("action", input)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Priority {
    Routine,
    Elevated,
    Critical,
}

impl fmt::Display for Priority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Priority::Routine => "routine",
            Priority::Elevated => "elevated",
            Priority::Critical => "critical",
        })
    }
}

impl FromStr for Priority {
    type Err = ParseEnumError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match normalize_token(input).as_str() {
            "routine" | "normal" => Ok(Priority::Routine),
            "elevated" | "high" => Ok(Priority::Elevated),
            "critical" | "urgent" => Ok(Priority::Critical),
            _ => Err(ParseEnumError::new("priority", input)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseEnumError {
    kind: &'static str,
    input: String,
}

impl ParseEnumError {
    fn new(kind: &'static str, input: &str) -> Self {
        Self {
            kind,
            input: input.to_owned(),
        }
    }
}

impl fmt::Display for ParseEnumError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown {} '{}'", self.kind, self.input)
    }
}

impl std::error::Error for ParseEnumError {}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MissionEvent {
    pub sequence: u64,
    pub id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    pub occurred_at: OffsetDateTime,
    pub actor: Actor,
    pub action: Action,
    pub subject: String,
    pub priority: Priority,
    pub payload: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<CommandAttestation>,
    pub previous_hash: Option<String>,
    pub hash: String,
}

impl MissionEvent {
    pub fn new(
        sequence: u64,
        actor: Actor,
        action: Action,
        subject: impl Into<String>,
        priority: Priority,
        payload: Value,
        previous_hash: Option<String>,
    ) -> Result<Self, EventHashError> {
        Self::new_attested(
            sequence,
            actor,
            action,
            subject,
            priority,
            payload,
            None,
            previous_hash,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_attested(
        sequence: u64,
        actor: Actor,
        action: Action,
        subject: impl Into<String>,
        priority: Priority,
        payload: Value,
        attestation: Option<CommandAttestation>,
        previous_hash: Option<String>,
    ) -> Result<Self, EventHashError> {
        let mut event = Self {
            sequence,
            id: Uuid::now_v7(),
            occurred_at: OffsetDateTime::now_utc(),
            actor,
            action,
            subject: subject.into(),
            priority,
            payload: canonicalize_value(&payload),
            attestation,
            previous_hash,
            hash: String::new(),
        };
        event.hash = event.compute_hash()?;
        Ok(event)
    }

    pub fn compute_hash(&self) -> Result<String, EventHashError> {
        #[derive(Serialize)]
        struct HashInput<'a> {
            sequence: u64,
            id: Uuid,
            occurred_at: String,
            actor: &'a Actor,
            action: Action,
            subject: &'a str,
            priority: Priority,
            payload: Value,
            #[serde(skip_serializing_if = "Option::is_none")]
            attestation: &'a Option<CommandAttestation>,
            previous_hash: &'a Option<String>,
        }

        let occurred_at = self.occurred_at.format(&Rfc3339)?;
        let input = HashInput {
            sequence: self.sequence,
            id: self.id,
            occurred_at,
            actor: &self.actor,
            action: self.action,
            subject: &self.subject,
            priority: self.priority,
            payload: canonicalize_value(&self.payload),
            attestation: &self.attestation,
            previous_hash: &self.previous_hash,
        };
        let bytes = serde_json::to_vec(&input)?;
        Ok(blake3::hash(&bytes).to_hex().to_string())
    }

    pub fn has_valid_hash(&self) -> Result<bool, EventHashError> {
        Ok(self.compute_hash()? == self.hash)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EventHashError {
    #[error("failed to format event timestamp: {0}")]
    TimeFormat(#[from] time::error::Format),
    #[error("failed to serialize event for hashing: {0}")]
    Json(#[from] serde_json::Error),
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

fn normalize_token(input: &str) -> String {
    input
        .chars()
        .filter(|character| *character != '_' && *character != '-' && !character.is_whitespace())
        .flat_map(char::to_lowercase)
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn hash_is_stable_for_payload_key_order() {
        let actor = Actor::new("ops", Role::Operator);
        let left = MissionEvent::new(
            1,
            actor.clone(),
            Action::RecordObservation,
            "sector-7",
            Priority::Elevated,
            json!({"b": 2, "a": 1}),
            None,
        )
        .expect("event");
        let mut right = left.clone();
        right.payload = json!({"a": 1, "b": 2});
        right.hash = right.compute_hash().expect("hash");

        assert_eq!(left.hash, right.hash);
    }

    #[test]
    fn enum_parsers_accept_human_aliases() {
        assert_eq!(
            "incident commander".parse::<Role>().unwrap(),
            Role::IncidentCommander
        );
        assert_eq!("dispatch".parse::<Action>().unwrap(), Action::DispatchTeam);
        assert_eq!("urgent".parse::<Priority>().unwrap(), Priority::Critical);
    }
}
