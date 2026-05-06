use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::event::{Action, Actor, Priority, Role};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommandRequest {
    pub actor: Actor,
    pub action: Action,
    pub subject: String,
    pub priority: Priority,
    pub payload: Value,
}

impl CommandRequest {
    pub fn new(
        actor: Actor,
        action: Action,
        subject: impl Into<String>,
        priority: Priority,
        payload: Value,
    ) -> Self {
        Self {
            actor,
            action,
            subject: subject.into(),
            priority,
            payload,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub allowed: bool,
    pub reason: String,
    pub required_role: Role,
}

impl PolicyDecision {
    fn allow(required_role: Role) -> Self {
        Self {
            allowed: true,
            reason: "command satisfies mission admission policy".to_owned(),
            required_role,
        }
    }

    fn deny(required_role: Role, reason: impl Into<String>) -> Self {
        Self {
            allowed: false,
            reason: reason.into(),
            required_role,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct AdmissionPolicy;

impl AdmissionPolicy {
    pub fn evaluate(&self, request: &CommandRequest) -> PolicyDecision {
        let required_role = request.action.required_role();

        if request.actor.name.trim().is_empty() {
            return PolicyDecision::deny(required_role, "actor name is required");
        }

        if request.subject.trim().is_empty() {
            return PolicyDecision::deny(required_role, "subject is required");
        }

        if !request.actor.role.allows(required_role) {
            return PolicyDecision::deny(
                required_role,
                format!(
                    "action '{}' requires role '{}', actor has '{}'",
                    request.action, required_role, request.actor.role
                ),
            );
        }

        if request.priority == Priority::Critical
            && request.actor.role != Role::IncidentCommander
            && request.actor.role != Role::System
        {
            return PolicyDecision::deny(
                Role::IncidentCommander,
                "critical priority requires incident commander or system authority",
            );
        }

        if request.action == Action::DispatchTeam && request.priority == Priority::Routine {
            return PolicyDecision::deny(
                Role::Operator,
                "dispatching a field team requires elevated or critical priority",
            );
        }

        PolicyDecision::allow(required_role)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn denies_dispatch_from_observer() {
        let policy = AdmissionPolicy;
        let request = CommandRequest::new(
            Actor::new("analyst", Role::Observer),
            Action::DispatchTeam,
            "sector-7",
            Priority::Elevated,
            json!({"team": "alpha"}),
        );

        let decision = policy.evaluate(&request);

        assert!(!decision.allowed);
        assert_eq!(decision.required_role, Role::Operator);
    }

    #[test]
    fn allows_critical_incident_commander_command() {
        let policy = AdmissionPolicy;
        let request = CommandRequest::new(
            Actor::new("lead", Role::IncidentCommander),
            Action::DeclareIncident,
            "river-east",
            Priority::Critical,
            json!({"reason": "water-level-threshold"}),
        );

        assert!(policy.evaluate(&request).allowed);
    }
}
