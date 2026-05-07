use std::collections::BTreeSet;

use astragrid_core::{
    Action, AdmissionPolicy, CommandRequest, DetachedSignature, IdentityError, OperatorIdentity,
    OperatorKeypair, PolicyDecision, Priority, Role,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const POLICY_RULE_PACK_SCHEMA: u16 = 1;
pub const POLICY_RULE_PACK_SIGNATURE_SCHEMA: u16 = 1;
pub const POLICY_RULE_PACK_SIGNATURE_PURPOSE: &str = "astragrid-policy-rule-pack-v1";
const DIGEST_ALGORITHM: &str = "sha256";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRulePack {
    pub schema: u16,
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub compatibility: PolicyPackCompatibility,
    pub rules: Vec<PolicyRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyPackCompatibility {
    pub min_astragrid_version: String,
    pub core_policy_schema: u16,
}

impl Default for PolicyPackCompatibility {
    fn default() -> Self {
        Self {
            min_astragrid_version: "0.1.0".to_owned(),
            core_policy_schema: 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: String,
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<Action>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_role: Option<Role>,
    #[serde(default)]
    pub allowed_priorities: Vec<Priority>,
    #[serde(default)]
    pub required_payload_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRulePackSignature {
    pub schema: u16,
    pub pack_sha256: String,
    pub signature: DetachedSignature,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRulePackSignatureReport {
    pub valid: bool,
    pub expected_sha256: String,
    pub actual_sha256: String,
    pub hash_match: bool,
    pub signature_valid: bool,
    pub signer: OperatorIdentity,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyPackDecision {
    pub allowed: bool,
    pub reason: String,
    pub required_role: Role,
    pub core: PolicyDecision,
    pub applied_rules: Vec<PolicyRuleDecision>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyRuleDecision {
    pub id: String,
    pub status: PolicyRuleDecisionStatus,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyRuleDecisionStatus {
    Pass,
    Fail,
}

impl PolicyRulePack {
    pub fn field_safety_template(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            schema: POLICY_RULE_PACK_SCHEMA,
            name: name.into(),
            version: version.into(),
            compatibility: PolicyPackCompatibility::default(),
            rules: vec![
                PolicyRule {
                    id: "dispatch-requires-team-id".to_owned(),
                    description: "Dispatch commands must name the field team in payload.team_id."
                        .to_owned(),
                    action: Some(Action::DispatchTeam),
                    subject_prefix: None,
                    min_role: Some(Role::Operator),
                    allowed_priorities: vec![Priority::Elevated, Priority::Critical],
                    required_payload_fields: vec!["team_id".to_owned()],
                    deny: None,
                },
                PolicyRule {
                    id: "incident-close-requires-rationale".to_owned(),
                    description: "Closing an incident must carry an operator rationale.".to_owned(),
                    action: Some(Action::CloseIncident),
                    subject_prefix: None,
                    min_role: Some(Role::IncidentCommander),
                    allowed_priorities: vec![Priority::Elevated, Priority::Critical],
                    required_payload_fields: vec!["rationale".to_owned()],
                    deny: None,
                },
            ],
        }
    }

    pub fn validate(&self) -> Result<(), PolicyPackError> {
        if self.schema != POLICY_RULE_PACK_SCHEMA {
            return Err(PolicyPackError::UnsupportedSchema(self.schema));
        }
        validate_label("name", &self.name)?;
        validate_label("version", &self.version)?;
        if self.compatibility.core_policy_schema != 1 {
            return Err(PolicyPackError::UnsupportedCorePolicySchema(
                self.compatibility.core_policy_schema,
            ));
        }
        if self.rules.is_empty() {
            return Err(PolicyPackError::InvalidPack(
                "policy rule pack must contain at least one rule".to_owned(),
            ));
        }

        let mut ids = BTreeSet::new();
        for rule in &self.rules {
            rule.validate()?;
            if !ids.insert(rule.id.clone()) {
                return Err(PolicyPackError::DuplicateRuleId(rule.id.clone()));
            }
        }
        Ok(())
    }

    pub fn evaluate_request(
        &self,
        request: &CommandRequest,
    ) -> Result<PolicyPackDecision, PolicyPackError> {
        self.validate()?;
        let core = AdmissionPolicy.evaluate(request);
        let mut required_role = core.required_role;
        let mut applied_rules = Vec::new();

        if !core.allowed {
            return Ok(PolicyPackDecision {
                allowed: false,
                reason: core.reason.clone(),
                required_role,
                core,
                applied_rules,
            });
        }

        for rule in &self.rules {
            if !rule.matches_request(request) {
                continue;
            }
            if let Some(min_role) = rule.min_role
                && min_role > required_role
            {
                required_role = min_role;
            }

            let decision = rule.evaluate_match(request);
            let failed = decision.status == PolicyRuleDecisionStatus::Fail;
            applied_rules.push(decision.clone());
            if failed {
                return Ok(PolicyPackDecision {
                    allowed: false,
                    reason: decision.reason,
                    required_role,
                    core,
                    applied_rules,
                });
            }
        }

        Ok(PolicyPackDecision {
            allowed: true,
            reason: "command satisfies core policy and policy rule pack".to_owned(),
            required_role,
            core,
            applied_rules,
        })
    }

    pub fn sha256(&self) -> Result<String, PolicyPackError> {
        Ok(sha256_bytes(&serde_json::to_vec(self)?))
    }
}

impl PolicyRule {
    fn validate(&self) -> Result<(), PolicyPackError> {
        validate_label("rule id", &self.id)?;
        validate_label("rule description", &self.description)?;
        if let Some(prefix) = &self.subject_prefix {
            validate_label("subject_prefix", prefix)?;
        }
        if self.min_role.is_none()
            && self.allowed_priorities.is_empty()
            && self.required_payload_fields.is_empty()
            && self.deny.is_none()
        {
            return Err(PolicyPackError::InvalidRule {
                id: self.id.clone(),
                reason: "rule has no effect".to_owned(),
            });
        }
        let mut priorities = Vec::new();
        for priority in &self.allowed_priorities {
            if priorities.contains(priority) {
                return Err(PolicyPackError::InvalidRule {
                    id: self.id.clone(),
                    reason: "allowed_priorities contains a duplicate".to_owned(),
                });
            }
            priorities.push(*priority);
        }
        let mut fields = BTreeSet::new();
        for field in &self.required_payload_fields {
            validate_label("required_payload_field", field)?;
            if !fields.insert(field.clone()) {
                return Err(PolicyPackError::InvalidRule {
                    id: self.id.clone(),
                    reason: "required_payload_fields contains a duplicate".to_owned(),
                });
            }
        }
        if let Some(reason) = &self.deny {
            validate_label("deny", reason)?;
        }
        Ok(())
    }

    fn matches_request(&self, request: &CommandRequest) -> bool {
        if let Some(action) = self.action
            && request.action != action
        {
            return false;
        }
        if let Some(prefix) = &self.subject_prefix
            && !request.subject.starts_with(prefix)
        {
            return false;
        }
        true
    }

    fn evaluate_match(&self, request: &CommandRequest) -> PolicyRuleDecision {
        if let Some(reason) = &self.deny {
            return self.fail(reason.clone());
        }
        if let Some(min_role) = self.min_role
            && !request.actor.role.allows(min_role)
        {
            return self.fail(format!(
                "rule '{}' requires role '{}', actor has '{}'",
                self.id, min_role, request.actor.role
            ));
        }
        if !self.allowed_priorities.is_empty()
            && !self.allowed_priorities.contains(&request.priority)
        {
            return self.fail(format!(
                "rule '{}' allows priorities {:?}, command has '{}'",
                self.id, self.allowed_priorities, request.priority
            ));
        }
        let missing = self
            .required_payload_fields
            .iter()
            .filter(|field| !payload_field_exists(&request.payload, field))
            .cloned()
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            return self.fail(format!(
                "rule '{}' requires payload field(s): {}",
                self.id,
                missing.join(", ")
            ));
        }
        PolicyRuleDecision {
            id: self.id.clone(),
            status: PolicyRuleDecisionStatus::Pass,
            reason: "rule passed".to_owned(),
        }
    }

    fn fail(&self, reason: String) -> PolicyRuleDecision {
        PolicyRuleDecision {
            id: self.id.clone(),
            status: PolicyRuleDecisionStatus::Fail,
            reason,
        }
    }
}

impl PolicyRulePackSignature {
    pub fn sign_pack(
        pack: &PolicyRulePack,
        keypair: &OperatorKeypair,
    ) -> Result<Self, PolicyPackError> {
        pack.validate()?;
        let digest = pack.sha256()?;
        Ok(Self {
            schema: POLICY_RULE_PACK_SIGNATURE_SCHEMA,
            pack_sha256: digest.clone(),
            signature: keypair.sign_digest(
                POLICY_RULE_PACK_SIGNATURE_PURPOSE,
                DIGEST_ALGORITHM,
                &digest,
            )?,
        })
    }

    pub fn verify_pack(
        &self,
        pack: &PolicyRulePack,
    ) -> Result<PolicyRulePackSignatureReport, PolicyPackError> {
        if self.schema != POLICY_RULE_PACK_SIGNATURE_SCHEMA {
            return Err(PolicyPackError::UnsupportedSignatureSchema(self.schema));
        }
        pack.validate()?;
        let actual_sha256 = pack.sha256()?;
        let expected_sha256 = normalize_digest(&self.pack_sha256);
        let hash_match = actual_sha256 == expected_sha256;
        let signature_result = self.signature.verify_digest(
            POLICY_RULE_PACK_SIGNATURE_PURPOSE,
            DIGEST_ALGORITHM,
            &expected_sha256,
        );
        let signature_valid = signature_result.is_ok();
        let valid = hash_match && signature_valid;
        let detail = if !hash_match {
            "policy rule pack sha256 mismatch".to_owned()
        } else if let Err(error) = signature_result {
            format!("policy rule pack signature verification failed: {error}")
        } else {
            "policy rule pack signature is valid".to_owned()
        };
        Ok(PolicyRulePackSignatureReport {
            valid,
            expected_sha256,
            actual_sha256,
            hash_match,
            signature_valid,
            signer: self.signature.identity.clone(),
            detail,
        })
    }
}

fn validate_label(field: &'static str, value: &str) -> Result<(), PolicyPackError> {
    if value.trim().is_empty() {
        return Err(PolicyPackError::InvalidPack(format!(
            "{field} cannot be empty"
        )));
    }
    if value
        .chars()
        .any(|character| matches!(character, '\n' | '\r' | '\0'))
    {
        return Err(PolicyPackError::InvalidPack(format!(
            "{field} cannot contain newline, carriage return, or NUL"
        )));
    }
    Ok(())
}

fn payload_field_exists(value: &Value, field_path: &str) -> bool {
    let mut current = value;
    for part in field_path.split('.') {
        let Some(object) = current.as_object() else {
            return false;
        };
        let Some(next) = object.get(part) else {
            return false;
        };
        current = next;
    }
    !current.is_null()
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_lower(hasher.finalize().as_slice())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn normalize_digest(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyPackError {
    #[error("unsupported policy rule pack schema {0}")]
    UnsupportedSchema(u16),
    #[error("unsupported policy rule pack signature schema {0}")]
    UnsupportedSignatureSchema(u16),
    #[error("unsupported core policy schema {0}")]
    UnsupportedCorePolicySchema(u16),
    #[error("invalid policy rule pack: {0}")]
    InvalidPack(String),
    #[error("duplicate policy rule id: {0}")]
    DuplicateRuleId(String),
    #[error("invalid policy rule {id}: {reason}")]
    InvalidRule { id: String, reason: String },
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use astragrid_core::{Actor, OperatorKeypair};
    use serde_json::json;

    use super::*;

    #[test]
    fn template_blocks_dispatch_without_team_id() {
        let pack = PolicyRulePack::field_safety_template("field-safety", "1.0.0");
        let request = CommandRequest::new(
            Actor::new("lead", Role::IncidentCommander),
            Action::DispatchTeam,
            "river-east",
            Priority::Elevated,
            json!({"note": "go"}),
        );

        let decision = pack.evaluate_request(&request).unwrap();

        assert!(!decision.allowed);
        assert!(decision.reason.contains("team_id"));
    }

    #[test]
    fn template_allows_dispatch_with_team_id() {
        let pack = PolicyRulePack::field_safety_template("field-safety", "1.0.0");
        let request = CommandRequest::new(
            Actor::new("lead", Role::IncidentCommander),
            Action::DispatchTeam,
            "river-east",
            Priority::Elevated,
            json!({"team_id": "alpha"}),
        );

        let decision = pack.evaluate_request(&request).unwrap();

        assert!(decision.allowed);
        assert_eq!(decision.applied_rules.len(), 1);
    }

    #[test]
    fn signature_verifies_and_fails_after_tamper() {
        let keypair = OperatorKeypair::generate("policy-signer", Role::Operator);
        let pack = PolicyRulePack::field_safety_template("field-safety", "1.0.0");
        let signature = PolicyRulePackSignature::sign_pack(&pack, &keypair).unwrap();

        assert!(signature.verify_pack(&pack).unwrap().valid);

        let mut tampered = pack.clone();
        tampered.rules[0].required_payload_fields = Vec::new();
        let report = signature.verify_pack(&tampered).unwrap();
        assert!(!report.valid);
        assert!(!report.hash_match);
    }

    #[test]
    fn rejects_duplicate_rule_ids() {
        let mut pack = PolicyRulePack::field_safety_template("field-safety", "1.0.0");
        pack.rules[1].id = pack.rules[0].id.clone();

        assert!(matches!(
            pack.validate(),
            Err(PolicyPackError::DuplicateRuleId(_))
        ));
    }
}
