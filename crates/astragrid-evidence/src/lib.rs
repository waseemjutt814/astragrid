use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceItem {
    pub id: String,
    pub source: String,
    pub kind: EvidenceKind,
    pub confidence: f64,
    pub digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub excerpt: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    Observation,
    Sensor,
    GeoFeature,
    LedgerEvent,
    HumanReport,
    ExternalDocument,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Recommendation {
    pub action: String,
    pub subject: String,
    pub rationale: String,
    pub confidence: f64,
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceBundle {
    pub schema: u16,
    pub id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    pub mission: String,
    pub evidence: Vec<EvidenceItem>,
    pub recommendation: Recommendation,
    pub bundle_hash: String,
}

impl EvidenceBundle {
    pub fn new(
        mission: impl Into<String>,
        evidence: Vec<EvidenceItem>,
        recommendation: Recommendation,
    ) -> Result<Self, EvidenceError> {
        validate_evidence(&evidence)?;
        validate_recommendation(&recommendation, &evidence)?;
        let mut bundle = Self {
            schema: 1,
            id: Uuid::now_v7(),
            created_at: OffsetDateTime::now_utc(),
            mission: mission.into(),
            evidence,
            recommendation,
            bundle_hash: String::new(),
        };
        bundle.bundle_hash = bundle.compute_hash()?;
        Ok(bundle)
    }

    pub fn verify(&self) -> Result<(), EvidenceError> {
        validate_evidence(&self.evidence)?;
        validate_recommendation(&self.recommendation, &self.evidence)?;
        let actual = self.compute_hash()?;
        if actual != self.bundle_hash {
            return Err(EvidenceError::HashMismatch);
        }
        Ok(())
    }

    pub fn compute_hash(&self) -> Result<String, EvidenceError> {
        #[derive(Serialize)]
        struct HashInput<'a> {
            schema: u16,
            id: Uuid,
            #[serde(with = "time::serde::rfc3339")]
            created_at: OffsetDateTime,
            mission: &'a str,
            evidence: &'a [EvidenceItem],
            recommendation: &'a Recommendation,
        }

        let input = HashInput {
            schema: self.schema,
            id: self.id,
            created_at: self.created_at,
            mission: &self.mission,
            evidence: &self.evidence,
            recommendation: &self.recommendation,
        };
        Ok(blake3::hash(&serde_json::to_vec(&input)?)
            .to_hex()
            .to_string())
    }
}

pub fn digest_bytes(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

fn validate_evidence(evidence: &[EvidenceItem]) -> Result<(), EvidenceError> {
    if evidence.is_empty() {
        return Err(EvidenceError::NoEvidence);
    }
    let mut ids = BTreeSet::new();
    for item in evidence {
        if item.id.trim().is_empty() {
            return Err(EvidenceError::EmptyEvidenceId);
        }
        if !ids.insert(item.id.as_str()) {
            return Err(EvidenceError::DuplicateEvidenceId(item.id.clone()));
        }
        validate_confidence(item.confidence)?;
        if item.source.trim().is_empty() {
            return Err(EvidenceError::EmptySource(item.id.clone()));
        }
        if item.digest.trim().is_empty() {
            return Err(EvidenceError::EmptyDigest(item.id.clone()));
        }
    }
    Ok(())
}

fn validate_recommendation(
    recommendation: &Recommendation,
    evidence: &[EvidenceItem],
) -> Result<(), EvidenceError> {
    if recommendation.action.trim().is_empty() {
        return Err(EvidenceError::EmptyRecommendationField("action"));
    }
    if recommendation.subject.trim().is_empty() {
        return Err(EvidenceError::EmptyRecommendationField("subject"));
    }
    if recommendation.rationale.trim().is_empty() {
        return Err(EvidenceError::EmptyRecommendationField("rationale"));
    }
    validate_confidence(recommendation.confidence)?;
    if recommendation.evidence_ids.is_empty() {
        return Err(EvidenceError::NoRecommendationEvidence);
    }
    let ids = evidence
        .iter()
        .map(|item| item.id.as_str())
        .collect::<BTreeSet<_>>();
    for id in &recommendation.evidence_ids {
        if !ids.contains(id.as_str()) {
            return Err(EvidenceError::UnknownEvidenceReference(id.clone()));
        }
    }
    Ok(())
}

fn validate_confidence(value: f64) -> Result<(), EvidenceError> {
    if !(0.0..=1.0).contains(&value) || !value.is_finite() {
        return Err(EvidenceError::InvalidConfidence(value));
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum EvidenceError {
    #[error("evidence JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("evidence bundle has no evidence")]
    NoEvidence,
    #[error("evidence item id cannot be empty")]
    EmptyEvidenceId,
    #[error("duplicate evidence id {0}")]
    DuplicateEvidenceId(String),
    #[error("evidence item {0} has empty source")]
    EmptySource(String),
    #[error("evidence item {0} has empty digest")]
    EmptyDigest(String),
    #[error("invalid confidence {0}; expected 0.0 through 1.0")]
    InvalidConfidence(f64),
    #[error("recommendation {0} cannot be empty")]
    EmptyRecommendationField(&'static str),
    #[error("recommendation must cite at least one evidence item")]
    NoRecommendationEvidence,
    #[error("recommendation references unknown evidence id {0}")]
    UnknownEvidenceReference(String),
    #[error("evidence bundle hash mismatch")]
    HashMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_item() -> EvidenceItem {
        EvidenceItem {
            id: "sensor-1".to_owned(),
            source: "river-gauge".to_owned(),
            kind: EvidenceKind::Sensor,
            confidence: 0.92,
            digest: digest_bytes(b"water=5.2"),
            excerpt: Some("water=5.2".to_owned()),
        }
    }

    #[test]
    fn builds_and_verifies_bundle() {
        let item = sample_item();
        let bundle = EvidenceBundle::new(
            "flood-watch",
            vec![item],
            Recommendation {
                action: "declare_incident".to_owned(),
                subject: "river-east".to_owned(),
                rationale: "Gauge exceeded incident threshold.".to_owned(),
                confidence: 0.88,
                evidence_ids: vec!["sensor-1".to_owned()],
            },
        )
        .unwrap();

        bundle.verify().unwrap();
    }

    #[test]
    fn detects_bundle_tampering() {
        let item = sample_item();
        let mut bundle = EvidenceBundle::new(
            "flood-watch",
            vec![item],
            Recommendation {
                action: "declare_incident".to_owned(),
                subject: "river-east".to_owned(),
                rationale: "Gauge exceeded incident threshold.".to_owned(),
                confidence: 0.88,
                evidence_ids: vec!["sensor-1".to_owned()],
            },
        )
        .unwrap();
        bundle.recommendation.subject = "river-west".to_owned();

        assert!(matches!(bundle.verify(), Err(EvidenceError::HashMismatch)));
    }
}
