use astragrid_evidence::{
    EvidenceBundle, EvidenceError, EvidenceItem, EvidenceKind, Recommendation, digest_bytes,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecommendationRule {
    pub id: String,
    pub mission: String,
    pub source: Option<String>,
    pub subject: String,
    pub metric: String,
    pub operator: ThresholdOperator,
    pub threshold: f64,
    pub action: String,
    pub rationale: String,
    #[serde(default = "default_min_confidence")]
    pub min_confidence: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThresholdOperator {
    GreaterThan,
    GreaterOrEqual,
    LessThan,
    LessOrEqual,
    Equal,
}

impl ThresholdOperator {
    fn matches(self, value: f64, threshold: f64) -> bool {
        match self {
            Self::GreaterThan => value > threshold,
            Self::GreaterOrEqual => value >= threshold,
            Self::LessThan => value < threshold,
            Self::LessOrEqual => value <= threshold,
            Self::Equal => (value - threshold).abs() <= f64::EPSILON,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SensorReading {
    pub id: String,
    pub source: String,
    pub subject: String,
    pub metric: String,
    pub value: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    pub confidence: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecommendationRunReport {
    pub rules: usize,
    pub readings: usize,
    pub bundles: Vec<EvidenceBundle>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelRecommendationCandidate {
    pub action: String,
    pub subject: String,
    pub rationale: String,
    pub confidence: f64,
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelRecommendationReport {
    pub mission: String,
    pub candidates: usize,
    pub evidence_items: usize,
    pub bundles: Vec<EvidenceBundle>,
}

pub fn run_recommendation_rules(
    rules: &[RecommendationRule],
    readings: &[SensorReading],
) -> Result<RecommendationRunReport, RecommendError> {
    validate_rules(rules)?;
    validate_readings(readings)?;

    let mut bundles = Vec::new();
    for rule in rules {
        let matched = readings
            .iter()
            .filter(|reading| rule_matches_reading(rule, reading))
            .collect::<Vec<_>>();
        if matched.is_empty() {
            continue;
        }

        let evidence = matched
            .iter()
            .map(|reading| evidence_from_reading(rule, reading))
            .collect::<Result<Vec<_>, _>>()?;
        let confidence = evidence
            .iter()
            .map(|item| item.confidence)
            .fold(1.0_f64, f64::min);
        if confidence < rule.min_confidence {
            continue;
        }

        let bundle = EvidenceBundle::new(
            rule.mission.clone(),
            evidence,
            Recommendation {
                action: rule.action.clone(),
                subject: rule.subject.clone(),
                rationale: render_rationale(rule, &matched),
                confidence,
                evidence_ids: matched
                    .iter()
                    .map(|reading| evidence_id(rule, reading))
                    .collect(),
            },
        )?;
        bundle.verify()?;
        bundles.push(bundle);
    }

    Ok(RecommendationRunReport {
        rules: rules.len(),
        readings: readings.len(),
        bundles,
    })
}

pub fn build_model_recommendation_bundles(
    mission: impl Into<String>,
    evidence: &[EvidenceItem],
    candidates: &[ModelRecommendationCandidate],
) -> Result<ModelRecommendationReport, RecommendError> {
    let mission = mission.into();
    if mission.trim().is_empty() {
        return Err(RecommendError::EmptyMission);
    }
    if candidates.is_empty() {
        return Err(RecommendError::NoModelCandidates);
    }
    validate_model_candidates(candidates)?;

    let mut bundles = Vec::new();
    for candidate in candidates {
        let evidence = candidate
            .evidence_ids
            .iter()
            .map(|id| {
                evidence
                    .iter()
                    .find(|item| item.id == *id)
                    .cloned()
                    .ok_or_else(|| RecommendError::UnknownModelEvidence(id.clone()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let bundle = EvidenceBundle::new(
            mission.clone(),
            evidence,
            Recommendation {
                action: candidate.action.clone(),
                subject: candidate.subject.clone(),
                rationale: candidate.rationale.clone(),
                confidence: candidate.confidence,
                evidence_ids: candidate.evidence_ids.clone(),
            },
        )?;
        bundle.verify()?;
        bundles.push(bundle);
    }

    Ok(ModelRecommendationReport {
        mission,
        candidates: candidates.len(),
        evidence_items: evidence.len(),
        bundles,
    })
}

fn rule_matches_reading(rule: &RecommendationRule, reading: &SensorReading) -> bool {
    if let Some(source) = &rule.source
        && source != &reading.source
    {
        return false;
    }
    rule.subject == reading.subject
        && rule.metric == reading.metric
        && rule.operator.matches(reading.value, rule.threshold)
}

fn evidence_from_reading(
    rule: &RecommendationRule,
    reading: &SensorReading,
) -> Result<EvidenceItem, RecommendError> {
    let payload = serde_json::to_vec(reading)?;
    Ok(EvidenceItem {
        id: evidence_id(rule, reading),
        source: reading.source.clone(),
        kind: EvidenceKind::Sensor,
        confidence: reading.confidence,
        digest: digest_bytes(&payload),
        excerpt: Some(format!(
            "{}={}{} for {}",
            reading.metric,
            reading.value,
            reading
                .unit
                .as_ref()
                .map(|unit| format!(" {unit}"))
                .unwrap_or_default(),
            reading.subject
        )),
    })
}

fn evidence_id(rule: &RecommendationRule, reading: &SensorReading) -> String {
    format!("{}:{}", rule.id, reading.id)
}

fn render_rationale(rule: &RecommendationRule, matched: &[&SensorReading]) -> String {
    let max_value = matched
        .iter()
        .map(|reading| reading.value)
        .fold(f64::NEG_INFINITY, f64::max);
    format!(
        "{} Matched {} reading(s); peak {} was {:.3} against threshold {:.3}.",
        rule.rationale,
        matched.len(),
        rule.metric,
        max_value,
        rule.threshold
    )
}

fn validate_rules(rules: &[RecommendationRule]) -> Result<(), RecommendError> {
    if rules.is_empty() {
        return Err(RecommendError::NoRules);
    }
    for rule in rules {
        if rule.id.trim().is_empty() {
            return Err(RecommendError::EmptyRuleField("id"));
        }
        if rule.mission.trim().is_empty() {
            return Err(RecommendError::EmptyRuleField("mission"));
        }
        if rule.subject.trim().is_empty() {
            return Err(RecommendError::EmptyRuleField("subject"));
        }
        if rule.metric.trim().is_empty() {
            return Err(RecommendError::EmptyRuleField("metric"));
        }
        if rule.action.trim().is_empty() {
            return Err(RecommendError::EmptyRuleField("action"));
        }
        if rule.rationale.trim().is_empty() {
            return Err(RecommendError::EmptyRuleField("rationale"));
        }
        validate_finite("threshold", rule.threshold)?;
        validate_confidence(rule.min_confidence)?;
    }
    Ok(())
}

fn validate_readings(readings: &[SensorReading]) -> Result<(), RecommendError> {
    if readings.is_empty() {
        return Err(RecommendError::NoReadings);
    }
    for reading in readings {
        if reading.id.trim().is_empty() {
            return Err(RecommendError::EmptyReadingField("id"));
        }
        if reading.source.trim().is_empty() {
            return Err(RecommendError::EmptyReadingField("source"));
        }
        if reading.subject.trim().is_empty() {
            return Err(RecommendError::EmptyReadingField("subject"));
        }
        if reading.metric.trim().is_empty() {
            return Err(RecommendError::EmptyReadingField("metric"));
        }
        validate_finite("value", reading.value)?;
        validate_confidence(reading.confidence)?;
        if let Some(observed_at) = &reading.observed_at {
            OffsetDateTime::parse(observed_at, &time::format_description::well_known::Rfc3339)?;
        }
    }
    Ok(())
}

fn validate_model_candidates(
    candidates: &[ModelRecommendationCandidate],
) -> Result<(), RecommendError> {
    for candidate in candidates {
        if candidate.action.trim().is_empty() {
            return Err(RecommendError::EmptyModelCandidateField("action"));
        }
        if candidate.subject.trim().is_empty() {
            return Err(RecommendError::EmptyModelCandidateField("subject"));
        }
        if candidate.rationale.trim().is_empty() {
            return Err(RecommendError::EmptyModelCandidateField("rationale"));
        }
        validate_confidence(candidate.confidence)?;
        if candidate.evidence_ids.is_empty() {
            return Err(RecommendError::ModelCandidateWithoutEvidence);
        }
    }
    Ok(())
}

fn validate_confidence(value: f64) -> Result<(), RecommendError> {
    if !(0.0..=1.0).contains(&value) || !value.is_finite() {
        return Err(RecommendError::InvalidConfidence(value));
    }
    Ok(())
}

fn validate_finite(name: &'static str, value: f64) -> Result<(), RecommendError> {
    if !value.is_finite() {
        return Err(RecommendError::NonFiniteNumber { name, value });
    }
    Ok(())
}

fn default_min_confidence() -> f64 {
    0.75
}

#[derive(Debug, thiserror::Error)]
pub enum RecommendError {
    #[error("recommendation JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("evidence bundle failed: {0}")]
    Evidence(#[from] EvidenceError),
    #[error("timestamp parsing failed: {0}")]
    Time(#[from] time::error::Parse),
    #[error("recommendation rule set is empty")]
    NoRules,
    #[error("sensor reading set is empty")]
    NoReadings,
    #[error("model recommendation candidate set is empty")]
    NoModelCandidates,
    #[error("mission cannot be empty")]
    EmptyMission,
    #[error("recommendation rule {0} cannot be empty")]
    EmptyRuleField(&'static str),
    #[error("sensor reading {0} cannot be empty")]
    EmptyReadingField(&'static str),
    #[error("model recommendation candidate {0} cannot be empty")]
    EmptyModelCandidateField(&'static str),
    #[error("model recommendation candidate must cite at least one evidence id")]
    ModelCandidateWithoutEvidence,
    #[error("model recommendation candidate references unknown evidence id {0}")]
    UnknownModelEvidence(String),
    #[error("invalid confidence {0}; expected 0.0 through 1.0")]
    InvalidConfidence(f64),
    #[error("{name} must be finite, got {value}")]
    NonFiniteNumber { name: &'static str, value: f64 },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule() -> RecommendationRule {
        RecommendationRule {
            id: "flood-threshold".to_owned(),
            mission: "flood-watch".to_owned(),
            source: Some("river-gauge".to_owned()),
            subject: "river-east".to_owned(),
            metric: "water_level_m".to_owned(),
            operator: ThresholdOperator::GreaterOrEqual,
            threshold: 5.0,
            action: "declare_incident".to_owned(),
            rationale: "Water level exceeded flood threshold.".to_owned(),
            min_confidence: 0.8,
        }
    }

    #[test]
    fn emits_verified_bundle_for_matching_reading() {
        let report = run_recommendation_rules(
            &[rule()],
            &[SensorReading {
                id: "reading-1".to_owned(),
                source: "river-gauge".to_owned(),
                subject: "river-east".to_owned(),
                metric: "water_level_m".to_owned(),
                value: 5.2,
                unit: Some("m".to_owned()),
                confidence: 0.92,
                observed_at: None,
            }],
        )
        .unwrap();

        assert_eq!(report.bundles.len(), 1);
        assert_eq!(report.bundles[0].recommendation.action, "declare_incident");
        report.bundles[0].verify().unwrap();
    }

    #[test]
    fn skips_non_matching_reading() {
        let report = run_recommendation_rules(
            &[rule()],
            &[SensorReading {
                id: "reading-1".to_owned(),
                source: "river-gauge".to_owned(),
                subject: "river-east".to_owned(),
                metric: "water_level_m".to_owned(),
                value: 4.2,
                unit: Some("m".to_owned()),
                confidence: 0.92,
                observed_at: None,
            }],
        )
        .unwrap();

        assert!(report.bundles.is_empty());
    }

    #[test]
    fn rejects_invalid_confidence() {
        let mut reading = SensorReading {
            id: "reading-1".to_owned(),
            source: "river-gauge".to_owned(),
            subject: "river-east".to_owned(),
            metric: "water_level_m".to_owned(),
            value: 5.2,
            unit: None,
            confidence: 1.5,
            observed_at: None,
        };

        assert!(matches!(
            run_recommendation_rules(&[rule()], std::slice::from_ref(&reading)),
            Err(RecommendError::InvalidConfidence(1.5))
        ));
        reading.confidence = 0.9;
        assert!(run_recommendation_rules(&[rule()], &[reading]).is_ok());
    }

    #[test]
    fn builds_bundles_from_structured_model_candidates() {
        let evidence = vec![EvidenceItem {
            id: "sensor-1".to_owned(),
            source: "river-gauge".to_owned(),
            kind: EvidenceKind::Sensor,
            confidence: 0.92,
            digest: digest_bytes(b"water=5.2"),
            excerpt: Some("water=5.2".to_owned()),
        }];
        let candidates = vec![ModelRecommendationCandidate {
            action: "declare_incident".to_owned(),
            subject: "river-east".to_owned(),
            rationale: "Gauge exceeded threshold.".to_owned(),
            confidence: 0.88,
            evidence_ids: vec!["sensor-1".to_owned()],
        }];

        let report =
            build_model_recommendation_bundles("flood-watch", &evidence, &candidates).unwrap();

        assert_eq!(report.bundles.len(), 1);
        report.bundles[0].verify().unwrap();
    }

    #[test]
    fn rejects_model_candidate_with_unknown_evidence() {
        let evidence = vec![EvidenceItem {
            id: "sensor-1".to_owned(),
            source: "river-gauge".to_owned(),
            kind: EvidenceKind::Sensor,
            confidence: 0.92,
            digest: digest_bytes(b"water=5.2"),
            excerpt: Some("water=5.2".to_owned()),
        }];
        let candidates = vec![ModelRecommendationCandidate {
            action: "declare_incident".to_owned(),
            subject: "river-east".to_owned(),
            rationale: "Gauge exceeded threshold.".to_owned(),
            confidence: 0.88,
            evidence_ids: vec!["missing".to_owned()],
        }];

        assert!(matches!(
            build_model_recommendation_bundles("flood-watch", &evidence, &candidates),
            Err(RecommendError::UnknownModelEvidence(id)) if id == "missing"
        ));
    }
}
