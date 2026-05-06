use astragrid_core::MissionEvent;
use astragrid_evidence::EvidenceBundle;
use astragrid_store::StoreSummary;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IncidentReport {
    pub title: String,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
    pub summary: StoreSummary,
    pub events: Vec<MissionEvent>,
    pub evidence_bundles: Vec<EvidenceBundle>,
}

impl IncidentReport {
    pub fn new(
        title: impl Into<String>,
        summary: StoreSummary,
        events: Vec<MissionEvent>,
        evidence_bundles: Vec<EvidenceBundle>,
    ) -> Self {
        Self {
            title: title.into(),
            generated_at: OffsetDateTime::now_utc(),
            summary,
            events,
            evidence_bundles,
        }
    }

    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("# {}\n\n", self.title));
        out.push_str(&format!("Generated: {}\n\n", self.generated_at));
        out.push_str("## Summary\n\n");
        out.push_str(&format!("- Events: {}\n", self.summary.event_count));
        out.push_str(&format!(
            "- Signed events: {}\n",
            self.summary.signed_event_count
        ));
        out.push_str(&format!(
            "- Critical events: {}\n",
            self.summary.critical_event_count
        ));
        if let Some(hash) = &self.summary.last_hash {
            out.push_str(&format!("- Last hash: `{hash}`\n"));
        }
        out.push_str("\n## Events\n\n");
        for event in &self.events {
            out.push_str(&format!(
                "- #{seq} `{action}` `{priority}` {subject} by {actor} hash `{hash}`\n",
                seq = event.sequence,
                action = event.action,
                priority = event.priority,
                subject = event.subject,
                actor = event.actor.name,
                hash = event.hash
            ));
        }
        if !self.evidence_bundles.is_empty() {
            out.push_str("\n## Evidence Bundles\n\n");
            for bundle in &self.evidence_bundles {
                out.push_str(&format!(
                    "- `{}` recommendation `{}` on `{}` using {} evidence items\n",
                    bundle.bundle_hash,
                    bundle.recommendation.action,
                    bundle.recommendation.subject,
                    bundle.evidence.len()
                ));
            }
        }
        out
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReportBundle {
    pub schema: u16,
    pub report: IncidentReport,
    pub markdown: String,
}

impl ReportBundle {
    pub fn new(report: IncidentReport) -> Self {
        let markdown = report.to_markdown();
        Self {
            schema: 1,
            report,
            markdown,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ReportError {
    #[error("report JSON failed: {0}")]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use astragrid_store::StoreSummary;

    use super::*;

    #[test]
    fn renders_markdown_summary() {
        let report = IncidentReport::new(
            "Flood Watch",
            StoreSummary {
                schema_version: 1,
                event_count: 2,
                signed_event_count: 1,
                critical_event_count: 1,
                last_hash: Some("abc".to_owned()),
            },
            Vec::new(),
            Vec::new(),
        );

        let markdown = report.to_markdown();

        assert!(markdown.contains("# Flood Watch"));
        assert!(markdown.contains("- Events: 2"));
    }

    #[test]
    fn builds_report_bundle_with_markdown() {
        let report = IncidentReport::new(
            "Flood Watch",
            StoreSummary {
                schema_version: 1,
                event_count: 1,
                signed_event_count: 1,
                critical_event_count: 0,
                last_hash: None,
            },
            Vec::new(),
            Vec::new(),
        );

        let bundle = ReportBundle::new(report);

        assert_eq!(bundle.schema, 1);
        assert!(bundle.markdown.contains("Flood Watch"));
    }
}
