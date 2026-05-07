use astragrid_approvals::{ApprovalItem, ApprovalStatus};
use astragrid_core::{MissionEvent, Priority};
use astragrid_evidence::EvidenceBundle;
use astragrid_state::MissionStateSummary;
use astragrid_store::StoreSummary;
use astragrid_sync_queue::{
    PeerSyncJob, QueueHealthSnapshot, QueueHealthStatus, QueueStatus, QueueSummary,
};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DashboardDocument {
    pub title: String,
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
    pub state: MissionStateSummary,
    pub store: Option<StoreSummary>,
    pub recent_events: Vec<MissionEvent>,
    pub approvals: Vec<ApprovalItem>,
    pub peer_queue: Option<QueueSummary>,
    pub peer_health: Option<QueueHealthSnapshot>,
    pub peer_jobs: Vec<PeerSyncJob>,
    pub evidence_bundles: Vec<EvidenceBundle>,
    pub audit_timeline: Vec<AuditTimelineItem>,
    pub map_href: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditTimelineItem {
    #[serde(with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
    pub source: AuditTimelineSource,
    pub severity: AuditTimelineSeverity,
    pub title: String,
    pub subject: String,
    pub actor: String,
    pub detail: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditTimelineSource {
    MissionEvent,
    Approval,
    PeerSync,
    Evidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditTimelineSeverity {
    Info,
    Warning,
    Critical,
}

impl DashboardDocument {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        title: impl Into<String>,
        state: MissionStateSummary,
        store: Option<StoreSummary>,
        recent_events: Vec<MissionEvent>,
        approvals: Vec<ApprovalItem>,
        peer_queue: Option<QueueSummary>,
        peer_health: Option<QueueHealthSnapshot>,
        peer_jobs: Vec<PeerSyncJob>,
        evidence_bundles: Vec<EvidenceBundle>,
        map_href: Option<String>,
    ) -> Result<Self, DashboardError> {
        let title = title.into();
        if title.trim().is_empty() {
            return Err(DashboardError::EmptyTitle);
        }
        for bundle in &evidence_bundles {
            bundle.verify()?;
        }
        let audit_timeline =
            build_audit_timeline(&recent_events, &approvals, &peer_jobs, &evidence_bundles);
        Ok(Self {
            title,
            generated_at: OffsetDateTime::now_utc(),
            state,
            store,
            recent_events,
            approvals,
            peer_queue,
            peer_health,
            peer_jobs,
            evidence_bundles,
            audit_timeline,
            map_href,
        })
    }

    pub fn to_html(&self) -> String {
        let mut html = String::new();
        html.push_str("<!doctype html>\n<html lang=\"en\">\n<head>\n");
        html.push_str("<meta charset=\"utf-8\">\n");
        html.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
        html.push_str(&format!("<title>{}</title>\n", escape_html(&self.title)));
        html.push_str("<style>\n");
        html.push_str(
            "body{margin:0;background:#f4f6f8;color:#17202a;font:14px/1.45 system-ui,-apple-system,Segoe UI,sans-serif}\
             header{background:#142f4a;color:#fff;padding:22px 26px;border-bottom:4px solid #2f855a}\
             h1{font-size:26px;margin:0 0 7px;letter-spacing:0}\
             h2{font-size:16px;margin:0 0 12px;color:#142f4a;letter-spacing:0}\
             h3{font-size:13px;margin:12px 0 8px;color:#52616f;text-transform:uppercase;letter-spacing:0}\
             p{margin:0;color:#dbe7f3}\
             main{padding:18px;display:grid;gap:16px;max-width:1480px;margin:0 auto}\
             .grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}\
             .two{display:grid;grid-template-columns:minmax(0,1.2fr) minmax(340px,.8fr);gap:16px}\
             section,.metric{background:#fff;border:1px solid #d7dde5;border-radius:6px;padding:14px;box-shadow:0 1px 2px rgba(15,23,42,.04)}\
             .banner{display:flex;gap:12px;align-items:center;justify-content:space-between;background:#fff;border-left:5px solid #2f855a}\
             .banner.degraded{border-left-color:#b7791f}.banner.failing{border-left-color:#c53030}\
             .banner strong{font-size:18px;color:#142f4a}.banner span{color:#52616f}\
             .metric strong{display:block;font-size:26px;color:#1f6f54}\
             .metric span{display:block;color:#52616f}\
             table{width:100%;border-collapse:collapse}\
             th,td{padding:8px 9px;border-bottom:1px solid #e5eaf0;text-align:left;vertical-align:top}\
             th{font-size:12px;text-transform:uppercase;color:#52616f;background:#f0f4f8;letter-spacing:0}\
             code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px}\
             .pill{display:inline-block;border-radius:999px;padding:2px 8px;font-size:12px;background:#e6f4ea;color:#1f6f54}\
             .warn{background:#fff4df;color:#8a4b13}\
             .bad{background:#fde8e8;color:#9b1c1c}\
             .muted{color:#687787}\
             .hash{max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}\
             .timeline{display:grid;gap:10px}\
             .timeline-item{display:grid;grid-template-columns:170px 110px minmax(0,1fr);gap:12px;align-items:start;border-top:1px solid #e5eaf0;padding-top:10px}\
             .timeline-item:first-child{border-top:0;padding-top:0}\
             .timeline-time{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px;color:#52616f}\
             .timeline-title{font-weight:650;color:#142f4a}.timeline-detail{color:#52616f;margin-top:2px}\
             .source{display:inline-block;border:1px solid #cbd5df;border-radius:999px;padding:2px 8px;font-size:12px;color:#35495e;background:#f7fafc}\
             .sev-warning{border-color:#d69e2e;color:#8a4b13;background:#fffaf0}.sev-critical{border-color:#c53030;color:#9b1c1c;background:#fff5f5}\
             .errors{margin-top:12px}\
             a{color:#1167b1}\
             @media(max-width:980px){.grid,.two,.timeline-item{grid-template-columns:1fr}main{padding:12px}header{padding:16px}}\n",
        );
        html.push_str("</style>\n</head>\n<body>\n");
        html.push_str(&format!(
            "<header><h1>{}</h1><p>Generated {}. Source ledger hash {}.</p></header>\n",
            escape_html(&self.title),
            escape_html(&self.generated_at.to_string()),
            self.state
                .last_hash
                .as_deref()
                .map(short_hash)
                .unwrap_or("none")
        ));
        html.push_str("<main>\n");
        html.push_str(&self.status_banner_html());
        html.push_str(&self.metrics_html());
        html.push_str(&self.audit_timeline_html());
        html.push_str("<div class=\"two\">\n");
        html.push_str(&self.events_html());
        html.push_str(&self.approvals_html());
        html.push_str("</div>\n<div class=\"two\">\n");
        html.push_str(&self.peer_queue_html());
        html.push_str(&self.evidence_html());
        html.push_str("</div>\n");
        html.push_str("</main>\n</body>\n</html>\n");
        html
    }

    fn metrics_html(&self) -> String {
        let event_count = self
            .store
            .as_ref()
            .map(|store| store.event_count)
            .unwrap_or(self.state.events as u64);
        let peer_work = self
            .peer_health
            .as_ref()
            .map(|health| health.due as u64)
            .or_else(|| {
                self.peer_queue
                    .as_ref()
                    .map(|queue| queue.pending + queue.retrying)
            })
            .unwrap_or(0);
        format!(
            "<section class=\"grid\" aria-label=\"Mission metrics\">\
             <div class=\"metric\"><strong>{}</strong><span>Events</span></div>\
             <div class=\"metric\"><strong>{}</strong><span>Open incidents</span></div>\
             <div class=\"metric\"><strong>{}</strong><span>Closed incidents</span></div>\
             <div class=\"metric\"><strong>{}</strong><span>Peer work due</span></div>\
             </section>\n",
            event_count, self.state.open_incidents, self.state.closed_incidents, peer_work
        )
    }

    fn status_banner_html(&self) -> String {
        let (class, label, detail) = match &self.peer_health {
            Some(health) => {
                let (class, label) = match health.status {
                    QueueHealthStatus::Healthy => ("banner", "Healthy"),
                    QueueHealthStatus::Degraded => ("banner degraded", "Degraded"),
                    QueueHealthStatus::Failing => ("banner failing", "Failing"),
                };
                (
                    class,
                    label,
                    format!(
                        "{} total peer job(s), {} due, {} stale retrying, {} recent error(s)",
                        health.summary.total,
                        health.due,
                        health.stale_retrying,
                        health.last_errors.len()
                    ),
                )
            }
            None => (
                "banner",
                "Snapshot",
                "Peer health was not loaded for this dashboard.".to_owned(),
            ),
        };
        format!(
            "<section class=\"{}\"><div><strong>{}</strong><br><span>{}</span></div><div class=\"muted\">Mission {}</div></section>\n",
            class,
            label,
            escape_html(&detail),
            escape_html(self.state.mission.as_deref().unwrap_or("unknown"))
        )
    }

    fn events_html(&self) -> String {
        let mut html = String::from(
            "<section><h2>Recent Events</h2><table><thead><tr><th>Seq</th><th>Action</th><th>Subject</th><th>Actor</th><th>Hash</th></tr></thead><tbody>",
        );
        if self.recent_events.is_empty() {
            html.push_str("<tr><td colspan=\"5\" class=\"muted\">No events loaded.</td></tr>");
        }
        for event in &self.recent_events {
            html.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td class=\"hash\"><code>{}</code></td></tr>",
                event.sequence,
                escape_html(&event.action.to_string()),
                escape_html(&event.subject),
                escape_html(&event.actor.name),
                short_hash(&event.hash)
            ));
        }
        html.push_str("</tbody></table></section>\n");
        html
    }

    fn approvals_html(&self) -> String {
        let mut html = String::from(
            "<section><h2>Approvals</h2><table><thead><tr><th>ID</th><th>Status</th><th>Subject</th><th>Reviewer</th></tr></thead><tbody>",
        );
        if self.approvals.is_empty() {
            html.push_str("<tr><td colspan=\"4\" class=\"muted\">No approvals loaded.</td></tr>");
        }
        for approval in &self.approvals {
            let subject = approval
                .draft
                .request
                .as_ref()
                .map(|request| request.subject.as_str())
                .unwrap_or("none");
            html.push_str(&format!(
                "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td></tr>",
                escape_html(&approval.id),
                status_pill(approval.status),
                escape_html(subject),
                escape_html(approval.reviewed_by.as_deref().unwrap_or("pending"))
            ));
        }
        html.push_str("</tbody></table></section>\n");
        html
    }

    fn audit_timeline_html(&self) -> String {
        let mut html =
            String::from("<section><h2>Operator Audit Timeline</h2><div class=\"timeline\">");
        if self.audit_timeline.is_empty() {
            html.push_str("<div class=\"muted\">No audit activity loaded.</div>");
        }
        for item in &self.audit_timeline {
            let reference = item
                .reference
                .as_deref()
                .map(short_hash)
                .map(|reference| format!(" <code>{}</code>", escape_html(reference)))
                .unwrap_or_default();
            html.push_str(&format!(
                "<div class=\"timeline-item\"><div class=\"timeline-time\">{}</div><div>{}</div><div><div class=\"timeline-title\">{}{} <span class=\"muted\">{}</span></div><div class=\"timeline-detail\">{} by {}. {}</div></div></div>",
                escape_html(&item.timestamp.to_string()),
                timeline_source_badge(item.source, item.severity),
                escape_html(&item.title),
                reference,
                escape_html(&item.subject),
                escape_html(&item.detail),
                escape_html(&item.actor),
                source_label(item.source)
            ));
        }
        html.push_str("</div></section>\n");
        html
    }

    fn peer_queue_html(&self) -> String {
        let mut html = String::from("<section><h2>Peer Queue</h2>");
        if let Some(summary) = &self.peer_queue {
            html.push_str(&format!(
                "<p class=\"muted\">total {}, pending {}, retrying {}, succeeded {}, failed {}</p>",
                summary.total, summary.pending, summary.retrying, summary.succeeded, summary.failed
            ));
        }
        if let Some(health) = &self.peer_health {
            html.push_str(&format!(
                "<p class=\"muted\">health {}, due {}, stale retrying {}, checked {}</p>",
                queue_health_label(health.status),
                health.due,
                health.stale_retrying,
                escape_html(&health.checked_at.to_string())
            ));
        }
        html.push_str("<table><thead><tr><th>Peer</th><th>Status</th><th>Attempts</th><th>Last error</th></tr></thead><tbody>");
        if self.peer_jobs.is_empty() {
            html.push_str("<tr><td colspan=\"4\" class=\"muted\">No peer jobs loaded.</td></tr>");
        }
        for job in &self.peer_jobs {
            html.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}/{}</td><td>{}</td></tr>",
                escape_html(&job.peer.name),
                queue_status_pill(job.status),
                job.attempts,
                job.max_attempts,
                escape_html(job.last_error.as_deref().unwrap_or(""))
            ));
        }
        html.push_str("</tbody></table>");
        if let Some(health) = &self.peer_health
            && !health.last_errors.is_empty()
        {
            html.push_str("<div class=\"errors\"><h3>Recent Peer Errors</h3><table><thead><tr><th>Peer</th><th>Status</th><th>Error</th></tr></thead><tbody>");
            for error in &health.last_errors {
                html.push_str(&format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                    escape_html(&error.peer_name),
                    queue_status_pill(error.status),
                    escape_html(&error.error)
                ));
            }
            html.push_str("</tbody></table></div>");
        }
        html.push_str("</section>\n");
        html
    }

    fn evidence_html(&self) -> String {
        let mut html = String::from(
            "<section><h2>Evidence</h2><table><thead><tr><th>Bundle</th><th>Action</th><th>Subject</th><th>Items</th></tr></thead><tbody>",
        );
        if self.evidence_bundles.is_empty() {
            html.push_str(
                "<tr><td colspan=\"4\" class=\"muted\">No evidence bundles loaded.</td></tr>",
            );
        }
        for bundle in &self.evidence_bundles {
            html.push_str(&format!(
                "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td></tr>",
                short_hash(&bundle.bundle_hash),
                escape_html(&bundle.recommendation.action),
                escape_html(&bundle.recommendation.subject),
                bundle.evidence.len()
            ));
        }
        if let Some(map_href) = &self.map_href {
            html.push_str(&format!(
                "<tr><td colspan=\"4\"><a href=\"{}\">Open feature map</a></td></tr>",
                escape_html(map_href)
            ));
        }
        html.push_str("</tbody></table></section>\n");
        html
    }
}

fn build_audit_timeline(
    events: &[MissionEvent],
    approvals: &[ApprovalItem],
    peer_jobs: &[PeerSyncJob],
    evidence_bundles: &[EvidenceBundle],
) -> Vec<AuditTimelineItem> {
    let mut items = Vec::new();
    for event in events {
        let signed = if event.attestation.is_some() {
            "signed"
        } else {
            "unsigned"
        };
        items.push(AuditTimelineItem {
            timestamp: event.occurred_at,
            source: AuditTimelineSource::MissionEvent,
            severity: severity_for_priority(event.priority),
            title: event.action.to_string(),
            subject: event.subject.clone(),
            actor: format!("{} ({})", event.actor.name, event.actor.role),
            detail: format!(
                "{} priority, sequence {}, {} event",
                event.priority, event.sequence, signed
            ),
            reference: Some(event.hash.clone()),
        });
    }

    for approval in approvals {
        let (timestamp, actor, detail) = match approval.status {
            ApprovalStatus::Executed => (
                approval.executed_at.unwrap_or(approval.submitted_at),
                approval.executed_by.as_deref().unwrap_or("unknown"),
                format!(
                    "approval executed; draft {}",
                    short_hash(&approval.draft_hash)
                ),
            ),
            ApprovalStatus::Approved | ApprovalStatus::Rejected => (
                approval.reviewed_at.unwrap_or(approval.submitted_at),
                approval.reviewed_by.as_deref().unwrap_or("unknown"),
                format!(
                    "approval {}; draft {}",
                    approval.status,
                    short_hash(&approval.draft_hash)
                ),
            ),
            ApprovalStatus::Pending => (
                approval.submitted_at,
                approval.submitted_by.as_str(),
                format!(
                    "approval pending; draft {}",
                    short_hash(&approval.draft_hash)
                ),
            ),
        };
        let subject = approval
            .draft
            .request
            .as_ref()
            .map(|request| request.subject.clone())
            .unwrap_or_else(|| "no command request".to_owned());
        items.push(AuditTimelineItem {
            timestamp,
            source: AuditTimelineSource::Approval,
            severity: severity_for_approval(approval.status),
            title: format!("approval {}", approval.status),
            subject,
            actor: actor.to_owned(),
            detail,
            reference: approval
                .ledger_event_hash
                .clone()
                .or_else(|| Some(approval.last_record_hash.clone())),
        });
    }

    for job in peer_jobs {
        let error_detail = job
            .last_error
            .as_deref()
            .map(|error| format!("; last error: {error}"))
            .unwrap_or_default();
        items.push(AuditTimelineItem {
            timestamp: job.updated_at,
            source: AuditTimelineSource::PeerSync,
            severity: severity_for_queue(job.status),
            title: format!("peer sync {}", job.status),
            subject: job.peer.name.clone(),
            actor: "peer queue".to_owned(),
            detail: format!(
                "attempts {}/{}; next attempt {}{}",
                job.attempts, job.max_attempts, job.next_attempt_at, error_detail
            ),
            reference: Some(job.id.clone()),
        });
    }

    for bundle in evidence_bundles {
        items.push(AuditTimelineItem {
            timestamp: bundle.created_at,
            source: AuditTimelineSource::Evidence,
            severity: AuditTimelineSeverity::Info,
            title: format!("evidence {}", bundle.recommendation.action),
            subject: bundle.recommendation.subject.clone(),
            actor: "evidence pipeline".to_owned(),
            detail: format!(
                "{} evidence item(s), confidence {:.2}",
                bundle.evidence.len(),
                bundle.recommendation.confidence
            ),
            reference: Some(bundle.bundle_hash.clone()),
        });
    }

    items.sort_by(|left, right| {
        right
            .timestamp
            .cmp(&left.timestamp)
            .then_with(|| source_label(left.source).cmp(source_label(right.source)))
            .then_with(|| left.title.cmp(&right.title))
    });
    items.truncate(80);
    items
}

fn severity_for_priority(priority: Priority) -> AuditTimelineSeverity {
    match priority {
        Priority::Routine => AuditTimelineSeverity::Info,
        Priority::Elevated => AuditTimelineSeverity::Warning,
        Priority::Critical => AuditTimelineSeverity::Critical,
    }
}

fn severity_for_approval(status: ApprovalStatus) -> AuditTimelineSeverity {
    match status {
        ApprovalStatus::Pending => AuditTimelineSeverity::Warning,
        ApprovalStatus::Approved | ApprovalStatus::Executed => AuditTimelineSeverity::Info,
        ApprovalStatus::Rejected => AuditTimelineSeverity::Critical,
    }
}

fn severity_for_queue(status: QueueStatus) -> AuditTimelineSeverity {
    match status {
        QueueStatus::Pending | QueueStatus::Retrying => AuditTimelineSeverity::Warning,
        QueueStatus::Succeeded => AuditTimelineSeverity::Info,
        QueueStatus::Failed => AuditTimelineSeverity::Critical,
    }
}

fn source_label(source: AuditTimelineSource) -> &'static str {
    match source {
        AuditTimelineSource::MissionEvent => "mission event",
        AuditTimelineSource::Approval => "approval",
        AuditTimelineSource::PeerSync => "peer sync",
        AuditTimelineSource::Evidence => "evidence",
    }
}

fn timeline_source_badge(source: AuditTimelineSource, severity: AuditTimelineSeverity) -> String {
    let class = match severity {
        AuditTimelineSeverity::Info => "source",
        AuditTimelineSeverity::Warning => "source sev-warning",
        AuditTimelineSeverity::Critical => "source sev-critical",
    };
    format!("<span class=\"{class}\">{}</span>", source_label(source))
}

#[derive(Debug, thiserror::Error)]
pub enum DashboardError {
    #[error("dashboard title cannot be empty")]
    EmptyTitle,
    #[error("evidence bundle failed: {0}")]
    Evidence(#[from] astragrid_evidence::EvidenceError),
}

fn status_pill(status: ApprovalStatus) -> String {
    let class = match status {
        ApprovalStatus::Pending => "pill warn",
        ApprovalStatus::Approved => "pill",
        ApprovalStatus::Rejected => "pill bad",
        ApprovalStatus::Executed => "pill",
    };
    format!("<span class=\"{class}\">{}</span>", status)
}

fn queue_status_pill(status: QueueStatus) -> String {
    let class = match status {
        QueueStatus::Pending | QueueStatus::Retrying => "pill warn",
        QueueStatus::Succeeded => "pill",
        QueueStatus::Failed => "pill bad",
    };
    format!("<span class=\"{class}\">{}</span>", status)
}

fn queue_health_label(status: QueueHealthStatus) -> &'static str {
    match status {
        QueueHealthStatus::Healthy => "healthy",
        QueueHealthStatus::Degraded => "degraded",
        QueueHealthStatus::Failing => "failing",
    }
}

fn short_hash(hash: &str) -> &str {
    hash.get(..12).unwrap_or(hash)
}

fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use astragrid_core::{Action, Actor, MissionEvent, Priority, Role};
    use astragrid_net::PeerEndpoint;
    use astragrid_state::MissionStateSummary;
    use time::Duration;

    use super::*;

    #[test]
    fn renders_dashboard_with_escaped_title() {
        let document = DashboardDocument::new(
            "A < B",
            MissionStateSummary {
                mission: Some("mission".to_owned()),
                events: 2,
                open_incidents: 1,
                closed_incidents: 0,
                observations: 0,
                dispatches: 0,
                annotations: 0,
                last_hash: Some("abcdef1234567890".to_owned()),
            },
            None,
            Vec::new(),
            Vec::new(),
            None,
            None,
            Vec::new(),
            Vec::new(),
            Some("features.html".to_owned()),
        )
        .unwrap();

        let html = document.to_html();

        assert!(html.contains("A &lt; B"));
        assert!(html.contains("Open incidents"));
        assert!(html.contains("features.html"));
        assert!(!html.contains("<script>"));
    }

    #[test]
    fn rejects_empty_title() {
        assert!(matches!(
            DashboardDocument::new(
                "",
                MissionStateSummary {
                    mission: None,
                    events: 0,
                    open_incidents: 0,
                    closed_incidents: 0,
                    observations: 0,
                    dispatches: 0,
                    annotations: 0,
                    last_hash: None,
                },
                None,
                Vec::new(),
                Vec::new(),
                None,
                None,
                Vec::new(),
                Vec::new(),
                None,
            ),
            Err(DashboardError::EmptyTitle)
        ));
    }

    #[test]
    fn renders_peer_health_and_escapes_errors() {
        use astragrid_sync_queue::QueueLastError;

        let document = DashboardDocument::new(
            "Ops",
            MissionStateSummary {
                mission: Some("mission-alpha".to_owned()),
                events: 4,
                open_incidents: 1,
                closed_incidents: 1,
                observations: 2,
                dispatches: 0,
                annotations: 0,
                last_hash: None,
            },
            None,
            Vec::new(),
            Vec::new(),
            Some(QueueSummary {
                schema_version: 1,
                total: 3,
                pending: 1,
                retrying: 1,
                succeeded: 1,
                failed: 0,
            }),
            Some(QueueHealthSnapshot {
                schema_version: 1,
                status: QueueHealthStatus::Degraded,
                checked_at: OffsetDateTime::UNIX_EPOCH,
                summary: QueueSummary {
                    schema_version: 1,
                    total: 3,
                    pending: 1,
                    retrying: 1,
                    succeeded: 1,
                    failed: 0,
                },
                due: 2,
                stale_retrying: 1,
                last_errors: vec![QueueLastError {
                    job_id: "job-1".to_owned(),
                    peer_name: "peer-west".to_owned(),
                    status: QueueStatus::Retrying,
                    attempts: 2,
                    max_attempts: 3,
                    updated_at: OffsetDateTime::UNIX_EPOCH,
                    error: "network <timeout>".to_owned(),
                }],
            }),
            Vec::new(),
            Vec::new(),
            None,
        )
        .unwrap();

        let html = document.to_html();

        assert!(html.contains("Degraded"));
        assert!(html.contains("Peer work due"));
        assert!(html.contains("Recent Peer Errors"));
        assert!(html.contains("network &lt;timeout&gt;"));
    }

    #[test]
    fn renders_operator_audit_timeline_from_loaded_artifacts() {
        let mut routine = MissionEvent::new(
            1,
            Actor::new("observer", Role::Observer),
            Action::RecordObservation,
            "river-east",
            Priority::Routine,
            serde_json::json!({"note": "normal"}),
            None,
        )
        .unwrap();
        routine.occurred_at = OffsetDateTime::UNIX_EPOCH + Duration::seconds(10);

        let mut critical = MissionEvent::new(
            2,
            Actor::new("lead", Role::IncidentCommander),
            Action::DeclareIncident,
            "river <east>",
            Priority::Critical,
            serde_json::json!({"water_level_m": 5.2}),
            Some(routine.hash.clone()),
        )
        .unwrap();
        critical.occurred_at = OffsetDateTime::UNIX_EPOCH + Duration::seconds(30);

        let peer_job = PeerSyncJob {
            id: "agsq_test".to_owned(),
            peer: PeerEndpoint {
                name: "peer <west>".to_owned(),
                addr: "127.0.0.1:17655".to_owned(),
            },
            status: QueueStatus::Retrying,
            attempts: 2,
            max_attempts: 3,
            created_at: OffsetDateTime::UNIX_EPOCH,
            updated_at: OffsetDateTime::UNIX_EPOCH + Duration::seconds(20),
            next_attempt_at: OffsetDateTime::UNIX_EPOCH + Duration::seconds(60),
            last_error: Some("network <down>".to_owned()),
            last_plan: None,
            last_apply: None,
        };

        let document = DashboardDocument::new(
            "Ops",
            MissionStateSummary {
                mission: Some("mission-alpha".to_owned()),
                events: 2,
                open_incidents: 1,
                closed_incidents: 0,
                observations: 1,
                dispatches: 0,
                annotations: 0,
                last_hash: Some(critical.hash.clone()),
            },
            None,
            vec![routine, critical],
            Vec::new(),
            None,
            None,
            vec![peer_job],
            Vec::new(),
            None,
        )
        .unwrap();

        assert_eq!(document.audit_timeline.len(), 3);
        assert_eq!(
            document.audit_timeline[0].source,
            AuditTimelineSource::MissionEvent
        );
        assert_eq!(
            document.audit_timeline[0].severity,
            AuditTimelineSeverity::Critical
        );

        let html = document.to_html();

        assert!(html.contains("Operator Audit Timeline"));
        assert!(html.contains("declare_incident"));
        assert!(html.contains("river &lt;east&gt;"));
        assert!(html.contains("peer &lt;west&gt;"));
        assert!(html.contains("network &lt;down&gt;"));
        assert!(html.contains("sev-critical"));
    }
}
