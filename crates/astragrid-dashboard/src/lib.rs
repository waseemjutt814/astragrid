use astragrid_approvals::{ApprovalItem, ApprovalStatus};
use astragrid_core::MissionEvent;
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
    pub map_href: Option<String>,
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
             .errors{margin-top:12px}\
             a{color:#1167b1}\
             @media(max-width:980px){.grid,.two{grid-template-columns:1fr}main{padding:12px}header{padding:16px}}\n",
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
    use astragrid_state::MissionStateSummary;

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
}
