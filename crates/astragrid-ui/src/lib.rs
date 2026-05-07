use astragrid_approvals::ApprovalStatus;
use astragrid_dashboard::DashboardDocument;
use astragrid_sync_queue::QueueHealthStatus;
use serde::Serialize;
use serde_json::json;

const OPERATOR_CONSOLE_SCHEMA: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorConsoleResponse {
    pub status: &'static str,
    pub content_type: &'static str,
    pub body: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum OperatorConsoleError {
    #[error("operator console JSON failed: {0}")]
    Json(#[from] serde_json::Error),
}

pub fn route_operator_console(
    document: &DashboardDocument,
    path: &str,
    refresh_seconds: u64,
    auth_token: Option<&str>,
) -> Result<OperatorConsoleResponse, OperatorConsoleError> {
    let normalized_path = normalized_path(path);
    if let Some(expected_token) = auth_token
        && !query_token_matches(path, expected_token)
    {
        return Ok(OperatorConsoleResponse {
            status: "401 Unauthorized",
            content_type: "application/json; charset=utf-8",
            body: br#"{"status":"unauthorized","detail":"operator console token is required"}"#
                .to_vec(),
        });
    }
    let request_token = auth_token.and_then(|_| query_value(path, "token"));
    match normalized_path {
        "/" | "/app" | "/console.html" => Ok(html_response(render_operator_console(
            document,
            refresh_seconds,
            request_token,
        ))),
        "/api/summary" => json_response(&operator_summary(document)),
        "/api/dashboard" => json_response(document),
        "/api/events" => json_response(&document.recent_events),
        "/api/approvals" => json_response(&document.approvals),
        "/api/audit" => json_response(&document.audit_timeline),
        "/api/peer-health" => json_response(&json!({
            "schema_version": OPERATOR_CONSOLE_SCHEMA,
            "queue": document.peer_queue,
            "health": document.peer_health,
            "jobs": document.peer_jobs,
        })),
        "/healthz" => json_response(&json!({
            "schema_version": OPERATOR_CONSOLE_SCHEMA,
            "status": "ok",
            "healthy": true,
            "generated_at": document.generated_at.to_string(),
            "mission": document.state.mission,
        })),
        _ => Ok(OperatorConsoleResponse {
            status: "404 Not Found",
            content_type: "text/plain; charset=utf-8",
            body: b"not found\n".to_vec(),
        }),
    }
}

pub fn render_operator_console(
    document: &DashboardDocument,
    refresh_seconds: u64,
    api_token: Option<&str>,
) -> String {
    let refresh_ms = refresh_seconds.saturating_mul(1000);
    let title = escape_html(&document.title);
    let api_token = api_token.map(escape_html).unwrap_or_default();
    let mission = document
        .state
        .mission
        .as_deref()
        .map(escape_html)
        .unwrap_or_else(|| "mission not set".to_owned());
    let generated_at = escape_html(&document.generated_at.to_string());
    let refresh_meta = if refresh_seconds == 0 {
        String::new()
    } else {
        format!("<meta http-equiv=\"refresh\" content=\"{refresh_seconds}\">\n")
    };

    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
{refresh_meta}<title>{title}</title>
<style>
:root {{
  color-scheme: light;
  --ink:#18212f;
  --muted:#657386;
  --line:#d8dee8;
  --panel:#ffffff;
  --wash:#f5f7fa;
  --brand:#16324f;
  --ok:#1f6f54;
  --warn:#9b5b10;
  --bad:#9b1c1c;
  --focus:#2f7dd1;
}}
* {{ box-sizing:border-box }}
body {{
  margin:0;
  background:var(--wash);
  color:var(--ink);
  font:14px/1.45 system-ui,-apple-system,Segoe UI,sans-serif;
}}
header {{
  background:var(--brand);
  color:#fff;
  border-bottom:4px solid var(--ok);
  padding:16px 22px;
}}
h1 {{ margin:0; font-size:22px; font-weight:700; letter-spacing:0 }}
h2 {{ margin:0 0 10px; font-size:15px; color:var(--brand); letter-spacing:0 }}
button {{ font:inherit }}
.topline {{ display:flex; flex-wrap:wrap; gap:8px 18px; margin-top:6px; color:#dbe7f3 }}
.shell {{
  width:min(1480px,100%);
  margin:0 auto;
  padding:16px;
  display:grid;
  grid-template-columns:250px minmax(0,1fr);
  gap:14px;
}}
.rail {{
  background:var(--panel);
  border:1px solid var(--line);
  border-radius:7px;
  padding:10px;
  align-self:start;
  position:sticky;
  top:12px;
}}
.rail button {{
  width:100%;
  min-height:38px;
  border:0;
  border-radius:5px;
  background:transparent;
  color:var(--ink);
  text-align:left;
  padding:8px 10px;
  cursor:pointer;
}}
.rail button[aria-selected="true"] {{
  background:#e9f2fc;
  color:#10375f;
  font-weight:700;
}}
.workspace {{ display:grid; gap:14px }}
.banner {{
  background:var(--panel);
  border:1px solid var(--line);
  border-left:5px solid var(--ok);
  border-radius:7px;
  padding:13px 14px;
  display:flex;
  justify-content:space-between;
  gap:14px;
  align-items:center;
}}
.banner.degraded {{ border-left-color:var(--warn) }}
.banner.failing {{ border-left-color:var(--bad) }}
.banner strong {{ display:block; font-size:17px; color:var(--brand) }}
.banner span {{ color:var(--muted) }}
.metrics {{
  display:grid;
  grid-template-columns:repeat(5,minmax(0,1fr));
  gap:10px;
}}
.metric,.panel {{
  background:var(--panel);
  border:1px solid var(--line);
  border-radius:7px;
  box-shadow:0 1px 2px rgba(15,23,42,.04);
}}
.metric {{ min-height:82px; padding:12px }}
.metric strong {{ display:block; font-size:25px; color:var(--ok) }}
.metric span {{ color:var(--muted) }}
.panel {{ padding:13px; min-width:0 }}
.split {{ display:grid; grid-template-columns:minmax(0,1.1fr) minmax(360px,.9fr); gap:14px }}
table {{ width:100%; border-collapse:collapse; table-layout:fixed }}
th,td {{ padding:8px 9px; border-bottom:1px solid #e7ebf1; text-align:left; vertical-align:top }}
th {{ font-size:12px; text-transform:uppercase; background:#f0f4f8; color:var(--muted); letter-spacing:0 }}
td {{ overflow-wrap:anywhere }}
code {{ font-family:ui-monospace,SFMono-Regular,Consolas,monospace; font-size:12px }}
.pill {{ display:inline-block; border-radius:999px; padding:2px 8px; font-size:12px; background:#e6f4ea; color:var(--ok) }}
.pill.warn {{ background:#fff4df; color:var(--warn) }}
.pill.bad {{ background:#fde8e8; color:var(--bad) }}
.muted {{ color:var(--muted) }}
.tab-panel[hidden] {{ display:none }}
.status-line {{
  min-height:28px;
  border:1px solid var(--line);
  border-radius:6px;
  background:#f9fbfd;
  color:var(--muted);
  padding:6px 9px;
}}
.map-link {{ color:#0f5ca8; font-weight:700; text-decoration:none }}
.map-link:focus,.rail button:focus {{ outline:2px solid var(--focus); outline-offset:2px }}
@media (max-width:980px) {{
  .shell {{ grid-template-columns:1fr }}
  .rail {{ position:static; display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:6px }}
  .metrics {{ grid-template-columns:repeat(2,minmax(0,1fr)) }}
  .split {{ grid-template-columns:1fr }}
}}
@media (max-width:560px) {{
  header {{ padding:14px }}
  .shell {{ padding:10px }}
  .rail {{ grid-template-columns:1fr }}
  .metrics {{ grid-template-columns:1fr }}
  th:nth-child(1),td:nth-child(1) {{ display:none }}
}}
</style>
</head>
<body>
<header>
  <h1>{title}</h1>
  <div class="topline"><span id="mission-name">{mission}</span><span id="generated-at">generated {generated_at}</span></div>
</header>
<main id="operator-console" class="shell" data-refresh-ms="{refresh_ms}" data-api-token="{api_token}">
  <nav class="rail" aria-label="Operator console sections">
    <button type="button" data-tab="overview" aria-selected="true">Overview</button>
    <button type="button" data-tab="events" aria-selected="false">Mission Events</button>
    <button type="button" data-tab="approvals" aria-selected="false">Approvals</button>
    <button type="button" data-tab="audit" aria-selected="false">Audit Timeline</button>
    <button type="button" data-tab="peers" aria-selected="false">Peer Sync</button>
  </nav>
  <div class="workspace">
    <section class="banner" id="health-banner"><div><strong id="health-title">Loading verified mission state</strong><span id="health-detail">Waiting for local API response.</span></div><a class="map-link" id="map-link" hidden>Map Console</a></section>
    <section class="metrics" aria-label="Mission metrics">
      <div class="metric"><strong id="metric-events">0</strong><span>Ledger Events</span></div>
      <div class="metric"><strong id="metric-open">0</strong><span>Open Incidents</span></div>
      <div class="metric"><strong id="metric-approvals">0</strong><span>Pending Approvals</span></div>
      <div class="metric"><strong id="metric-peer-due">0</strong><span>Peer Jobs Due</span></div>
      <div class="metric"><strong id="metric-evidence">0</strong><span>Evidence Bundles</span></div>
    </section>
    <section class="tab-panel" id="tab-overview">
      <h2>Operational Summary</h2>
      <div class="split">
        <div>
          <table>
            <tbody id="summary-rows"></tbody>
          </table>
        </div>
        <div>
          <div class="status-line" id="status-line">API sync pending</div>
        </div>
      </div>
    </section>
    <section class="tab-panel" id="tab-events" hidden>
      <h2>Mission Events</h2>
      <table>
        <thead><tr><th>Seq</th><th>Action</th><th>Subject</th><th>Actor</th><th>Priority</th><th>Hash</th></tr></thead>
        <tbody id="event-rows"></tbody>
      </table>
    </section>
    <section class="tab-panel" id="tab-approvals" hidden>
      <h2>Approvals</h2>
      <table>
        <thead><tr><th>ID</th><th>Status</th><th>Submitted By</th><th>Reviewed By</th><th>Draft Hash</th></tr></thead>
        <tbody id="approval-rows"></tbody>
      </table>
    </section>
    <section class="tab-panel" id="tab-audit" hidden>
      <h2>Audit Timeline</h2>
      <table>
        <thead><tr><th>Time</th><th>Severity</th><th>Source</th><th>Title</th><th>Subject</th><th>Actor</th></tr></thead>
        <tbody id="audit-rows"></tbody>
      </table>
    </section>
    <section class="tab-panel" id="tab-peers" hidden>
      <h2>Peer Sync</h2>
      <div class="split">
        <div>
          <table>
            <thead><tr><th>ID</th><th>Peer</th><th>Status</th><th>Attempts</th><th>Next Attempt</th></tr></thead>
            <tbody id="peer-rows"></tbody>
          </table>
        </div>
        <div>
          <table>
            <tbody id="peer-summary-rows"></tbody>
          </table>
        </div>
      </div>
    </section>
  </div>
</main>
<script>
const root = document.getElementById("operator-console");
const refreshMs = Number(root.dataset.refreshMs || "0");
const apiToken = root.dataset.apiToken || "";
const apiPath = (path) => {{
  if (!apiToken) return path;
  const separator = path.includes("?") ? "&" : "?";
  return `${{path}}${{separator}}token=${{encodeURIComponent(apiToken)}}`;
}};
const api = async (path) => {{
  const requestPath = apiPath(path);
  const response = await fetch(requestPath, {{ cache: "no-store" }});
  if (!response.ok) throw new Error(`${{path}} returned ${{response.status}}`);
  return response.json();
}};
const setText = (id, value) => {{
  document.getElementById(id).textContent = value === null || value === undefined || value === "" ? "--" : String(value);
}};
const escapeHtml = (value) => String(value === null || value === undefined || value === "" ? "--" : value).replace(/[&<>"']/g, (character) => ({{
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  "\"": "&quot;",
  "'": "&#39;",
}}[character]));
const html = (value) => ({{ html: String(value) }});
const cell = (value) => value && typeof value === "object" && Object.hasOwn(value, "html") ? value.html : escapeHtml(value);
const classify = (value) => value === "critical" || value === "failing" || value === "failed" ? "bad" : value === "elevated" || value === "warning" || value === "degraded" || value === "retrying" || value === "pending" ? "warn" : "";
const pill = (value) => html(`<span class="pill ${{classify(String(value))}}">${{escapeHtml(value)}}</span>`);
const code = (value) => html(`<code>${{escapeHtml(value)}}</code>`);
const cells = (values) => `<tr>${{values.map((value) => `<td>${{cell(value)}}</td>`).join("")}}</tr>`;
const emptyRow = (count, label) => `<tr><td colspan="${{count}}" class="muted">${{escapeHtml(label)}}</td></tr>`;

function tableRows(id, rows, count, render, emptyLabel) {{
  const target = document.getElementById(id);
  target.innerHTML = rows.length === 0 ? emptyRow(count, emptyLabel) : rows.map(render).join("");
}}

function renderSummary(summary) {{
  setText("mission-name", summary.mission || "mission not set");
  setText("generated-at", `generated ${{summary.generated_at}}`);
  setText("metric-events", summary.events);
  setText("metric-open", summary.open_incidents);
  setText("metric-approvals", summary.pending_approvals);
  setText("metric-peer-due", summary.peer_due);
  setText("metric-evidence", summary.evidence_bundles);
  const banner = document.getElementById("health-banner");
  banner.classList.toggle("degraded", summary.peer_health_status === "degraded");
  banner.classList.toggle("failing", summary.peer_health_status === "failing");
  setText("health-title", summary.healthy ? "Mission state verified" : "Mission state needs attention");
  setText("health-detail", `peer health: ${{summary.peer_health_status}} | last hash: ${{summary.last_hash || "--"}}`);
  const map = document.getElementById("map-link");
  if (summary.map_href && !String(summary.map_href).trim().toLowerCase().startsWith("javascript:")) {{
    map.href = summary.map_href;
    map.hidden = false;
  }} else {{
    map.hidden = true;
  }}
  document.getElementById("summary-rows").innerHTML = [
    ["Open incidents", summary.open_incidents],
    ["Closed incidents", summary.closed_incidents],
    ["Observations", summary.observations],
    ["Dispatches", summary.dispatches],
    ["Annotations", summary.annotations],
    ["Store events", summary.store_events ?? "--"],
    ["Peer jobs", summary.peer_jobs],
    ["Audit items", summary.audit_items],
  ].map(([label, value]) => cells([label, value])).join("");
  setText("status-line", `local API healthy: ${{summary.healthy}} | refresh: ${{refreshMs === 0 ? "manual" : `${{refreshMs / 1000}}s`}}`);
}}

function renderEvents(events) {{
  tableRows("event-rows", events, 6, (event) => cells([
    event.sequence,
    pill(event.action),
    event.subject,
    `${{event.actor?.name || "--"}} (${{event.actor?.role || "--"}})`,
    pill(event.priority),
    code(event.hash),
  ]), "No mission events in the current dashboard window.");
}}

function renderApprovals(approvals) {{
  tableRows("approval-rows", approvals, 5, (item) => cells([
    code(item.id),
    pill(item.status),
    item.submitted_by,
    item.reviewed_by || "--",
    code(item.draft_hash),
  ]), "No approval records loaded.");
}}

function renderAudit(items) {{
  tableRows("audit-rows", items, 6, (item) => cells([
    item.timestamp,
    pill(item.severity),
    item.source,
    item.title,
    item.subject,
    item.actor,
  ]), "No audit timeline entries loaded.");
}}

function renderPeers(payload) {{
  const jobs = payload.jobs || [];
  tableRows("peer-rows", jobs, 5, (job) => cells([
    code(job.id),
    `${{job.peer?.name || "--"}} ${{job.peer?.addr ? `(${{job.peer.addr}})` : ""}}`,
    pill(job.status),
    `${{job.attempts}}/${{job.max_attempts}}`,
    job.next_attempt_at,
  ]), "No peer sync jobs configured.");
  const summary = payload.queue || {{}};
  const health = payload.health || {{}};
  document.getElementById("peer-summary-rows").innerHTML = [
    ["Health", pill(health.status || "not_configured")],
    ["Total", summary.total ?? 0],
    ["Pending", summary.pending ?? 0],
    ["Retrying", summary.retrying ?? 0],
    ["Succeeded", summary.succeeded ?? 0],
    ["Failed", summary.failed ?? 0],
    ["Due now", health.due ?? 0],
    ["Stale retrying", health.stale_retrying ?? 0],
  ].map(([label, value]) => cells([label, value])).join("");
}}

async function loadConsole() {{
  const [summary, events, approvals, audit, peers] = await Promise.all([
    api("/api/summary"),
    api("/api/events"),
    api("/api/approvals"),
    api("/api/audit"),
    api("/api/peer-health"),
  ]);
  renderSummary(summary);
  renderEvents(events);
  renderApprovals(approvals);
  renderAudit(audit);
  renderPeers(peers);
}}

document.querySelectorAll(".rail button").forEach((button) => {{
  button.addEventListener("click", () => {{
    document.querySelectorAll(".rail button").forEach((item) => item.setAttribute("aria-selected", String(item === button)));
    document.querySelectorAll(".tab-panel").forEach((panel) => panel.hidden = panel.id !== `tab-${{button.dataset.tab}}`);
  }});
}});

loadConsole().catch((error) => {{
  setText("health-title", "Local API unavailable");
  setText("health-detail", error.message);
  document.getElementById("health-banner").classList.add("failing");
  setText("status-line", error.message);
}});
if (refreshMs > 0) {{
  setInterval(() => loadConsole().catch((error) => setText("status-line", error.message)), refreshMs);
}}
</script>
</body>
</html>
"#
    )
}

fn normalized_path(path: &str) -> &str {
    let path = path.split_once('?').map_or(path, |(path, _)| path);
    path.split_once('#').map_or(path, |(path, _)| path)
}

fn query_token_matches(path: &str, expected_token: &str) -> bool {
    query_value(path, "token")
        .is_some_and(|actual_token| constant_time_eq(actual_token, expected_token))
}

fn query_value<'a>(path: &'a str, key: &str) -> Option<&'a str> {
    let query = path.split_once('?')?.1;
    let query = query.split_once('#').map_or(query, |(query, _)| query);
    for pair in query.split('&') {
        let (actual_key, actual_value) = pair.split_once('=').unwrap_or((pair, ""));
        if actual_key == key {
            return Some(actual_value);
        }
    }
    None
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    let mut diff = left.len() ^ right.len();
    let max_len = left.len().max(right.len());
    for index in 0..max_len {
        let left_byte = left.get(index).copied().unwrap_or(0);
        let right_byte = right.get(index).copied().unwrap_or(0);
        diff |= usize::from(left_byte ^ right_byte);
    }
    diff == 0
}

fn operator_summary(document: &DashboardDocument) -> OperatorConsoleSummary<'_> {
    let pending_approvals = document
        .approvals
        .iter()
        .filter(|item| item.status == ApprovalStatus::Pending)
        .count();
    let peer_health_status = document
        .peer_health
        .as_ref()
        .map(|health| queue_health_status(health.status))
        .unwrap_or("not_configured");
    let peer_due = document
        .peer_health
        .as_ref()
        .map(|health| health.due)
        .unwrap_or(0);
    OperatorConsoleSummary {
        schema_version: OPERATOR_CONSOLE_SCHEMA,
        healthy: peer_health_status != "failing",
        title: &document.title,
        mission: document.state.mission.as_deref(),
        generated_at: document.generated_at.to_string(),
        events: document.state.events,
        open_incidents: document.state.open_incidents,
        closed_incidents: document.state.closed_incidents,
        observations: document.state.observations,
        dispatches: document.state.dispatches,
        annotations: document.state.annotations,
        store_events: document.store.as_ref().map(|store| store.event_count),
        approvals: document.approvals.len(),
        pending_approvals,
        peer_jobs: document.peer_jobs.len(),
        peer_due,
        peer_health_status,
        evidence_bundles: document.evidence_bundles.len(),
        audit_items: document.audit_timeline.len(),
        last_hash: document.state.last_hash.as_deref(),
        map_href: document.map_href.as_deref(),
    }
}

#[derive(Debug, Serialize)]
struct OperatorConsoleSummary<'a> {
    schema_version: u16,
    healthy: bool,
    title: &'a str,
    mission: Option<&'a str>,
    generated_at: String,
    events: usize,
    open_incidents: usize,
    closed_incidents: usize,
    observations: usize,
    dispatches: usize,
    annotations: usize,
    store_events: Option<u64>,
    approvals: usize,
    pending_approvals: usize,
    peer_jobs: usize,
    peer_due: usize,
    peer_health_status: &'static str,
    evidence_bundles: usize,
    audit_items: usize,
    last_hash: Option<&'a str>,
    map_href: Option<&'a str>,
}

fn queue_health_status(status: QueueHealthStatus) -> &'static str {
    match status {
        QueueHealthStatus::Healthy => "healthy",
        QueueHealthStatus::Degraded => "degraded",
        QueueHealthStatus::Failing => "failing",
    }
}

fn json_response<T: Serialize>(value: &T) -> Result<OperatorConsoleResponse, OperatorConsoleError> {
    Ok(OperatorConsoleResponse {
        status: "200 OK",
        content_type: "application/json; charset=utf-8",
        body: serde_json::to_vec_pretty(value)?,
    })
}

fn html_response(html: String) -> OperatorConsoleResponse {
    OperatorConsoleResponse {
        status: "200 OK",
        content_type: "text/html; charset=utf-8",
        body: html.into_bytes(),
    }
}

fn escape_html(value: &str) -> String {
    value
        .chars()
        .flat_map(|character| match character {
            '&' => "&amp;".chars().collect::<Vec<_>>(),
            '<' => "&lt;".chars().collect::<Vec<_>>(),
            '>' => "&gt;".chars().collect::<Vec<_>>(),
            '"' => "&quot;".chars().collect::<Vec<_>>(),
            '\'' => "&#39;".chars().collect::<Vec<_>>(),
            _ => vec![character],
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use astragrid_state::MissionStateSummary;
    use serde_json::Value;

    use super::*;

    fn document(title: &str) -> DashboardDocument {
        DashboardDocument::new(
            title,
            MissionStateSummary {
                mission: Some("flood-watch".to_owned()),
                events: 3,
                open_incidents: 1,
                closed_incidents: 0,
                observations: 1,
                dispatches: 1,
                annotations: 0,
                last_hash: Some("abc123".to_owned()),
            },
            None,
            Vec::new(),
            Vec::new(),
            None,
            None,
            Vec::new(),
            Vec::new(),
            Some("map-console.html".to_owned()),
        )
        .unwrap()
    }

    #[test]
    fn summary_api_reports_verified_counts() {
        let response =
            route_operator_console(&document("Ops"), "/api/summary?x=1", 0, None).unwrap();
        assert_eq!(response.status, "200 OK");
        assert_eq!(response.content_type, "application/json; charset=utf-8");
        let value: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(value["healthy"], true);
        assert_eq!(value["mission"], "flood-watch");
        assert_eq!(value["open_incidents"], 1);
        assert_eq!(value["peer_health_status"], "not_configured");
        assert_eq!(value["map_href"], "map-console.html");
    }

    #[test]
    fn console_html_escapes_title_and_mounts_app() {
        let response = route_operator_console(
            &document("<script>alert(1)</script>"),
            "/console.html",
            0,
            None,
        )
        .unwrap();
        let html = String::from_utf8(response.body).unwrap();
        assert!(html.contains("id=\"operator-console\""));
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(!html.contains("<title><script>alert(1)</script></title>"));
        assert!(!html.contains("http-equiv=\"refresh\""));
    }

    #[test]
    fn console_html_can_auto_refresh() {
        let response = route_operator_console(&document("Ops"), "/", 7, None).unwrap();
        let html = String::from_utf8(response.body).unwrap();
        assert!(html.contains("http-equiv=\"refresh\" content=\"7\""));
        assert!(html.contains("data-refresh-ms=\"7000\""));
    }

    #[test]
    fn unknown_route_returns_plain_404() {
        let response = route_operator_console(&document("Ops"), "/missing", 0, None).unwrap();
        assert_eq!(response.status, "404 Not Found");
        assert_eq!(response.content_type, "text/plain; charset=utf-8");
        assert_eq!(response.body, b"not found\n");
    }

    #[test]
    fn token_gate_rejects_missing_or_wrong_token() {
        let document = document("Ops");
        let missing = route_operator_console(&document, "/api/summary", 0, Some("secret")).unwrap();
        assert_eq!(missing.status, "401 Unauthorized");

        let wrong =
            route_operator_console(&document, "/api/summary?token=wrong", 0, Some("secret"))
                .unwrap();
        assert_eq!(wrong.status, "401 Unauthorized");
    }

    #[test]
    fn token_gate_allows_matching_token_and_embeds_it_for_api_calls() {
        let document = document("Ops");
        let summary =
            route_operator_console(&document, "/api/summary?token=secret", 0, Some("secret"))
                .unwrap();
        assert_eq!(summary.status, "200 OK");

        let console =
            route_operator_console(&document, "/console.html?token=secret", 0, Some("secret"))
                .unwrap();
        let html = String::from_utf8(console.body).unwrap();
        assert!(html.contains("data-api-token=\"secret\""));
        assert!(html.contains("encodeURIComponent(apiToken)"));
    }
}
