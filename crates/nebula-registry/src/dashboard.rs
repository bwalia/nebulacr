//! Embedded metrics dashboard and JSON API endpoints.
//!
//! Serves:
//!   GET /dashboard         - HTML dashboard with live metrics
//!   GET /api/stats         - Summary statistics JSON
//!   GET /api/activity      - Recent activity feed JSON
//!   GET /api/audit         - Audit log with filtering JSON

use std::sync::Arc;

use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use crate::audit::{AuditStats, RegistryAuditLog};

/// State shared with dashboard handlers.
#[derive(Clone)]
pub struct DashboardState {
    pub audit_log: Arc<RegistryAuditLog>,
    pub start_time: std::time::Instant,
}

// ── JSON API ────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct StatsResponse {
    uptime_seconds: u64,
    #[serde(flatten)]
    audit: AuditStats,
}

pub async fn api_stats(State(state): State<DashboardState>) -> Json<StatsResponse> {
    let audit = state.audit_log.stats().await;
    Json(StatsResponse {
        uptime_seconds: state.start_time.elapsed().as_secs(),
        audit,
    })
}

#[derive(Deserialize)]
pub struct ActivityQuery {
    pub limit: Option<usize>,
    #[serde(rename = "type")]
    pub event_type: Option<String>,
    pub subject: Option<String>,
}

pub async fn api_activity(
    State(state): State<DashboardState>,
    Query(query): Query<ActivityQuery>,
) -> impl IntoResponse {
    let limit = query.limit.unwrap_or(50).min(500);

    let events = if let Some(ref event_type) = query.event_type {
        state.audit_log.by_type(event_type, limit).await
    } else if let Some(ref subject) = query.subject {
        state.audit_log.by_subject(subject, limit).await
    } else {
        state.audit_log.recent(limit).await
    };

    Json(serde_json::json!({
        "events": events,
        "count": events.len(),
    }))
}

pub async fn api_audit(
    State(state): State<DashboardState>,
    Query(query): Query<ActivityQuery>,
) -> impl IntoResponse {
    let limit = query.limit.unwrap_or(100).min(1000);

    let events = if let Some(ref event_type) = query.event_type {
        state.audit_log.by_type(event_type, limit).await
    } else if let Some(ref subject) = query.subject {
        state.audit_log.by_subject(subject, limit).await
    } else {
        state.audit_log.recent(limit).await
    };

    Json(serde_json::json!({
        "audit_events": events,
        "total_in_buffer": state.audit_log.count().await,
    }))
}

// ── HTML Dashboard ──────────────────────────────────────────────────────

pub async fn dashboard_html(State(state): State<DashboardState>) -> Response {
    let stats = state.audit_log.stats().await;
    let recent = state.audit_log.recent(20).await;
    let uptime = state.start_time.elapsed().as_secs();

    // Build recent activity rows
    let mut rows = String::new();
    for e in &recent {
        let size_display = if e.size_bytes > 0 {
            format_bytes(e.size_bytes)
        } else {
            "-".to_string()
        };
        rows.push_str(&format!(
            "<tr><td>{}</td><td><span class=\"badge badge-{}\">{}</span></td><td>{}</td><td>{}/{}/{}</td><td>{}</td><td>{}</td><td>{}ms</td></tr>\n",
            e.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
            event_badge_class(&e.event_type),
            e.event_type,
            e.subject,
            e.tenant, e.project, e.repository,
            e.reference,
            size_display,
            e.duration_ms,
        ));
    }

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NebulaCR Dashboard</title>
<style>
:root {{
    --bg: #0f172a;
    --surface: #1e293b;
    --surface2: #334155;
    --border: #475569;
    --text: #e2e8f0;
    --text-muted: #94a3b8;
    --accent: #38bdf8;
    --green: #4ade80;
    --yellow: #fbbf24;
    --red: #f87171;
    --purple: #a78bfa;
}}
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace; background: var(--bg); color: var(--text); min-height:100vh; }}
.header {{ background: var(--surface); border-bottom: 1px solid var(--border); padding: 16px 24px; display:flex; align-items:center; justify-content:space-between; }}
.header h1 {{ font-size: 20px; font-weight: 600; }}
.header h1 span {{ color: var(--accent); }}
.header .status {{ color: var(--green); font-size: 14px; }}
.container {{ max-width: 1400px; margin: 0 auto; padding: 24px; }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }}
.card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 20px; }}
.card .label {{ font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); margin-bottom: 4px; }}
.card .value {{ font-size: 28px; font-weight: 700; }}
.card .value.green {{ color: var(--green); }}
.card .value.accent {{ color: var(--accent); }}
.card .value.yellow {{ color: var(--yellow); }}
.card .value.red {{ color: var(--red); }}
.card .value.purple {{ color: var(--purple); }}
.section {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 24px; }}
.section-header {{ padding: 16px 20px; border-bottom: 1px solid var(--border); display:flex; justify-content:space-between; align-items:center; }}
.section-header h2 {{ font-size: 16px; font-weight: 600; }}
.section-header .controls {{ display:flex; gap:8px; }}
.section-header select, .section-header input {{ background: var(--surface2); border: 1px solid var(--border); color: var(--text); padding: 6px 10px; border-radius: 4px; font-size: 13px; }}
table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
th {{ text-align: left; padding: 10px 16px; color: var(--text-muted); font-weight: 500; font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid var(--border); }}
td {{ padding: 10px 16px; border-bottom: 1px solid var(--surface2); }}
tr:hover {{ background: var(--surface2); }}
.badge {{ padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }}
.badge-push {{ background: rgba(74,222,128,0.15); color: var(--green); }}
.badge-pull {{ background: rgba(56,189,248,0.15); color: var(--accent); }}
.badge-delete {{ background: rgba(248,113,113,0.15); color: var(--red); }}
.badge-other {{ background: rgba(167,139,250,0.15); color: var(--purple); }}
.footer {{ text-align: center; color: var(--text-muted); font-size: 12px; padding: 16px; }}
.refresh-btn {{ background: var(--accent); color: var(--bg); border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; font-size: 13px; font-weight: 600; }}
.refresh-btn:hover {{ opacity: 0.8; }}
.empty {{ text-align: center; padding: 40px; color: var(--text-muted); }}
</style>
</head>
<body>

<div class="header">
    <h1><span>Nebula</span>CR Registry Dashboard</h1>
    <div class="status">Healthy &bull; Uptime: {uptime_display}</div>
</div>

<div class="container">
    <div class="grid">
        <div class="card">
            <div class="label">Total Pushes</div>
            <div class="value green">{total_pushes}</div>
        </div>
        <div class="card">
            <div class="label">Total Pulls</div>
            <div class="value accent">{total_pulls}</div>
        </div>
        <div class="card">
            <div class="label">Total Deletes</div>
            <div class="value red">{total_deletes}</div>
        </div>
        <div class="card">
            <div class="label">Data Pushed</div>
            <div class="value yellow">{total_push_bytes}</div>
        </div>
        <div class="card">
            <div class="label">Avg Latency</div>
            <div class="value purple">{avg_latency:.1}ms</div>
        </div>
        <div class="card">
            <div class="label">Events Logged</div>
            <div class="value">{total_events}</div>
        </div>
    </div>

    <div class="section">
        <div class="section-header">
            <h2>Recent Activity &amp; Audit Log</h2>
            <div class="controls">
                <select id="filter-type" onchange="filterTable()">
                    <option value="">All Events</option>
                    <option value="manifest.push">Pushes</option>
                    <option value="manifest.pull">Pulls</option>
                    <option value="manifest.delete">Deletes</option>
                    <option value="blob.push">Blob Push</option>
                    <option value="blob.pull">Blob Pull</option>
                </select>
                <input type="text" id="filter-user" placeholder="Filter by user..." oninput="filterTable()">
                <button class="refresh-btn" onclick="location.reload()">Refresh</button>
            </div>
        </div>
        <table id="audit-table">
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Event</th>
                    <th>User</th>
                    <th>Repository</th>
                    <th>Reference</th>
                    <th>Size</th>
                    <th>Latency</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
        {empty_msg}
    </div>

    <div class="section">
        <div class="section-header">
            <h2>API Endpoints</h2>
        </div>
        <table>
            <thead><tr><th>Endpoint</th><th>Description</th></tr></thead>
            <tbody>
                <tr><td><code>/metrics</code></td><td>Prometheus metrics (scrape target)</td></tr>
                <tr><td><code>/api/stats</code></td><td>Summary statistics JSON</td></tr>
                <tr><td><code>/api/activity?limit=50&amp;type=manifest.push</code></td><td>Recent activity feed (filterable)</td></tr>
                <tr><td><code>/api/audit?limit=100&amp;subject=user</code></td><td>Full audit log (filterable)</td></tr>
                <tr><td><code>/dashboard</code></td><td>This dashboard</td></tr>
            </tbody>
        </table>
    </div>
</div>

<div class="footer">
    NebulaCR Registry &mdash; Prometheus endpoint at <a href="/metrics" style="color:var(--accent)">/metrics</a>
    &bull; Auto-refresh: <select onchange="setupAutoRefresh(this.value)" style="background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:4px;padding:2px;">
        <option value="0">Off</option>
        <option value="5">5s</option>
        <option value="15">15s</option>
        <option value="30" selected>30s</option>
        <option value="60">60s</option>
    </select>
</div>

<script>
let refreshTimer;
function setupAutoRefresh(sec) {{
    clearInterval(refreshTimer);
    if (sec > 0) refreshTimer = setInterval(() => location.reload(), sec * 1000);
}}
setupAutoRefresh(30);

function filterTable() {{
    const typeFilter = document.getElementById('filter-type').value.toLowerCase();
    const userFilter = document.getElementById('filter-user').value.toLowerCase();
    const rows = document.querySelectorAll('#audit-table tbody tr');
    rows.forEach(row => {{
        const eventType = row.cells[1]?.textContent.toLowerCase() || '';
        const user = row.cells[2]?.textContent.toLowerCase() || '';
        const showType = !typeFilter || eventType.includes(typeFilter);
        const showUser = !userFilter || user.includes(userFilter);
        row.style.display = (showType && showUser) ? '' : 'none';
    }});
}}
</script>
</body>
</html>"#,
        uptime_display = format_uptime(uptime),
        total_pushes = stats.total_pushes,
        total_pulls = stats.total_pulls,
        total_deletes = stats.total_deletes,
        total_push_bytes = format_bytes(stats.total_push_bytes),
        avg_latency = stats.avg_latency_ms,
        total_events = stats.total_events,
        rows = rows,
        empty_msg = if recent.is_empty() {
            r#"<div class="empty">No activity yet. Push an image to see it here.</div>"#
        } else {
            ""
        },
    );

    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        )],
        Html(html),
    )
        .into_response()
}

fn event_badge_class(event_type: &str) -> &'static str {
    if event_type.contains("push") {
        "push"
    } else if event_type.contains("pull") {
        "pull"
    } else if event_type.contains("delete") {
        "delete"
    } else {
        "other"
    }
}

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    const TB: u64 = 1024 * GB;

    if bytes >= TB {
        format!("{:.1} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

fn format_uptime(secs: u64) -> String {
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let minutes = (secs % 3600) / 60;
    if days > 0 {
        format!("{days}d {hours}h {minutes}m")
    } else if hours > 0 {
        format!("{hours}h {minutes}m")
    } else {
        format!("{minutes}m")
    }
}
