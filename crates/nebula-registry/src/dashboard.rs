//! Embedded metrics dashboard and JSON API endpoints.
//!
//! Serves:
//!   GET /dashboard         - HTML dashboard with live metrics
//!   GET /api/stats         - Summary statistics JSON
//!   GET /api/activity      - Recent activity feed JSON
//!   GET /api/audit         - Audit log with filtering JSON
//!   GET /api/system        - System metrics (CPU, RAM, disk) JSON
//!   GET /api/ha-status     - HA peer region health status JSON

use std::sync::Arc;

use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use sysinfo::{Disks, System};

use crate::audit::{AuditStats, RegistryAuditLog};
use nebula_replication::failover::FailoverManager;

/// State shared with dashboard handlers.
#[derive(Clone)]
pub struct DashboardState {
    pub audit_log: Arc<RegistryAuditLog>,
    pub start_time: std::time::Instant,
    pub failover_manager: Option<Arc<FailoverManager>>,
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

// ── System Metrics API ──────────────────────────────────────────────────

#[derive(Serialize)]
pub struct SystemMetrics {
    cpu_usage_percent: f32,
    cpu_count: usize,
    memory_total_bytes: u64,
    memory_used_bytes: u64,
    memory_available_bytes: u64,
    memory_usage_percent: f32,
    disks: Vec<DiskInfo>,
}

#[derive(Serialize)]
pub struct DiskInfo {
    mount_point: String,
    total_bytes: u64,
    available_bytes: u64,
    usage_percent: f32,
}

pub async fn api_system(_state: State<DashboardState>) -> Json<SystemMetrics> {
    let metrics = collect_system_metrics();
    Json(metrics)
}

fn collect_system_metrics() -> SystemMetrics {
    let mut sys = System::new();
    sys.refresh_cpu_all();
    sys.refresh_memory();

    // Brief pause for CPU measurement accuracy
    std::thread::sleep(std::time::Duration::from_millis(200));
    sys.refresh_cpu_all();

    let cpu_usage = sys.global_cpu_usage();
    let cpu_count = sys.cpus().len();
    let memory_total = sys.total_memory();
    let memory_used = sys.used_memory();
    let memory_available = sys.available_memory();
    let memory_usage_pct = if memory_total > 0 {
        (memory_used as f32 / memory_total as f32) * 100.0
    } else {
        0.0
    };

    let disk_list = Disks::new_with_refreshed_list();
    let disks: Vec<DiskInfo> = disk_list
        .iter()
        .filter(|d| {
            let mp = d.mount_point().to_string_lossy();
            // Filter to meaningful mount points
            mp == "/" || mp.starts_with("/var") || mp.starts_with("/data") || mp.starts_with("/home")
        })
        .map(|d| {
            let total = d.total_space();
            let available = d.available_space();
            let used = total.saturating_sub(available);
            let usage_pct = if total > 0 {
                (used as f32 / total as f32) * 100.0
            } else {
                0.0
            };
            DiskInfo {
                mount_point: d.mount_point().to_string_lossy().to_string(),
                total_bytes: total,
                available_bytes: available,
                usage_percent: usage_pct,
            }
        })
        .collect();

    SystemMetrics {
        cpu_usage_percent: cpu_usage,
        cpu_count,
        memory_total_bytes: memory_total,
        memory_used_bytes: memory_used,
        memory_available_bytes: memory_available,
        memory_usage_percent: memory_usage_pct,
        disks,
    }
}

// ── HA Status API ───────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct HaStatusResponse {
    ha_enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    local_is_primary: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    regions: Option<Vec<RegionStatus>>,
}

#[derive(Serialize)]
pub struct RegionStatus {
    region: String,
    healthy: bool,
    last_check: String,
    consecutive_failures: u32,
    response_time_ms: Option<u64>,
}

pub async fn api_ha_status(State(state): State<DashboardState>) -> Json<HaStatusResponse> {
    match &state.failover_manager {
        Some(fm) => {
            let health = fm.all_health().await;
            let regions: Vec<RegionStatus> = health
                .into_iter()
                .map(|h| RegionStatus {
                    region: h.region,
                    healthy: h.healthy,
                    last_check: h.last_check.to_rfc3339(),
                    consecutive_failures: h.consecutive_failures,
                    response_time_ms: h.response_time_ms,
                })
                .collect();
            Json(HaStatusResponse {
                ha_enabled: true,
                local_is_primary: Some(fm.is_local_primary()),
                regions: Some(regions),
            })
        }
        None => Json(HaStatusResponse {
            ha_enabled: false,
            local_is_primary: None,
            regions: None,
        }),
    }
}

// ── HTML Dashboard ──────────────────────────────────────────────────────

pub async fn dashboard_html(State(state): State<DashboardState>) -> Response {
    let stats = state.audit_log.stats().await;
    let recent = state.audit_log.recent(20).await;
    let uptime = state.start_time.elapsed().as_secs();
    let sys_metrics = collect_system_metrics();

    // Collect HA status
    let (ha_enabled, ha_local_primary, ha_regions) = match &state.failover_manager {
        Some(fm) => {
            let health = fm.all_health().await;
            (true, fm.is_local_primary(), health)
        }
        None => (false, false, vec![]),
    };

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

    // Build disk info for the primary disk
    let primary_disk = sys_metrics.disks.first();
    let disk_avail_display = primary_disk
        .map(|d| format_bytes(d.available_bytes))
        .unwrap_or_else(|| "N/A".to_string());
    let disk_usage_pct = primary_disk.map(|d| d.usage_percent).unwrap_or(0.0);

    // Build HA status section
    let ha_section = if ha_enabled {
        let mut region_rows = String::new();
        for r in &ha_regions {
            let status_class = if r.healthy { "green" } else { "red" };
            let status_label = if r.healthy { "Healthy" } else { "Unhealthy" };
            let latency = r
                .response_time_ms
                .map(|ms| format!("{ms}ms"))
                .unwrap_or_else(|| "-".to_string());
            region_rows.push_str(&format!(
                "<tr><td>{region}</td><td><span class=\"badge badge-{status_class}\">{status_label}</span></td><td>{latency}</td><td>{failures}</td><td>{last_check}</td></tr>\n",
                region = r.region,
                status_class = status_class,
                status_label = status_label,
                latency = latency,
                failures = r.consecutive_failures,
                last_check = r.last_check.format("%Y-%m-%d %H:%M:%S UTC"),
            ));
        }

        let role = if ha_local_primary { "Primary" } else { "Secondary" };
        let healthy_count = ha_regions.iter().filter(|r| r.healthy).count();
        let total_count = ha_regions.len();

        format!(
            r#"<div class="section">
        <div class="section-header">
            <h2>HA Multi-Region Status</h2>
            <div class="controls">
                <span class="badge badge-green" style="font-size:13px;">Local Role: {role}</span>
                <span style="color:var(--text-muted);font-size:13px;">{healthy_count}/{total_count} regions healthy</span>
            </div>
        </div>
        <table>
            <thead>
                <tr>
                    <th>Region</th>
                    <th>Status</th>
                    <th>Latency</th>
                    <th>Failures</th>
                    <th>Last Check</th>
                </tr>
            </thead>
            <tbody>
                {region_rows}
            </tbody>
        </table>
    </div>"#,
        )
    } else {
        r#"<div class="section">
        <div class="section-header">
            <h2>HA Multi-Region Status</h2>
        </div>
        <div class="empty">Multi-region HA is not configured. Enable it in <code>[multi_region]</code> config to see peer status.</div>
    </div>"#
            .to_string()
    };

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
    --orange: #fb923c;
    --teal: #2dd4bf;
}}
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace; background: var(--bg); color: var(--text); min-height:100vh; }}
.header {{ background: var(--surface); border-bottom: 1px solid var(--border); padding: 16px 24px; display:flex; align-items:center; justify-content:space-between; }}
.header h1 {{ font-size: 20px; font-weight: 600; }}
.header h1 span {{ color: var(--accent); }}
.header .status {{ color: var(--green); font-size: 14px; }}
.container {{ max-width: 1400px; margin: 0 auto; padding: 24px; }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 24px; }}
.card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 20px; }}
.card .label {{ font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); margin-bottom: 4px; }}
.card .value {{ font-size: 28px; font-weight: 700; }}
.card .sub {{ font-size: 11px; color: var(--text-muted); margin-top: 4px; }}
.card .value.green {{ color: var(--green); }}
.card .value.accent {{ color: var(--accent); }}
.card .value.yellow {{ color: var(--yellow); }}
.card .value.red {{ color: var(--red); }}
.card .value.purple {{ color: var(--purple); }}
.card .value.orange {{ color: var(--orange); }}
.card .value.teal {{ color: var(--teal); }}
.progress-bar {{ height: 6px; background: var(--surface2); border-radius: 3px; margin-top: 8px; overflow: hidden; }}
.progress-bar .fill {{ height: 100%; border-radius: 3px; transition: width 0.3s; }}
.fill-green {{ background: var(--green); }}
.fill-yellow {{ background: var(--yellow); }}
.fill-red {{ background: var(--red); }}
.fill-accent {{ background: var(--accent); }}
.fill-orange {{ background: var(--orange); }}
.section {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 24px; }}
.section-header {{ padding: 16px 20px; border-bottom: 1px solid var(--border); display:flex; justify-content:space-between; align-items:center; }}
.section-header h2 {{ font-size: 16px; font-weight: 600; }}
.section-header .controls {{ display:flex; gap:8px; align-items:center; }}
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
.badge-green {{ background: rgba(74,222,128,0.15); color: var(--green); }}
.badge-red {{ background: rgba(248,113,113,0.15); color: var(--red); }}
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
            <div class="label">CPU Usage</div>
            <div class="value {cpu_color}">{cpu_usage:.1}%</div>
            <div class="sub">{cpu_count} cores</div>
            <div class="progress-bar"><div class="fill {cpu_bar_color}" style="width:{cpu_usage:.0}%"></div></div>
        </div>
        <div class="card">
            <div class="label">RAM Usage</div>
            <div class="value {ram_color}">{ram_used}</div>
            <div class="sub">{ram_usage_pct:.1}% of {ram_total}</div>
            <div class="progress-bar"><div class="fill {ram_bar_color}" style="width:{ram_usage_pct:.0}%"></div></div>
        </div>
        <div class="card">
            <div class="label">Disk Available</div>
            <div class="value {disk_color}">{disk_avail}</div>
            <div class="sub">{disk_usage_pct:.1}% used</div>
            <div class="progress-bar"><div class="fill {disk_bar_color}" style="width:{disk_usage_pct:.0}%"></div></div>
        </div>
        <div class="card">
            <div class="label">HA Status</div>
            <div class="value {ha_color}">{ha_display}</div>
            <div class="sub">{ha_sub}</div>
        </div>
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

    {ha_section}

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
                <tr><td><code>/api/system</code></td><td>System metrics (CPU, RAM, disk) JSON</td></tr>
                <tr><td><code>/api/ha-status</code></td><td>HA multi-region peer health JSON</td></tr>
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
        // System metrics
        cpu_usage = sys_metrics.cpu_usage_percent,
        cpu_count = sys_metrics.cpu_count,
        cpu_color = usage_color_class(sys_metrics.cpu_usage_percent),
        cpu_bar_color = usage_bar_color(sys_metrics.cpu_usage_percent),
        ram_used = format_bytes(sys_metrics.memory_used_bytes),
        ram_total = format_bytes(sys_metrics.memory_total_bytes),
        ram_usage_pct = sys_metrics.memory_usage_percent,
        ram_color = usage_color_class(sys_metrics.memory_usage_percent),
        ram_bar_color = usage_bar_color(sys_metrics.memory_usage_percent),
        disk_avail = disk_avail_display,
        disk_usage_pct = disk_usage_pct,
        disk_color = usage_color_class(disk_usage_pct),
        disk_bar_color = usage_bar_color(disk_usage_pct),
        // HA status
        ha_color = if !ha_enabled {
            "text-muted"
        } else if ha_regions.iter().all(|r| r.healthy) {
            "green"
        } else if ha_regions.iter().any(|r| r.healthy) {
            "yellow"
        } else {
            "red"
        },
        ha_display = if !ha_enabled {
            "N/A".to_string()
        } else {
            let healthy = ha_regions.iter().filter(|r| r.healthy).count();
            let total = ha_regions.len();
            format!("{healthy}/{total}")
        },
        ha_sub = if !ha_enabled {
            "Not configured".to_string()
        } else if ha_local_primary {
            "Primary node".to_string()
        } else {
            "Secondary node".to_string()
        },
        ha_section = ha_section,
        // Registry stats
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

fn usage_color_class(pct: f32) -> &'static str {
    if pct >= 90.0 {
        "red"
    } else if pct >= 70.0 {
        "yellow"
    } else {
        "green"
    }
}

fn usage_bar_color(pct: f32) -> &'static str {
    if pct >= 90.0 {
        "fill-red"
    } else if pct >= 70.0 {
        "fill-yellow"
    } else {
        "fill-green"
    }
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
