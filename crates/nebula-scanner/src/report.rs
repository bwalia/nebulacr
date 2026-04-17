//! Report generation.
//!
//! `to_json` is just pretty-printed serde; `to_html` produces a single
//! self-contained document (inline CSS, no external assets) so it prints
//! cleanly, embeds in emails, and uploads as-is to S3. Hand-rolled HTML
//! rather than a template engine — one file, no new deps.

use std::fmt::Write;

use crate::Result;
use crate::model::{PolicyStatus, ScanResult, ScanStatus, Severity, Vulnerability};

pub fn to_json(result: &ScanResult) -> Result<String> {
    Ok(serde_json::to_string_pretty(result)?)
}

pub fn to_html(result: &ScanResult) -> String {
    let mut s = String::with_capacity(8 * 1024);
    let image_ref = format!(
        "{}/{}/{}:{}",
        escape(&result.tenant),
        escape(&result.project),
        escape(&result.repository),
        escape(&result.reference)
    );
    let status_label = match result.status {
        ScanStatus::Queued => "queued",
        ScanStatus::InProgress => "in-progress",
        ScanStatus::Completed => "completed",
        ScanStatus::Failed => "failed",
    };

    write!(
        s,
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<title>Scan report — {image}</title>{css}</head><body>\
<header><h1>NebulaCR scan report</h1>\
<p class=\"meta\"><span class=\"k\">image</span> {image}<br>\
<span class=\"k\">digest</span> <code>{digest}</code><br>\
<span class=\"k\">status</span> {status}<br>\
<span class=\"k\">started</span> {started}{completed}</p></header>",
        image = image_ref,
        digest = escape(&result.digest),
        status = status_label,
        started = result.started_at,
        completed = match result.completed_at {
            Some(t) => format!(
                "<br><span class=\"k\">completed</span> {t}"
            ),
            None => String::new(),
        },
        css = INLINE_CSS,
    )
    .unwrap();

    // ── Policy verdict banner ─────────────────────────────────────────────
    if let Some(pe) = &result.policy_evaluation {
        let (cls, label) = match pe.status {
            PolicyStatus::Pass => ("verdict pass", "PASS"),
            PolicyStatus::Fail => ("verdict fail", "FAIL"),
        };
        write!(s, "<section class=\"{cls}\"><h2>{label}</h2>").unwrap();
        if let Some(reason) = &pe.reason {
            write!(s, "<p>{}</p>", escape(reason)).unwrap();
        }
        if !pe.violations.is_empty() {
            s.push_str("<ul class=\"violations\">");
            for v in &pe.violations {
                write!(
                    s,
                    "<li><span class=\"sev {sev_cls}\">{sev:?}</span> \
                     count <strong>{count}</strong> \
                     (threshold {thr})</li>",
                    sev_cls = severity_class(v.severity),
                    sev = v.severity,
                    count = v.count,
                    thr = escape(&v.threshold),
                )
                .unwrap();
            }
            s.push_str("</ul>");
        }
        s.push_str("</section>");
    }

    // ── Summary pills ─────────────────────────────────────────────────────
    write!(
        s,
        "<section class=\"summary\"><h2>Summary</h2>\
<ul class=\"pills\">\
<li class=\"sev critical\">critical <strong>{}</strong></li>\
<li class=\"sev high\">high <strong>{}</strong></li>\
<li class=\"sev medium\">medium <strong>{}</strong></li>\
<li class=\"sev low\">low <strong>{}</strong></li>\
<li class=\"sev unknown\">unknown <strong>{}</strong></li>\
</ul></section>",
        result.summary.critical,
        result.summary.high,
        result.summary.medium,
        result.summary.low,
        result.summary.unknown
    )
    .unwrap();

    // ── Vulnerabilities table ────────────────────────────────────────────
    let mut vulns: Vec<&Vulnerability> = result.vulnerabilities.iter().collect();
    vulns.sort_by_key(|v| (std::cmp::Reverse(v.severity.rank()), v.package.clone(), v.id.clone()));

    s.push_str(
        "<section><h2>Findings</h2>\
<table><thead><tr>\
<th>ID</th><th>Severity</th><th>CVSS</th><th>Package</th><th>Ecosystem</th>\
<th>Installed</th><th>Fixed</th><th>Layer</th><th>Summary</th>\
</tr></thead><tbody>",
    );
    for v in &vulns {
        let row_cls = if v.suppressed { "suppressed" } else { "" };
        write!(
            s,
            "<tr class=\"{row_cls}\">\
<td><code>{id}</code>{aliases}</td>\
<td><span class=\"sev {sev_cls}\">{sev:?}</span></td>\
<td>{cvss}</td>\
<td>{pkg}</td>\
<td>{eco}</td>\
<td><code>{installed}</code></td>\
<td>{fixed}</td>\
<td>{layer}</td>\
<td>{summary}</td>\
</tr>",
            id = escape(&v.id),
            aliases = if v.aliases.is_empty() {
                String::new()
            } else {
                format!(
                    "<div class=\"aliases\">aka {}</div>",
                    v.aliases
                        .iter()
                        .map(|a| format!("<code>{}</code>", escape(a)))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            },
            sev_cls = severity_class(v.severity),
            sev = v.severity,
            cvss = v
                .cvss_score
                .map(|s| format!("{:.1}", s))
                .unwrap_or_else(|| "—".into()),
            pkg = escape(&v.package),
            eco = escape(&v.ecosystem),
            installed = escape(&v.installed_version),
            fixed = v
                .fixed_version
                .as_deref()
                .map(|f| format!("<code>{}</code>", escape(f)))
                .unwrap_or_else(|| "—".into()),
            layer = v
                .layer_digest
                .as_deref()
                .map(|l| format!("<code title=\"{l}\">{}…</code>", escape(&short_digest(l))))
                .unwrap_or_else(|| "—".into()),
            summary = v
                .summary
                .as_deref()
                .map(escape)
                .unwrap_or_else(String::new),
        )
        .unwrap();
    }
    s.push_str("</tbody></table></section>");

    // ── Suppressions callout ─────────────────────────────────────────────
    let suppressed: Vec<&Vulnerability> = result.vulnerabilities.iter().filter(|v| v.suppressed).collect();
    if !suppressed.is_empty() {
        write!(
            s,
            "<section class=\"suppressed-note\"><h2>Suppressed findings ({})</h2>\
<p>These CVEs were intentionally excluded from policy evaluation. They remain \
visible above with the <em>suppressed</em> row style.</p></section>",
            suppressed.len(),
        )
        .unwrap();
    }

    s.push_str("</body></html>");
    s
}

fn severity_class(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Unknown => "unknown",
    }
}

fn short_digest(s: &str) -> String {
    s.strip_prefix("sha256:")
        .unwrap_or(s)
        .chars()
        .take(12)
        .collect()
}

/// Minimal HTML escape — enough for user-controlled strings in attributes and
/// text content. We never emit the `'` or `/` sequences in report output.
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(ch),
        }
    }
    out
}

const INLINE_CSS: &str = "<style>\
*{box-sizing:border-box}\
body{font:14px/1.4 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;color:#111;margin:2rem auto;max-width:1100px;padding:0 1rem}\
h1{margin:0 0 .5rem 0;font-size:1.4rem}\
h2{font-size:1.05rem;margin:1.5rem 0 .5rem 0;border-bottom:1px solid #ddd;padding-bottom:.25rem}\
.meta .k{display:inline-block;min-width:5rem;color:#666;font-size:.85rem;text-transform:uppercase;letter-spacing:.04em}\
code{font:12px/1 ui-monospace,SFMono-Regular,Consolas,monospace;background:#f5f5f5;padding:1px 4px;border-radius:3px}\
.verdict{padding:.75rem 1rem;border-radius:6px;margin:1rem 0;border-left:4px solid}\
.verdict h2{margin:0;border:none;font-size:1rem}\
.verdict.pass{background:#e8f8ef;border-color:#14864a;color:#0b5030}\
.verdict.fail{background:#fdecea;border-color:#b8262b;color:#721a1f}\
.violations{margin:.5rem 0 0 0;padding-left:1.2rem}\
.pills{display:flex;gap:.5rem;flex-wrap:wrap;list-style:none;padding:0;margin:0}\
.pills li{padding:.35rem .75rem;border-radius:99px;font-size:.85rem}\
.sev{display:inline-block;padding:1px 6px;border-radius:3px;font-size:.75rem;font-weight:600;text-transform:uppercase}\
.sev.critical{background:#7a0013;color:#fff}\
.sev.high{background:#b8262b;color:#fff}\
.sev.medium{background:#b8731f;color:#fff}\
.sev.low{background:#5b6c7a;color:#fff}\
.sev.unknown{background:#9aa;color:#fff}\
table{width:100%;border-collapse:collapse;font-size:.9rem;margin-top:.5rem}\
th,td{text-align:left;padding:.4rem .55rem;border-bottom:1px solid #eee;vertical-align:top}\
th{background:#fafafa;font-weight:600;font-size:.8rem;text-transform:uppercase;letter-spacing:.03em;color:#555}\
tr.suppressed td{opacity:.5;text-decoration:line-through}\
.aliases{font-size:.75rem;color:#666;margin-top:2px}\
.suppressed-note{background:#fff8e5;padding:.5rem .75rem;border-left:3px solid #caa400;border-radius:4px;margin-top:1rem}\
@media print{body{margin:0;max-width:none}section{break-inside:avoid}}\
</style>";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn sample_result() -> ScanResult {
        ScanResult {
            id: Uuid::new_v4(),
            digest: "sha256:abc123def456".into(),
            tenant: "acme".into(),
            project: "web".into(),
            repository: "api".into(),
            reference: "1.2.3".into(),
            status: ScanStatus::Completed,
            error: None,
            started_at: Utc::now(),
            completed_at: Some(Utc::now()),
            summary: ScanSummary {
                critical: 1,
                high: 2,
                medium: 0,
                low: 0,
                unknown: 0,
            },
            vulnerabilities: vec![
                Vulnerability {
                    id: "CVE-2025-1".into(),
                    aliases: vec!["GHSA-xxxx".into()],
                    package: "openssl".into(),
                    ecosystem: "deb".into(),
                    installed_version: "1.1.1".into(),
                    fixed_version: Some("1.1.1k".into()),
                    severity: Severity::Critical,
                    cvss_score: Some(9.8),
                    summary: Some("heap overflow".into()),
                    description: None,
                    layer_digest: Some("sha256:layerA".into()),
                    references: vec![],
                    suppressed: false,
                },
                Vulnerability {
                    id: "CVE-2025-2".into(),
                    aliases: vec![],
                    package: "curl".into(),
                    ecosystem: "deb".into(),
                    installed_version: "7.80".into(),
                    fixed_version: None,
                    severity: Severity::High,
                    cvss_score: None,
                    summary: None,
                    description: None,
                    layer_digest: None,
                    references: vec![],
                    suppressed: true,
                },
            ],
            policy_evaluation: Some(PolicyEvaluation {
                status: PolicyStatus::Fail,
                violations: vec![PolicyViolation {
                    severity: Severity::Critical,
                    count: 1,
                    threshold: ">0".into(),
                }],
                reason: Some("critical vulnerabilities exceed threshold".into()),
            }),
        }
    }

    #[test]
    fn renders_key_fields() {
        let html = to_html(&sample_result());
        assert!(html.contains("acme/web/api:1.2.3"));
        assert!(html.contains("sha256:abc123def456"));
        assert!(html.contains("CVE-2025-1"));
        assert!(html.contains("heap overflow"));
        assert!(html.contains("FAIL"));
        assert!(html.contains("verdict fail"));
        // Suppressed row gets its class.
        assert!(html.contains("tr class=\"suppressed\""));
        // CSS is inlined.
        assert!(html.contains("<style>"));
    }

    #[test]
    fn escapes_html_metacharacters() {
        let mut r = sample_result();
        r.vulnerabilities[0].summary = Some("<script>alert(1)</script>".into());
        let html = to_html(&r);
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    }
}
