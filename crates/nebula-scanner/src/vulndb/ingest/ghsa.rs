//! GitHub Security Advisories (GHSA) ingester (slice 2c).
//!
//! Unlike NVD, GHSA ships real ecosystem-level ranges (`vulnerableVersionRange`,
//! `firstPatchedVersion`), so we go through the full `write_advisory` path
//! and populate `affected_ranges` alongside the metadata row. GHSA's
//! ecosystem vocabulary (NPM, PIP, RUST, GO, MAVEN, …) maps 1:1 onto ours;
//! ecosystems we don't match (RUBYGEMS, COMPOSER, NUGET, PUB, SWIFT,
//! ACTIONS, …) are skipped at normalisation time.
//!
//! Query strategy:
//! - First run with no cursor → full bootstrap, cursor-paged at 100/page.
//! - Subsequent runs → delta via the `updatedSince` parameter, starting
//!   from the stored `last_modified`.
//! - A GitHub token is required. The official public API gives
//!   anonymous callers ~60 req/hr, which is too tight for full bootstrap;
//!   authenticated tokens get 5000/hr.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tokio::sync::Mutex;
use tracing::{info, warn};

use super::writer::{stored_last_modified, update_cursor, write_advisory};
use super::{AffectedRangeRow, IngestStats, Ingester, VulnerabilityRow};
use crate::model::Severity;
use crate::{Result, ScanError};

const SOURCE: &str = "ghsa";
const DEFAULT_ENDPOINT: &str = "https://api.github.com/graphql";
const DEFAULT_PAGE_SIZE: usize = 100;

pub struct GhsaIngester {
    http: reqwest::Client,
    endpoint: String,
    token: String,
    page_size: usize,
    lock: Arc<Mutex<()>>,
}

pub struct GhsaConfig {
    pub endpoint: Option<String>,
    pub token: String,
    pub page_size: Option<usize>,
}

impl GhsaIngester {
    pub fn new(cfg: GhsaConfig) -> Result<Self> {
        if cfg.token.trim().is_empty() {
            return Err(ScanError::Other(
                "GHSA ingester requires a GitHub token".into(),
            ));
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .user_agent("nebulacr-scanner")
            .build()?;
        Ok(Self {
            http,
            endpoint: cfg.endpoint.unwrap_or_else(|| DEFAULT_ENDPOINT.into()),
            token: cfg.token,
            page_size: cfg.page_size.unwrap_or(DEFAULT_PAGE_SIZE),
            lock: Arc::new(Mutex::new(())),
        })
    }
}

#[async_trait]
impl Ingester for GhsaIngester {
    fn source(&self) -> &'static str {
        SOURCE
    }

    async fn run(&self, pool: &PgPool) -> Result<IngestStats> {
        let _guard = self.lock.lock().await;
        let updated_since = stored_last_modified(pool, SOURCE).await?;
        let mut stats = IngestStats::default();
        let mut max_modified = updated_since.unwrap_or_else(|| Utc::now() - chrono::Duration::days(3650));
        let mut cursor: Option<String> = None;

        loop {
            let page = match self.fetch_page(cursor.as_deref(), updated_since).await {
                Ok(p) => p,
                Err(e) => {
                    warn!(error = %e, "GHSA page fetch failed; persisting partial progress");
                    update_cursor(
                        pool,
                        SOURCE,
                        None,
                        Some(max_modified),
                        &stats,
                        Some(&e.to_string()),
                    )
                    .await?;
                    return Err(e);
                }
            };
            for node in &page.nodes {
                match normalise_ghsa(node) {
                    Some((vuln, ranges)) => {
                        if let Some(t) = vuln.modified_at {
                            if t > max_modified {
                                max_modified = t;
                            }
                        }
                        match write_advisory(pool, &vuln, &ranges).await {
                            Ok(()) => stats.advisories += 1,
                            Err(e) => {
                                warn!(id = %vuln.id, error = %e, "GHSA advisory write failed");
                                stats.errors += 1;
                            }
                        }
                    }
                    None => stats.skipped += 1,
                }
            }
            if !page.has_next {
                break;
            }
            cursor = page.end_cursor;
        }

        update_cursor(pool, SOURCE, None, Some(max_modified), &stats, None).await?;
        info!(
            advisories = stats.advisories,
            skipped = stats.skipped,
            errors = stats.errors,
            "GHSA ingest run complete"
        );
        Ok(stats)
    }
}

impl GhsaIngester {
    async fn fetch_page(
        &self,
        cursor: Option<&str>,
        updated_since: Option<DateTime<Utc>>,
    ) -> Result<Page> {
        let query = build_query(self.page_size, cursor, updated_since);
        let resp = self
            .http
            .post(&self.endpoint)
            .bearer_auth(&self.token)
            .json(&GraphqlRequest { query })
            .send()
            .await?
            .error_for_status()?;
        let body: GraphqlResponse = resp.json().await.map_err(|e| {
            ScanError::VulnDb(format!("ghsa json decode: {e}"))
        })?;
        if let Some(errs) = body.errors {
            if !errs.is_empty() {
                return Err(ScanError::VulnDb(format!("ghsa graphql errors: {errs:?}")));
            }
        }
        let data = body.data.ok_or_else(|| {
            ScanError::VulnDb("ghsa graphql response missing data".into())
        })?;
        Ok(Page {
            nodes: data.security_advisories.nodes,
            end_cursor: data.security_advisories.page_info.end_cursor,
            has_next: data.security_advisories.page_info.has_next_page,
        })
    }
}

struct Page {
    nodes: Vec<GhsaNode>,
    end_cursor: Option<String>,
    has_next: bool,
}

fn build_query(
    page_size: usize,
    cursor: Option<&str>,
    updated_since: Option<DateTime<Utc>>,
) -> String {
    let after = cursor
        .map(|c| format!(", after: \"{c}\""))
        .unwrap_or_default();
    let since = updated_since
        .map(|t| format!(", updatedSince: \"{}\"", t.to_rfc3339()))
        .unwrap_or_default();
    // GraphQL inlines values for simplicity; `page_size` is bounded internally
    // and `cursor` / `updated_since` come from our own DB cursor — no
    // external input surface.
    format!(
        r#"{{
  securityAdvisories(first: {page_size}{after}{since}, orderBy: {{field: UPDATED_AT, direction: ASC}}) {{
    nodes {{
      ghsaId
      identifiers {{ type value }}
      summary
      description
      severity
      publishedAt
      updatedAt
      references {{ url }}
      cvss {{ score vectorString }}
      vulnerabilities(first: 100) {{
        nodes {{
          package {{ name ecosystem }}
          vulnerableVersionRange
          firstPatchedVersion {{ identifier }}
        }}
      }}
    }}
    pageInfo {{ hasNextPage endCursor }}
  }}
}}"#
    )
}

// ── GraphQL types ──────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct GraphqlRequest {
    query: String,
}

#[derive(Debug, Deserialize)]
struct GraphqlResponse {
    data: Option<GraphqlData>,
    #[serde(default)]
    errors: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Deserialize)]
struct GraphqlData {
    #[serde(rename = "securityAdvisories")]
    security_advisories: SecurityAdvisories,
}

#[derive(Debug, Deserialize)]
struct SecurityAdvisories {
    nodes: Vec<GhsaNode>,
    #[serde(rename = "pageInfo")]
    page_info: PageInfo,
}

#[derive(Debug, Deserialize)]
struct PageInfo {
    #[serde(rename = "hasNextPage")]
    has_next_page: bool,
    #[serde(rename = "endCursor")]
    end_cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GhsaNode {
    #[serde(rename = "ghsaId")]
    ghsa_id: String,
    #[serde(default)]
    identifiers: Vec<GhsaIdentifier>,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    description: Option<String>,
    severity: String,
    #[serde(rename = "publishedAt", default)]
    published_at: Option<DateTime<Utc>>,
    #[serde(rename = "updatedAt", default)]
    updated_at: Option<DateTime<Utc>>,
    #[serde(default)]
    references: Vec<GhsaReference>,
    #[serde(default)]
    cvss: Option<GhsaCvss>,
    #[serde(default)]
    vulnerabilities: GhsaVulnerabilities,
}

#[derive(Debug, Deserialize)]
struct GhsaIdentifier {
    #[serde(rename = "type")]
    id_type: String,
    value: String,
}

#[derive(Debug, Deserialize)]
struct GhsaReference {
    url: String,
}

#[derive(Debug, Deserialize)]
struct GhsaCvss {
    #[serde(default)]
    score: Option<f64>,
}

#[derive(Debug, Deserialize, Default)]
struct GhsaVulnerabilities {
    #[serde(default)]
    nodes: Vec<GhsaVulnerabilityNode>,
}

#[derive(Debug, Deserialize)]
struct GhsaVulnerabilityNode {
    package: GhsaPackage,
    #[serde(rename = "vulnerableVersionRange", default)]
    vulnerable_range: Option<String>,
    #[serde(rename = "firstPatchedVersion", default)]
    first_patched: Option<GhsaPatched>,
}

#[derive(Debug, Deserialize)]
struct GhsaPackage {
    name: String,
    ecosystem: String,
}

#[derive(Debug, Deserialize)]
struct GhsaPatched {
    identifier: String,
}

// ── Normaliser ──────────────────────────────────────────────────────────────

fn normalise_ghsa(node: &GhsaNode) -> Option<(VulnerabilityRow, Vec<AffectedRangeRow>)> {
    let ranges: Vec<AffectedRangeRow> = node
        .vulnerabilities
        .nodes
        .iter()
        .filter_map(|v| vuln_node_to_range(v))
        .collect();
    if ranges.is_empty() {
        // No matchable ecosystem — skip to avoid orphaning the vuln row.
        return None;
    }

    let cve_alias = node
        .identifiers
        .iter()
        .find(|i| i.id_type.eq_ignore_ascii_case("CVE"))
        .map(|i| i.value.clone());
    let aliases: Vec<String> = node
        .identifiers
        .iter()
        .filter(|i| !i.id_type.eq_ignore_ascii_case("GHSA"))
        .map(|i| i.value.clone())
        .collect();

    // Prefer the CVE id as the canonical id when present so OSV/NVD rows
    // collapse onto the same row; fall back to the GHSA id otherwise.
    let canonical_id = cve_alias.clone().unwrap_or_else(|| node.ghsa_id.clone());
    let source = if cve_alias.is_some() { "ghsa" } else { "ghsa" };

    let severity = parse_ghsa_severity(&node.severity);
    let cvss = node.cvss.as_ref().and_then(|c| c.score);
    let references: Vec<String> = node.references.iter().map(|r| r.url.clone()).collect();

    Some((
        VulnerabilityRow {
            id: canonical_id,
            source: source.into(),
            summary: node.summary.clone(),
            description: node.description.clone(),
            severity,
            cvss_score: cvss,
            published_at: node.published_at,
            modified_at: node.updated_at,
            aliases,
            references,
        },
        ranges,
    ))
}

fn parse_ghsa_severity(s: &str) -> Severity {
    match s.to_ascii_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MODERATE" | "MEDIUM" => Severity::Medium,
        "LOW" => Severity::Low,
        _ => Severity::Unknown,
    }
}

fn vuln_node_to_range(v: &GhsaVulnerabilityNode) -> Option<AffectedRangeRow> {
    let ecosystem = ghsa_ecosystem_to_ours(&v.package.ecosystem)?;
    let (introduced, fixed, last_affected) = parse_range(
        v.vulnerable_range.as_deref(),
        v.first_patched.as_ref().map(|p| p.identifier.as_str()),
    );
    Some(AffectedRangeRow {
        ecosystem: ecosystem.into(),
        package: v.package.name.clone(),
        introduced,
        fixed,
        last_affected,
        purl: None,
    })
}

fn ghsa_ecosystem_to_ours(e: &str) -> Option<&'static str> {
    match e.to_ascii_uppercase().as_str() {
        "NPM" => Some("npm"),
        "PIP" => Some("pypi"),
        "RUST" => Some("cargo"),
        "GO" => Some("go"),
        "MAVEN" => Some("maven"),
        // Skip ecosystems we don't have matchers for yet; the ingester would
        // produce unusable rows otherwise.
        _ => None,
    }
}

/// Parse a GHSA `vulnerableVersionRange` string like `">= 1.0, < 1.5"` into
/// (introduced, fixed, last_affected). Missing fields map to None. Falls
/// back to `first_patched` for `fixed` when the range string didn't pin it.
fn parse_range(
    range: Option<&str>,
    first_patched: Option<&str>,
) -> (Option<String>, Option<String>, Option<String>) {
    let mut introduced = None;
    let mut fixed = None;
    let mut last_affected = None;

    if let Some(r) = range {
        for part in r.split(',') {
            let part = part.trim();
            if let Some(v) = part.strip_prefix(">=") {
                introduced = Some(v.trim().to_string());
            } else if let Some(v) = part.strip_prefix('>') {
                // Strictly greater; approximate by using the same version as
                // the introduced bound — slightly over-inclusive but safer
                // than missing the vuln entirely.
                introduced = Some(v.trim().to_string());
            } else if let Some(v) = part.strip_prefix("<=") {
                last_affected = Some(v.trim().to_string());
            } else if let Some(v) = part.strip_prefix('<') {
                fixed = Some(v.trim().to_string());
            } else if let Some(v) = part.strip_prefix('=') {
                let t = v.trim().to_string();
                introduced = Some(t.clone());
                last_affected = Some(t);
            }
        }
    }

    if fixed.is_none() {
        if let Some(p) = first_patched {
            fixed = Some(p.to_string());
        }
    }

    (introduced, fixed, last_affected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_greater_and_less() {
        let (i, f, la) = parse_range(Some(">= 1.0, < 1.5"), None);
        assert_eq!(i.as_deref(), Some("1.0"));
        assert_eq!(f.as_deref(), Some("1.5"));
        assert!(la.is_none());
    }

    #[test]
    fn range_with_equals_pins_both_ends() {
        let (i, _f, la) = parse_range(Some("= 1.2.3"), None);
        assert_eq!(i.as_deref(), Some("1.2.3"));
        assert_eq!(la.as_deref(), Some("1.2.3"));
    }

    #[test]
    fn range_falls_back_to_first_patched_for_fixed() {
        let (_i, f, _la) = parse_range(Some(">= 1.0"), Some("1.5.0"));
        assert_eq!(f.as_deref(), Some("1.5.0"));
    }

    #[test]
    fn ecosystem_map_trims_unsupported() {
        assert_eq!(ghsa_ecosystem_to_ours("NPM"), Some("npm"));
        assert_eq!(ghsa_ecosystem_to_ours("RUST"), Some("cargo"));
        assert!(ghsa_ecosystem_to_ours("RUBYGEMS").is_none());
    }

    #[test]
    fn normalises_ghsa_node_to_vuln_and_ranges() {
        let node: GhsaNode = serde_json::from_str(
            r#"{
                "ghsaId":"GHSA-xxxx-yyyy",
                "identifiers":[{"type":"GHSA","value":"GHSA-xxxx-yyyy"},{"type":"CVE","value":"CVE-2025-42"}],
                "summary":"something bad",
                "description":"longer text",
                "severity":"HIGH",
                "publishedAt":"2025-01-01T00:00:00Z",
                "updatedAt":"2025-02-01T00:00:00Z",
                "references":[{"url":"https://example.org"}],
                "cvss":{"score":8.1},
                "vulnerabilities":{"nodes":[
                    {"package":{"name":"left-pad","ecosystem":"NPM"},"vulnerableVersionRange":">= 1.0, < 1.5","firstPatchedVersion":{"identifier":"1.5.0"}},
                    {"package":{"name":"weird","ecosystem":"PUB"},"vulnerableVersionRange":"< 1","firstPatchedVersion":null}
                ]}
            }"#,
        ).unwrap();

        let (v, ranges) = normalise_ghsa(&node).unwrap();
        assert_eq!(v.id, "CVE-2025-42");  // CVE alias wins
        assert_eq!(v.severity, Severity::High);
        assert_eq!(v.cvss_score, Some(8.1));
        assert_eq!(ranges.len(), 1);  // PUB skipped
        assert_eq!(ranges[0].ecosystem, "npm");
        assert_eq!(ranges[0].package, "left-pad");
        assert_eq!(ranges[0].fixed.as_deref(), Some("1.5"));
    }

    #[test]
    fn skips_advisory_with_no_matchable_ecosystems() {
        let node: GhsaNode = serde_json::from_str(
            r#"{
                "ghsaId":"GHSA-aa","identifiers":[],
                "severity":"LOW","publishedAt":null,"updatedAt":null,
                "references":[],"cvss":null,
                "vulnerabilities":{"nodes":[
                    {"package":{"name":"x","ecosystem":"RUBYGEMS"},"vulnerableVersionRange":"< 1","firstPatchedVersion":null}
                ]}
            }"#,
        ).unwrap();
        assert!(normalise_ghsa(&node).is_none());
    }
}
