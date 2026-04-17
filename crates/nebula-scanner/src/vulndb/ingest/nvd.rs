//! NVD 2.0 CVE API ingester (slice 2b).
//!
//! Purpose: enrich vulnerability *metadata* (severity, CVSS, summary,
//! references, published/modified) using NVD as the canonical source. We
//! intentionally do **not** write to `affected_ranges` from NVD — NVD's CPE
//! model doesn't line up cleanly with PURL ecosystems, and OSV/GHSA already
//! give us usable range data. Conflicts favour the field we have:
//! `write_advisory_metadata_only` uses `COALESCE` so OSV ranges stay intact
//! and OSV's summary/description survive when NVD provides none.
//!
//! Query strategy:
//! - First run with no cursor → pull the last `bootstrap_window_days`
//!   (default 30) so operators don't wait hours on cold start.
//! - Subsequent runs → delta from stored `last_modified`.
//! - Each query window is at most 120 days (an NVD API constraint).
//! - Pages are 2000 CVEs each; we sleep between pages to stay under the
//!   public rate limit (5 req / 30s ≈ one every 6s). An API key lifts
//!   this to 50 req / 30s; configure `sleep_between_pages_secs` accordingly.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use sqlx::PgPool;
use tokio::sync::Mutex;
use tracing::{info, warn};

use super::writer::{stored_last_modified, update_cursor, write_advisory_metadata_only};
use super::{IngestStats, Ingester, VulnerabilityRow};
use crate::model::Severity;
use crate::vulndb::severity::classify;
use crate::{Result, ScanError};

const SOURCE: &str = "nvd";
const DEFAULT_BASE_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const PAGE_SIZE: usize = 2000;
const MAX_WINDOW_DAYS: i64 = 119;

pub struct NvdIngester {
    http: reqwest::Client,
    base_url: String,
    api_key: Option<String>,
    bootstrap_window_days: i64,
    sleep_between_pages: Duration,
    // Serialises concurrent run() calls (admin trigger vs. scheduler).
    lock: Arc<Mutex<()>>,
}

pub struct NvdConfig {
    pub base_url: Option<String>,
    pub api_key: Option<String>,
    pub bootstrap_window_days: i64,
    pub sleep_between_pages_secs: u64,
}

impl Default for NvdConfig {
    fn default() -> Self {
        Self {
            base_url: None,
            api_key: None,
            bootstrap_window_days: 30,
            sleep_between_pages_secs: 6,
        }
    }
}

impl NvdIngester {
    pub fn new(cfg: NvdConfig) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .build()?;
        Ok(Self {
            http,
            base_url: cfg.base_url.unwrap_or_else(|| DEFAULT_BASE_URL.into()),
            api_key: cfg.api_key,
            bootstrap_window_days: cfg.bootstrap_window_days.max(1),
            sleep_between_pages: Duration::from_secs(cfg.sleep_between_pages_secs.max(1)),
            lock: Arc::new(Mutex::new(())),
        })
    }
}

#[async_trait]
impl Ingester for NvdIngester {
    fn source(&self) -> &'static str {
        SOURCE
    }

    async fn run(&self, pool: &PgPool) -> Result<IngestStats> {
        let _guard = self.lock.lock().await;
        let now = Utc::now();
        let start = match stored_last_modified(pool, SOURCE).await? {
            Some(ts) => ts,
            None => {
                warn!(
                    days = self.bootstrap_window_days,
                    "NVD ingest first run: bootstrapping last {} days. \
                     Operators can set a shorter window via config if needed.",
                    self.bootstrap_window_days
                );
                now - chrono::Duration::days(self.bootstrap_window_days)
            }
        };

        let mut stats = IngestStats::default();
        let mut max_modified = start;
        let mut cursor = start;
        while cursor < now {
            let window_end =
                (cursor + chrono::Duration::days(MAX_WINDOW_DAYS)).min(now);
            match self
                .ingest_window(pool, cursor, window_end, &mut max_modified, &mut stats)
                .await
            {
                Ok(()) => {}
                Err(e) => {
                    warn!(
                        start = %cursor,
                        end = %window_end,
                        error = %e,
                        "NVD window failed; persisting partial progress"
                    );
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
            }
            cursor = window_end;
        }

        update_cursor(pool, SOURCE, None, Some(max_modified), &stats, None).await?;
        info!(
            advisories = stats.advisories,
            skipped = stats.skipped,
            errors = stats.errors,
            "NVD ingest run complete"
        );
        Ok(stats)
    }
}

impl NvdIngester {
    async fn ingest_window(
        &self,
        pool: &PgPool,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        max_modified: &mut DateTime<Utc>,
        stats: &mut IngestStats,
    ) -> Result<()> {
        let mut start_index = 0usize;
        loop {
            let page = self.fetch_page(start, end, start_index).await?;
            let page_len = page.vulnerabilities.len();
            for item in page.vulnerabilities {
                match normalise_nvd(&item) {
                    Some(row) => {
                        if let Some(t) = row.modified_at {
                            if t > *max_modified {
                                *max_modified = t;
                            }
                        }
                        match write_advisory_metadata_only(pool, &row).await {
                            Ok(()) => stats.advisories += 1,
                            Err(e) => {
                                warn!(id = %row.id, error = %e, "NVD advisory write failed");
                                stats.errors += 1;
                            }
                        }
                    }
                    None => stats.skipped += 1,
                }
            }
            let next = start_index + page_len;
            if page_len == 0 || next >= page.total_results {
                break;
            }
            start_index = next;
            tokio::time::sleep(self.sleep_between_pages).await;
        }
        Ok(())
    }

    async fn fetch_page(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        start_index: usize,
    ) -> Result<NvdApiResponse> {
        let mut req = self
            .http
            .get(&self.base_url)
            .query(&[
                ("lastModStartDate", format_nvd_ts(start)),
                ("lastModEndDate", format_nvd_ts(end)),
                ("resultsPerPage", PAGE_SIZE.to_string()),
                ("startIndex", start_index.to_string()),
            ]);
        if let Some(key) = &self.api_key {
            req = req.header("apiKey", key);
        }
        let resp = req.send().await?.error_for_status()?;
        let body: NvdApiResponse = resp.json().await.map_err(|e| {
            ScanError::VulnDb(format!("nvd json decode: {e}"))
        })?;
        Ok(body)
    }
}

fn format_nvd_ts(ts: DateTime<Utc>) -> String {
    // NVD 2.0 expects ISO-8601 with millisecond precision and a trailing offset.
    ts.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

// ── NVD response types (minimal, only what we read) ─────────────────────────

#[derive(Debug, Deserialize)]
struct NvdApiResponse {
    #[serde(rename = "totalResults", default)]
    total_results: usize,
    #[serde(default)]
    vulnerabilities: Vec<NvdVulnEnvelope>,
}

#[derive(Debug, Deserialize)]
struct NvdVulnEnvelope {
    cve: NvdCve,
}

#[derive(Debug, Deserialize)]
struct NvdCve {
    id: String,
    #[serde(default)]
    published: Option<DateTime<Utc>>,
    #[serde(rename = "lastModified", default)]
    last_modified: Option<DateTime<Utc>>,
    #[serde(default)]
    descriptions: Vec<NvdDescription>,
    #[serde(default)]
    references: Vec<NvdReference>,
    #[serde(default)]
    metrics: NvdMetrics,
    #[serde(default)]
    weaknesses: Vec<NvdWeakness>,
}

#[derive(Debug, Deserialize)]
struct NvdDescription {
    lang: String,
    value: String,
}

#[derive(Debug, Deserialize)]
struct NvdReference {
    url: String,
}

#[derive(Debug, Deserialize, Default)]
struct NvdMetrics {
    #[serde(rename = "cvssMetricV31", default)]
    v31: Vec<NvdCvssWrapper>,
    #[serde(rename = "cvssMetricV30", default)]
    v30: Vec<NvdCvssWrapper>,
    #[serde(rename = "cvssMetricV2", default)]
    v2: Vec<NvdCvssWrapper>,
}

#[derive(Debug, Deserialize)]
struct NvdCvssWrapper {
    #[serde(rename = "cvssData")]
    cvss_data: NvdCvssData,
}

#[derive(Debug, Deserialize)]
struct NvdCvssData {
    #[serde(rename = "baseScore", default)]
    base_score: Option<f64>,
    #[serde(rename = "baseSeverity", default)]
    base_severity: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NvdWeakness {
    #[serde(default)]
    description: Vec<NvdDescription>,
}

// ── Normaliser ──────────────────────────────────────────────────────────────

fn normalise_nvd(env: &NvdVulnEnvelope) -> Option<VulnerabilityRow> {
    let cve = &env.cve;
    if !cve.id.starts_with("CVE-") {
        return None;
    }
    let summary = pick_english(&cve.descriptions).map(|s| first_sentence(s).to_string());
    let description = pick_english(&cve.descriptions).map(|s| s.to_string());
    let (cvss_score, severity) = extract_severity(&cve.metrics);
    let references: Vec<String> = cve.references.iter().map(|r| r.url.clone()).collect();
    // NVD doesn't ship aliases inline; CWE IDs from weaknesses are the
    // closest thing — we skip them here to keep the alias field meaningful
    // (OSV/GHSA provide the cross-source mapping).
    let _ = &cve.weaknesses;

    Some(VulnerabilityRow {
        id: cve.id.clone(),
        source: "nvd".into(),
        summary,
        description,
        severity,
        cvss_score,
        published_at: cve.published,
        modified_at: cve.last_modified,
        aliases: Vec::new(),
        references,
    })
}

fn pick_english(descs: &[NvdDescription]) -> Option<&str> {
    descs
        .iter()
        .find(|d| d.lang == "en")
        .map(|d| d.value.as_str())
}

fn first_sentence(s: &str) -> &str {
    match s.find(". ") {
        Some(i) if i < 200 => &s[..i + 1],
        _ => &s[..s.len().min(200)],
    }
}

fn extract_severity(m: &NvdMetrics) -> (Option<f64>, Severity) {
    // Prefer v3.1, then v3.0, then v2.
    let chosen = m
        .v31
        .first()
        .or_else(|| m.v30.first())
        .or_else(|| m.v2.first());
    let Some(c) = chosen else {
        return (None, Severity::Unknown);
    };
    let score = c.cvss_data.base_score;
    let sev = c
        .cvss_data
        .base_severity
        .as_deref()
        .map(|s| match s.to_ascii_uppercase().as_str() {
            "CRITICAL" => Severity::Critical,
            "HIGH" => Severity::High,
            "MEDIUM" => Severity::Medium,
            "LOW" => Severity::Low,
            _ => Severity::Unknown,
        })
        .unwrap_or_else(|| classify(score));
    (score, sev)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(json: &str) -> NvdVulnEnvelope {
        serde_json::from_str(json).expect("parse")
    }

    #[test]
    fn normalises_minimal_cve() {
        let row = normalise_nvd(&raw(
            r#"{"cve":{"id":"CVE-2020-1234","published":"2020-01-01T00:00:00.000Z",
                "lastModified":"2020-02-01T00:00:00.000Z",
                "descriptions":[{"lang":"en","value":"Example flaw."}],
                "references":[{"url":"https://example.org"}],
                "metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":7.5,"baseSeverity":"HIGH"}}]},
                "weaknesses":[]}}"#,
        ))
        .unwrap();
        assert_eq!(row.id, "CVE-2020-1234");
        assert_eq!(row.source, "nvd");
        assert_eq!(row.severity, Severity::High);
        assert_eq!(row.cvss_score, Some(7.5));
        assert_eq!(row.references, vec!["https://example.org"]);
        assert!(row.summary.unwrap().starts_with("Example flaw"));
    }

    #[test]
    fn skips_non_cve_ids() {
        // Defensive: NVD 2.0 API only emits CVE-* but future-proof.
        let out = normalise_nvd(&raw(
            r#"{"cve":{"id":"ADV-xxxx","descriptions":[],"references":[],"metrics":{},"weaknesses":[]}}"#,
        ));
        assert!(out.is_none());
    }

    #[test]
    fn falls_back_when_severity_missing() {
        let row = normalise_nvd(&raw(
            r#"{"cve":{"id":"CVE-2024-0001",
                "descriptions":[{"lang":"en","value":"x"}],
                "references":[],"metrics":{},"weaknesses":[]}}"#,
        ))
        .unwrap();
        assert_eq!(row.severity, Severity::Unknown);
        assert!(row.cvss_score.is_none());
    }

    #[test]
    fn infers_severity_from_score_when_label_absent() {
        let row = normalise_nvd(&raw(
            r#"{"cve":{"id":"CVE-2024-0002",
                "descriptions":[{"lang":"en","value":"x"}],
                "references":[],
                "metrics":{"cvssMetricV30":[{"cvssData":{"baseScore":9.8}}]},
                "weaknesses":[]}}"#,
        ))
        .unwrap();
        assert_eq!(row.cvss_score, Some(9.8));
        assert_eq!(row.severity, Severity::Critical);
    }
}
