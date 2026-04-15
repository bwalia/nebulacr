//! OSV.dev client — bootstrap `VulnDb` implementation.
//!
//! Flow:
//! 1. Build a `querybatch` request containing one entry per package
//!    (`{"package":{"purl":"..."}}`), up to `BATCH_LIMIT` per HTTP call.
//! 2. Response carries `results[i].vulns[] = [{ id }]` — just IDs.
//! 3. For each unique ID, fetch full details from `/v1/vulns/{id}`.
//! 4. Normalise into our `Vulnerability` struct, pairing each advisory back
//!    to the originating package so the caller gets a flat list.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use super::VulnDb;
use crate::model::{Severity, Vulnerability};
use crate::sbom::Package;
use crate::{Result, ScanError};

const BATCH_LIMIT: usize = 1000;

pub struct OsvClient {
    http: reqwest::Client,
    base: String,
}

impl OsvClient {
    pub fn new() -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Self {
            http,
            base: "https://api.osv.dev".into(),
        })
    }

    #[cfg(test)]
    pub fn with_base(base: String) -> Result<Self> {
        Ok(Self {
            http: reqwest::Client::new(),
            base,
        })
    }
}

#[derive(Serialize)]
struct BatchReq<'a> {
    queries: Vec<BatchQuery<'a>>,
}

#[derive(Serialize)]
struct BatchQuery<'a> {
    package: BatchPackage<'a>,
}

#[derive(Serialize)]
struct BatchPackage<'a> {
    purl: &'a str,
}

#[derive(Deserialize)]
struct BatchResp {
    results: Vec<BatchResultEntry>,
}

#[derive(Deserialize, Default)]
struct BatchResultEntry {
    #[serde(default)]
    vulns: Vec<BatchVulnStub>,
}

#[derive(Deserialize)]
struct BatchVulnStub {
    id: String,
}

#[derive(Deserialize)]
struct OsvVuln {
    id: String,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    details: Option<String>,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
    #[serde(default)]
    affected: Vec<OsvAffected>,
    #[serde(default)]
    references: Vec<OsvRef>,
}

#[derive(Deserialize)]
struct OsvSeverity {
    #[serde(rename = "type")]
    kind: String,
    score: String,
}

#[derive(Deserialize, Default)]
struct OsvAffected {
    #[serde(default)]
    ranges: Vec<OsvRange>,
}

#[derive(Deserialize, Default)]
struct OsvRange {
    #[serde(default)]
    events: Vec<OsvEvent>,
}

#[derive(Deserialize, Default)]
struct OsvEvent {
    #[serde(default)]
    fixed: Option<String>,
}

#[derive(Deserialize)]
struct OsvRef {
    url: String,
}

#[async_trait]
impl VulnDb for OsvClient {
    async fn query(&self, packages: &[Package]) -> Result<Vec<Vulnerability>> {
        if packages.is_empty() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        let mut seen_details: HashMap<String, OsvVuln> = HashMap::new();

        for chunk in packages.chunks(BATCH_LIMIT) {
            let queries: Vec<BatchQuery> = chunk
                .iter()
                .map(|p| BatchQuery {
                    package: BatchPackage { purl: &p.purl },
                })
                .collect();
            let url = format!("{}/v1/querybatch", self.base);
            let resp = self
                .http
                .post(&url)
                .json(&BatchReq { queries })
                .send()
                .await?
                .error_for_status()?
                .json::<BatchResp>()
                .await?;

            if resp.results.len() != chunk.len() {
                warn!(
                    expected = chunk.len(),
                    got = resp.results.len(),
                    "osv querybatch result count mismatch"
                );
            }

            // Collect unique IDs across this batch for detail fetch.
            let mut to_fetch: HashSet<String> = HashSet::new();
            for entry in &resp.results {
                for v in &entry.vulns {
                    if !seen_details.contains_key(&v.id) {
                        to_fetch.insert(v.id.clone());
                    }
                }
            }

            for id in to_fetch {
                match self.fetch_detail(&id).await {
                    Ok(detail) => {
                        seen_details.insert(id, detail);
                    }
                    Err(e) => warn!(%id, error = %e, "osv vuln detail fetch failed"),
                }
            }

            // Pair package → advisory.
            for (pkg, entry) in chunk.iter().zip(resp.results.iter()) {
                for stub in &entry.vulns {
                    if let Some(detail) = seen_details.get(&stub.id) {
                        out.push(normalise(pkg, detail));
                    }
                }
            }
        }

        debug!(count = out.len(), "osv query complete");
        Ok(out)
    }
}

impl OsvClient {
    async fn fetch_detail(&self, id: &str) -> Result<OsvVuln> {
        let url = format!("{}/v1/vulns/{}", self.base, id);
        let resp = self
            .http
            .get(&url)
            .send()
            .await?
            .error_for_status()?
            .json::<OsvVuln>()
            .await?;
        Ok(resp)
    }
}

fn normalise(pkg: &Package, v: &OsvVuln) -> Vulnerability {
    let cvss_score = v
        .severity
        .iter()
        .find(|s| s.kind.starts_with("CVSS"))
        .and_then(|s| parse_cvss_base(&s.score));

    let severity = classify(cvss_score);

    let fixed_version = v
        .affected
        .iter()
        .flat_map(|a| a.ranges.iter())
        .flat_map(|r| r.events.iter())
        .filter_map(|e| e.fixed.clone())
        .next();

    // OSV splits prose between `summary` (short) and `details` (long). Alpine
    // advisories typically only fill `details`. Expose both when available and
    // back-fill summary from details so UI consumers aren't empty-handed.
    let summary = v.summary.clone().or_else(|| {
        v.details
            .as_ref()
            .map(|d| d.split('.').next().unwrap_or(d).trim().to_string())
            .filter(|s| !s.is_empty())
    });

    Vulnerability {
        id: v.id.clone(),
        aliases: v.aliases.clone(),
        package: pkg.name.clone(),
        ecosystem: pkg.ecosystem.clone(),
        installed_version: pkg.version.clone(),
        fixed_version,
        severity,
        cvss_score,
        summary,
        description: v.details.clone(),
        layer_digest: pkg.layer_digest.clone(),
        references: v.references.iter().map(|r| r.url.clone()).collect(),
        suppressed: false,
    }
}

/// Extract a base score from an OSV severity `score`.
///
/// OSV encodes the score either as a literal float (rare) or as a CVSS vector
/// string like `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (common). We
/// accept both and compute the CVSS v3 base score from the vector per the
/// CVSS 3.1 specification.
fn parse_cvss_base(s: &str) -> Option<f64> {
    if let Ok(v) = s.parse::<f64>() {
        return Some(v);
    }
    if s.starts_with("CVSS:3") {
        return cvss3_base(s);
    }
    None
}

/// CVSS v3/v3.1 base-score calculator. Returns None if required metrics are
/// missing or the vector is malformed.
fn cvss3_base(vector: &str) -> Option<f64> {
    // Parse key=value pairs after the prefix.
    let mut av = None;
    let mut ac = None;
    let mut pr_raw = None;
    let mut ui = None;
    let mut scope = None;
    let mut c_m = None;
    let mut i_m = None;
    let mut a_m = None;

    for tok in vector.split('/').skip(1) {
        let (k, v) = tok.split_once(':')?;
        match k {
            "AV" => av = match v { "N" => Some(0.85), "A" => Some(0.62), "L" => Some(0.55), "P" => Some(0.20), _ => None },
            "AC" => ac = match v { "L" => Some(0.77), "H" => Some(0.44), _ => None },
            "PR" => pr_raw = Some(v.to_string()),
            "UI" => ui = match v { "N" => Some(0.85), "R" => Some(0.62), _ => None },
            "S" => scope = Some(v.to_string()),
            "C" => c_m = impact_metric(v),
            "I" => i_m = impact_metric(v),
            "A" => a_m = impact_metric(v),
            _ => {}
        }
    }

    let av = av?;
    let ac = ac?;
    let ui = ui?;
    let scope = scope?;
    let c = c_m?;
    let i = i_m?;
    let a = a_m?;
    let pr_raw = pr_raw?;

    // PR depends on scope.
    let scope_changed = scope == "C";
    let pr = if scope_changed {
        match pr_raw.as_str() { "N" => 0.85, "L" => 0.68, "H" => 0.50, _ => return None }
    } else {
        match pr_raw.as_str() { "N" => 0.85, "L" => 0.62, "H" => 0.27, _ => return None }
    };

    let iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a));
    let impact = if scope_changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powi(15)
    } else {
        6.42 * iss
    };
    if impact <= 0.0 {
        return Some(0.0);
    }
    let exploitability = 8.22 * av * ac * pr * ui;
    let base = if scope_changed {
        ((impact + exploitability) * 1.08).min(10.0)
    } else {
        (impact + exploitability).min(10.0)
    };
    Some(roundup_cvss(base))
}

fn impact_metric(v: &str) -> Option<f64> {
    match v {
        "N" => Some(0.0),
        "L" => Some(0.22),
        "H" => Some(0.56),
        _ => None,
    }
}

/// CVSS "roundup" — round up to one decimal place.
fn roundup_cvss(x: f64) -> f64 {
    let scaled = (x * 100_000.0).round() as i64;
    if scaled % 10_000 == 0 {
        (scaled / 10_000) as f64 / 10.0
    } else {
        (((scaled / 10_000) + 1) as f64) / 10.0
    }
}

fn classify(score: Option<f64>) -> Severity {
    match score {
        Some(s) if s >= 9.0 => Severity::Critical,
        Some(s) if s >= 7.0 => Severity::High,
        Some(s) if s >= 4.0 => Severity::Medium,
        Some(s) if s > 0.0 => Severity::Low,
        _ => Severity::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_buckets() {
        assert!(matches!(classify(Some(9.8)), Severity::Critical));
        assert!(matches!(classify(Some(7.5)), Severity::High));
        assert!(matches!(classify(Some(5.0)), Severity::Medium));
        assert!(matches!(classify(Some(2.0)), Severity::Low));
        assert!(matches!(classify(None), Severity::Unknown));
    }

    #[test]
    fn cvss_vector_critical() {
        // Log4Shell vector → score 10.0
        let s = parse_cvss_base("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H").unwrap();
        assert!((s - 10.0).abs() < 0.05, "got {s}");
    }

    #[test]
    fn cvss_vector_high() {
        // A common high-severity memory corruption vector → 7.5
        let s = parse_cvss_base("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H").unwrap();
        assert!((s - 7.5).abs() < 0.05, "got {s}");
    }

    #[test]
    fn cvss_vector_medium() {
        // Local, user-interaction-required, low impact → 5.x
        let s = parse_cvss_base("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N").unwrap();
        assert!(s >= 4.0 && s < 7.0, "got {s}");
    }

    #[test]
    fn cvss_literal_float_still_accepted() {
        assert_eq!(parse_cvss_base("9.8").unwrap(), 9.8);
    }
}
