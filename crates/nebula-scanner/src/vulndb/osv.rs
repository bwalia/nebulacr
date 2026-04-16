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

use super::severity::{classify, parse_cvss_base};
use super::VulnDb;
use crate::model::Vulnerability;
use crate::sbom::Package;
use crate::Result;

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

