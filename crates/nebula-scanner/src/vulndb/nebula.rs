//! Our own Postgres-backed `VulnDb`. Populated by the ingesters in
//! `vulndb::ingest`; selected when `NEBULACR_SCANNER__VULNDB=nebula`.
//!
//! Query flow: for each input `Package`, pull `affected_ranges` joined
//! with `vulnerabilities` by `(ecosystem, package)`, then filter each row
//! in-process using the per-ecosystem comparator from `crate::matcher`.
//! Ranges with a version the comparator can't parse are skipped (we never
//! claim a vuln applies based on a version we couldn't order).

use std::cmp::Ordering;
use std::collections::HashSet;

use async_trait::async_trait;
use sqlx::PgPool;
use tracing::warn;

use super::VulnDb;
use crate::Result;
use crate::matcher::{self, VersionCompare};
use crate::model::{Severity, Vulnerability};
use crate::sbom::Package;

pub struct NebulaVulnDb {
    pool: PgPool,
}

impl NebulaVulnDb {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct QueryRow {
    id: String,
    aliases: Vec<String>,
    summary: Option<String>,
    description: Option<String>,
    severity: Option<String>,
    cvss_score: Option<f64>,
    refs: serde_json::Value,
    introduced: Option<String>,
    fixed: Option<String>,
    last_affected: Option<String>,
}

#[async_trait]
impl VulnDb for NebulaVulnDb {
    async fn query(&self, packages: &[Package]) -> Result<Vec<Vulnerability>> {
        let mut out = Vec::new();
        for pkg in packages {
            let Some(cmp) = matcher::for_ecosystem(&pkg.ecosystem) else {
                continue;
            };
            let rows: Vec<QueryRow> = sqlx::query_as(
                r#"SELECT v.id, v.aliases, v.summary, v.description, v.severity,
                          v.cvss_score, v.refs,
                          r.introduced, r.fixed, r.last_affected
                   FROM affected_ranges r
                   JOIN vulnerabilities v ON v.id = r.vuln_id
                   WHERE r.ecosystem = $1 AND r.package = $2"#,
            )
            .bind(&pkg.ecosystem)
            .bind(&pkg.name)
            .fetch_all(&self.pool)
            .await
            .map_err(nebula_db::DbError::from)?;

            let mut seen: HashSet<String> = HashSet::new();
            for row in rows {
                if !in_range(&*cmp, &pkg.version, &row) {
                    continue;
                }
                if !seen.insert(row.id.clone()) {
                    continue;
                }
                out.push(Vulnerability {
                    id: row.id,
                    aliases: row.aliases,
                    package: pkg.name.clone(),
                    ecosystem: pkg.ecosystem.clone(),
                    installed_version: pkg.version.clone(),
                    fixed_version: row.fixed,
                    severity: parse_severity(row.severity.as_deref()),
                    cvss_score: row.cvss_score,
                    summary: row.summary,
                    description: row.description,
                    layer_digest: pkg.layer_digest.clone(),
                    references: extract_refs(&row.refs),
                    suppressed: false,
                });
            }
        }
        Ok(out)
    }
}

/// An installed version is in a given range if it is at or above
/// `introduced`, strictly below `fixed`, and at or below `last_affected`.
/// A missing bound is vacuously satisfied. The OSV sentinel `introduced="0"`
/// is treated as "no lower bound" — comparators can't parse "0" for
/// ecosystems like Go or PyPI.
fn in_range(cmp: &dyn VersionCompare, installed: &str, row: &QueryRow) -> bool {
    if let Some(intro) = row.introduced.as_deref()
        && intro != "0"
    {
        match cmp.compare(installed, intro) {
            Ok(Ordering::Less) => return false,
            Err(e) => {
                warn!(installed, introduced = intro, error = %e, "version compare failed");
                return false;
            }
            _ => {}
        }
    }
    if let Some(fixed) = row.fixed.as_deref() {
        match cmp.compare(installed, fixed) {
            Ok(Ordering::Less) => {}
            Ok(_) => return false,
            Err(e) => {
                warn!(installed, fixed, error = %e, "version compare failed");
                return false;
            }
        }
    }
    if let Some(last) = row.last_affected.as_deref() {
        match cmp.compare(installed, last) {
            Ok(Ordering::Greater) => return false,
            Err(e) => {
                warn!(installed, last_affected = last, error = %e, "version compare failed");
                return false;
            }
            _ => {}
        }
    }
    true
}

fn parse_severity(s: Option<&str>) -> Severity {
    match s {
        Some("CRITICAL") => Severity::Critical,
        Some("HIGH") => Severity::High,
        Some("MEDIUM") => Severity::Medium,
        Some("LOW") => Severity::Low,
        _ => Severity::Unknown,
    }
}

fn extract_refs(v: &serde_json::Value) -> Vec<String> {
    match v {
        serde_json::Value::Array(items) => items
            .iter()
            .filter_map(|it| it.as_str().map(|s| s.to_string()))
            .collect(),
        _ => Vec::new(),
    }
}
