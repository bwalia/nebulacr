//! VEX (Vulnerability EXchange) ingestion — OpenVEX format.
//!
//! VEX documents let a vendor declare their opinion on whether a CVE
//! *actually* affects their product. In our model a statement of
//! `not_affected` or `fixed` maps to a CVE suppression with provenance
//! (author + justification + document id), since the downstream policy
//! engine already excludes suppressed CVEs from its threshold counts.
//!
//! We accept [OpenVEX](https://github.com/openvex/spec) JSON for the MVP;
//! CSAF VEX and CycloneDX VEX can slot in later under the same endpoint
//! with a dispatch on payload shape.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::Result;
use crate::suppress::{NewSuppression, Suppressions};

/// Minimal OpenVEX 0.2.0 envelope. Fields we don't read are allowed through
/// with `#[serde(default)]` so upstream additions don't break ingest.
#[derive(Debug, Deserialize)]
pub struct OpenVex {
    #[serde(rename = "@id", default)]
    pub id: Option<String>,
    #[serde(default)]
    pub author: Option<String>,
    #[serde(default)]
    pub timestamp: Option<DateTime<Utc>>,
    #[serde(default)]
    pub statements: Vec<VexStatement>,
}

#[derive(Debug, Deserialize)]
pub struct VexStatement {
    pub vulnerability: VexVuln,
    #[serde(default)]
    pub products: Vec<VexProduct>,
    pub status: String,
    #[serde(default)]
    pub justification: Option<String>,
    #[serde(rename = "impact_statement", default)]
    pub impact: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct VexVuln {
    /// OpenVEX uses `name` for the CVE id (`CVE-2024-...`).
    #[serde(default)]
    pub name: Option<String>,
    #[serde(rename = "@id", default)]
    pub iri: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct VexProduct {
    #[serde(rename = "@id", default)]
    pub iri: Option<String>,
    #[serde(default)]
    pub identifiers: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct VexIngestReport {
    pub statements: usize,
    pub suppressions_created: usize,
    pub skipped: usize,
}

pub async fn apply_openvex(
    doc: &OpenVex,
    suppressions: &Suppressions,
    actor_override: Option<&str>,
    tenant: Option<&str>,
    project: Option<&str>,
    repository: Option<&str>,
) -> Result<VexIngestReport> {
    let author = actor_override
        .map(|s| s.to_string())
        .or(doc.author.clone())
        .unwrap_or_else(|| "vex".into());

    let mut report = VexIngestReport {
        statements: doc.statements.len(),
        suppressions_created: 0,
        skipped: 0,
    };

    for stmt in &doc.statements {
        // Only `not_affected` and `fixed` shrink the reportable-CVE set.
        // `affected` and `under_investigation` are informational — ignore.
        let applies = matches!(stmt.status.as_str(), "not_affected" | "fixed");
        if !applies {
            report.skipped += 1;
            continue;
        }
        let Some(cve) = stmt.vulnerability.name.clone() else {
            report.skipped += 1;
            continue;
        };
        let reason = build_reason(
            &stmt.status,
            stmt.justification.as_deref(),
            stmt.impact.as_deref(),
        );

        // One suppression per (CVE, package). If products is empty we fall
        // back to a CVE-scoped suppression.
        let packages: Vec<Option<String>> = if stmt.products.is_empty() {
            vec![None]
        } else {
            stmt.products.iter().map(package_from_product).collect()
        };

        for pkg in packages {
            let input = NewSuppression {
                cve_id: cve.clone(),
                scope_tenant: tenant.map(str::to_string),
                scope_project: project.map(str::to_string),
                scope_repository: repository.map(str::to_string),
                scope_package: pkg,
                reason: reason.clone(),
                expires_at: None,
            };
            match suppressions.create(&author, input).await {
                Ok(_) => report.suppressions_created += 1,
                Err(_) => report.skipped += 1,
            }
        }
    }

    Ok(report)
}

fn build_reason(status: &str, justification: Option<&str>, impact: Option<&str>) -> String {
    let mut parts = vec![format!("VEX:{status}")];
    if let Some(j) = justification {
        parts.push(j.to_string());
    }
    if let Some(i) = impact {
        parts.push(i.to_string());
    }
    parts.join(" — ")
}

/// Extract a package name from an OpenVEX product. Product IRIs are often
/// PURLs like `pkg:npm/lodash@1.2.3`; we pull the package name portion.
/// Falls back to `None` for non-PURL shapes.
fn package_from_product(p: &VexProduct) -> Option<String> {
    let iri = p.iri.as_deref()?;
    let rest = iri.strip_prefix("pkg:")?;
    // rest looks like `npm/@scope%2fname@ver` or `deb/openssl@1.1.1`
    let (_ecosystem, tail) = rest.split_once('/')?;
    let name_with_ver = tail.split('?').next().unwrap_or(tail);
    let name = name_with_ver.split('@').next().unwrap_or(name_with_ver);
    // Common PURL encodings in the package segment: %40 → @ (npm scope),
    // %2f → / (also npm scope separator). More exotic escapes are rare
    // here and we accept the raw string in those cases.
    let decoded = name
        .replace("%40", "@")
        .replace("%2f", "/")
        .replace("%2F", "/");
    Some(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_openvex_envelope() {
        let doc: OpenVex = serde_json::from_str(
            r#"{
                "@context":"https://openvex.dev/ns",
                "@id":"https://example.org/vex/1",
                "author":"security@example.org",
                "timestamp":"2025-04-01T00:00:00Z",
                "version":1,
                "statements":[
                    {"vulnerability":{"name":"CVE-2024-1"},"products":[{"@id":"pkg:npm/left-pad@1.2.3"}],"status":"not_affected","justification":"vulnerable_code_not_present"},
                    {"vulnerability":{"name":"CVE-2024-2"},"products":[],"status":"affected"},
                    {"vulnerability":{"name":"CVE-2024-3"},"products":[{"@id":"pkg:deb/openssl@1.1.1"}],"status":"fixed","impact_statement":"patched in 1.1.1k"}
                ]
            }"#,
        ).unwrap();
        assert_eq!(doc.author.as_deref(), Some("security@example.org"));
        assert_eq!(doc.statements.len(), 3);
        assert_eq!(doc.statements[0].status, "not_affected");
    }

    #[test]
    fn package_extract_from_purl() {
        let p = VexProduct {
            iri: Some("pkg:npm/left-pad@1.2.3".into()),
            identifiers: None,
        };
        assert_eq!(package_from_product(&p).as_deref(), Some("left-pad"));
    }

    #[test]
    fn scoped_purl_url_decodes() {
        let p = VexProduct {
            iri: Some("pkg:npm/%40angular%2fcore@15.0.0".into()),
            identifiers: None,
        };
        assert_eq!(package_from_product(&p).as_deref(), Some("@angular/core"));
    }

    #[test]
    fn non_purl_iri_returns_none() {
        let p = VexProduct {
            iri: Some("https://example.org/some-product".into()),
            identifiers: None,
        };
        assert!(package_from_product(&p).is_none());
    }

    #[test]
    fn reason_includes_status_and_justification() {
        assert_eq!(
            build_reason("not_affected", Some("vulnerable_code_not_present"), None),
            "VEX:not_affected — vulnerable_code_not_present"
        );
        assert_eq!(
            build_reason("fixed", None, Some("patched in 1.2")),
            "VEX:fixed — patched in 1.2"
        );
    }
}
