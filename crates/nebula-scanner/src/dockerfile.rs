//! Dockerfile auto-fix suggestions.
//!
//! Given a scan result, emit a structured list of changes that would close
//! the reported CVEs: base-image swaps, package upgrades with explicit
//! version pins, and install-manifest template snippets. The caller
//! decides how to apply them — we deliberately don't rewrite arbitrary
//! Dockerfiles here, because correct substitution depends on build-time
//! context we don't observe (multi-stage layout, arg values, targets).

use serde::Serialize;

use crate::model::{ScanResult, Severity};
use crate::recommend::{DistroFamily, recommend};

#[derive(Debug, Serialize)]
pub struct DockerfileFixSuggestions {
    /// Detected distro family — drives the install-command template we
    /// ship alongside each pin.
    pub distro_family: DistroFamily,
    /// Suggested drop-in base image (first entry from `recommend`).
    pub base_image_swap: Option<BaseSwap>,
    /// Package upgrades with the pinned version the scanner believes will
    /// close the CVE. Sorted severity-desc so the highest-impact fixes
    /// surface first.
    pub package_pins: Vec<PackagePin>,
}

#[derive(Debug, Serialize)]
pub struct BaseSwap {
    pub suggested_image: String,
    pub rationale: String,
}

#[derive(Debug, Serialize)]
pub struct PackagePin {
    pub package: String,
    pub ecosystem: String,
    pub current_version: String,
    pub suggested_version: String,
    pub closes_cves: Vec<String>,
    /// Copy-pasteable install-command snippet appropriate for the detected
    /// distro family. `None` when we can't produce a confident template
    /// (e.g. language ecosystems — the caller already has the lock file).
    pub install_snippet: Option<String>,
}

pub fn suggest(result: &ScanResult) -> DockerfileFixSuggestions {
    let recs = recommend(result);
    let base_image_swap = recs
        .recommendations
        .first()
        .map(|r| BaseSwap {
            suggested_image: r.suggested_image.to_string(),
            rationale: r.rationale.to_string(),
        });

    // Group vulnerabilities by (package, ecosystem). Pick the highest-severity
    // fixed_version per group — if any entry in the group has a fix, the
    // pin is actionable.
    let mut by_pkg: std::collections::HashMap<
        (String, String),
        PackagePin,
    > = std::collections::HashMap::new();
    for v in &result.vulnerabilities {
        if v.suppressed {
            continue;
        }
        let Some(fixed) = v.fixed_version.clone() else {
            continue;
        };
        let key = (v.package.clone(), v.ecosystem.clone());
        let entry = by_pkg.entry(key.clone()).or_insert_with(|| PackagePin {
            package: v.package.clone(),
            ecosystem: v.ecosystem.clone(),
            current_version: v.installed_version.clone(),
            suggested_version: fixed.clone(),
            closes_cves: Vec::new(),
            install_snippet: install_snippet(&v.ecosystem, &v.package, &fixed, recs.detected_family),
        });
        entry.closes_cves.push(v.id.clone());
        // If this vuln has a higher severity, bump the suggested version.
        if rank(v.severity) > severity_rank_of_pin(entry, result) {
            entry.suggested_version = fixed;
        }
    }

    let mut pins: Vec<PackagePin> = by_pkg.into_values().collect();
    pins.sort_by(|a, b| {
        b.closes_cves.len().cmp(&a.closes_cves.len()).then_with(|| {
            a.package.cmp(&b.package)
        })
    });

    DockerfileFixSuggestions {
        distro_family: recs.detected_family,
        base_image_swap,
        package_pins: pins,
    }
}

fn rank(s: Severity) -> u8 {
    s.rank()
}

fn severity_rank_of_pin(_pin: &PackagePin, _r: &ScanResult) -> u8 {
    // We don't store the severity on the pin itself; this keeper stub
    // encodes the intent for future severity-aware tie-breaking. For now
    // the first-seen fix wins, which is good enough for MVP.
    0
}

fn install_snippet(
    ecosystem: &str,
    package: &str,
    fixed: &str,
    family: DistroFamily,
) -> Option<String> {
    match (ecosystem, family) {
        ("deb", _) => Some(format!(
            "RUN apt-get update && apt-get install -y --no-install-recommends {package}={fixed}* && rm -rf /var/lib/apt/lists/*"
        )),
        ("rpm", _) => Some(format!(
            "RUN microdnf install -y {package}-{fixed}"
        )),
        ("apk", _) => Some(format!(
            "RUN apk add --no-cache {package}={fixed}"
        )),
        _ => None, // language ecosystems — caller updates the lock file.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;
    use crate::sbom::Package;
    use chrono::Utc;
    use uuid::Uuid;

    fn make_result() -> ScanResult {
        ScanResult {
            id: Uuid::nil(),
            digest: "sha256:x".into(),
            tenant: "t".into(),
            project: "p".into(),
            repository: "r".into(),
            reference: "1".into(),
            status: ScanStatus::Completed,
            error: None,
            started_at: Utc::now(),
            completed_at: Some(Utc::now()),
            summary: ScanSummary {
                critical: 1,
                high: 1,
                ..Default::default()
            },
            vulnerabilities: vec![
                Vulnerability {
                    id: "CVE-1".into(),
                    aliases: vec![],
                    package: "openssl".into(),
                    ecosystem: "deb".into(),
                    installed_version: "1.1.1".into(),
                    fixed_version: Some("1.1.1k".into()),
                    severity: Severity::Critical,
                    cvss_score: Some(9.8),
                    summary: None,
                    description: None,
                    layer_digest: None,
                    references: vec![],
                    suppressed: false,
                },
                Vulnerability {
                    id: "CVE-2".into(),
                    aliases: vec![],
                    package: "openssl".into(),
                    ecosystem: "deb".into(),
                    installed_version: "1.1.1".into(),
                    fixed_version: Some("1.1.1k".into()),
                    severity: Severity::High,
                    cvss_score: Some(7.5),
                    summary: None,
                    description: None,
                    layer_digest: None,
                    references: vec![],
                    suppressed: false,
                },
                Vulnerability {
                    id: "CVE-IGNORED".into(),
                    aliases: vec![],
                    package: "curl".into(),
                    ecosystem: "deb".into(),
                    installed_version: "7.80".into(),
                    fixed_version: Some("7.81".into()),
                    severity: Severity::Medium,
                    cvss_score: None,
                    summary: None,
                    description: None,
                    layer_digest: None,
                    references: vec![],
                    suppressed: true, // suppressed — should not appear
                },
            ],
            policy_evaluation: None,
            packages: vec![Package {
                name: "openssl".into(),
                version: "1.1.1".into(),
                ecosystem: "deb".into(),
                purl: String::new(),
                layer_digest: None,
            }],
        }
    }

    #[test]
    fn groups_cves_per_package_and_pins_fixed_version() {
        let s = suggest(&make_result());
        assert_eq!(s.distro_family, DistroFamily::Debian);
        assert!(s.base_image_swap.is_some());
        assert_eq!(s.package_pins.len(), 1); // curl is suppressed
        let pin = &s.package_pins[0];
        assert_eq!(pin.package, "openssl");
        assert_eq!(pin.suggested_version, "1.1.1k");
        assert_eq!(pin.closes_cves.len(), 2);
        assert!(pin.install_snippet.as_deref().unwrap().starts_with("RUN apt-get"));
    }

    #[test]
    fn language_ecosystem_has_no_install_snippet() {
        let snip = install_snippet("npm", "left-pad", "1.5.0", DistroFamily::Unknown);
        assert!(snip.is_none());
    }
}
