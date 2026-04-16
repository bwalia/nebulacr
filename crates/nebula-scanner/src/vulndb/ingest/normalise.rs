//! OSV schema → our DB row shape.
//!
//! Pure, synchronous, no I/O. Input is the decoded OSV JSON record; output
//! is one `VulnerabilityRow` plus zero-or-more `AffectedRangeRow`s.
//!
//! Ecosystem mapping collapses OSV's distro-suffixed ecosystem names (e.g.
//! `Alpine:v3.16`, `Debian:11`) to their family name (`apk`, `deb`). We
//! lose per-distro-version precision for slice 2a; revisit when NVD/GHSA
//! land. Unknown ecosystems are dropped — we don't pollute the DB with
//! rows no matcher can handle.
//!
//! Source classification is developer-friendly: `CVE-*` advisories become
//! `"nvd"` even when ingested via OSV, so filtering by source in admin
//! queries returns what a developer expects.

use chrono::{DateTime, Utc};
use serde::Deserialize;

use super::{AffectedRangeRow, VulnerabilityRow};
use crate::vulndb::severity::{classify, parse_cvss_base};

#[derive(Debug, Deserialize)]
pub struct OsvRecord {
    pub id: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub details: Option<String>,
    #[serde(default)]
    pub published: Option<DateTime<Utc>>,
    #[serde(default)]
    pub modified: Option<DateTime<Utc>>,
    #[serde(default)]
    pub withdrawn: Option<DateTime<Utc>>,
    #[serde(default)]
    pub severity: Vec<OsvSeverity>,
    #[serde(default)]
    pub affected: Vec<OsvAffected>,
    #[serde(default)]
    pub references: Vec<OsvReference>,
}

#[derive(Debug, Deserialize)]
pub struct OsvSeverity {
    #[serde(rename = "type")]
    pub kind: String,
    pub score: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct OsvAffected {
    #[serde(default)]
    pub package: OsvPackage,
    #[serde(default)]
    pub ranges: Vec<OsvRange>,
    #[serde(default)]
    pub versions: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct OsvPackage {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub ecosystem: String,
    #[serde(default)]
    pub purl: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct OsvRange {
    #[serde(default, rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub events: Vec<OsvEvent>,
}

#[derive(Debug, Deserialize, Default)]
pub struct OsvEvent {
    #[serde(default)]
    pub introduced: Option<String>,
    #[serde(default)]
    pub fixed: Option<String>,
    #[serde(default)]
    pub last_affected: Option<String>,
    #[serde(default)]
    pub limit: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OsvReference {
    pub url: String,
}

/// Normalisation outcome: `None` for records we can't usefully store
/// (withdrawn advisories, or advisories whose every `affected` entry is in
/// an unknown ecosystem). The caller increments `skipped` in that case.
pub fn normalise(rec: &OsvRecord) -> Option<(VulnerabilityRow, Vec<AffectedRangeRow>)> {
    if rec.withdrawn.is_some() {
        return None;
    }

    let ranges: Vec<AffectedRangeRow> = rec.affected.iter().flat_map(decompose).collect();
    if ranges.is_empty() {
        return None;
    }

    let cvss_score = rec
        .severity
        .iter()
        .find(|s| s.kind.starts_with("CVSS"))
        .and_then(|s| parse_cvss_base(&s.score));
    let severity = classify(cvss_score);

    let summary = rec.summary.clone().or_else(|| {
        rec.details
            .as_ref()
            .map(|d| d.split('.').next().unwrap_or(d).trim().to_string())
            .filter(|s| !s.is_empty())
    });

    let vuln = VulnerabilityRow {
        id: rec.id.clone(),
        source: classify_source(&rec.id),
        summary,
        description: rec.details.clone(),
        severity,
        cvss_score,
        published_at: rec.published,
        modified_at: rec.modified,
        aliases: rec.aliases.clone(),
        references: rec.references.iter().map(|r| r.url.clone()).collect(),
    };
    Some((vuln, ranges))
}

/// Flatten one `affected[]` entry into DB rows. An OSV affected entry may
/// carry multiple `ranges[]` and each range has an ordered `events[]`
/// sequence. We walk events left-to-right, opening a row on `introduced`
/// and closing it on `fixed`/`last_affected`/`limit` — then emit the row.
/// A trailing `introduced` with no closer emits a row with only
/// `introduced` set (meaning "every version at or above this is affected").
fn decompose(a: &OsvAffected) -> Vec<AffectedRangeRow> {
    let Some(ecosystem) = map_ecosystem(&a.package.ecosystem) else {
        return Vec::new();
    };
    if a.package.name.is_empty() {
        return Vec::new();
    }
    let pkg_name = a.package.name.clone();
    let purl = a.package.purl.clone();
    let mut out = Vec::new();

    for range in &a.ranges {
        let mut introduced: Option<String> = None;
        for ev in &range.events {
            if let Some(v) = &ev.introduced {
                if v == "0" {
                    introduced = Some(String::from("0"));
                } else {
                    introduced = Some(v.clone());
                }
            } else if let Some(v) = &ev.fixed {
                out.push(AffectedRangeRow {
                    ecosystem: ecosystem.clone(),
                    package: pkg_name.clone(),
                    introduced: introduced.take(),
                    fixed: Some(v.clone()),
                    last_affected: None,
                    purl: purl.clone(),
                });
            } else if let Some(v) = &ev.last_affected {
                out.push(AffectedRangeRow {
                    ecosystem: ecosystem.clone(),
                    package: pkg_name.clone(),
                    introduced: introduced.take(),
                    fixed: None,
                    last_affected: Some(v.clone()),
                    purl: purl.clone(),
                });
            } else if ev.limit.is_some() {
                // `limit` events cap the range but don't represent a fix;
                // skip rather than mis-model as `fixed`.
                introduced = None;
            }
        }
        if let Some(v) = introduced {
            out.push(AffectedRangeRow {
                ecosystem: ecosystem.clone(),
                package: pkg_name.clone(),
                introduced: Some(v),
                fixed: None,
                last_affected: None,
                purl: purl.clone(),
            });
        }
    }

    // Some distro advisories use `versions[]` instead of `ranges[]` — encode
    // each enumerated affected version as a last_affected point.
    if out.is_empty() && !a.versions.is_empty() {
        for v in &a.versions {
            out.push(AffectedRangeRow {
                ecosystem: ecosystem.clone(),
                package: pkg_name.clone(),
                introduced: None,
                fixed: None,
                last_affected: Some(v.clone()),
                purl: purl.clone(),
            });
        }
    }

    out
}

/// Map OSV ecosystem name (possibly distro-suffixed like `Alpine:v3.16`) to
/// our internal family string. Unknown ecosystems return `None` so the
/// caller drops the advisory rather than emitting unmatchable rows.
pub fn map_ecosystem(osv: &str) -> Option<String> {
    let family = osv.split(':').next()?.trim();
    let v = match family {
        "Alpine" => "apk",
        "Debian" | "Ubuntu" => "deb",
        "AlmaLinux" | "Rocky Linux" | "Red Hat" | "RHEL" | "openSUSE" | "SUSE" => "rpm",
        "Go" => "go",
        "PyPI" => "pypi",
        "npm" => "npm",
        "crates.io" => "cargo",
        "Maven" => "maven",
        _ => return None,
    };
    Some(v.to_string())
}

/// Classify an advisory's upstream source by ID prefix so a developer
/// filtering `WHERE source='nvd'` gets what they expect even though the
/// ingest pipeline went through OSV.
pub fn classify_source(id: &str) -> String {
    let v = if id.starts_with("CVE-") {
        "nvd"
    } else if id.starts_with("GHSA-") {
        "ghsa"
    } else if id.starts_with("PYSEC-") {
        "pysec"
    } else if id.starts_with("GO-") {
        "go"
    } else if id.starts_with("ALSA-")
        || id.starts_with("DLA-")
        || id.starts_with("DSA-")
        || id.starts_with("USN-")
        || id.starts_with("RHSA-")
        || id.starts_with("RLSA-")
    {
        "distro"
    } else {
        "osv"
    };
    v.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Severity;

    fn parse(json: &str) -> OsvRecord {
        serde_json::from_str(json).expect("fixture parses")
    }

    const GHSA_SIMPLE: &str = r#"{
      "id": "GHSA-xxxx-yyyy-zzzz",
      "aliases": ["CVE-2023-12345"],
      "summary": "Prototype pollution in libfoo",
      "details": "Malicious input can modify Object prototype.",
      "published": "2023-05-01T00:00:00Z",
      "modified": "2023-05-10T00:00:00Z",
      "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
      "affected": [{
        "package": {"ecosystem": "npm", "name": "libfoo"},
        "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.3.4"}]}]
      }],
      "references": [{"type": "ADVISORY", "url": "https://example/advisory"}]
    }"#;

    #[test]
    fn normalises_ghsa_with_cve_alias() {
        let rec = parse(GHSA_SIMPLE);
        let (v, ranges) = normalise(&rec).unwrap();
        assert_eq!(v.id, "GHSA-xxxx-yyyy-zzzz");
        assert_eq!(v.source, "ghsa");
        assert!(v.aliases.contains(&"CVE-2023-12345".to_string()));
        assert_eq!(v.summary.as_deref(), Some("Prototype pollution in libfoo"));
        assert!(matches!(v.severity, Severity::Critical)); // score 9.8
        assert_eq!(v.cvss_score, Some(9.8));
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].ecosystem, "npm");
        assert_eq!(ranges[0].package, "libfoo");
        assert_eq!(ranges[0].introduced.as_deref(), Some("0"));
        assert_eq!(ranges[0].fixed.as_deref(), Some("2.3.4"));
    }

    const ALPINE_DISTRO: &str = r#"{
      "id": "CVE-2023-55555",
      "affected": [{
        "package": {"ecosystem": "Alpine:v3.16", "name": "openssl"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.1.1t-r3"}]}]
      }]
    }"#;

    #[test]
    fn cve_prefix_maps_to_nvd_source_and_alpine_collapses_to_apk() {
        let rec = parse(ALPINE_DISTRO);
        let (v, ranges) = normalise(&rec).unwrap();
        assert_eq!(v.source, "nvd");
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].ecosystem, "apk");
        assert_eq!(ranges[0].fixed.as_deref(), Some("1.1.1t-r3"));
    }

    const MULTI_RANGE: &str = r#"{
      "id": "CVE-2024-0001",
      "affected": [{
        "package": {"ecosystem": "PyPI", "name": "django"},
        "ranges": [{
          "type": "ECOSYSTEM",
          "events": [
            {"introduced": "3.0"},
            {"fixed": "3.2.25"},
            {"introduced": "4.0"},
            {"fixed": "4.2.10"}
          ]
        }]
      }]
    }"#;

    #[test]
    fn multi_event_range_decomposes_into_two_rows() {
        let (_, ranges) = normalise(&parse(MULTI_RANGE)).unwrap();
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].introduced.as_deref(), Some("3.0"));
        assert_eq!(ranges[0].fixed.as_deref(), Some("3.2.25"));
        assert_eq!(ranges[1].introduced.as_deref(), Some("4.0"));
        assert_eq!(ranges[1].fixed.as_deref(), Some("4.2.10"));
    }

    const LAST_AFFECTED: &str = r#"{
      "id": "PYSEC-2023-99",
      "affected": [{
        "package": {"ecosystem": "PyPI", "name": "requests"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"last_affected": "2.25.0"}]}]
      }]
    }"#;

    #[test]
    fn last_affected_is_preserved() {
        let (v, ranges) = normalise(&parse(LAST_AFFECTED)).unwrap();
        assert_eq!(v.source, "pysec");
        assert_eq!(ranges[0].last_affected.as_deref(), Some("2.25.0"));
        assert_eq!(ranges[0].fixed, None);
    }

    const NO_CLOSER: &str = r#"{
      "id": "CVE-2024-2",
      "affected": [{
        "package": {"ecosystem": "Go", "name": "github.com/foo/bar"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.5.0"}]}]
      }]
    }"#;

    #[test]
    fn unclosed_introduced_emits_row_with_only_introduced() {
        let (_, ranges) = normalise(&parse(NO_CLOSER)).unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].ecosystem, "go");
        assert_eq!(ranges[0].introduced.as_deref(), Some("1.5.0"));
        assert!(ranges[0].fixed.is_none());
        assert!(ranges[0].last_affected.is_none());
    }

    const WITHDRAWN: &str = r#"{
      "id": "CVE-2020-99",
      "withdrawn": "2021-01-01T00:00:00Z",
      "affected": [{"package": {"ecosystem": "npm", "name": "x"}, "ranges": []}]
    }"#;

    #[test]
    fn withdrawn_advisory_is_skipped() {
        assert!(normalise(&parse(WITHDRAWN)).is_none());
    }

    const UNKNOWN_ECO: &str = r#"{
      "id": "CVE-2024-3",
      "affected": [{
        "package": {"ecosystem": "Hex", "name": "whatever"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0"}]}]
      }]
    }"#;

    #[test]
    fn advisory_with_only_unknown_ecosystems_is_skipped() {
        assert!(normalise(&parse(UNKNOWN_ECO)).is_none());
    }

    #[test]
    fn ecosystem_mapping_covers_expected_families() {
        assert_eq!(map_ecosystem("Alpine:v3.16").as_deref(), Some("apk"));
        assert_eq!(map_ecosystem("Debian:11").as_deref(), Some("deb"));
        assert_eq!(map_ecosystem("Ubuntu:22.04").as_deref(), Some("deb"));
        assert_eq!(map_ecosystem("Rocky Linux:8").as_deref(), Some("rpm"));
        assert_eq!(map_ecosystem("Go").as_deref(), Some("go"));
        assert_eq!(map_ecosystem("PyPI").as_deref(), Some("pypi"));
        assert_eq!(map_ecosystem("npm").as_deref(), Some("npm"));
        assert_eq!(map_ecosystem("crates.io").as_deref(), Some("cargo"));
        assert_eq!(map_ecosystem("Maven").as_deref(), Some("maven"));
        assert_eq!(map_ecosystem("Unknown"), None);
    }

    #[test]
    fn source_classifier_covers_expected_prefixes() {
        assert_eq!(classify_source("CVE-2024-1"), "nvd");
        assert_eq!(classify_source("GHSA-xxxx-yyyy-zzzz"), "ghsa");
        assert_eq!(classify_source("PYSEC-2023-1"), "pysec");
        assert_eq!(classify_source("GO-2024-1"), "go");
        assert_eq!(classify_source("ALSA-2024-1"), "distro");
        assert_eq!(classify_source("DSA-5000-1"), "distro");
        assert_eq!(classify_source("USN-6000-1"), "distro");
        assert_eq!(classify_source("RHSA-2024:1"), "distro");
        assert_eq!(classify_source("OSV-2024-1"), "osv");
    }
}
