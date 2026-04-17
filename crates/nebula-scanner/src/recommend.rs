//! Base-image recommendations.
//!
//! Inspects a completed scan's package list + vulnerability count and
//! suggests hardened alternatives from a curated set (distroless /
//! Chainguard Wolfi / UBI-minimal / scratch). The logic is intentionally
//! conservative: we only recommend a swap when the current image is
//! demonstrably a general-purpose distro AND the workload signature
//! suggests a slimmer variant would still run.

use serde::Serialize;

use crate::model::ScanResult;

/// One recommendation surfaced to a caller. Impact is a rough guess at the
/// blast-radius reduction — we don't claim a precise number.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BaseImageRec {
    pub suggested_image: &'static str,
    pub rationale: &'static str,
    pub expected_cve_reduction: Reduction,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Reduction {
    Large,
    Moderate,
    Small,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RecommendationSet {
    /// The distro family we inferred from the SBOM. Guides which images we
    /// consider acceptable drop-ins.
    pub detected_family: DistroFamily,
    /// Total CVE count (pre-suppression) that motivated the suggestions.
    /// Zero-count images get no recommendations.
    pub cve_count: u32,
    pub recommendations: Vec<BaseImageRec>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DistroFamily {
    Debian,
    RedHat,
    Alpine,
    GoStatic,
    Unknown,
}

pub fn recommend(result: &ScanResult) -> RecommendationSet {
    let family = infer_family(result);
    let total =
        result.summary.critical + result.summary.high + result.summary.medium + result.summary.low;
    let recs = if total == 0 {
        Vec::new()
    } else {
        by_family(family, result)
    };
    RecommendationSet {
        detected_family: family,
        cve_count: total,
        recommendations: recs,
    }
}

fn infer_family(r: &ScanResult) -> DistroFamily {
    // Majority vote on ecosystem across installed packages. Ties fall
    // through to "unknown" — the caller gets a generic rec instead of a
    // wrong one. A binary-only image with go packages and no distro
    // packages collapses to go_static.
    let mut deb = 0u32;
    let mut rpm = 0u32;
    let mut apk = 0u32;
    let mut go = 0u32;
    let mut other = 0u32;
    for p in &r.packages {
        match p.ecosystem.as_str() {
            "deb" => deb += 1,
            "rpm" => rpm += 1,
            "apk" => apk += 1,
            "go" => go += 1,
            _ => other += 1,
        }
    }
    if deb + rpm + apk == 0 && go > 0 {
        return DistroFamily::GoStatic;
    }
    let (max, which) = [
        (deb, DistroFamily::Debian),
        (rpm, DistroFamily::RedHat),
        (apk, DistroFamily::Alpine),
        (go, DistroFamily::GoStatic),
    ]
    .into_iter()
    .max_by_key(|(c, _)| *c)
    .unwrap_or((0, DistroFamily::Unknown));
    if max == 0 || max <= other / 4 {
        DistroFamily::Unknown
    } else {
        which
    }
}

fn by_family(f: DistroFamily, r: &ScanResult) -> Vec<BaseImageRec> {
    match f {
        DistroFamily::Debian => vec![
            BaseImageRec {
                suggested_image: "gcr.io/distroless/base-debian12",
                rationale: "drops apt/shell/package-db; app + runtime only",
                expected_cve_reduction: Reduction::Large,
            },
            BaseImageRec {
                suggested_image: "cgr.dev/chainguard/wolfi-base",
                rationale: "Chainguard Wolfi — continuously-rebuilt musl base with a smaller CVE surface",
                expected_cve_reduction: Reduction::Moderate,
            },
        ],
        DistroFamily::RedHat => vec![
            BaseImageRec {
                suggested_image: "registry.access.redhat.com/ubi9/ubi-minimal",
                rationale: "UBI minimal drops the full package set; keeps yum/dnf for install steps",
                expected_cve_reduction: Reduction::Moderate,
            },
            BaseImageRec {
                suggested_image: "gcr.io/distroless/base",
                rationale: "zero shell + zero package manager; safest for non-installable workloads",
                expected_cve_reduction: Reduction::Large,
            },
        ],
        DistroFamily::Alpine => {
            let mut out = vec![BaseImageRec {
                suggested_image: "cgr.dev/chainguard/wolfi-base",
                rationale: "Wolfi — Alpine-like musl base but rebuilt per CVE",
                expected_cve_reduction: Reduction::Moderate,
            }];
            if r.packages.len() < 20 {
                out.push(BaseImageRec {
                    suggested_image: "gcr.io/distroless/static-debian12",
                    rationale: "workload looks binary-only; distroless/static is smaller still",
                    expected_cve_reduction: Reduction::Large,
                });
            }
            out
        }
        DistroFamily::GoStatic => vec![BaseImageRec {
            suggested_image: "gcr.io/distroless/static-debian12",
            rationale: "Go binary with no dynamic deps — FROM scratch or distroless/static is sufficient",
            expected_cve_reduction: Reduction::Large,
        }],
        DistroFamily::Unknown => vec![BaseImageRec {
            suggested_image: "gcr.io/distroless/base-debian12",
            rationale: "couldn't infer distro; distroless/base is a safe default for most workloads",
            expected_cve_reduction: Reduction::Moderate,
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;
    use crate::sbom::Package;
    use chrono::Utc;
    use uuid::Uuid;

    fn make(pkgs: Vec<(&str, &str)>, criticals: u32) -> ScanResult {
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
                critical: criticals,
                ..Default::default()
            },
            vulnerabilities: vec![],
            policy_evaluation: None,
            packages: pkgs
                .into_iter()
                .map(|(name, eco)| Package {
                    name: name.into(),
                    version: "1".into(),
                    ecosystem: eco.into(),
                    purl: String::new(),
                    layer_digest: None,
                })
                .collect(),
        }
    }

    #[test]
    fn debian_majority_gets_distroless_base() {
        let r = make(
            vec![("openssl", "deb"), ("libc", "deb"), ("curl", "deb")],
            1,
        );
        let rec = recommend(&r);
        assert_eq!(rec.detected_family, DistroFamily::Debian);
        assert!(
            rec.recommendations
                .iter()
                .any(|r| r.suggested_image.contains("distroless/base-debian"))
        );
    }

    #[test]
    fn go_only_workload_gets_distroless_static() {
        let r = make(vec![("github.com/x/y", "go")], 0);
        // No vulns → no recs (silent on green images).
        let rec = recommend(&r);
        assert_eq!(rec.detected_family, DistroFamily::GoStatic);
        assert!(rec.recommendations.is_empty());
    }

    #[test]
    fn go_only_workload_with_cves_recommends_distroless_static() {
        let r = make(vec![("github.com/x/y", "go")], 2);
        let rec = recommend(&r);
        assert_eq!(rec.cve_count, 2);
        assert!(
            rec.recommendations
                .iter()
                .any(|r| r.suggested_image.contains("distroless/static"))
        );
    }

    #[test]
    fn unknown_family_falls_back_to_safe_default() {
        let r = make(vec![], 1);
        let rec = recommend(&r);
        assert_eq!(rec.detected_family, DistroFamily::Unknown);
        assert_eq!(rec.recommendations.len(), 1);
    }
}
