//! 014 Extended scanning — Detector trait.
//!
//! Slice 1 ships the trait + Finding shape + the unified Postgres
//! findings store. The existing CVE pipeline (worker + policy +
//! suppression) still writes Severity rows directly; slice 2
//! generalises the worker so every detector emits Findings.
//!
//! License / Secret / Malware detectors land in slices 2-4.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingKind {
    Cve,
    License,
    Secret,
    Malware,
}

impl FindingKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Cve => "cve",
            Self::License => "license",
            Self::Secret => "secret",
            Self::Malware => "malware",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "cve" => Some(Self::Cve),
            "license" => Some(Self::License),
            "secret" => Some(Self::Secret),
            "malware" => Some(Self::Malware),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl FindingSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageRef {
    pub name: String,
    pub version: Option<String>,
    pub ecosystem: Option<String>,
    pub purl: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixSuggestion {
    pub kind: String,                 // 'upgrade-package' | 'rotate-secret' | 'patch-license' | ...
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub kind: FindingKind,
    pub severity: FindingSeverity,
    pub finding_id: String,           // CVE id | SPDX id | rule id | signature
    pub title: String,
    pub package: Option<PackageRef>,
    pub path: Option<String>,
    pub line: Option<u32>,
    pub fix: Option<FixSuggestion>,
}

#[derive(Debug, thiserror::Error)]
pub enum DetectorError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse: {0}")]
    Parse(String),
    #[error("{0}")]
    Other(String),
}

/// Each detector walks a layer's tarball (or other artifact bytes) and
/// emits findings. Implementations MUST be cancellable — workers are
/// killed on shutdown.
#[async_trait]
pub trait Detector: Send + Sync {
    fn id(&self) -> FindingKind;

    /// Cheap predicate the worker uses to decide whether to invoke this
    /// detector for a given media type (e.g. skip license detector for
    /// non-tar layers).
    fn supports_media_type(&self, mt: &str) -> bool;

    /// Inspect bytes (typically a layer tarball) and emit findings.
    async fn scan(&self, bytes: bytes::Bytes) -> Result<Vec<Finding>, DetectorError>;
}

pub mod license;
pub mod store;
pub use license::{LicenseClass, LicenseDetector};
pub use store::{FindingsStore, PgFindingsStore};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finding_kind_round_trip() {
        for k in [
            FindingKind::Cve,
            FindingKind::License,
            FindingKind::Secret,
            FindingKind::Malware,
        ] {
            assert_eq!(FindingKind::parse(k.as_str()), Some(k));
        }
    }
}
