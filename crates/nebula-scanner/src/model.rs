use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Severity buckets — uppercase on the wire to match OSV / NVD conventions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Unknown,
}

impl Severity {
    pub fn rank(self) -> u8 {
        match self {
            Severity::Critical => 4,
            Severity::High => 3,
            Severity::Medium => 2,
            Severity::Low => 1,
            Severity::Unknown => 0,
        }
    }
}

/// One normalised vulnerability finding attached to one package instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String, // CVE-… or GHSA-…
    pub aliases: Vec<String>,
    pub package: String,
    pub ecosystem: String, // deb | rpm | apk | npm | cargo | pypi | go | maven
    pub installed_version: String,
    pub fixed_version: Option<String>,
    pub severity: Severity,
    pub cvss_score: Option<f64>,
    pub summary: Option<String>,
    pub description: Option<String>,
    pub layer_digest: Option<String>,
    pub references: Vec<String>,
    #[serde(default)]
    pub suppressed: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanSummary {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub unknown: u32,
}

impl ScanSummary {
    pub fn add(&mut self, sev: Severity) {
        match sev {
            Severity::Critical => self.critical += 1,
            Severity::High => self.high += 1,
            Severity::Medium => self.medium += 1,
            Severity::Low => self.low += 1,
            Severity::Unknown => self.unknown += 1,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    Queued,
    InProgress,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyViolation {
    pub severity: Severity,
    pub count: u32,
    pub threshold: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEvaluation {
    pub status: PolicyStatus,
    pub violations: Vec<PolicyViolation>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum PolicyStatus {
    Pass,
    Fail,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub id: Uuid,
    pub digest: String,
    pub tenant: String,
    pub project: String,
    pub repository: String,
    pub reference: String,
    pub status: ScanStatus,
    pub error: Option<String>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub summary: ScanSummary,
    pub vulnerabilities: Vec<Vulnerability>,
    pub policy_evaluation: Option<PolicyEvaluation>,
}

/// Enqueued scan job, produced by the manifest.push webhook subscriber and
/// consumed by the worker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanJob {
    pub id: Uuid,
    pub digest: String,
    pub tenant: String,
    pub project: String,
    pub repository: String,
    pub reference: String,
    pub enqueued_at: DateTime<Utc>,
}
