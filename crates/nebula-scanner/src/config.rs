use serde::{Deserialize, Serialize};

/// Scanner configuration. Loaded from env under `NEBULACR_SCANNER__*` via
/// the existing `config` crate machinery in `nebula-common`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub postgres_url: String,
    pub redis_url: String,
    #[serde(default = "default_vulndb")]
    pub vulndb: VulnDbBackend,
    #[serde(default = "default_true")]
    pub ai_enabled: bool,
    #[serde(default = "default_ai_endpoint")]
    pub ai_endpoint: String,
    #[serde(default = "default_ai_model")]
    pub ai_model: String,
    #[serde(default = "default_workers")]
    pub workers: usize,
    #[serde(default = "default_queue_capacity")]
    pub queue_capacity: usize,
    #[serde(default = "default_result_ttl")]
    pub result_ttl_secs: u64,
    #[serde(default = "default_pg_conns")]
    pub pg_max_connections: u32,
    /// Run vuln-DB ingesters on a schedule. Default on — operators who
    /// don't want the ~300MB OSV download flip it off explicitly.
    #[serde(default = "default_true")]
    pub ingest_enabled: bool,
    /// Interval between successive ingest runs, in seconds. Default 6h.
    #[serde(default = "default_ingest_interval")]
    pub ingest_interval_secs: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VulnDbBackend {
    Osv,
    /// Our own Postgres-backed DB fed by NVD/OSV/GHSA ingesters (slice 2).
    Nebula,
}

fn default_true() -> bool {
    true
}
fn default_vulndb() -> VulnDbBackend {
    VulnDbBackend::Osv
}
fn default_ai_endpoint() -> String {
    "http://127.0.0.1:11434".into()
}
fn default_ai_model() -> String {
    "qwen2.5-coder:7b".into()
}
fn default_workers() -> usize {
    2
}
fn default_queue_capacity() -> usize {
    256
}
fn default_result_ttl() -> u64 {
    3600
}
fn default_pg_conns() -> u32 {
    8
}
fn default_ingest_interval() -> u64 {
    21_600 // 6h
}
