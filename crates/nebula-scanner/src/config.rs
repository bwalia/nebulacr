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
    /// Object-store prefix under which `/v2/export/s3/{id}` writes report
    /// pairs. Defaults to `scanner-exports`; callers with a dedicated
    /// export bucket can point this at an empty string.
    #[serde(default = "default_export_prefix")]
    pub export_prefix: String,
    /// Enable the NVD 2.0 ingester. Off by default because public-rate-limit
    /// bootstrap takes hours; flip on after minting an NVD API key.
    #[serde(default)]
    pub nvd_enabled: bool,
    /// NVD API key; without one the public rate limit (5 req / 30s) applies.
    #[serde(default)]
    pub nvd_api_key: Option<String>,
    /// Days of backfill on first run. Default 30 — wider windows cost more
    /// rate-limit budget.
    #[serde(default = "default_nvd_bootstrap")]
    pub nvd_bootstrap_window_days: u32,
    /// Sleep between paged requests. Default 6s (public limit). With an
    /// API key a value of 1s stays comfortably under the 50/30s limit.
    #[serde(default = "default_nvd_sleep")]
    pub nvd_sleep_between_pages_secs: u64,
    /// Enable the GHSA ingester. Requires `ghsa_token`. Off by default.
    #[serde(default)]
    pub ghsa_enabled: bool,
    /// GitHub token with read access; required when ghsa_enabled=true.
    #[serde(default)]
    pub ghsa_token: Option<String>,
    /// Requests-per-minute cap per API key (or `system` bucket for
    /// unauthenticated callers). Default 600 rpm ≈ 10 rps — enough headroom
    /// for a CI polling /scan/live every few seconds and a dashboard.
    #[serde(default = "default_rate_limit_rpm")]
    pub rate_limit_rpm: u32,
    /// Optional webhook URL. Alerts fire on scan FAIL only; PASS scans are
    /// silent.
    #[serde(default)]
    pub alerts_webhook_url: Option<String>,
    /// `slack` | `teams` | `generic`. Default `generic` emits a flat JSON
    /// event — useful for self-hosted receivers or tools like n8n.
    #[serde(default = "default_alerts_format")]
    pub alerts_format: String,
    /// Queue backend. `tokio` (default) keeps the queue in-process — fine
    /// when workers run in the same binary as the enqueue side. `postgres`
    /// writes into the `scan_jobs` table so workers in a separate
    /// `nebula-scanner` binary can claim jobs.
    #[serde(default)]
    pub queue_backend: QueueBackend,
    /// When true, build the queue + API router but don't spawn workers or
    /// the ingest scheduler. Set this in the registry process when workers
    /// run in a separate `nebula-scanner` deployment. Default false.
    #[serde(default)]
    pub enqueue_only: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum QueueBackend {
    #[default]
    Tokio,
    Postgres,
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
fn default_export_prefix() -> String {
    "scanner-exports".into()
}
fn default_nvd_bootstrap() -> u32 {
    30
}
fn default_nvd_sleep() -> u64 {
    6
}
fn default_rate_limit_rpm() -> u32 {
    600
}
fn default_alerts_format() -> String {
    "generic".into()
}
