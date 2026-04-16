//! Vuln-DB ingestion (slice 2a).
//!
//! Each upstream feed (OSV, eventually NVD and GHSA) implements `Ingester`
//! and is driven by the scheduler in `runtime.rs`. Ingesters produce
//! `VulnerabilityRow` + `AffectedRangeRow` values that map 1:1 onto the
//! `vulnerabilities` and `affected_ranges` tables in `0001_init.sql`.
//!
//! The trait split keeps the normalisation layer (pure, unit-tested) away
//! from the I/O layer (HTTP downloads, SQL writes).

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::Result;
use crate::model::Severity;

pub mod normalise;
pub mod osv;
pub mod writer;

pub use osv::OsvIngester;

/// A vuln ingester. Each implementation owns its own upstream feed, cursor
/// handling, and error recovery. Runs are idempotent: re-running against
/// an unchanged upstream must be a near-no-op thanks to the cursor stored
/// in the `ingest_cursor` table.
#[async_trait]
pub trait Ingester: Send + Sync {
    /// Short identifier matching the `ingest_cursor.source` primary key
    /// (e.g. `"osv"`, `"nvd"`, `"ghsa"`).
    fn source(&self) -> &'static str;

    /// Run one ingestion pass. Must be cancellation-safe — on error,
    /// persist as much as was already written and report stats.
    async fn run(&self, pool: &PgPool) -> Result<IngestStats>;
}

#[derive(Debug, Clone, Default)]
pub struct IngestStats {
    /// Advisories written (INSERTed or UPDATEd).
    pub advisories: u64,
    /// Advisories skipped (e.g. withdrawn, no matchable ecosystem).
    pub skipped: u64,
    /// Non-fatal errors during normalisation (malformed records).
    pub errors: u64,
}

/// Row shape for `vulnerabilities`. Matches the column order in the
/// migration; constructors fill only the fields the ingester has — the
/// writer layer is responsible for the INSERT.
#[derive(Debug, Clone, PartialEq)]
pub struct VulnerabilityRow {
    pub id: String,
    pub source: String,
    pub summary: Option<String>,
    pub description: Option<String>,
    pub severity: Severity,
    pub cvss_score: Option<f64>,
    pub published_at: Option<DateTime<Utc>>,
    pub modified_at: Option<DateTime<Utc>>,
    pub aliases: Vec<String>,
    pub references: Vec<String>,
}

/// Row shape for `affected_ranges`. `introduced`, `fixed`, and
/// `last_affected` are version-strings as the upstream expressed them; the
/// matcher compares them against installed versions at query time.
#[derive(Debug, Clone, PartialEq)]
pub struct AffectedRangeRow {
    pub ecosystem: String,
    pub package: String,
    pub introduced: Option<String>,
    pub fixed: Option<String>,
    pub last_affected: Option<String>,
    pub purl: Option<String>,
}

/// Spawn one tokio task per ingester that runs once, then loops on
/// `interval`. Runs are best-effort — transient errors are logged, the
/// ingester keeps its schedule. The returned handles are kept by
/// `ScannerRuntime` for shutdown.
pub fn spawn_scheduler(
    ingesters: Vec<Arc<dyn Ingester>>,
    pool: PgPool,
    interval: Duration,
) -> Vec<JoinHandle<()>> {
    ingesters
        .into_iter()
        .map(|ing| {
            let pool = pool.clone();
            tokio::spawn(async move {
                info!(
                    source = ing.source(),
                    secs = interval.as_secs(),
                    "vuln-DB ingest scheduler starting"
                );
                loop {
                    match ing.run(&pool).await {
                        Ok(stats) => info!(
                            source = ing.source(),
                            advisories = stats.advisories,
                            skipped = stats.skipped,
                            errors = stats.errors,
                            "ingest tick ok"
                        ),
                        Err(e) => warn!(source = ing.source(), error = %e, "ingest tick failed"),
                    }
                    tokio::time::sleep(interval).await;
                }
            })
        })
        .collect()
}
