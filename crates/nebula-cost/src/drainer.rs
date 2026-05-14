//! Drainer: moves rows from `usage_events_staging` (UNLOGGED) into
//! `usage_events` (durable) on a periodic interval. The staging
//! table is unlogged so the request hot path stays cheap; this
//! drainer is the durability boundary.

use sqlx::{Pool, Postgres};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
pub struct DrainerConfig {
    /// How often to flush staging → durable.
    pub interval: Duration,
    /// Maximum rows moved per cycle. Caps the worst-case write
    /// amplification when the registry has been hot.
    pub batch_size: i64,
}

impl Default for DrainerConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(60),
            batch_size: 5000,
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct DrainerStats {
    pub rows_drained: u64,
    pub cycles: u64,
    pub errors: u64,
}

pub struct DrainerControl {
    stop: AtomicBool,
}

impl DrainerControl {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            stop: AtomicBool::new(false),
        })
    }
    pub fn shutdown(&self) {
        self.stop.store(true, Ordering::Release);
    }
    pub fn is_stopped(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DrainerError {
    #[error("sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),
}

pub struct Drainer {
    pool: Pool<Postgres>,
    config: DrainerConfig,
    control: Arc<DrainerControl>,
}

impl Drainer {
    pub fn new(pool: Pool<Postgres>, config: DrainerConfig, control: Arc<DrainerControl>) -> Self {
        Self {
            pool,
            config,
            control,
        }
    }

    pub async fn run(&self) -> DrainerStats {
        let mut stats = DrainerStats::default();
        info!(
            interval_secs = self.config.interval.as_secs(),
            batch = self.config.batch_size,
            "usage drainer starting"
        );
        while !self.control.is_stopped() {
            stats.cycles += 1;
            match self.drain_one_cycle().await {
                Ok(n) => stats.rows_drained += n as u64,
                Err(e) => {
                    stats.errors += 1;
                    warn!(error = %e, "usage drainer cycle failed");
                }
            }
            tokio::time::sleep(self.config.interval).await;
        }
        info!(rows = stats.rows_drained, "usage drainer stopped");
        stats
    }

    /// Drain one batch. Public so tests + ad-hoc admin endpoints can
    /// kick it without spawning the full loop.
    pub async fn drain_one_cycle(&self) -> Result<i64, DrainerError> {
        // Move rows out of staging into durable in one shot. The
        // CTE-based DELETE...RETURNING is atomic — either all the
        // rows we're moving land durably or none do.
        let row: Option<(i64,)> = sqlx::query_as(
            "WITH moved AS (
                 DELETE FROM usage_events_staging
                 WHERE ctid IN (
                     SELECT ctid FROM usage_events_staging
                     ORDER BY at
                     LIMIT $1
                 )
                 RETURNING at, tenant, project, repository, op,
                           bytes, src, status, ip, sub
             ),
             ins AS (
                 INSERT INTO usage_events
                     (at, tenant, project, repository, op,
                      bytes, src, status, ip, sub)
                 SELECT * FROM moved
                 RETURNING 1
             )
             SELECT COUNT(*)::BIGINT FROM ins",
        )
        .bind(self.config.batch_size)
        .fetch_optional(&self.pool)
        .await?;
        let n = row.map(|(n,)| n).unwrap_or(0);
        if n > 0 {
            debug!(rows = n, "usage drainer flushed batch");
        }
        Ok(n)
    }
}
