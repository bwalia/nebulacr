//! Hourly + daily rollups.
//!
//! Aggregates `usage_events` rows into `usage_hourly` (and the daily
//! roll-up into `usage_daily`) on a fixed cadence. Re-running over a
//! window is idempotent — `(bucket_at, tenant, project, repo, op,
//! src)` is the primary key and we ON CONFLICT DO UPDATE the totals.

use sqlx::{Pool, Postgres};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
pub struct RollupConfig {
    /// How often the loop wakes up. The actual rollup operates on
    /// the previous-hour bucket so a 5-minute interval just makes
    /// late-arriving rows show up sooner.
    pub interval: Duration,
}

impl Default for RollupConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(300),
        }
    }
}

pub struct RollupControl {
    stop: AtomicBool,
}

impl RollupControl {
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

#[derive(Debug, Default, Clone, Copy)]
pub struct RollupStats {
    pub hourly_buckets: u64,
    pub daily_buckets: u64,
    pub cycles: u64,
    pub errors: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum RollupError {
    #[error("sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),
}

pub struct Rollup {
    pool: Pool<Postgres>,
    config: RollupConfig,
    control: Arc<RollupControl>,
}

impl Rollup {
    pub fn new(pool: Pool<Postgres>, config: RollupConfig, control: Arc<RollupControl>) -> Self {
        Self {
            pool,
            config,
            control,
        }
    }

    pub async fn run(&self) -> RollupStats {
        let mut stats = RollupStats::default();
        info!(
            interval_secs = self.config.interval.as_secs(),
            "usage rollup starting"
        );
        while !self.control.is_stopped() {
            stats.cycles += 1;
            match self.rollup_recent().await {
                Ok((h, d)) => {
                    stats.hourly_buckets += h as u64;
                    stats.daily_buckets += d as u64;
                }
                Err(e) => {
                    stats.errors += 1;
                    warn!(error = %e, "usage rollup cycle failed");
                }
            }
            tokio::time::sleep(self.config.interval).await;
        }
        info!(
            hourly = stats.hourly_buckets,
            daily = stats.daily_buckets,
            "usage rollup stopped"
        );
        stats
    }

    /// Roll up the past 2 hours hourly + the past 2 days daily.
    /// Re-running is idempotent.
    pub async fn rollup_recent(&self) -> Result<(i64, i64), RollupError> {
        // Hourly bucket: floor(at, 'hour'). Walk the last 2 hours so
        // late-arriving rows from the drainer get folded in.
        let hourly_count: Option<(i64,)> = sqlx::query_as(
            "WITH ins AS (
                 INSERT INTO usage_hourly (
                     bucket_at, tenant, project, repository, op, src,
                     bytes, requests
                 )
                 SELECT date_trunc('hour', at) AS bucket_at,
                        tenant, project, repository, op, src,
                        SUM(bytes)::BIGINT,
                        COUNT(*)::BIGINT
                 FROM usage_events
                 WHERE at >= NOW() - INTERVAL '2 hours'
                 GROUP BY 1, tenant, project, repository, op, src
                 ON CONFLICT (bucket_at, tenant, project, repository, op, src) DO UPDATE
                 SET bytes    = EXCLUDED.bytes,
                     requests = EXCLUDED.requests
                 RETURNING 1
             )
             SELECT COUNT(*)::BIGINT FROM ins",
        )
        .fetch_optional(&self.pool)
        .await?;

        let daily_count: Option<(i64,)> = sqlx::query_as(
            "WITH ins AS (
                 INSERT INTO usage_daily (
                     bucket_at, tenant, project, repository, op, src,
                     bytes, requests
                 )
                 SELECT date_trunc('day', bucket_at) AS bucket_at,
                        tenant, project, repository, op, src,
                        SUM(bytes)::BIGINT,
                        SUM(requests)::BIGINT
                 FROM usage_hourly
                 WHERE bucket_at >= date_trunc('day', NOW() - INTERVAL '1 day')
                 GROUP BY 1, tenant, project, repository, op, src
                 ON CONFLICT (bucket_at, tenant, project, repository, op, src) DO UPDATE
                 SET bytes    = EXCLUDED.bytes,
                     requests = EXCLUDED.requests
                 RETURNING 1
             )
             SELECT COUNT(*)::BIGINT FROM ins",
        )
        .fetch_optional(&self.pool)
        .await?;

        let h = hourly_count.map(|(n,)| n).unwrap_or(0);
        let d = daily_count.map(|(n,)| n).unwrap_or(0);
        if h > 0 || d > 0 {
            debug!(hourly = h, daily = d, "usage rollup applied");
        }
        Ok((h, d))
    }
}
