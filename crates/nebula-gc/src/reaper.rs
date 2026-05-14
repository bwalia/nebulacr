//! Continuous reaper.
//!
//! Drains rows from `blob_refcounts` whose refcount has been zero
//! for longer than the configured grace period. For each, looks up
//! every storage path in `blob_paths`, deletes the object via the
//! supplied [`ObjectStore`], and removes the bookkeeping rows in a
//! single transaction. `FOR UPDATE SKIP LOCKED` lets multiple
//! reapers coexist (HA registry) without duplicate work.
//!
//! Pause/resume is cooperative — the reaper consults a
//! [`ReaperControl`] flag at the top of each cycle.

use crate::refcount::GcError;
use object_store::ObjectStore;
use object_store::path::Path as StorePath;
use sqlx::{Pool, Postgres};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Cooperative pause/resume + shutdown control.
///
/// The reaper checks `paused.load(Acquire)` and `stop.load(Acquire)`
/// once per cycle. Setting them is safe from any task.
pub struct ReaperControl {
    pub paused: AtomicBool,
    pub stop: AtomicBool,
}

impl ReaperControl {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            paused: AtomicBool::new(false),
            stop: AtomicBool::new(false),
        })
    }

    pub fn pause(&self) {
        self.paused.store(true, Ordering::Release);
    }

    pub fn resume(&self) {
        self.paused.store(false, Ordering::Release);
    }

    pub fn shutdown(&self) {
        self.stop.store(true, Ordering::Release);
    }

    pub fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Acquire)
    }

    pub fn is_stopped(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }
}

#[derive(Debug, Clone)]
pub struct ReaperConfig {
    /// How long a row must sit at refcount=0 before it is eligible.
    pub grace: Duration,
    /// Maximum rows reaped per drain cycle.
    pub batch_size: i64,
    /// How long the reaper sleeps between cycles when there is no
    /// eligible work.
    pub idle_sleep: Duration,
    /// Cap on how many storage delete operations the reaper can issue
    /// per second. Slows the reaper if the storage backend rate-limits.
    pub sweep_qps: u32,
}

impl Default for ReaperConfig {
    fn default() -> Self {
        Self {
            grace: Duration::from_secs(24 * 3600),
            batch_size: 200,
            idle_sleep: Duration::from_secs(30),
            sweep_qps: 100,
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ReaperStats {
    pub blobs_reaped: u64,
    pub bytes_freed: u64,
    pub cycles: u64,
    pub paused_cycles: u64,
    pub errors: u64,
}

pub struct ContinuousReaper {
    pool: Pool<Postgres>,
    store: Arc<dyn ObjectStore>,
    config: ReaperConfig,
    control: Arc<ReaperControl>,
}

impl ContinuousReaper {
    pub fn new(
        pool: Pool<Postgres>,
        store: Arc<dyn ObjectStore>,
        config: ReaperConfig,
        control: Arc<ReaperControl>,
    ) -> Self {
        Self {
            pool,
            store,
            config,
            control,
        }
    }

    /// Long-running entrypoint. Returns when `control.shutdown()` is
    /// called.
    pub async fn run(&self) -> ReaperStats {
        let mut stats = ReaperStats::default();
        info!(
            grace_secs = self.config.grace.as_secs(),
            batch = self.config.batch_size,
            qps = self.config.sweep_qps,
            "online-gc reaper starting"
        );

        while !self.control.is_stopped() {
            stats.cycles += 1;

            if self.control.is_paused() {
                stats.paused_cycles += 1;
                tokio::time::sleep(self.config.idle_sleep).await;
                continue;
            }

            match self.reap_one_cycle().await {
                Ok(reaped) => {
                    stats.blobs_reaped += reaped.blobs as u64;
                    stats.bytes_freed += reaped.bytes as u64;
                    if reaped.blobs == 0 {
                        tokio::time::sleep(self.config.idle_sleep).await;
                    }
                }
                Err(e) => {
                    stats.errors += 1;
                    warn!(error = %e, "online-gc reaper cycle failed");
                    tokio::time::sleep(self.config.idle_sleep).await;
                }
            }
        }

        info!(
            blobs_reaped = stats.blobs_reaped,
            bytes_freed = stats.bytes_freed,
            cycles = stats.cycles,
            "online-gc reaper stopped"
        );
        stats
    }

    /// Drain one batch. Public so tests can drive the reaper one
    /// cycle at a time without spawning the full loop.
    pub async fn reap_one_cycle(&self) -> Result<CycleResult, GcError> {
        let grace_secs = self.config.grace.as_secs() as i64;

        // Pull a batch of zero-refcount rows under SKIP LOCKED so
        // multiple reapers coexist. We use a CTE so the lock is
        // released as soon as we've collected the rows; the row-by-row
        // delete loop below uses its own short transactions.
        let candidates: Vec<(String, String, i64)> = sqlx::query_as(
            "WITH eligible AS (
                 SELECT tenant, blob_digest, bytes
                 FROM blob_refcounts
                 WHERE refcount = 0
                   AND zeroed_at IS NOT NULL
                   AND zeroed_at < NOW() - make_interval(secs => $1)
                 ORDER BY zeroed_at
                 LIMIT $2
                 FOR UPDATE SKIP LOCKED
             )
             SELECT tenant, blob_digest, bytes FROM eligible",
        )
        .bind(grace_secs)
        .bind(self.config.batch_size)
        .fetch_all(&self.pool)
        .await
        .map_err(GcError::from)?;

        if candidates.is_empty() {
            return Ok(CycleResult::default());
        }

        debug!(count = candidates.len(), "online-gc reaper batch acquired");

        let mut result = CycleResult::default();
        let interval = Duration::from_secs_f64(1.0 / self.config.sweep_qps.max(1) as f64);
        let mut next_tick = Instant::now();

        for (tenant, blob_digest, bytes) in candidates {
            // Cooperative pause / shutdown checks at the inner loop —
            // long batches shouldn't hold up an operator's pause.
            if self.control.is_stopped() || self.control.is_paused() {
                break;
            }

            // Token bucket via instant-stepping: sleep until next_tick
            // before each delete.
            let now = Instant::now();
            if now < next_tick {
                tokio::time::sleep(next_tick - now).await;
            }
            next_tick += interval;

            match self.reap_blob(&tenant, &blob_digest, bytes).await {
                Ok(true) => {
                    result.blobs += 1;
                    result.bytes += bytes;
                }
                Ok(false) => {
                    // Row vanished between SELECT and DELETE — another
                    // reaper got there first. Not an error.
                }
                Err(e) => {
                    result.errors += 1;
                    warn!(
                        tenant = %tenant,
                        digest = %blob_digest,
                        error = %e,
                        "online-gc reap failed"
                    );
                }
            }
        }

        Ok(result)
    }

    async fn reap_blob(
        &self,
        tenant: &str,
        blob_digest: &str,
        bytes: i64,
    ) -> Result<bool, GcError> {
        // 1. Re-fetch storage paths and lock the refcount row in a tx.
        //    If the refcount has gone non-zero since our SELECT, we
        //    abort and the next cycle will pick it up again.
        let mut tx = self.pool.begin().await?;

        let still_zero: Option<(i64,)> = sqlx::query_as(
            "SELECT refcount FROM blob_refcounts
             WHERE tenant = $1 AND blob_digest = $2
             FOR UPDATE",
        )
        .bind(tenant)
        .bind(blob_digest)
        .fetch_optional(&mut *tx)
        .await?;

        let still_zero = matches!(still_zero, Some((0,)));
        if !still_zero {
            return Ok(false);
        }

        let paths: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT tenant, project, repository
             FROM blob_paths
             WHERE tenant = $1 AND blob_digest = $2",
        )
        .bind(tenant)
        .bind(blob_digest)
        .fetch_all(&mut *tx)
        .await?;

        // 2. Delete each storage object. Failures are logged but do
        //    not abort the row deletion — the design treats storage as
        //    best-effort and the reconciler (slice 3) cleans up
        //    orphans.
        let hex = blob_digest.strip_prefix("sha256:").unwrap_or(blob_digest);
        for (t, p, r) in &paths {
            let key = format!("{t}/{p}/{r}/blobs/sha256/{hex}");
            let store_path = StorePath::from(key);
            match self.store.delete(&store_path).await {
                Ok(()) => {}
                Err(object_store::Error::NotFound { .. }) => {
                    debug!(path = %store_path, "online-gc: storage object already gone");
                }
                Err(e) => {
                    warn!(path = %store_path, error = %e, "online-gc: storage delete failed");
                    // Bail out of this row's tx — don't drop bookkeeping
                    // when storage is unhealthy. Caller increments
                    // `errors` and we'll retry next cycle.
                    return Err(GcError::Sqlx(sqlx::Error::Protocol(format!(
                        "storage delete failed: {e}"
                    ))));
                }
            }
        }

        // 3. Drop bookkeeping rows.
        sqlx::query("DELETE FROM blob_paths WHERE tenant = $1 AND blob_digest = $2")
            .bind(tenant)
            .bind(blob_digest)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM blob_refcounts WHERE tenant = $1 AND blob_digest = $2")
            .bind(tenant)
            .bind(blob_digest)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO gc_reaps (tenant, blob_digest, bytes_freed, reconciler)
             VALUES ($1, $2, $3, FALSE)",
        )
        .bind(tenant)
        .bind(blob_digest)
        .bind(bytes)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(true)
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct CycleResult {
    pub blobs: i64,
    pub bytes: i64,
    pub errors: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_pause_resume_round_trip() {
        let c = ReaperControl::new();
        assert!(!c.is_paused());
        c.pause();
        assert!(c.is_paused());
        c.resume();
        assert!(!c.is_paused());
    }

    #[test]
    fn control_shutdown_is_one_way() {
        let c = ReaperControl::new();
        assert!(!c.is_stopped());
        c.shutdown();
        assert!(c.is_stopped());
    }

    #[test]
    fn config_defaults_are_safe() {
        let c = ReaperConfig::default();
        assert!(
            c.grace.as_secs() >= 3600,
            "grace must be long enough to survive uploads"
        );
        assert!(c.batch_size > 0);
        assert!(c.sweep_qps > 0);
    }
}
