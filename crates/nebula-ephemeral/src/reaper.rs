//! TTL reaper for the `tags` table.
//!
//! Drains rows whose `expires_at` is in the past. For each, deletes
//! the tag-link object in storage (under
//! `<tenant>/<project>/<repo>/tags/<tag>`) and removes the row, then
//! records the reap in `ttl_reaps`. The underlying manifest blob is
//! NOT deleted by this reaper — that is online-GC's job (009): the
//! tag-link removal triggers a manifest_blob_refs decrement on the
//! next manifest delete, and GC drains the blob once its refcount
//! hits zero.
//!
//! `FOR UPDATE SKIP LOCKED` lets multiple registries share the work
//! without double-deleting. Cooperative pause/resume mirrors the
//! 009 reaper.

use object_store::ObjectStore;
use object_store::path::Path as StorePath;
use sqlx::{Pool, Postgres};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tracing::{debug, info, warn};

#[derive(Debug, thiserror::Error)]
pub enum TtlReaperError {
    #[error("sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),
}

pub struct TtlReaperControl {
    pub paused: AtomicBool,
    pub stop: AtomicBool,
}

impl TtlReaperControl {
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
pub struct TtlReaperConfig {
    pub batch_size: i64,
    pub idle_sleep: Duration,
}

impl Default for TtlReaperConfig {
    fn default() -> Self {
        Self {
            batch_size: 100,
            idle_sleep: Duration::from_secs(60),
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct TtlReaperStats {
    pub tags_reaped: u64,
    pub cycles: u64,
    pub paused_cycles: u64,
    pub errors: u64,
}

pub struct TtlReaper {
    pool: Pool<Postgres>,
    store: Arc<dyn ObjectStore>,
    config: TtlReaperConfig,
    control: Arc<TtlReaperControl>,
}

impl TtlReaper {
    pub fn new(
        pool: Pool<Postgres>,
        store: Arc<dyn ObjectStore>,
        config: TtlReaperConfig,
        control: Arc<TtlReaperControl>,
    ) -> Self {
        Self {
            pool,
            store,
            config,
            control,
        }
    }

    pub async fn run(&self) -> TtlReaperStats {
        let mut stats = TtlReaperStats::default();
        info!(batch = self.config.batch_size, "ttl reaper starting");

        while !self.control.is_stopped() {
            stats.cycles += 1;
            if self.control.is_paused() {
                stats.paused_cycles += 1;
                tokio::time::sleep(self.config.idle_sleep).await;
                continue;
            }
            match self.reap_one_cycle().await {
                Ok(reaped) => {
                    stats.tags_reaped += reaped as u64;
                    if reaped == 0 {
                        tokio::time::sleep(self.config.idle_sleep).await;
                    }
                }
                Err(e) => {
                    stats.errors += 1;
                    warn!(error = %e, "ttl reaper cycle failed");
                    tokio::time::sleep(self.config.idle_sleep).await;
                }
            }
        }
        info!(
            tags_reaped = stats.tags_reaped,
            cycles = stats.cycles,
            "ttl reaper stopped"
        );
        stats
    }

    /// One drain cycle. Returns the number of tags reaped.
    pub async fn reap_one_cycle(&self) -> Result<i64, TtlReaperError> {
        let candidates: Vec<(String, String, String, String)> = sqlx::query_as(
            "WITH eligible AS (
                 SELECT tenant, project, repository, tag
                 FROM tags
                 WHERE expires_at IS NOT NULL
                   AND expires_at < NOW()
                 ORDER BY expires_at
                 LIMIT $1
                 FOR UPDATE SKIP LOCKED
             )
             SELECT tenant, project, repository, tag FROM eligible",
        )
        .bind(self.config.batch_size)
        .fetch_all(&self.pool)
        .await?;

        if candidates.is_empty() {
            return Ok(0);
        }

        debug!(count = candidates.len(), "ttl reaper batch acquired");
        let mut reaped = 0i64;
        for (tenant, project, repo, tag) in candidates {
            if self.control.is_stopped() || self.control.is_paused() {
                break;
            }
            match self.reap_tag(&tenant, &project, &repo, &tag).await {
                Ok(true) => reaped += 1,
                Ok(false) => {} // gone-by-now (race) — fine
                Err(e) => warn!(
                    tag = %tag, tenant = %tenant, error = %e,
                    "ttl reap failed"
                ),
            }
        }
        Ok(reaped)
    }

    async fn reap_tag(
        &self,
        tenant: &str,
        project: &str,
        repo: &str,
        tag: &str,
    ) -> Result<bool, TtlReaperError> {
        // 1. Re-fetch + lock.
        let mut tx = self.pool.begin().await?;
        let row: Option<(Option<chrono::DateTime<chrono::Utc>>,)> = sqlx::query_as(
            "SELECT expires_at FROM tags
             WHERE tenant=$1 AND project=$2 AND repository=$3 AND tag=$4
             FOR UPDATE",
        )
        .bind(tenant)
        .bind(project)
        .bind(repo)
        .bind(tag)
        .fetch_optional(&mut *tx)
        .await?;
        let still_expired = match row {
            Some((Some(t),)) => t < chrono::Utc::now(),
            _ => false,
        };
        if !still_expired {
            return Ok(false);
        }

        // 2. Delete the tag-link object in storage. Best-effort —
        //    a missing link means the tag was already removed.
        let key = format!("{tenant}/{project}/{repo}/tags/{tag}");
        let store_path = StorePath::from(key);
        match self.store.delete(&store_path).await {
            Ok(()) => {}
            Err(object_store::Error::NotFound { .. }) => {
                debug!(path = %store_path, "ttl reap: tag link already gone");
            }
            Err(e) => {
                // Don't drop bookkeeping if storage is unhealthy; let
                // the next cycle retry. Surface as an error so callers
                // count it.
                return Err(TtlReaperError::Sqlx(sqlx::Error::Protocol(format!(
                    "storage delete failed: {e}"
                ))));
            }
        }

        // 3. Remove the row + record the reap in one tx.
        sqlx::query(
            "DELETE FROM tags
             WHERE tenant=$1 AND project=$2 AND repository=$3 AND tag=$4",
        )
        .bind(tenant)
        .bind(project)
        .bind(repo)
        .bind(tag)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO ttl_reaps (tenant, project, repository, tag, reason)
             VALUES ($1, $2, $3, $4, 'ttl')",
        )
        .bind(tenant)
        .bind(project)
        .bind(repo)
        .bind(tag)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_pause_resume() {
        let c = TtlReaperControl::new();
        assert!(!c.is_paused());
        c.pause();
        assert!(c.is_paused());
        c.resume();
        assert!(!c.is_paused());
    }

    #[test]
    fn config_default_sane() {
        let c = TtlReaperConfig::default();
        assert!(c.batch_size > 0);
        assert!(c.idle_sleep.as_secs() > 0);
    }
}
