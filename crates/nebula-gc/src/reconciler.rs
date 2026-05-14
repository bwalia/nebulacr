//! Reconciler — recomputes refcounts from authoritative state and
//! records drift.
//!
//! The reaper (slice 2) trusts `blob_refcounts`. Bugs in the writer,
//! crashes between the manifest write and the refcount update, or
//! manual operator surgery can leave that table out of sync. The
//! reconciler walks `manifest_blob_refs` (the per-edge table that's
//! always written in the same tx as the refcount bump) and compares
//! the expected counts to the observed counts. Differences go to
//! `gc_drift` with one of three classifications:
//!
//! - `orphan`  — refcount row exists, no edges point at the digest.
//!   Storage may still hold bytes; reaper will pick it up once the
//!   row's zeroed_at is older than grace.
//! - `missing` — edges exist but the refcount row doesn't. Bug in
//!   the writer; reconciler creates the row at the expected count.
//! - `underflow` — observed > expected. Bug in `remove_refs`; reset
//!   to expected.
//!
//! Backfill (`reconcile_backfill`) is a one-shot for existing
//! registries: walks the storage tree to populate `blob_paths` and
//! `manifest_blob_refs` from manifests that pre-date the GC schema.
//! Slice 3 ships the audit mode + a backfill stub; slice 4 wires the
//! storage walk.

use crate::refcount::GcError;
use sqlx::{Pool, Postgres};
use tracing::{debug, info, warn};

#[derive(Debug, Default, Clone, Copy)]
pub struct ReconcileStats {
    pub blobs_examined: u64,
    pub orphan_count: u64,
    pub missing_count: u64,
    pub underflow_count: u64,
    pub corrected: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct ReconcileConfig {
    /// Examine at most this many digests in one pass. Pass `None` to
    /// walk the whole table — fine for small registries, slow for
    /// large ones.
    pub max_blobs: Option<i64>,
    /// When true, write corrections to `blob_refcounts`. When false,
    /// the reconciler only records drift — useful for dry-runs and
    /// scheduled audits.
    pub apply_fix: bool,
}

impl Default for ReconcileConfig {
    fn default() -> Self {
        Self {
            max_blobs: Some(10_000),
            apply_fix: false,
        }
    }
}

pub struct Reconciler {
    pool: Pool<Postgres>,
}

impl Reconciler {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }

    /// Audit mode — walk every digest known to either table and
    /// classify any drift. With `apply_fix=true`, also corrects.
    pub async fn reconcile(&self, config: ReconcileConfig) -> Result<ReconcileStats, GcError> {
        info!(
            apply_fix = config.apply_fix,
            max_blobs = ?config.max_blobs,
            "online-gc reconciler starting"
        );

        let mut stats = ReconcileStats::default();

        // The pivot is `(tenant, blob_digest)`. Pull the union of
        // distinct digests from both tables; for each, compare
        // observed (refcount table) vs. expected (count of edges).
        let limit = config.max_blobs.unwrap_or(i64::MAX);

        let rows: Vec<(String, String, Option<i64>, i64)> = sqlx::query_as(
            "WITH digests AS (
                 SELECT tenant, blob_digest FROM blob_refcounts
                 UNION
                 SELECT tenant, blob_digest FROM manifest_blob_refs
             ),
             expected AS (
                 SELECT tenant, blob_digest, COUNT(*)::BIGINT AS edges
                 FROM manifest_blob_refs
                 GROUP BY tenant, blob_digest
             )
             SELECT d.tenant,
                    d.blob_digest,
                    rc.refcount,
                    COALESCE(e.edges, 0) AS edges
             FROM digests d
             LEFT JOIN blob_refcounts rc
                    ON rc.tenant = d.tenant AND rc.blob_digest = d.blob_digest
             LEFT JOIN expected e
                    ON e.tenant = d.tenant AND e.blob_digest = d.blob_digest
             ORDER BY d.tenant, d.blob_digest
             LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        debug!(
            rows = rows.len(),
            "online-gc reconcile candidates collected"
        );

        for (tenant, digest, observed, expected) in rows {
            stats.blobs_examined += 1;

            match (observed, expected) {
                (None, e) if e > 0 => {
                    // Edges exist, refcount row missing.
                    stats.missing_count += 1;
                    self.record_drift(&tenant, &digest, "missing", e, 0).await?;
                    if config.apply_fix {
                        self.fix_missing(&tenant, &digest, e).await?;
                        stats.corrected += 1;
                    }
                }
                (Some(o), 0) if o > 0 => {
                    // Refcount > 0 but no edges — orphan refcount row.
                    stats.orphan_count += 1;
                    self.record_drift(&tenant, &digest, "orphan", 0, o).await?;
                    if config.apply_fix {
                        self.fix_orphan(&tenant, &digest).await?;
                        stats.corrected += 1;
                    }
                }
                (Some(o), e) if o > e => {
                    // Observed > expected — write-side leak (likely a
                    // missed `remove_refs`).
                    stats.underflow_count += 1;
                    self.record_drift(&tenant, &digest, "underflow", e, o)
                        .await?;
                    if config.apply_fix {
                        self.fix_underflow(&tenant, &digest, e).await?;
                        stats.corrected += 1;
                    }
                }
                _ => {
                    // observed == expected, OR observed = 0 + expected = 0 — clean.
                }
            }
        }

        info!(
            examined = stats.blobs_examined,
            orphan = stats.orphan_count,
            missing = stats.missing_count,
            underflow = stats.underflow_count,
            corrected = stats.corrected,
            "online-gc reconciler finished"
        );
        Ok(stats)
    }

    async fn record_drift(
        &self,
        tenant: &str,
        digest: &str,
        kind: &str,
        expected: i64,
        observed: i64,
    ) -> Result<(), GcError> {
        sqlx::query(
            "INSERT INTO gc_drift (tenant, blob_digest, kind, expected, observed)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(tenant)
        .bind(digest)
        .bind(kind)
        .bind(expected)
        .bind(observed)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn fix_missing(&self, tenant: &str, digest: &str, expected: i64) -> Result<(), GcError> {
        sqlx::query(
            "INSERT INTO blob_refcounts (tenant, blob_digest, refcount, last_seen_at, bytes)
             VALUES ($1, $2, $3, NOW(), 0)
             ON CONFLICT (tenant, blob_digest) DO UPDATE
             SET refcount = EXCLUDED.refcount,
                 zeroed_at = NULL,
                 last_seen_at = NOW()",
        )
        .bind(tenant)
        .bind(digest)
        .bind(expected)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn fix_orphan(&self, tenant: &str, digest: &str) -> Result<(), GcError> {
        // Force the refcount to zero so the reaper's grace timer
        // starts now. Don't delete the row — the reaper handles that.
        sqlx::query(
            "UPDATE blob_refcounts
             SET refcount = 0,
                 zeroed_at = COALESCE(zeroed_at, NOW())
             WHERE tenant = $1 AND blob_digest = $2",
        )
        .bind(tenant)
        .bind(digest)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn fix_underflow(
        &self,
        tenant: &str,
        digest: &str,
        expected: i64,
    ) -> Result<(), GcError> {
        sqlx::query(
            "UPDATE blob_refcounts
             SET refcount = $3,
                 zeroed_at = CASE WHEN $3 = 0 THEN NOW() ELSE NULL END
             WHERE tenant = $1 AND blob_digest = $2",
        )
        .bind(tenant)
        .bind(digest)
        .bind(expected)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Mark older drift rows as corrected once they've been resolved.
    /// Used by operators after they fix data manually; not called
    /// automatically.
    pub async fn mark_drift_corrected(&self, tenant: &str, digest: &str) -> Result<u64, GcError> {
        let res = sqlx::query(
            "UPDATE gc_drift SET corrected_at = NOW()
             WHERE tenant = $1 AND blob_digest = $2 AND corrected_at IS NULL",
        )
        .bind(tenant)
        .bind(digest)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    /// Backfill stub — for an existing registry, walks the storage
    /// tree to populate `blob_paths` and `manifest_blob_refs` from
    /// pre-existing manifests. Slice 4 implements the storage walk;
    /// for now this returns an explicit error so operators get a
    /// clear signal instead of silent success.
    pub async fn reconcile_backfill(&self) -> Result<ReconcileStats, GcError> {
        warn!("online-gc backfill mode not yet implemented (slice 4)");
        Err(GcError::Sqlx(sqlx::Error::Protocol(
            "online-gc backfill mode not yet implemented".into(),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_dryrun() {
        let c = ReconcileConfig::default();
        assert!(!c.apply_fix, "default reconciler is dry-run");
        assert!(c.max_blobs.is_some());
    }

    #[test]
    fn stats_default_zero() {
        let s = ReconcileStats::default();
        assert_eq!(s.blobs_examined, 0);
        assert_eq!(s.corrected, 0);
    }
}
