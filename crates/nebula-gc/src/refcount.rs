//! Refcount writer trait + Postgres implementation.

use crate::manifest::BlobDescriptor;
use async_trait::async_trait;
use sqlx::{Pool, Postgres};

#[derive(Debug, thiserror::Error)]
pub enum GcError {
    #[error("sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),
}

/// Writes that flow through the manifest mutation paths in
/// `nebula-registry`. Implementations MUST be cheap when called from
/// the request hot path — `add_refs` is on every successful manifest
/// PUT.
///
/// Operations are NOT transactional with the manifest write today; the
/// refcount table is its own source of truth, reconciled by the
/// reconciler in slice 3. Slice 1 is intentionally minimal: collect
/// the data so the reaper has something to drain, then add atomicity
/// in a follow-up once the registry's manifest write moves into a
/// transaction.
#[async_trait]
pub trait BlobRefCounter: Send + Sync {
    /// Bump refcount for every digest. Idempotent on
    /// `(tenant, manifest_digest, blob_digest)` — called twice for the
    /// same manifest re-pushes the same edges, which is fine.
    ///
    /// `project` + `repository` are recorded in `blob_paths` so the
    /// reaper (slice 2) can locate every storage object for a digest
    /// when its refcount drops to zero.
    async fn add_refs(
        &self,
        tenant: &str,
        project: &str,
        repository: &str,
        manifest_digest: &str,
        blobs: &[BlobDescriptor],
    ) -> Result<(), GcError>;

    /// Decrement refcounts when a manifest is deleted. Caller passes
    /// only the manifest digest; we look up its edges in
    /// `manifest_blob_refs` and decrement each blob.
    async fn remove_refs(&self, tenant: &str, manifest_digest: &str) -> Result<(), GcError>;
}

/// Disabled implementation — a no-op. Used when `[gc.online]` is off.
pub struct NoopBlobRefCounter;

#[async_trait]
impl BlobRefCounter for NoopBlobRefCounter {
    async fn add_refs(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: &str,
        _: &[BlobDescriptor],
    ) -> Result<(), GcError> {
        Ok(())
    }
    async fn remove_refs(&self, _: &str, _: &str) -> Result<(), GcError> {
        Ok(())
    }
}

/// Postgres-backed refcount writer. Writes go to the tables shipped in
/// `migrations/0004_online_gc.sql`.
pub struct PgBlobRefCounter {
    pool: Pool<Postgres>,
}

impl PgBlobRefCounter {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &Pool<Postgres> {
        &self.pool
    }
}

#[async_trait]
impl BlobRefCounter for PgBlobRefCounter {
    async fn add_refs(
        &self,
        tenant: &str,
        project: &str,
        repository: &str,
        manifest_digest: &str,
        blobs: &[BlobDescriptor],
    ) -> Result<(), GcError> {
        if blobs.is_empty() {
            return Ok(());
        }

        let mut tx = self.pool.begin().await?;

        for blob in blobs {
            // Always record the storage path so the reaper can find
            // every copy of this blob when it eventually drops to
            // refcount=0 — even if this push is a re-push that doesn't
            // bump the refcount.
            sqlx::query(
                "INSERT INTO blob_paths
                     (tenant, project, repository, blob_digest)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT DO NOTHING",
            )
            .bind(tenant)
            .bind(project)
            .bind(repository)
            .bind(&blob.digest)
            .execute(&mut *tx)
            .await?;

            // Insert the edge — ON CONFLICT DO NOTHING means re-pushing
            // the same manifest is a no-op (idempotent).
            let edge_inserted: Option<(bool,)> = sqlx::query_as(
                "INSERT INTO manifest_blob_refs (tenant, manifest_digest, blob_digest)
                 VALUES ($1, $2, $3)
                 ON CONFLICT DO NOTHING
                 RETURNING true",
            )
            .bind(tenant)
            .bind(manifest_digest)
            .bind(&blob.digest)
            .fetch_optional(&mut *tx)
            .await?;

            if edge_inserted.is_none() {
                // Edge already existed — do not double-count the blob.
                continue;
            }

            // Bump the refcount. If the row didn't exist, create it.
            // Clear `zeroed_at` if it was set so the reaper skips this
            // blob until it goes back to refcount=0.
            sqlx::query(
                "INSERT INTO blob_refcounts
                   (tenant, blob_digest, refcount, zeroed_at, last_seen_at, bytes)
                 VALUES ($1, $2, 1, NULL, NOW(), $3)
                 ON CONFLICT (tenant, blob_digest) DO UPDATE
                 SET refcount = blob_refcounts.refcount + 1,
                     zeroed_at = NULL,
                     last_seen_at = NOW(),
                     bytes = GREATEST(blob_refcounts.bytes, EXCLUDED.bytes)",
            )
            .bind(tenant)
            .bind(&blob.digest)
            .bind(blob.size)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    async fn remove_refs(&self, tenant: &str, manifest_digest: &str) -> Result<(), GcError> {
        let mut tx = self.pool.begin().await?;

        // Pull the edges and delete them in one swoop. Postgres returns
        // the deleted rows so we know exactly which blobs to decrement.
        let rows: Vec<(String,)> = sqlx::query_as(
            "DELETE FROM manifest_blob_refs
             WHERE tenant = $1 AND manifest_digest = $2
             RETURNING blob_digest",
        )
        .bind(tenant)
        .bind(manifest_digest)
        .fetch_all(&mut *tx)
        .await?;

        for (blob,) in rows {
            // Decrement refcount; flip zeroed_at if it just hit 0.
            sqlx::query(
                "UPDATE blob_refcounts
                 SET refcount = refcount - 1,
                     zeroed_at = CASE
                         WHEN refcount - 1 = 0 THEN NOW()
                         ELSE zeroed_at
                     END,
                     last_seen_at = NOW()
                 WHERE tenant = $1 AND blob_digest = $2 AND refcount > 0",
            )
            .bind(tenant)
            .bind(&blob)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }
}
