//! OCI 1.1 referrers index.
//!
//! Shared across 010 (TOC artifacts), 015 (attestations), and future
//! producers. Slice-1 deliverable: trait + Postgres impl + register/list.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Referrer {
    pub subject_digest: String,
    pub artifact_digest: String,
    pub artifact_type: String,
    pub media_type: String,
    pub size: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum ReferrerError {
    #[error("sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),
}

#[async_trait]
pub trait ReferrerStore: Send + Sync {
    async fn register(&self, r: &Referrer) -> Result<(), ReferrerError>;
    async fn list(&self, subject_digest: &str) -> Result<Vec<Referrer>, ReferrerError>;
    async fn list_by_type(
        &self,
        subject_digest: &str,
        artifact_type: &str,
    ) -> Result<Vec<Referrer>, ReferrerError>;
}

pub struct PgReferrerStore {
    pool: Pool<Postgres>,
}

impl PgReferrerStore {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ReferrerStore for PgReferrerStore {
    async fn register(&self, r: &Referrer) -> Result<(), ReferrerError> {
        sqlx::query(
            "INSERT INTO referrers
                 (subject_digest, artifact_digest, artifact_type, media_type, size)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (subject_digest, artifact_digest) DO UPDATE
             SET artifact_type = EXCLUDED.artifact_type,
                 media_type = EXCLUDED.media_type,
                 size = EXCLUDED.size",
        )
        .bind(&r.subject_digest)
        .bind(&r.artifact_digest)
        .bind(&r.artifact_type)
        .bind(&r.media_type)
        .bind(r.size)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list(&self, subject_digest: &str) -> Result<Vec<Referrer>, ReferrerError> {
        let rows: Vec<(String, String, String, String, i64)> = sqlx::query_as(
            "SELECT subject_digest, artifact_digest, artifact_type, media_type, size
             FROM referrers WHERE subject_digest = $1",
        )
        .bind(subject_digest)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(s, a, t, m, sz)| Referrer {
                subject_digest: s,
                artifact_digest: a,
                artifact_type: t,
                media_type: m,
                size: sz,
            })
            .collect())
    }

    async fn list_by_type(
        &self,
        subject_digest: &str,
        artifact_type: &str,
    ) -> Result<Vec<Referrer>, ReferrerError> {
        let rows: Vec<(String, String, String, String, i64)> = sqlx::query_as(
            "SELECT subject_digest, artifact_digest, artifact_type, media_type, size
             FROM referrers WHERE subject_digest = $1 AND artifact_type = $2",
        )
        .bind(subject_digest)
        .bind(artifact_type)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(s, a, t, m, sz)| Referrer {
                subject_digest: s,
                artifact_digest: a,
                artifact_type: t,
                media_type: m,
                size: sz,
            })
            .collect())
    }
}
