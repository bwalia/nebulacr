//! Postgres-backed artifact-meta store.

use crate::types::ArtifactMetadata;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{Pool, Postgres};

#[derive(Debug, Clone)]
pub struct ArtifactMetaRow {
    pub digest: String,
    pub type_id: String,
    pub metadata: serde_json::Value,
    pub media_type: String,
    pub bytes: i64,
    pub validated: bool,
    pub validation_msg: Option<String>,
    pub parsed_at: DateTime<Utc>,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),
}

#[async_trait]
pub trait ArtifactStore: Send + Sync {
    async fn upsert(
        &self,
        digest: &str,
        meta: &ArtifactMetadata,
        validation_msg: Option<&str>,
    ) -> Result<(), StoreError>;
    async fn get(&self, digest: &str) -> Result<Option<ArtifactMetaRow>, StoreError>;
}

pub struct PgArtifactStore {
    pool: Pool<Postgres>,
}

impl PgArtifactStore {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ArtifactStore for PgArtifactStore {
    async fn upsert(
        &self,
        digest: &str,
        meta: &ArtifactMetadata,
        validation_msg: Option<&str>,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO artifact_meta
                 (digest, type_id, metadata, media_type, bytes, validated, validation_msg)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (digest) DO UPDATE
             SET type_id = EXCLUDED.type_id,
                 metadata = EXCLUDED.metadata,
                 media_type = EXCLUDED.media_type,
                 bytes = EXCLUDED.bytes,
                 validated = EXCLUDED.validated,
                 validation_msg = EXCLUDED.validation_msg,
                 parsed_at = NOW()",
        )
        .bind(digest)
        .bind(meta.type_id.as_str())
        .bind(&meta.fields)
        .bind(&meta.media_type)
        .bind(meta.bytes)
        .bind(validation_msg.is_none())
        .bind(validation_msg)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get(&self, digest: &str) -> Result<Option<ArtifactMetaRow>, StoreError> {
        let row: Option<(
            String,
            String,
            serde_json::Value,
            String,
            i64,
            bool,
            Option<String>,
            DateTime<Utc>,
        )> = sqlx::query_as(
            "SELECT digest, type_id, metadata, media_type, bytes, validated, validation_msg, parsed_at
             FROM artifact_meta WHERE digest = $1",
        )
        .bind(digest)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(d, t, m, mt, b, v, msg, ts)| ArtifactMetaRow {
            digest: d,
            type_id: t,
            metadata: m,
            media_type: mt,
            bytes: b,
            validated: v,
            validation_msg: msg,
            parsed_at: ts,
        }))
    }
}
