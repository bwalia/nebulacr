//! Postgres-backed attestation store.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{Pool, Postgres};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Attestation {
    pub id: Uuid,
    pub subject_digest: String,
    pub envelope_digest: String,
    pub predicate_type: String,
    pub builder_id: Option<String>,
    pub builder_kind: Option<String>,
    pub slsa_level: Option<i32>,
    pub verified: bool,
    pub uploaded_at: DateTime<Utc>,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),
}

#[async_trait]
pub trait AttestationStore: Send + Sync {
    async fn put(&self, att: &Attestation, raw: &serde_json::Value) -> Result<(), StoreError>;
    async fn list(&self, subject_digest: &str) -> Result<Vec<Attestation>, StoreError>;
}

pub struct PgAttestationStore {
    pool: Pool<Postgres>,
}

impl PgAttestationStore {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AttestationStore for PgAttestationStore {
    async fn put(&self, att: &Attestation, raw: &serde_json::Value) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO attestations
                 (id, subject_digest, envelope_digest, predicate_type,
                  builder_id, builder_kind, slsa_level, materials,
                  signed_by, verified, raw)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL, $9, $10)
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(att.id)
        .bind(&att.subject_digest)
        .bind(&att.envelope_digest)
        .bind(&att.predicate_type)
        .bind(&att.builder_id)
        .bind(&att.builder_kind)
        .bind(att.slsa_level)
        .bind(serde_json::Value::Null)
        .bind(att.verified)
        .bind(raw)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list(&self, subject_digest: &str) -> Result<Vec<Attestation>, StoreError> {
        let rows: Vec<(
            Uuid,
            String,
            String,
            String,
            Option<String>,
            Option<String>,
            Option<i32>,
            bool,
            DateTime<Utc>,
        )> = sqlx::query_as(
            "SELECT id, subject_digest, envelope_digest, predicate_type,
                    builder_id, builder_kind, slsa_level, verified, uploaded_at
             FROM attestations WHERE subject_digest = $1 ORDER BY uploaded_at DESC",
        )
        .bind(subject_digest)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(id, sd, ed, pt, bid, bk, lvl, ver, ua)| Attestation {
                id,
                subject_digest: sd,
                envelope_digest: ed,
                predicate_type: pt,
                builder_id: bid,
                builder_kind: bk,
                slsa_level: lvl,
                verified: ver,
                uploaded_at: ua,
            })
            .collect())
    }
}
