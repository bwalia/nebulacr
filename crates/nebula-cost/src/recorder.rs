//! UsageRecorder trait + Postgres impl.
//!
//! The recorder is invoked from the registry's blob/manifest paths.
//! Slice 1 writes directly into `usage_events_staging` synchronously;
//! slice 2 will batch through a per-second bounded channel.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageOp {
    Pull,
    Push,
    ManifestGet,
    ManifestPut,
    Delete,
}

impl UsageOp {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pull => "pull",
            Self::Push => "push",
            Self::ManifestGet => "manifest_get",
            Self::ManifestPut => "manifest_put",
            Self::Delete => "delete",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UsageSrc {
    Origin,
    Cache,
    Peer,
    PullThrough,
}

impl UsageSrc {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Origin => "origin",
            Self::Cache => "cache",
            Self::Peer => "peer",
            Self::PullThrough => "pull-through",
        }
    }
}

#[derive(Debug, Clone)]
pub struct UsageEvent {
    pub at: DateTime<Utc>,
    pub tenant: String,
    pub project: String,
    pub repository: String,
    pub op: UsageOp,
    pub bytes: i64,
    pub src: UsageSrc,
    pub status: i32,
    pub sub: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum UsageError {
    #[error("sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),
}

#[async_trait]
pub trait UsageRecorder: Send + Sync {
    async fn record(&self, event: &UsageEvent) -> Result<(), UsageError>;
}

pub struct NoopUsageRecorder;

#[async_trait]
impl UsageRecorder for NoopUsageRecorder {
    async fn record(&self, _: &UsageEvent) -> Result<(), UsageError> {
        Ok(())
    }
}

pub struct PgUsageRecorder {
    pool: Pool<Postgres>,
}

impl PgUsageRecorder {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UsageRecorder for PgUsageRecorder {
    async fn record(&self, event: &UsageEvent) -> Result<(), UsageError> {
        sqlx::query(
            "INSERT INTO usage_events_staging
                 (at, tenant, project, repository, op, bytes, src, status, sub)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(event.at)
        .bind(&event.tenant)
        .bind(&event.project)
        .bind(&event.repository)
        .bind(event.op.as_str())
        .bind(event.bytes)
        .bind(event.src.as_str())
        .bind(event.status)
        .bind(&event.sub)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
