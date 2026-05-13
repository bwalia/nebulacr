//! Lazy-pull job persistence.
//!
//! Slice-1 deliverable: trait + Postgres-backed store + status enum.
//! The actual worker that drains the queue ships in slice 2.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JobStatus {
    Queued,
    Running,
    Done,
    Failed,
}

impl JobStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Done => "done",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone)]
pub struct LazyJob {
    pub id: Uuid,
    pub layer_digest: String,
    pub format: String,
    pub status: JobStatus,
    pub error: Option<String>,
    pub enqueued_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub attempts: i32,
}

#[derive(Debug, thiserror::Error)]
pub enum JobError {
    #[error("sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),
}

#[async_trait]
pub trait LazyJobStore: Send + Sync {
    async fn enqueue(&self, layer_digest: &str, format: &str) -> Result<Uuid, JobError>;
    async fn get(&self, id: Uuid) -> Result<Option<LazyJob>, JobError>;
}

pub struct PgLazyJobStore {
    pool: Pool<Postgres>,
}

impl PgLazyJobStore {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl LazyJobStore for PgLazyJobStore {
    async fn enqueue(&self, layer_digest: &str, format: &str) -> Result<Uuid, JobError> {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO lazy_jobs (id, layer_digest, format, status, attempts)
             VALUES ($1, $2, $3, 'queued', 0)
             ON CONFLICT DO NOTHING",
        )
        .bind(id)
        .bind(layer_digest)
        .bind(format)
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    async fn get(&self, id: Uuid) -> Result<Option<LazyJob>, JobError> {
        let row: Option<(
            Uuid,
            String,
            String,
            String,
            Option<String>,
            DateTime<Utc>,
            Option<DateTime<Utc>>,
            Option<DateTime<Utc>>,
            i32,
        )> = sqlx::query_as(
            "SELECT id, layer_digest, format, status, error,
                    enqueued_at, started_at, finished_at, attempts
             FROM lazy_jobs WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|(id, layer, format, status, error, enq, started, finished, attempts)| {
            let status = match status.as_str() {
                "running" => JobStatus::Running,
                "done" => JobStatus::Done,
                "failed" => JobStatus::Failed,
                _ => JobStatus::Queued,
            };
            LazyJob {
                id,
                layer_digest: layer,
                format,
                status,
                error,
                enqueued_at: enq,
                started_at: started,
                finished_at: finished,
                attempts,
            }
        }))
    }
}
