//! Import job persistence.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ImportPhase {
    Queued,
    Running,
    Succeeded,
    Failed,
    Aborted,
}

impl ImportPhase {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Aborted => "aborted",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ImportJobRow {
    pub id: Uuid,
    pub tenant: String,
    pub spec: serde_json::Value,
    pub phase: ImportPhase,
    pub repos_total: i32,
    pub repos_copied: i32,
    pub tags_total: i32,
    pub tags_copied: i32,
    pub bytes_copied: i64,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
}

#[derive(Debug, thiserror::Error)]
pub enum JobError {
    #[error("sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),
}

#[async_trait]
pub trait ImportJobStore: Send + Sync {
    async fn create(
        &self,
        tenant: &str,
        spec: serde_json::Value,
    ) -> Result<ImportJobRow, JobError>;
    async fn get(&self, id: Uuid) -> Result<Option<ImportJobRow>, JobError>;
    async fn set_phase(&self, id: Uuid, phase: ImportPhase) -> Result<(), JobError>;
}

pub struct PgImportJobStore {
    pool: Pool<Postgres>,
}

impl PgImportJobStore {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ImportJobStore for PgImportJobStore {
    async fn create(
        &self,
        tenant: &str,
        spec: serde_json::Value,
    ) -> Result<ImportJobRow, JobError> {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO import_jobs (id, tenant, spec, phase) VALUES ($1, $2, $3, 'queued')",
        )
        .bind(id)
        .bind(tenant)
        .bind(&spec)
        .execute(&self.pool)
        .await?;

        Ok(ImportJobRow {
            id,
            tenant: tenant.into(),
            spec,
            phase: ImportPhase::Queued,
            repos_total: 0,
            repos_copied: 0,
            tags_total: 0,
            tags_copied: 0,
            bytes_copied: 0,
            started_at: None,
            finished_at: None,
        })
    }

    async fn get(&self, id: Uuid) -> Result<Option<ImportJobRow>, JobError> {
        let row: Option<(
            Uuid,
            String,
            serde_json::Value,
            String,
            i32,
            i32,
            i32,
            i32,
            i64,
            Option<DateTime<Utc>>,
            Option<DateTime<Utc>>,
        )> = sqlx::query_as(
            "SELECT id, tenant, spec, phase,
                    repos_total, repos_copied, tags_total, tags_copied,
                    bytes_copied, started_at, finished_at
             FROM import_jobs WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(
            |(id, t, spec, phase, rt, rc, tt, tc, bc, sa, fa)| ImportJobRow {
                id,
                tenant: t,
                spec,
                phase: match phase.as_str() {
                    "running" => ImportPhase::Running,
                    "succeeded" => ImportPhase::Succeeded,
                    "failed" => ImportPhase::Failed,
                    "aborted" => ImportPhase::Aborted,
                    _ => ImportPhase::Queued,
                },
                repos_total: rt,
                repos_copied: rc,
                tags_total: tt,
                tags_copied: tc,
                bytes_copied: bc,
                started_at: sa,
                finished_at: fa,
            },
        ))
    }

    async fn set_phase(&self, id: Uuid, phase: ImportPhase) -> Result<(), JobError> {
        sqlx::query("UPDATE import_jobs SET phase = $1 WHERE id = $2")
            .bind(phase.as_str())
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
