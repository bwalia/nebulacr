//! Scan-job queue abstraction.
//!
//! Two backends:
//!   - [`TokioQueue`] — in-process MPSC; fast, zero infra, but dies with the
//!     registry process (no cross-pod / cross-binary).
//!   - [`PostgresQueue`] — durable Postgres-backed queue using
//!     `DELETE ... FOR UPDATE SKIP LOCKED`; safe when workers run in a
//!     separate `nebula-scanner` binary from the enqueue-only registry.
//!
//! Picked via [`crate::config::QueueBackend`] at runtime build time.

use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use sqlx::Row;
use sqlx::postgres::PgRow;
use tokio::sync::{Mutex, mpsc};
use tracing::warn;

use crate::model::ScanJob;

#[derive(Debug, thiserror::Error)]
pub enum QueueError {
    #[error("queue closed")]
    Closed,
    #[error("queue full")]
    Full,
    #[error("queue backend error: {0}")]
    Backend(String),
}

#[async_trait]
pub trait Queue: Send + Sync {
    async fn enqueue(&self, job: ScanJob) -> Result<(), QueueError>;
    async fn dequeue(&self) -> Option<ScanJob>;
}

// ── TokioQueue ─────────────────────────────────────────────────────────────

pub struct TokioQueue {
    tx: mpsc::Sender<ScanJob>,
    rx: Mutex<mpsc::Receiver<ScanJob>>,
}

impl TokioQueue {
    pub fn new(capacity: usize) -> Self {
        let (tx, rx) = mpsc::channel(capacity);
        Self {
            tx,
            rx: Mutex::new(rx),
        }
    }

    /// Producer handle suitable for cloning into webhook subscribers.
    pub fn sender(&self) -> mpsc::Sender<ScanJob> {
        self.tx.clone()
    }
}

#[async_trait]
impl Queue for TokioQueue {
    async fn enqueue(&self, job: ScanJob) -> Result<(), QueueError> {
        self.tx.send(job).await.map_err(|_| QueueError::Closed)
    }

    async fn dequeue(&self) -> Option<ScanJob> {
        let mut rx = self.rx.lock().await;
        rx.recv().await
    }
}

// ── PostgresQueue ──────────────────────────────────────────────────────────

/// Postgres-backed durable queue.
///
/// `enqueue` is a single INSERT. `dequeue` atomically claims-and-deletes
/// the oldest pending row under `FOR UPDATE SKIP LOCKED`, so N workers can
/// poll concurrently without stepping on each other. Empty-queue polling
/// sleeps `poll_interval` between attempts; good enough for "scans every
/// few minutes" cadences and trivially replaceable with LISTEN/NOTIFY later.
///
/// At-most-once delivery: a crash between claim (DELETE) and scan completion
/// loses the job. We accept this; scans are idempotent re-trigger on push.
pub struct PostgresQueue {
    pool: PgPool,
    poll_interval: Duration,
}

impl PostgresQueue {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            poll_interval: Duration::from_millis(500),
        }
    }

    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    fn row_to_job(row: &PgRow) -> Result<ScanJob, sqlx::Error> {
        Ok(ScanJob {
            id: row.try_get("id")?,
            digest: row.try_get("digest")?,
            tenant: row.try_get("tenant")?,
            project: row.try_get("project")?,
            repository: row.try_get("repository")?,
            reference: row.try_get("reference")?,
            enqueued_at: row.try_get::<DateTime<Utc>, _>("enqueued_at")?,
        })
    }
}

#[async_trait]
impl Queue for PostgresQueue {
    async fn enqueue(&self, job: ScanJob) -> Result<(), QueueError> {
        sqlx::query(
            "INSERT INTO scan_jobs (id, digest, tenant, project, repository, reference, enqueued_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(job.id)
        .bind(&job.digest)
        .bind(&job.tenant)
        .bind(&job.project)
        .bind(&job.repository)
        .bind(&job.reference)
        .bind(job.enqueued_at)
        .execute(&self.pool)
        .await
        .map_err(|e| QueueError::Backend(e.to_string()))?;
        Ok(())
    }

    async fn dequeue(&self) -> Option<ScanJob> {
        loop {
            let res: Result<Option<PgRow>, sqlx::Error> = sqlx::query(
                "DELETE FROM scan_jobs \
                 WHERE id = ( \
                    SELECT id FROM scan_jobs \
                    ORDER BY enqueued_at \
                    FOR UPDATE SKIP LOCKED \
                    LIMIT 1 \
                 ) \
                 RETURNING id, digest, tenant, project, repository, reference, enqueued_at",
            )
            .fetch_optional(&self.pool)
            .await;

            match res {
                Ok(Some(row)) => match Self::row_to_job(&row) {
                    Ok(job) => return Some(job),
                    Err(e) => {
                        warn!(error = %e, "scan_jobs row decode failed; skipping");
                        continue;
                    }
                },
                Ok(None) => {
                    // Empty queue — sleep and retry.
                    tokio::time::sleep(self.poll_interval).await;
                }
                Err(e) => {
                    warn!(error = %e, "scan_jobs dequeue failed; backing off");
                    tokio::time::sleep(self.poll_interval).await;
                }
            }
        }
    }
}

