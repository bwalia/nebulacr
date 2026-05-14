//! Postgres findings store.

use super::{Finding, FindingKind, FindingSeverity};
use async_trait::async_trait;
use sqlx::{Pool, Postgres};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),
}

#[async_trait]
pub trait FindingsStore: Send + Sync {
    async fn record(
        &self,
        scan_id: Uuid,
        digest: &str,
        finding: &Finding,
    ) -> Result<Uuid, StoreError>;

    async fn list_by_digest(&self, digest: &str) -> Result<Vec<Finding>, StoreError>;
}

pub struct PgFindingsStore {
    pool: Pool<Postgres>,
}

impl PgFindingsStore {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl FindingsStore for PgFindingsStore {
    async fn record(
        &self,
        scan_id: Uuid,
        digest: &str,
        finding: &Finding,
    ) -> Result<Uuid, StoreError> {
        let id = Uuid::new_v4();
        let raw = serde_json::to_value(finding)?;
        sqlx::query(
            "INSERT INTO findings
                 (id, scan_id, digest, detector, severity, title, finding_id,
                  package_purl, path, line, fix, raw)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        )
        .bind(id)
        .bind(scan_id)
        .bind(digest)
        .bind(finding.kind.as_str())
        .bind(finding.severity.as_str())
        .bind(&finding.title)
        .bind(&finding.finding_id)
        .bind(finding.package.as_ref().and_then(|p| p.purl.clone()))
        .bind(&finding.path)
        .bind(finding.line.map(|l| l as i32))
        .bind(
            finding
                .fix
                .as_ref()
                .map(serde_json::to_value)
                .transpose()?
                .unwrap_or(serde_json::Value::Null),
        )
        .bind(&raw)
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    async fn list_by_digest(&self, digest: &str) -> Result<Vec<Finding>, StoreError> {
        let rows: Vec<(serde_json::Value,)> =
            sqlx::query_as("SELECT raw FROM findings WHERE digest = $1 ORDER BY detected_at DESC")
                .bind(digest)
                .fetch_all(&self.pool)
                .await?;
        let mut out = Vec::with_capacity(rows.len());
        for (raw,) in rows {
            out.push(serde_json::from_value::<Finding>(raw)?);
        }
        Ok(out)
    }
}

// Suppress the unused-FindingKind/FindingSeverity warnings — these
// trait alias re-imports keep the file self-contained for slice 2.
#[allow(dead_code)]
fn _trait_imports(_k: FindingKind, _s: FindingSeverity) {}
