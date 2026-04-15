//! CVE suppression + audit log. Task #11.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{Result, ScanError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewSuppression {
    pub cve_id: String,
    pub scope_tenant: Option<String>,
    pub scope_project: Option<String>,
    pub scope_repository: Option<String>,
    pub scope_package: Option<String>,
    pub reason: String,
    pub expires_at: Option<DateTime<Utc>>,
}

pub struct Suppressions {
    pool: PgPool,
}

impl Suppressions {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a new suppression and write an audit_log row in one transaction.
    pub async fn create(&self, actor: &str, input: NewSuppression) -> Result<Uuid> {
        let id = Uuid::new_v4();
        let mut tx = self.pool.begin().await.map_err(nebula_db::DbError::from)?;
        sqlx::query(
            r#"INSERT INTO suppressions
                (id, cve_id, scope_tenant, scope_project, scope_repository, scope_package, reason, created_by, expires_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#,
        )
        .bind(id)
        .bind(&input.cve_id)
        .bind(&input.scope_tenant)
        .bind(&input.scope_project)
        .bind(&input.scope_repository)
        .bind(&input.scope_package)
        .bind(&input.reason)
        .bind(actor)
        .bind(input.expires_at)
        .execute(&mut *tx)
        .await
        .map_err(nebula_db::DbError::from)?;

        let details = serde_json::to_value(&input).map_err(ScanError::from)?;
        sqlx::query(
            r#"INSERT INTO audit_log (id, actor, action, target_kind, target_id, details)
                VALUES ($1, $2, $3, $4, $5, $6)"#,
        )
        .bind(Uuid::new_v4())
        .bind(actor)
        .bind("suppression.create")
        .bind("suppression")
        .bind(id.to_string())
        .bind(details)
        .execute(&mut *tx)
        .await
        .map_err(nebula_db::DbError::from)?;

        tx.commit().await.map_err(nebula_db::DbError::from)?;
        Ok(id)
    }

    /// Mark vulnerabilities as `suppressed` in place, based on DB state.
    pub async fn apply(
        &self,
        tenant: &str,
        project: &str,
        repository: &str,
        vulns: &mut [crate::model::Vulnerability],
    ) -> Result<()> {
        // TODO(task 11): single query for all active suppressions matching
        // (cve_id, scope). For now, a per-CVE lookup keeps the first PR simple.
        for v in vulns.iter_mut() {
            let hit: Option<(Uuid,)> = sqlx::query_as(
                r#"SELECT id FROM suppressions
                    WHERE cve_id = $1
                      AND revoked_at IS NULL
                      AND (expires_at IS NULL OR expires_at > NOW())
                      AND (scope_tenant IS NULL OR scope_tenant = $2)
                      AND (scope_project IS NULL OR scope_project = $3)
                      AND (scope_repository IS NULL OR scope_repository = $4)
                      AND (scope_package IS NULL OR scope_package = $5)
                    LIMIT 1"#,
            )
            .bind(&v.id)
            .bind(tenant)
            .bind(project)
            .bind(repository)
            .bind(&v.package)
            .fetch_optional(&self.pool)
            .await
            .map_err(nebula_db::DbError::from)?;
            if hit.is_some() {
                v.suppressed = true;
            }
        }
        Ok(())
    }
}
