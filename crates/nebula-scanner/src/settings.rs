//! Per-repository scanner settings. Backed by Postgres `image_settings`.
//! Consumed by the worker (scan_enabled gate, policy override) and by the
//! PATCH endpoint.

use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::{Result, ScanError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageSettings {
    pub tenant: String,
    pub project: String,
    pub repository: String,
    pub scan_enabled: bool,
    pub policy_yaml: Option<String>,
}

impl ImageSettings {
    /// Default when no row exists: scan enabled, no custom policy.
    pub fn default_for(tenant: &str, project: &str, repo: &str) -> Self {
        Self {
            tenant: tenant.into(),
            project: project.into(),
            repository: repo.into(),
            scan_enabled: true,
            policy_yaml: None,
        }
    }
}

pub struct ImageSettingsStore {
    pool: PgPool,
}

impl ImageSettingsStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn get(&self, tenant: &str, project: &str, repo: &str) -> Result<ImageSettings> {
        let row: Option<(bool, Option<String>)> = sqlx::query_as(
            r#"SELECT scan_enabled, policy_yaml FROM image_settings
                WHERE tenant = $1 AND project = $2 AND repository = $3"#,
        )
        .bind(tenant)
        .bind(project)
        .bind(repo)
        .fetch_optional(&self.pool)
        .await
        .map_err(nebula_db::DbError::from)?;

        Ok(match row {
            Some((scan_enabled, policy_yaml)) => ImageSettings {
                tenant: tenant.into(),
                project: project.into(),
                repository: repo.into(),
                scan_enabled,
                policy_yaml,
            },
            None => ImageSettings::default_for(tenant, project, repo),
        })
    }

    /// Upsert. Validates policy YAML (if provided) before writing.
    pub async fn upsert(
        &self,
        actor: &str,
        tenant: &str,
        project: &str,
        repo: &str,
        scan_enabled: bool,
        policy_yaml: Option<&str>,
    ) -> Result<ImageSettings> {
        if let Some(y) = policy_yaml {
            crate::policy::Policy::from_yaml(y)
                .map_err(|e| ScanError::Other(format!("invalid policy yaml: {e}")))?;
        }
        sqlx::query(
            r#"INSERT INTO image_settings
                (tenant, project, repository, scan_enabled, policy_yaml, updated_by)
                VALUES ($1, $2, $3, $4, $5, $6)
                ON CONFLICT (tenant, project, repository) DO UPDATE SET
                  scan_enabled = EXCLUDED.scan_enabled,
                  policy_yaml  = EXCLUDED.policy_yaml,
                  updated_by   = EXCLUDED.updated_by,
                  updated_at   = NOW()"#,
        )
        .bind(tenant)
        .bind(project)
        .bind(repo)
        .bind(scan_enabled)
        .bind(policy_yaml)
        .bind(actor)
        .execute(&self.pool)
        .await
        .map_err(nebula_db::DbError::from)?;

        // Audit log row describing the change.
        let details = serde_json::json!({
            "scan_enabled": scan_enabled,
            "has_policy": policy_yaml.is_some(),
        });
        sqlx::query(
            r#"INSERT INTO audit_log (id, actor, action, target_kind, target_id, details)
                VALUES ($1, $2, $3, $4, $5, $6)"#,
        )
        .bind(uuid::Uuid::new_v4())
        .bind(actor)
        .bind("image_settings.upsert")
        .bind("image_settings")
        .bind(format!("{tenant}/{project}/{repo}"))
        .bind(details)
        .execute(&self.pool)
        .await
        .map_err(nebula_db::DbError::from)?;

        Ok(ImageSettings {
            tenant: tenant.into(),
            project: project.into(),
            repository: repo.into(),
            scan_enabled,
            policy_yaml: policy_yaml.map(str::to_string),
        })
    }
}
