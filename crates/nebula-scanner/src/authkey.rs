//! Scanner API keys for CI/CD clients.
//!
//! Keys are long random strings prefixed with `nck_` ("nebulacr key"); only
//! the SHA-256 hex digest is stored, so a compromised database doesn't leak
//! usable credentials. The raw key is shown to the operator exactly once at
//! creation time.
//!
//! Callers present `Authorization: Bearer nck_<secret>`. Requests with any
//! other bearer format (e.g. registry JWTs) fall through to a permissive
//! `system` principal — existing flows that don't use an API key keep working
//! until an operator flips on enforcement at the handler level.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::warn;
use uuid::Uuid;

use crate::{Result, ScanError};

/// Permission grants on a scanner API key. Strings land in the
/// `scanner_api_keys.permissions` column; `admin` is the superuser wildcard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    ScanRead,
    ScanWrite,
    PolicyEvaluate,
    CveSearch,
    CveSuppress,
    SettingsWrite,
    Admin,
}

impl Permission {
    pub fn as_str(self) -> &'static str {
        match self {
            Permission::ScanRead => "scan:read",
            Permission::ScanWrite => "scan:write",
            Permission::PolicyEvaluate => "policy:evaluate",
            Permission::CveSearch => "cve:search",
            Permission::CveSuppress => "cve:suppress",
            Permission::SettingsWrite => "settings:write",
            Permission::Admin => "admin",
        }
    }
}

/// Resolved identity of the caller. A `system` principal (no key) is treated
/// as permissive for backward compatibility with pre-API-key smoke tests.
#[derive(Debug, Clone)]
pub struct Principal {
    pub actor: String,
    pub tenant: Option<String>,
    pub permissions: Vec<String>,
    /// When true, the request did not carry an API key — we fall back to the
    /// legacy "system" identity and skip permission checks.
    pub system: bool,
}

impl Principal {
    pub fn system() -> Self {
        Self {
            actor: "system".into(),
            tenant: None,
            permissions: Vec::new(),
            system: true,
        }
    }

    pub fn has(&self, perm: Permission) -> bool {
        if self.system {
            return true;
        }
        self.permissions.iter().any(|p| p == "admin")
            || self.permissions.iter().any(|p| p == perm.as_str())
    }

    pub fn require(&self, perm: Permission) -> Result<()> {
        if self.has(perm) {
            Ok(())
        } else {
            Err(ScanError::Other(format!(
                "forbidden: missing permission {}",
                perm.as_str()
            )))
        }
    }
}

#[derive(Debug, Serialize)]
pub struct IssuedKey {
    pub id: Uuid,
    pub name: String,
    pub tenant: Option<String>,
    pub permissions: Vec<String>,
    pub created_at: DateTime<Utc>,
    /// The raw key — returned exactly once on creation; we only persist the hash.
    pub key: String,
}

#[derive(Debug, Deserialize)]
pub struct NewKeyRequest {
    pub name: String,
    pub tenant: Option<String>,
    #[serde(default)]
    pub permissions: Vec<String>,
    /// Optional role preset. Expanded into `permissions` server-side; the
    /// explicit `permissions` array is merged on top so callers can widen or
    /// trim a role.
    #[serde(default)]
    pub role: Option<String>,
}

/// Built-in role presets. Map role name → permission list. Unknown role
/// names return an empty slice, so handlers can surface a clear error.
pub fn role_permissions(role: &str) -> Vec<&'static str> {
    match role {
        "viewer" => vec!["scan:read", "cve:search"],
        "ci" => vec!["scan:read", "policy:evaluate", "cve:search"],
        "security_admin" => vec![
            "scan:read",
            "scan:write",
            "policy:evaluate",
            "cve:search",
            "cve:suppress",
            "settings:write",
        ],
        "admin" => vec!["admin"],
        _ => Vec::new(),
    }
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct KeyRow {
    pub id: Uuid,
    pub name: String,
    pub tenant: Option<String>,
    pub permissions: Vec<String>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

pub struct ApiKeys {
    pool: PgPool,
}

impl ApiKeys {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Generate a fresh key, persist its hash, and return the raw value once.
    /// Role presets expand into permissions on the way in; the request's
    /// explicit permission list is merged on top so callers can widen or
    /// trim a role.
    pub async fn create(&self, actor: &str, req: NewKeyRequest) -> Result<IssuedKey> {
        let mut perms: Vec<String> = match &req.role {
            Some(r) => {
                let base = role_permissions(r);
                if base.is_empty() && r != "none" {
                    return Err(ScanError::Other(format!("unknown role: {r}")));
                }
                base.into_iter().map(String::from).collect()
            }
            None => Vec::new(),
        };
        for p in &req.permissions {
            if !perms.iter().any(|q| q == p) {
                perms.push(p.clone());
            }
        }
        if perms.is_empty() {
            return Err(ScanError::Other(
                "key must have at least one permission (use role or permissions)".into(),
            ));
        }

        let id = Uuid::new_v4();
        let raw = generate_raw_key();
        let hash = hash_key(&raw);
        let created_at: DateTime<Utc> = sqlx::query_scalar(
            r#"INSERT INTO scanner_api_keys
                (id, name, key_hash, tenant, permissions, created_by)
                VALUES ($1, $2, $3, $4, $5, $6)
                RETURNING created_at"#,
        )
        .bind(id)
        .bind(&req.name)
        .bind(&hash)
        .bind(&req.tenant)
        .bind(&perms)
        .bind(actor)
        .fetch_one(&self.pool)
        .await
        .map_err(nebula_db::DbError::from)?;
        Ok(IssuedKey {
            id,
            name: req.name,
            tenant: req.tenant,
            permissions: perms,
            created_at,
            key: raw,
        })
    }

    pub async fn list(&self, include_revoked: bool) -> Result<Vec<KeyRow>> {
        let rows = sqlx::query_as::<_, KeyRow>(
            r#"SELECT id, name, tenant, permissions, created_by, created_at,
                      last_used_at, revoked_at
               FROM scanner_api_keys
               WHERE ($1 OR revoked_at IS NULL)
               ORDER BY created_at DESC"#,
        )
        .bind(include_revoked)
        .fetch_all(&self.pool)
        .await
        .map_err(nebula_db::DbError::from)?;
        Ok(rows)
    }

    pub async fn revoke(&self, id: Uuid) -> Result<bool> {
        let r = sqlx::query(
            r#"UPDATE scanner_api_keys SET revoked_at = NOW()
               WHERE id = $1 AND revoked_at IS NULL"#,
        )
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(nebula_db::DbError::from)?;
        Ok(r.rows_affected() > 0)
    }

    /// Look up a raw key. `Ok(None)` for unknown/revoked keys — caller decides
    /// whether that maps to 401 (enforcement) or system fallback (compat).
    pub async fn lookup(&self, raw: &str) -> Result<Option<Principal>> {
        if !raw.starts_with("nck_") {
            return Ok(None);
        }
        let hash = hash_key(raw);
        let row: Option<KeyRow> = sqlx::query_as(
            r#"SELECT id, name, tenant, permissions, created_by, created_at,
                      last_used_at, revoked_at
               FROM scanner_api_keys
               WHERE key_hash = $1 AND revoked_at IS NULL"#,
        )
        .bind(&hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(nebula_db::DbError::from)?;
        let Some(row) = row else {
            return Ok(None);
        };
        // Best-effort `last_used_at` stamp; failures shouldn't deny a valid key.
        if let Err(e) =
            sqlx::query("UPDATE scanner_api_keys SET last_used_at = NOW() WHERE id = $1")
                .bind(row.id)
                .execute(&self.pool)
                .await
        {
            warn!(error = %e, key_id = %row.id, "failed to stamp last_used_at");
        }
        Ok(Some(Principal {
            actor: row.name,
            tenant: row.tenant,
            permissions: row.permissions,
            system: false,
        }))
    }
}

fn generate_raw_key() -> String {
    let buf: [u8; 24] = rand::random();
    format!("nck_{}", hex::encode(buf))
}

fn hash_key(raw: &str) -> String {
    let mut h = Sha256::new();
    h.update(raw.as_bytes());
    hex::encode(h.finalize())
}
