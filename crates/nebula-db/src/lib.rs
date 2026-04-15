//! Postgres persistence layer for NebulaCR scanner metadata.
//!
//! Owns the pool, migrations, and strongly-typed row structs for:
//! - `scans` — scan job bookkeeping (Redis still holds ephemeral results)
//! - `vulnerabilities` — normalised CVE records (populated by our own DB
//!   ingestion in slice 2; the OSV bootstrap path does not write here)
//! - `suppressions` — CVE suppressions with expiry + justification
//! - `audit_log` — immutable audit trail for suppressions and policy overrides
//! - `image_settings` — per-image/per-repo scan-enabled flags and overrides
//! - `scanner_api_keys` — API keys for CI/CD with scoped permissions

use sqlx::postgres::{PgPool, PgPoolOptions};
use std::time::Duration;

pub use sqlx;

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("migrate: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
}

pub type Result<T> = std::result::Result<T, DbError>;

pub async fn connect(url: &str, max_connections: u32) -> Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .acquire_timeout(Duration::from_secs(10))
        .connect(url)
        .await?;
    Ok(pool)
}

pub async fn migrate(pool: &PgPool) -> Result<()> {
    sqlx::migrate!("./migrations").run(pool).await?;
    Ok(())
}

pub mod models;
