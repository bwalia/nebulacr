//! Per-advisory writer used by every ingester.
//!
//! One transaction per advisory: UPSERT into `vulnerabilities`, delete the
//! old `affected_ranges` rows, re-insert the fresh ones. Isolating each
//! advisory lets a single malformed record fail without poisoning the rest
//! of the ingest run.

use chrono::Utc;
use sqlx::PgPool;

use super::{AffectedRangeRow, IngestStats, VulnerabilityRow};
use crate::Result;

/// Write one advisory plus its ranges atomically.
pub async fn write_advisory(
    pool: &PgPool,
    vuln: &VulnerabilityRow,
    ranges: &[AffectedRangeRow],
) -> Result<()> {
    let mut tx = pool.begin().await.map_err(nebula_db::DbError::from)?;

    let severity_str = format!("{:?}", vuln.severity).to_uppercase();
    sqlx::query(
        r#"INSERT INTO vulnerabilities
            (id, source, summary, description, severity, cvss_score,
             published_at, modified_at, aliases, refs)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
         ON CONFLICT (id) DO UPDATE SET
            source = EXCLUDED.source,
            summary = EXCLUDED.summary,
            description = EXCLUDED.description,
            severity = EXCLUDED.severity,
            cvss_score = EXCLUDED.cvss_score,
            published_at = EXCLUDED.published_at,
            modified_at = EXCLUDED.modified_at,
            aliases = EXCLUDED.aliases,
            refs = EXCLUDED.refs"#,
    )
    .bind(&vuln.id)
    .bind(&vuln.source)
    .bind(&vuln.summary)
    .bind(&vuln.description)
    .bind(&severity_str)
    .bind(vuln.cvss_score)
    .bind(vuln.published_at)
    .bind(vuln.modified_at)
    .bind(&vuln.aliases)
    .bind(serde_json::to_value(&vuln.references).unwrap_or(serde_json::json!([])))
    .execute(&mut *tx)
    .await
    .map_err(nebula_db::DbError::from)?;

    sqlx::query("DELETE FROM affected_ranges WHERE vuln_id = $1")
        .bind(&vuln.id)
        .execute(&mut *tx)
        .await
        .map_err(nebula_db::DbError::from)?;

    for r in ranges {
        sqlx::query(
            r#"INSERT INTO affected_ranges
                (vuln_id, ecosystem, package, introduced, fixed, last_affected, purl)
             VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
        )
        .bind(&vuln.id)
        .bind(&r.ecosystem)
        .bind(&r.package)
        .bind(&r.introduced)
        .bind(&r.fixed)
        .bind(&r.last_affected)
        .bind(&r.purl)
        .execute(&mut *tx)
        .await
        .map_err(nebula_db::DbError::from)?;
    }

    tx.commit().await.map_err(nebula_db::DbError::from)?;
    Ok(())
}

/// Update (or insert) the `ingest_cursor` row for a source after a run
/// completes. `error` is `Some` when the run failed partway through.
///
/// `last_modified` is the *upstream* cursor — the most recent advisory
/// `modified_at` we've observed. Delta-query ingesters (NVD) use it to pick
/// up where they left off; ETag-based ingesters (OSV) pass `None`.
pub async fn update_cursor(
    pool: &PgPool,
    source: &str,
    etag: Option<&str>,
    last_modified: Option<chrono::DateTime<Utc>>,
    stats: &IngestStats,
    error: Option<&str>,
) -> Result<()> {
    sqlx::query(
        r#"INSERT INTO ingest_cursor
            (source, etag, last_modified, last_run_at, last_run_advisories, last_run_error)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (source) DO UPDATE SET
            etag = EXCLUDED.etag,
            last_modified = COALESCE(EXCLUDED.last_modified, ingest_cursor.last_modified),
            last_run_at = EXCLUDED.last_run_at,
            last_run_advisories = EXCLUDED.last_run_advisories,
            last_run_error = EXCLUDED.last_run_error"#,
    )
    .bind(source)
    .bind(etag)
    .bind(last_modified)
    .bind(Utc::now())
    .bind(i32::try_from(stats.advisories).unwrap_or(i32::MAX))
    .bind(error)
    .execute(pool)
    .await
    .map_err(nebula_db::DbError::from)?;
    Ok(())
}

/// Fetch the stored upstream cursor for a source. Used by NVD to delta-query
/// from the last `lastModified` we've seen.
pub async fn stored_last_modified(
    pool: &PgPool,
    source: &str,
) -> Result<Option<chrono::DateTime<Utc>>> {
    let row: Option<(Option<chrono::DateTime<Utc>>,)> =
        sqlx::query_as("SELECT last_modified FROM ingest_cursor WHERE source = $1")
            .bind(source)
            .fetch_optional(pool)
            .await
            .map_err(nebula_db::DbError::from)?;
    Ok(row.and_then(|(ts,)| ts))
}

/// Upsert a vulnerability row without touching its `affected_ranges`. Used
/// by metadata-only ingesters (NVD) so we don't clobber ecosystem ranges
/// produced by OSV or GHSA.
pub async fn write_advisory_metadata_only(
    pool: &PgPool,
    vuln: &VulnerabilityRow,
) -> Result<()> {
    let severity_str = format!("{:?}", vuln.severity).to_uppercase();
    sqlx::query(
        r#"INSERT INTO vulnerabilities
            (id, source, summary, description, severity, cvss_score,
             published_at, modified_at, aliases, refs)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
         ON CONFLICT (id) DO UPDATE SET
            source = EXCLUDED.source,
            summary = COALESCE(EXCLUDED.summary, vulnerabilities.summary),
            description = COALESCE(EXCLUDED.description, vulnerabilities.description),
            severity = CASE
                WHEN EXCLUDED.severity <> 'UNKNOWN' THEN EXCLUDED.severity
                ELSE vulnerabilities.severity
              END,
            cvss_score = COALESCE(EXCLUDED.cvss_score, vulnerabilities.cvss_score),
            published_at = COALESCE(EXCLUDED.published_at, vulnerabilities.published_at),
            modified_at = COALESCE(EXCLUDED.modified_at, vulnerabilities.modified_at),
            aliases = EXCLUDED.aliases,
            refs = EXCLUDED.refs"#,
    )
    .bind(&vuln.id)
    .bind(&vuln.source)
    .bind(&vuln.summary)
    .bind(&vuln.description)
    .bind(&severity_str)
    .bind(vuln.cvss_score)
    .bind(vuln.published_at)
    .bind(vuln.modified_at)
    .bind(&vuln.aliases)
    .bind(serde_json::to_value(&vuln.references).unwrap_or(serde_json::json!([])))
    .execute(pool)
    .await
    .map_err(nebula_db::DbError::from)?;
    Ok(())
}

/// Fetch the stored ETag for a source, used to short-circuit when the
/// upstream hasn't changed since the last run. `None` on first run or if
/// the row is missing.
pub async fn stored_etag(pool: &PgPool, source: &str) -> Result<Option<String>> {
    let row: Option<(Option<String>,)> =
        sqlx::query_as("SELECT etag FROM ingest_cursor WHERE source = $1")
            .bind(source)
            .fetch_optional(pool)
            .await
            .map_err(nebula_db::DbError::from)?;
    Ok(row.and_then(|(e,)| e))
}
