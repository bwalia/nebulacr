//! `GET /v2/cve/search` — query the own vuln-DB populated by the ingesters.
//!
//! Filters are all optional and composable. A filter on `package` / `ecosystem`
//! forces an `EXISTS` subquery against `affected_ranges`; everything else
//! stays on the `vulnerabilities` table. Results include an aggregated
//! `affected` array so callers don't need a second round-trip for range data.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, QueryBuilder, Row};

use crate::Result;

/// Maximum page size callers can request. Caps DB load + response bytes.
const MAX_LIMIT: i64 = 200;
const DEFAULT_LIMIT: i64 = 50;

#[derive(Debug, Default, Clone, Deserialize)]
pub struct SearchQuery {
    /// Exact CVE / GHSA identifier match.
    pub id: Option<String>,
    /// Substring match across `summary` and `description` (case-insensitive).
    pub q: Option<String>,
    pub package: Option<String>,
    pub ecosystem: Option<String>,
    /// Comma-separated severity list, e.g. `CRITICAL,HIGH`.
    pub severity: Option<String>,
    /// Source classification (`nvd`, `osv`, `ghsa`, `pysec`, `go`, `distro`).
    pub source: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct SearchResponse {
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
    pub results: Vec<CveHit>,
}

#[derive(Debug, Serialize)]
pub struct CveHit {
    pub id: String,
    pub source: String,
    pub aliases: Vec<String>,
    pub severity: Option<String>,
    pub cvss_score: Option<f64>,
    pub summary: Option<String>,
    pub description: Option<String>,
    pub published_at: Option<DateTime<Utc>>,
    pub modified_at: Option<DateTime<Utc>>,
    pub references: Vec<String>,
    pub affected: Vec<AffectedRange>,
}

#[derive(Debug, Serialize)]
pub struct AffectedRange {
    pub ecosystem: String,
    pub package: String,
    pub introduced: Option<String>,
    pub fixed: Option<String>,
    pub last_affected: Option<String>,
}

pub struct CveSearch {
    pool: PgPool,
}

impl CveSearch {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn search(&self, query: &SearchQuery) -> Result<SearchResponse> {
        let limit = query.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
        let offset = query.offset.unwrap_or(0).max(0);

        let severities: Vec<String> = query
            .severity
            .as_deref()
            .map(|s| {
                s.split(',')
                    .map(|p| p.trim().to_ascii_uppercase())
                    .filter(|p| !p.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        // --- total count ------------------------------------------------
        let mut count_qb: QueryBuilder<sqlx::Postgres> =
            QueryBuilder::new("SELECT COUNT(*) FROM vulnerabilities v WHERE 1=1");
        apply_filters(&mut count_qb, query, &severities);
        let total: i64 = count_qb
            .build()
            .fetch_one(&self.pool)
            .await
            .map_err(nebula_db::DbError::from)?
            .try_get(0)
            .map_err(nebula_db::DbError::from)?;

        // --- page fetch -------------------------------------------------
        let mut qb: QueryBuilder<sqlx::Postgres> = QueryBuilder::new(
            r#"SELECT v.id, v.source, v.aliases, v.severity, v.cvss_score,
                      v.summary, v.description, v.published_at, v.modified_at,
                      v.refs,
                      COALESCE(
                        (SELECT jsonb_agg(jsonb_build_object(
                            'ecosystem', r.ecosystem,
                            'package', r.package,
                            'introduced', r.introduced,
                            'fixed', r.fixed,
                            'last_affected', r.last_affected))
                         FROM affected_ranges r WHERE r.vuln_id = v.id),
                        '[]'::jsonb
                      ) AS affected
               FROM vulnerabilities v
               WHERE 1=1"#,
        );
        apply_filters(&mut qb, query, &severities);
        qb.push(" ORDER BY v.modified_at DESC NULLS LAST, v.id ");
        qb.push(" LIMIT ").push_bind(limit);
        qb.push(" OFFSET ").push_bind(offset);

        let rows = qb
            .build()
            .fetch_all(&self.pool)
            .await
            .map_err(nebula_db::DbError::from)?;

        let mut results = Vec::with_capacity(rows.len());
        for row in rows {
            let refs_json: serde_json::Value =
                row.try_get("refs").map_err(nebula_db::DbError::from)?;
            let affected_json: serde_json::Value =
                row.try_get("affected").map_err(nebula_db::DbError::from)?;
            results.push(CveHit {
                id: row.try_get("id").map_err(nebula_db::DbError::from)?,
                source: row.try_get("source").map_err(nebula_db::DbError::from)?,
                aliases: row
                    .try_get::<Vec<String>, _>("aliases")
                    .map_err(nebula_db::DbError::from)?,
                severity: row.try_get("severity").map_err(nebula_db::DbError::from)?,
                cvss_score: row
                    .try_get("cvss_score")
                    .map_err(nebula_db::DbError::from)?,
                summary: row.try_get("summary").map_err(nebula_db::DbError::from)?,
                description: row
                    .try_get("description")
                    .map_err(nebula_db::DbError::from)?,
                published_at: row
                    .try_get("published_at")
                    .map_err(nebula_db::DbError::from)?,
                modified_at: row
                    .try_get("modified_at")
                    .map_err(nebula_db::DbError::from)?,
                references: extract_strings(&refs_json),
                affected: parse_affected(&affected_json),
            });
        }

        Ok(SearchResponse {
            total,
            limit,
            offset,
            results,
        })
    }
}

fn apply_filters<'a>(
    qb: &mut QueryBuilder<'a, sqlx::Postgres>,
    q: &'a SearchQuery,
    severities: &'a [String],
) {
    if let Some(id) = q.id.as_deref() {
        qb.push(" AND v.id = ").push_bind(id);
    }
    if let Some(src) = q.source.as_deref() {
        qb.push(" AND v.source = ").push_bind(src);
    }
    if !severities.is_empty() {
        qb.push(" AND v.severity = ANY(")
            .push_bind(severities.to_vec());
        qb.push(")");
    }
    if let Some(text) = q.q.as_deref() {
        let like = format!("%{}%", text);
        qb.push(" AND (v.summary ILIKE ")
            .push_bind(like.clone())
            .push(" OR v.description ILIKE ")
            .push_bind(like)
            .push(")");
    }
    if q.package.is_some() || q.ecosystem.is_some() {
        qb.push(" AND EXISTS (SELECT 1 FROM affected_ranges r WHERE r.vuln_id = v.id");
        if let Some(pkg) = q.package.as_deref() {
            qb.push(" AND r.package = ").push_bind(pkg);
        }
        if let Some(eco) = q.ecosystem.as_deref() {
            qb.push(" AND r.ecosystem = ").push_bind(eco);
        }
        qb.push(")");
    }
}

fn extract_strings(v: &serde_json::Value) -> Vec<String> {
    match v {
        serde_json::Value::Array(items) => items
            .iter()
            .filter_map(|it| it.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    }
}

fn parse_affected(v: &serde_json::Value) -> Vec<AffectedRange> {
    let Some(arr) = v.as_array() else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|item| {
            let obj = item.as_object()?;
            Some(AffectedRange {
                ecosystem: obj.get("ecosystem")?.as_str()?.to_string(),
                package: obj.get("package")?.as_str()?.to_string(),
                introduced: obj
                    .get("introduced")
                    .and_then(|s| s.as_str())
                    .map(str::to_string),
                fixed: obj
                    .get("fixed")
                    .and_then(|s| s.as_str())
                    .map(str::to_string),
                last_affected: obj
                    .get("last_affected")
                    .and_then(|s| s.as_str())
                    .map(str::to_string),
            })
        })
        .collect()
}
