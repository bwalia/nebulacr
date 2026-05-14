//! Read-side queries for the rollup tables. Used by the registry's
//! `/v2/_usage/*` endpoints (017 polish).

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::{Pool, Postgres};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Granularity {
    Hour,
    Day,
}

impl Granularity {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "1h" | "hour" | "hourly" => Some(Self::Hour),
            "1d" | "day" | "daily" => Some(Self::Day),
            _ => None,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Hour => "hour",
            Self::Day => "day",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct UsageBucket {
    pub bucket_at: DateTime<Utc>,
    pub op: String,
    pub src: String,
    pub bytes: i64,
    pub requests: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TopPulledRow {
    pub tenant: String,
    pub project: String,
    pub repository: String,
    pub bytes: i64,
    pub pulls: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum ReaderError {
    #[error("sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),
}

pub struct UsageReader {
    pool: Pool<Postgres>,
}

impl UsageReader {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }

    /// Time-series for a tenant. `since_secs` controls the window;
    /// `granularity` chooses hourly vs daily rollup.
    pub async fn tenant_series(
        &self,
        tenant: &str,
        since_secs: i64,
        granularity: Granularity,
    ) -> Result<Vec<UsageBucket>, ReaderError> {
        let table = match granularity {
            Granularity::Hour => "usage_hourly",
            Granularity::Day => "usage_daily",
        };
        // Manually format the table — only one of two known values, no
        // injection risk.
        let sql = format!(
            "SELECT bucket_at, op, src,
                    SUM(bytes)::BIGINT AS bytes,
                    SUM(requests)::BIGINT AS requests
             FROM {table}
             WHERE tenant = $1
               AND bucket_at >= NOW() - make_interval(secs => $2)
             GROUP BY bucket_at, op, src
             ORDER BY bucket_at"
        );
        let rows: Vec<(DateTime<Utc>, String, String, i64, i64)> = sqlx::query_as(&sql)
            .bind(tenant)
            .bind(since_secs)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows
            .into_iter()
            .map(|(at, op, src, bytes, requests)| UsageBucket {
                bucket_at: at,
                op,
                src,
                bytes,
                requests,
            })
            .collect())
    }

    /// Top-pulled repositories across a window. Uses `usage_daily`
    /// for windows >= 24h; `usage_hourly` otherwise so short windows
    /// stay accurate.
    pub async fn top_pulled(
        &self,
        since_secs: i64,
        limit: i64,
    ) -> Result<Vec<TopPulledRow>, ReaderError> {
        let table = if since_secs >= 24 * 3600 {
            "usage_daily"
        } else {
            "usage_hourly"
        };
        let sql = format!(
            "SELECT tenant, project, repository,
                    SUM(bytes)::BIGINT AS bytes,
                    SUM(requests)::BIGINT AS pulls
             FROM {table}
             WHERE bucket_at >= NOW() - make_interval(secs => $1)
               AND op = 'pull'
             GROUP BY tenant, project, repository
             ORDER BY pulls DESC, bytes DESC
             LIMIT $2"
        );
        let rows: Vec<(String, String, String, i64, i64)> = sqlx::query_as(&sql)
            .bind(since_secs)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows
            .into_iter()
            .map(|(t, p, r, b, n)| TopPulledRow {
                tenant: t,
                project: p,
                repository: r,
                bytes: b,
                pulls: n,
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn granularity_parse_round_trip() {
        for s in &["1h", "hour", "hourly"] {
            assert_eq!(Granularity::parse(s), Some(Granularity::Hour));
        }
        for s in &["1d", "day", "daily"] {
            assert_eq!(Granularity::parse(s), Some(Granularity::Day));
        }
        assert_eq!(Granularity::parse("forever"), None);
    }
}
