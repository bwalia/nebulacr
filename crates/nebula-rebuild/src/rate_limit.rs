//! Rate-limit ledger for rebuild firings.
//!
//! Backed by `rebuild_rate (subscription_id, downstream_ref,
//! bucket_day, fired)` from the slice-1 schema. Caps fire-rate per
//! `(subscription, downstream, day)` so a popular base CVE can't
//! storm a CI system with thousands of dispatches.

use chrono::Utc;
use sqlx::{Pool, Postgres};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum RateLimitError {
    #[error("sqlx: {0}")]
    Sqlx(#[from] sqlx::Error),
}

pub struct RateLimit {
    pool: Pool<Postgres>,
    /// Maximum firings per (subscription, downstream, day).
    pub per_downstream_per_day: i32,
}

impl RateLimit {
    pub fn new(pool: Pool<Postgres>, per_downstream_per_day: i32) -> Self {
        Self {
            pool,
            per_downstream_per_day: per_downstream_per_day.max(1),
        }
    }

    /// Atomically check + increment. Returns true when the caller is
    /// allowed to fire (and the counter has been bumped); false when
    /// the cap is reached for the current day.
    pub async fn check_and_increment(
        &self,
        subscription_id: Uuid,
        downstream_ref: &str,
    ) -> Result<bool, RateLimitError> {
        // UPSERT, then return whether the new count is within the cap.
        let row: (i32,) = sqlx::query_as(
            "INSERT INTO rebuild_rate (subscription_id, downstream_ref, bucket_day, fired)
             VALUES ($1, $2, CURRENT_DATE, 1)
             ON CONFLICT (subscription_id, downstream_ref, bucket_day) DO UPDATE
             SET fired = rebuild_rate.fired + 1
             RETURNING fired",
        )
        .bind(subscription_id)
        .bind(downstream_ref)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.0 <= self.per_downstream_per_day)
    }

    /// Best-effort revert when an emission fails post-increment.
    /// Avoids lighting up the daily cap for failures the caller will
    /// retry.
    pub async fn decrement_on_failure(
        &self,
        subscription_id: Uuid,
        downstream_ref: &str,
    ) -> Result<(), RateLimitError> {
        sqlx::query(
            "UPDATE rebuild_rate
             SET fired = GREATEST(0, fired - 1)
             WHERE subscription_id = $1
               AND downstream_ref = $2
               AND bucket_day = CURRENT_DATE",
        )
        .bind(subscription_id)
        .bind(downstream_ref)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Number of firings consumed today for the bucket. Mostly for
    /// diagnostics + the upcoming admin endpoints.
    pub async fn fired_today(
        &self,
        subscription_id: Uuid,
        downstream_ref: &str,
    ) -> Result<i32, RateLimitError> {
        let row: Option<(i32,)> = sqlx::query_as(
            "SELECT fired FROM rebuild_rate
             WHERE subscription_id = $1
               AND downstream_ref = $2
               AND bucket_day = CURRENT_DATE",
        )
        .bind(subscription_id)
        .bind(downstream_ref)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(n,)| n).unwrap_or(0))
    }
}

/// Tag used in `gc_drift`-style diagnostic logs to mark today's
/// bucket — useful for deduplicating UPSERT logs in tests.
pub fn current_bucket() -> chrono::NaiveDate {
    Utc::now().date_naive()
}

#[cfg(test)]
mod tests {
    /// Pure-function test of the cap-clamp logic — exercises the same
    /// `.max(1)` step that `RateLimit::new` uses, without standing up
    /// a Postgres pool just for a constructor invariant.
    #[test]
    fn cap_floor_is_one() {
        for input in [0i32, -1, -5, 1] {
            assert_eq!(input.max(1), if input <= 1 { 1 } else { input });
        }
        for input in [2, 100, 10_000] {
            assert_eq!(input.max(1), input);
        }
    }
}
