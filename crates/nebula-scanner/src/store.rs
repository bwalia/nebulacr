//! Ephemeral scan-result store (Redis). Keyed by `scan:{digest}` with TTL.

use async_trait::async_trait;
use deadpool_redis::{Config as RedisConfig, Pool as RedisPool, Runtime};
use redis::AsyncCommands;

use crate::model::ScanResult;
use crate::{Result, ScanError};

#[async_trait]
pub trait EphemeralStore: Send + Sync {
    async fn put(&self, result: &ScanResult) -> Result<()>;
    async fn get(&self, digest: &str) -> Result<Option<ScanResult>>;
    async fn status(&self, digest: &str) -> Result<Option<String>>;
}

pub struct RedisStore {
    pool: RedisPool,
    ttl_secs: u64,
}

impl RedisStore {
    pub fn connect(url: &str, ttl_secs: u64) -> Result<Self> {
        let cfg = RedisConfig::from_url(url);
        let pool = cfg
            .create_pool(Some(Runtime::Tokio1))
            .map_err(|e| ScanError::Store(format!("redis pool: {e}")))?;
        Ok(Self { pool, ttl_secs })
    }

    pub fn ttl(&self) -> u64 {
        self.ttl_secs
    }

    fn key(digest: &str) -> String {
        format!("scan:{}", digest)
    }
}

#[async_trait]
impl EphemeralStore for RedisStore {
    async fn put(&self, result: &ScanResult) -> Result<()> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| ScanError::Store(format!("redis get: {e}")))?;
        let payload = serde_json::to_vec(result)?;
        let key = Self::key(&result.digest);
        // SET key value EX ttl
        let _: () = conn
            .set_ex(&key, payload, self.ttl_secs)
            .await
            .map_err(|e| ScanError::Store(format!("redis setex: {e}")))?;
        Ok(())
    }

    async fn get(&self, digest: &str) -> Result<Option<ScanResult>> {
        let mut conn = self
            .pool
            .get()
            .await
            .map_err(|e| ScanError::Store(format!("redis get: {e}")))?;
        let key = Self::key(digest);
        let bytes: Option<Vec<u8>> = conn
            .get(&key)
            .await
            .map_err(|e| ScanError::Store(format!("redis get: {e}")))?;
        match bytes {
            None => Ok(None),
            Some(b) => Ok(Some(serde_json::from_slice(&b)?)),
        }
    }

    async fn status(&self, digest: &str) -> Result<Option<String>> {
        match self.get(digest).await? {
            None => Ok(None),
            Some(r) => Ok(Some(
                match r.status {
                    crate::model::ScanStatus::Queued => "queued",
                    crate::model::ScanStatus::InProgress => "in_progress",
                    crate::model::ScanStatus::Completed => "completed",
                    crate::model::ScanStatus::Failed => "failed",
                }
                .into(),
            )),
        }
    }
}
