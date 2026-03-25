use std::sync::Arc;

use chrono::{DateTime, Utc};
use object_store::{ObjectStore, path::Path as StorePath};
use serde::{Deserialize, Serialize};
use tracing::info;

/// Metadata about a cached upstream artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    pub digest: String,
    pub upstream_name: String,
    pub upstream_repo: String,
    pub cached_at: DateTime<Utc>,
    pub size: u64,
    pub content_type: String,
}

/// Index of all cached entries for a repository.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CacheIndex {
    pub entries: Vec<CacheEntry>,
}

/// Manages cache metadata for mirrored content.
pub struct CacheManager {
    store: Arc<dyn ObjectStore>,
    default_ttl_secs: u64,
}

impl CacheManager {
    pub fn new(store: Arc<dyn ObjectStore>, default_ttl_secs: u64) -> Self {
        Self {
            store,
            default_ttl_secs,
        }
    }

    /// Build the path to the cache index for a repository.
    fn cache_index_path(tenant: &str, project: &str, repo: &str) -> String {
        format!("{tenant}/{project}/{repo}/.mirror/cache-index.json")
    }

    /// Record that an artifact was cached from an upstream.
    pub async fn record_cached(
        &self,
        tenant: &str,
        project: &str,
        repo: &str,
        entry: CacheEntry,
    ) -> Result<(), CacheError> {
        let path = Self::cache_index_path(tenant, project, repo);
        let store_path = StorePath::from(path);

        let mut index = self.load_index(&store_path).await;

        // Remove existing entry with same digest to avoid duplicates
        index.entries.retain(|e| e.digest != entry.digest);
        index.entries.push(entry);

        let data = serde_json::to_vec_pretty(&index)
            .map_err(|e| CacheError::Serialization(e.to_string()))?;
        self.store
            .put(&store_path, data.into())
            .await
            .map_err(|e| CacheError::Storage(e.to_string()))?;

        Ok(())
    }

    /// Check if a cached entry is still valid (not expired).
    pub async fn is_cached_valid(
        &self,
        tenant: &str,
        project: &str,
        repo: &str,
        digest: &str,
        ttl_secs: Option<u64>,
    ) -> bool {
        let path = Self::cache_index_path(tenant, project, repo);
        let store_path = StorePath::from(path);

        let index = self.load_index(&store_path).await;
        let ttl = ttl_secs.unwrap_or(self.default_ttl_secs);

        if let Some(entry) = index.entries.iter().find(|e| e.digest == digest) {
            let age = Utc::now()
                .signed_duration_since(entry.cached_at)
                .num_seconds();
            age >= 0 && (age as u64) < ttl
        } else {
            false
        }
    }

    /// Evict expired cache entries. Returns the number of entries evicted.
    pub async fn evict_expired(
        &self,
        tenant: &str,
        project: &str,
        repo: &str,
        ttl_secs: Option<u64>,
    ) -> Result<usize, CacheError> {
        let path = Self::cache_index_path(tenant, project, repo);
        let store_path = StorePath::from(path);

        let mut index = self.load_index(&store_path).await;
        let ttl = ttl_secs.unwrap_or(self.default_ttl_secs);
        let now = Utc::now();

        let before = index.entries.len();
        index.entries.retain(|entry| {
            let age = now.signed_duration_since(entry.cached_at).num_seconds();
            age >= 0 && (age as u64) < ttl
        });
        let evicted = before - index.entries.len();

        if evicted > 0 {
            info!(
                tenant,
                project, repo, evicted, "Evicted expired cache entries"
            );
            let data = serde_json::to_vec_pretty(&index)
                .map_err(|e| CacheError::Serialization(e.to_string()))?;
            self.store
                .put(&store_path, data.into())
                .await
                .map_err(|e| CacheError::Storage(e.to_string()))?;
        }

        Ok(evicted)
    }

    async fn load_index(&self, path: &StorePath) -> CacheIndex {
        match self.store.get(path).await {
            Ok(result) => match result.bytes().await {
                Ok(data) => serde_json::from_slice(&data).unwrap_or_default(),
                Err(_) => CacheIndex::default(),
            },
            Err(_) => CacheIndex::default(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("storage error: {0}")]
    Storage(String),
    #[error("serialization error: {0}")]
    Serialization(String),
}
