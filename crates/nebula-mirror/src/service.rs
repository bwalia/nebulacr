use std::collections::HashMap;
use std::sync::Arc;

use bytes::Bytes;
use chrono::Utc;
use nebula_common::storage::{blob_path, manifest_path, sha256_digest};
use object_store::{ObjectStore, path::Path as StorePath};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::cache::{CacheEntry, CacheManager};
use crate::upstream::{UpstreamClient, UpstreamConfig, UpstreamError};

/// Top-level mirror configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MirrorConfig {
    /// Whether mirroring is enabled.
    pub enabled: bool,
    /// List of upstream registries.
    pub upstreams: Vec<UpstreamConfig>,
    /// Default cache TTL in seconds.
    pub cache_ttl_secs: u64,
}

impl Default for MirrorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            upstreams: vec![],
            cache_ttl_secs: 3600,
        }
    }
}

/// Result of a mirror fetch operation.
pub struct MirrorFetchResult {
    pub data: Bytes,
    pub content_type: String,
    pub digest: String,
}

/// The mirror service provides pull-through cache functionality.
/// When a local lookup fails, it attempts to fetch from configured upstream registries.
pub struct MirrorService {
    upstreams: Vec<UpstreamClient>,
    /// Map from tenant prefix to upstream index for targeted routing.
    tenant_routing: HashMap<String, usize>,
    local_store: Arc<dyn ObjectStore>,
    cache_manager: CacheManager,
    #[allow(dead_code)]
    default_cache_ttl: u64,
}

impl MirrorService {
    pub fn new(config: &MirrorConfig, local_store: Arc<dyn ObjectStore>) -> Self {
        let mut upstreams = Vec::new();
        let mut tenant_routing = HashMap::new();

        for (idx, upstream_config) in config.upstreams.iter().enumerate() {
            if let Some(ref prefix) = upstream_config.tenant_prefix {
                tenant_routing.insert(prefix.clone(), idx);
            }
            upstreams.push(UpstreamClient::new(upstream_config.clone()));
        }

        let cache_manager = CacheManager::new(local_store.clone(), config.cache_ttl_secs);

        Self {
            upstreams,
            tenant_routing,
            local_store,
            cache_manager,
            default_cache_ttl: config.cache_ttl_secs,
        }
    }

    /// Attempt to fetch a manifest from upstream registries and cache it locally.
    pub async fn fetch_manifest(
        &self,
        tenant: &str,
        project: &str,
        name: &str,
        reference: &str,
    ) -> Result<MirrorFetchResult, MirrorError> {
        let upstream_repo = format!("{project}/{name}");

        // Try tenant-specific upstream first, then all upstreams
        let upstream_indices = self.resolve_upstreams(tenant);

        let mut last_err = None;
        for idx in upstream_indices {
            let upstream = &self.upstreams[idx];
            match upstream.get_manifest(&upstream_repo, reference).await {
                Ok(response) => {
                    let digest = response
                        .digest
                        .unwrap_or_else(|| sha256_digest(&response.data));

                    // Cache locally: store by digest
                    let digest_store_path =
                        StorePath::from(manifest_path(tenant, project, name, &digest));
                    if let Err(e) = self
                        .local_store
                        .put(&digest_store_path, response.data.clone().into())
                        .await
                    {
                        warn!(error = %e, "Failed to cache manifest locally");
                    }

                    // If reference is a tag, create tag link
                    if !reference.starts_with("sha256:") {
                        let tag_path =
                            nebula_common::storage::tag_link_path(tenant, project, name, reference);
                        let tag_store_path = StorePath::from(tag_path);
                        if let Err(e) = self
                            .local_store
                            .put(&tag_store_path, Bytes::from(digest.clone()).into())
                            .await
                        {
                            warn!(error = %e, "Failed to cache tag link locally");
                        }
                    }

                    // Record in cache index
                    let _ = self
                        .cache_manager
                        .record_cached(
                            tenant,
                            project,
                            name,
                            CacheEntry {
                                digest: digest.clone(),
                                upstream_name: upstream.config().name.clone(),
                                upstream_repo: upstream_repo.clone(),
                                cached_at: Utc::now(),
                                size: response.data.len() as u64,
                                content_type: response.content_type.clone(),
                            },
                        )
                        .await;

                    info!(
                        upstream = %upstream.config().name,
                        repo = %upstream_repo,
                        reference = %reference,
                        digest = %digest,
                        "Cached manifest from upstream"
                    );

                    return Ok(MirrorFetchResult {
                        data: response.data,
                        content_type: response.content_type,
                        digest,
                    });
                }
                Err(e) => {
                    debug!(
                        upstream = %upstream.config().name,
                        error = %e,
                        "Upstream manifest fetch failed, trying next"
                    );
                    last_err = Some(e);
                }
            }
        }

        Err(last_err
            .map(MirrorError::Upstream)
            .unwrap_or(MirrorError::NoUpstreamsConfigured))
    }

    /// Attempt to fetch a blob from upstream registries and cache it locally.
    pub async fn fetch_blob(
        &self,
        tenant: &str,
        project: &str,
        name: &str,
        digest: &str,
    ) -> Result<MirrorFetchResult, MirrorError> {
        let upstream_repo = format!("{project}/{name}");

        let upstream_indices = self.resolve_upstreams(tenant);

        let mut last_err = None;
        for idx in upstream_indices {
            let upstream = &self.upstreams[idx];
            match upstream.get_blob(&upstream_repo, digest).await {
                Ok(response) => {
                    // Cache locally
                    let store_path = StorePath::from(blob_path(tenant, project, name, digest));
                    if let Err(e) = self
                        .local_store
                        .put(&store_path, response.data.clone().into())
                        .await
                    {
                        warn!(error = %e, "Failed to cache blob locally");
                    }

                    // Record in cache index
                    let _ = self
                        .cache_manager
                        .record_cached(
                            tenant,
                            project,
                            name,
                            CacheEntry {
                                digest: digest.to_string(),
                                upstream_name: upstream.config().name.clone(),
                                upstream_repo: upstream_repo.clone(),
                                cached_at: Utc::now(),
                                size: response.data.len() as u64,
                                content_type: response.content_type.clone(),
                            },
                        )
                        .await;

                    info!(
                        upstream = %upstream.config().name,
                        repo = %upstream_repo,
                        digest = %digest,
                        "Cached blob from upstream"
                    );

                    return Ok(MirrorFetchResult {
                        data: response.data,
                        content_type: response.content_type,
                        digest: digest.to_string(),
                    });
                }
                Err(e) => {
                    debug!(
                        upstream = %upstream.config().name,
                        error = %e,
                        "Upstream blob fetch failed, trying next"
                    );
                    last_err = Some(e);
                }
            }
        }

        Err(last_err
            .map(MirrorError::Upstream)
            .unwrap_or(MirrorError::NoUpstreamsConfigured))
    }

    /// Resolve which upstreams to try for a given tenant.
    /// Returns indices into self.upstreams.
    fn resolve_upstreams(&self, tenant: &str) -> Vec<usize> {
        let mut indices = Vec::new();

        // Tenant-specific upstream first
        if let Some(&idx) = self.tenant_routing.get(tenant) {
            indices.push(idx);
        }

        // Then all upstreams (excluding already-added ones)
        for i in 0..self.upstreams.len() {
            if !indices.contains(&i) {
                indices.push(i);
            }
        }

        indices
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MirrorError {
    #[error("upstream error: {0}")]
    Upstream(UpstreamError),
    #[error("no upstream registries configured")]
    NoUpstreamsConfigured,
    #[error("storage error: {0}")]
    Storage(String),
}
