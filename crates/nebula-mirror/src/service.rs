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
    /// Scope rules controlling which (tenant, project) pairs are
    /// eligible for upstream pullthrough. Private projects should
    /// NOT be in scope — there is no plausible reason to ask a public
    /// upstream whether it has a sha256 from a project nebulacr is
    /// the origin of truth for, and doing so trips upstream circuit
    /// breakers and amplifies latency.
    #[serde(default)]
    pub scope: MirrorScope,
}

/// Which requests are considered eligible for upstream pullthrough.
///
/// The default mode — `DefaultTenantOnly` — limits mirroring to the
/// default tenant `_`, which by convention carries 2-segment Docker
/// paths like `library/alpine`. Everything else (private multi-tenant
/// projects) skips the mirror path entirely.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum MirrorScope {
    /// Mirror every request (legacy, NOT recommended — will re-introduce
    /// the push-time circuit-breaker trip if used with private projects).
    All,
    /// Only the default tenant is mirror-eligible.
    DefaultTenantOnly {
        #[serde(default = "default_tenant_name")]
        default_tenant: String,
    },
    /// Only the listed tenants / `tenant/project` pairs are eligible.
    Allowlist {
        #[serde(default)]
        tenants: Vec<String>,
        #[serde(default)]
        projects: Vec<String>,
    },
    /// Everything except the listed tenants / projects is eligible.
    Denylist {
        #[serde(default)]
        tenants: Vec<String>,
        #[serde(default)]
        projects: Vec<String>,
    },
    /// Only requests whose blob digest is already linked to an
    /// upstream-fetched manifest are eligible. This is the most
    /// self-maintaining mode, but requires a populated cache index.
    ManifestLinked,
}

impl Default for MirrorScope {
    fn default() -> Self {
        MirrorScope::DefaultTenantOnly {
            default_tenant: default_tenant_name(),
        }
    }
}

fn default_tenant_name() -> String {
    "_".to_string()
}

impl MirrorScope {
    /// True when the (tenant, project) pair is eligible for upstream
    /// pullthrough under this scope. `ManifestLinked` always returns
    /// false here — its decision is deferred to a per-request check
    /// against the cache index performed by `MirrorService`.
    pub fn tenant_project_eligible(&self, tenant: &str, project: &str) -> bool {
        match self {
            MirrorScope::All => true,
            MirrorScope::DefaultTenantOnly { default_tenant } => tenant == default_tenant,
            MirrorScope::Allowlist { tenants, projects } => {
                if tenants.iter().any(|t| t == tenant) {
                    return true;
                }
                let key = format!("{tenant}/{project}");
                projects.iter().any(|p| p == &key || p == project)
            }
            MirrorScope::Denylist { tenants, projects } => {
                if tenants.iter().any(|t| t == tenant) {
                    return false;
                }
                let key = format!("{tenant}/{project}");
                !projects.iter().any(|p| p == &key || p == project)
            }
            // ManifestLinked requires a per-blob cache-index lookup;
            // callers handle that separately after the tenant/project
            // pre-check passes. At the tenant/project level, we return
            // true so the request reaches the manifest-linkage check.
            MirrorScope::ManifestLinked => true,
        }
    }

    /// True when scope evaluation at the tenant/project level is the
    /// final answer. False for `ManifestLinked`, which needs a
    /// per-digest cache-index check.
    pub fn decides_at_tenant_level(&self) -> bool {
        !matches!(self, MirrorScope::ManifestLinked)
    }
}

impl Default for MirrorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            upstreams: vec![],
            cache_ttl_secs: 3600,
            scope: MirrorScope::default(),
        }
    }
}

/// Result of a mirror fetch operation.
#[derive(Debug)]
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
    scope: MirrorScope,
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
            scope: config.scope.clone(),
            default_cache_ttl: config.cache_ttl_secs,
        }
    }

    /// Scope check: whether upstream pullthrough should even be attempted
    /// for this (tenant, project). Returns false for private projects
    /// under the default scope, so push-time blob probes never contact
    /// upstream and never trip upstream circuit breakers.
    pub fn is_scope_eligible(&self, tenant: &str, project: &str) -> bool {
        self.scope.tenant_project_eligible(tenant, project)
    }

    /// Returns true if a specific blob digest is linked to a manifest
    /// that nebulacr previously cached from upstream. Used by the
    /// `ManifestLinked` scope.
    pub async fn is_blob_manifest_linked(
        &self,
        tenant: &str,
        project: &str,
        name: &str,
        digest: &str,
    ) -> bool {
        // is_cached_valid with a very large TTL = "has it ever been recorded?"
        self.cache_manager
            .is_cached_valid(tenant, project, name, digest, Some(u64::MAX))
            .await
    }

    pub fn scope(&self) -> &MirrorScope {
        &self.scope
    }

    /// Attempt to fetch a manifest from upstream registries and cache it locally.
    pub async fn fetch_manifest(
        &self,
        tenant: &str,
        project: &str,
        name: &str,
        reference: &str,
    ) -> Result<MirrorFetchResult, MirrorError> {
        // R3: scope check. Private projects skip the upstream path
        // entirely, no matter what the upstream list contains.
        if !self.is_scope_eligible(tenant, project) {
            return Err(MirrorError::NotInScope);
        }

        let upstream_repo = format!("{project}/{name}");

        // Try tenant-specific upstream first, then all upstreams
        let upstream_indices = self.resolve_upstreams(tenant);
        if upstream_indices.is_empty() {
            return Err(MirrorError::NoUpstreamsConfigured);
        }

        let mut all_not_found = true;
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
                    if !e.is_not_found_equivalent() {
                        all_not_found = false;
                    }
                    debug!(
                        upstream = %upstream.config().name,
                        error = %e,
                        "Upstream manifest fetch failed, trying next"
                    );
                    last_err = Some(e);
                }
            }
        }

        // If every upstream attempt collapsed to "not found / unavailable",
        // surface a single domain-level NotFoundOnAnyUpstream. Only
        // non-not-found-equivalent failures (auth errors) keep the
        // original Upstream() wrapper.
        if all_not_found {
            return Err(MirrorError::NotFoundOnAnyUpstream);
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
        // R3: scope check. Blob probes for private projects skip the
        // upstream path entirely.
        if !self.is_scope_eligible(tenant, project) {
            return Err(MirrorError::NotInScope);
        }

        // For ManifestLinked scope, additionally require that the
        // digest was previously recorded against a manifest fetched
        // from upstream. Without this, a private layer digest would
        // still trigger the upstream probe and trip the breaker.
        if matches!(self.scope, MirrorScope::ManifestLinked)
            && !self.is_blob_manifest_linked(tenant, project, name, digest).await
        {
            return Err(MirrorError::NotInScope);
        }

        let upstream_repo = format!("{project}/{name}");

        let upstream_indices = self.resolve_upstreams(tenant);
        if upstream_indices.is_empty() {
            return Err(MirrorError::NoUpstreamsConfigured);
        }

        let mut all_not_found = true;
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
                    if !e.is_not_found_equivalent() {
                        all_not_found = false;
                    }
                    debug!(
                        upstream = %upstream.config().name,
                        error = %e,
                        "Upstream blob fetch failed, trying next"
                    );
                    last_err = Some(e);
                }
            }
        }

        if all_not_found {
            return Err(MirrorError::NotFoundOnAnyUpstream);
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
    /// The requested artefact is not present on any upstream, either
    /// because every upstream cleanly returned 404, or because every
    /// upstream is unavailable (circuit-breaker open, network failure,
    /// 5xx). This is the "try another source" signal — the HTTP layer
    /// above must translate it into a domain 404 (BlobUnknown /
    /// ManifestUnknown), NOT into a 5xx. See R1/R2 in the mirror
    /// isolation fix.
    #[error("artefact not found on any upstream")]
    NotFoundOnAnyUpstream,
    /// Request was not eligible for upstream pullthrough under the
    /// configured scope. Caller should treat this exactly like a
    /// local miss in a non-mirrored registry — i.e. return 404, not
    /// 5xx, and never consult the upstream path.
    #[error("mirror scope does not include this request")]
    NotInScope,
    #[error("storage error: {0}")]
    Storage(String),
}

impl MirrorError {
    /// True when this error means "the artefact is not reachable via
    /// any mirror path." Equivalent to "we have no answer for the
    /// client from the mirror layer — fall through to a domain 404."
    ///
    /// This is deliberately broad. Breaker-open, upstream 5xx, and
    /// upstream 404 all collapse to the same domain meaning: nebulacr
    /// does not have this blob and cannot get it. The breaker state
    /// is an internal availability signal; it MUST NOT leak into the
    /// HTTP status as a 502.
    pub fn is_not_found_equivalent(&self) -> bool {
        match self {
            MirrorError::NotFoundOnAnyUpstream => true,
            MirrorError::NoUpstreamsConfigured => true,
            MirrorError::NotInScope => true,
            MirrorError::Upstream(u) => u.is_not_found_equivalent(),
            MirrorError::Storage(_) => false,
        }
    }
}
