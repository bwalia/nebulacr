//! NebulaCR OCI Registry Service
//!
//! Implements the Docker Registry HTTP API V2 / OCI Distribution Specification
//! with multi-tenant isolation, JWT authentication, and filesystem-backed storage.

mod audit;
mod dashboard;
mod webhook;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use axum::{
    Router,
    extract::{FromRequestParts, Path, Query, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header, request::Parts},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, head, patch, post},
};
use bytes::Bytes;
use futures::TryStreamExt;
use governor::{Quota, RateLimiter, clock::DefaultClock, state::keyed::DefaultKeyedStateStore};
use jsonwebtoken::{DecodingKey, TokenData, Validation};
use metrics::{counter, histogram};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use object_store::aws::AmazonS3Builder;
use object_store::azure::MicrosoftAzureBuilder;
use object_store::gcp::GoogleCloudStorageBuilder;
use object_store::{ObjectStore, local::LocalFileSystem, path::Path as StorePath};
use tokio::sync::RwLock;
use tower_http::trace::TraceLayer;
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

use nebula_common::auth::TokenClaims;
use nebula_common::config::RegistryConfig;
use nebula_common::errors::RegistryError;
use nebula_common::models::Action;
use nebula_common::storage::{
    blob_path, manifest_path, sha256_digest, tag_link_path, tags_prefix, upload_path,
};

use nebula_mirror::MirrorService;
use nebula_mirror::service::MirrorConfig as MirrorServiceConfig;
use nebula_mirror::upstream::UpstreamConfig;
use nebula_replication::event::ReplicationEvent;
use nebula_replication::failover::FailoverManager;
use nebula_replication::region::{
    MultiRegionConfig as ReplicationMultiRegionConfig, RegionConfig as ReplicationRegionConfig,
    ReplicationMode, ReplicationPolicy,
};
use nebula_replication::replicator::{ReplicationHandle, Replicator};
use nebula_resilience::{CircuitBreakerConfig, ResilientObjectStore, RetryPolicy};

// ── Application State ────────────────────────────────────────────────────────

type KeyedRateLimiter = RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>;

/// Shared application state available to all handlers.
#[derive(Clone)]
struct AppState {
    store: Arc<dyn ObjectStore>,
    config: Arc<RegistryConfig>,
    decoding_key: Arc<DecodingKey>,
    prom_handle: PrometheusHandle,
    #[allow(dead_code)]
    rate_limiters: Arc<RwLock<HashMap<String, Arc<KeyedRateLimiter>>>>,
    default_rate_limiter: Arc<KeyedRateLimiter>,
    /// Pull-through mirror service (optional).
    mirror_service: Option<Arc<MirrorService>>,
    /// Replication handle for enqueuing events (optional).
    replication_handle: Option<ReplicationHandle>,
    /// Failover manager for multi-region read failover (optional).
    failover_manager: Option<Arc<FailoverManager>>,
    /// Webhook notifier handle for external event notifications (optional).
    webhook_handle: Option<webhook::WebhookHandle>,
    /// Registry audit log for tracking who pushed/pulled what.
    audit_log: Arc<audit::RegistryAuditLog>,
    /// Process start time for uptime tracking.
    #[allow(dead_code)]
    start_time: Instant,
}

// ── JWT Auth Extractor ───────────────────────────────────────────────────────

/// Extracts and validates JWT bearer tokens from the Authorization header.
/// Handlers that need authentication should include `AuthenticatedClaims` as a parameter.
struct AuthenticatedClaims(TokenClaims);

/// Helper trait to extract AppState from itself (used by the FromRequestParts impl).
trait FromRef<T> {
    fn from_ref(input: &T) -> Self;
}

impl FromRef<AppState> for AppState {
    fn from_ref(input: &AppState) -> Self {
        input.clone()
    }
}

impl<S> FromRequestParts<S> for AuthenticatedClaims
where
    S: Send + Sync,
    AppState: FromRef<S>,
{
    type Rejection = RegistryError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);

        let auth_header = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(RegistryError::Unauthorized)?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or(RegistryError::Unauthorized)?;

        let mut validation = Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_audience(&[&app_state.config.auth.audience]);
        validation.set_issuer(&[&app_state.config.auth.issuer]);
        validation.validate_exp = true;

        let token_data: TokenData<TokenClaims> = jsonwebtoken::decode(
            token,
            &app_state.decoding_key,
            &validation,
        )
        .map_err(|e| match e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => RegistryError::TokenExpired,
            _ => RegistryError::TokenInvalid {
                reason: e.to_string(),
            },
        })?;

        Ok(AuthenticatedClaims(token_data.claims))
    }
}

// ── Auth Helpers ─────────────────────────────────────────────────────────────

/// Check that the token's claims authorize the given action on the specified repository.
fn authorize(
    claims: &TokenClaims,
    tenant: &str,
    project: &str,
    name: &str,
    action: Action,
) -> Result<(), RegistryError> {
    let repo_path = format!("{tenant}/{project}/{name}");

    // Check role-level permission first
    if !claims.role.can(action) {
        return Err(RegistryError::Forbidden {
            reason: format!("role {:?} does not permit action {:?}", claims.role, action),
        });
    }

    // Check scopes: at least one scope must match the repository and include the action
    let scope_ok = claims
        .scopes
        .iter()
        .any(|s| (s.repository == repo_path || s.repository == "*") && s.actions.contains(&action));

    if !scope_ok {
        return Err(RegistryError::Forbidden {
            reason: format!("token scopes do not grant {action:?} on {repo_path}"),
        });
    }

    Ok(())
}

// ── Request ID Middleware ────────────────────────────────────────────────────

async fn request_id_middleware(mut request: Request, next: Next) -> Response {
    let request_id = Uuid::new_v4().to_string();
    if let Ok(val) = HeaderValue::from_str(&request_id) {
        request.headers_mut().insert("x-request-id", val);
    }

    let mut response = next.run(request).await;
    if let Ok(val) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("x-request-id", val);
    }
    response
}

// ── Rate Limiting Middleware ─────────────────────────────────────────────────

async fn rate_limit_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, RegistryError> {
    // Extract tenant from path if present, otherwise use IP-based limiting
    let path = request.uri().path().to_string();
    let key = {
        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        // /v2/{tenant}/{project}/{name}/...
        if segments.len() >= 2 && segments[0] == "v2" && segments[1] != "_catalog" {
            segments[1].to_string()
        } else {
            "anonymous".to_string()
        }
    };

    if state.default_rate_limiter.check_key(&key).is_err() {
        return Err(RegistryError::RateLimitExceeded);
    }

    Ok(next.run(request).await)
}

// ── Path Parameters ──────────────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
struct RepoPath {
    tenant: String,
    project: String,
    name: String,
}

#[derive(Debug, serde::Deserialize)]
struct ManifestRef {
    tenant: String,
    project: String,
    name: String,
    reference: String,
}

#[derive(Debug, serde::Deserialize)]
struct BlobRef {
    tenant: String,
    project: String,
    name: String,
    digest: String,
}

#[derive(Debug, serde::Deserialize)]
struct UploadRef {
    tenant: String,
    project: String,
    name: String,
    uuid: String,
}

#[derive(Debug, serde::Deserialize)]
struct DigestQuery {
    digest: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct PaginationQuery {
    n: Option<usize>,
    last: Option<String>,
}

// ── Handlers ─────────────────────────────────────────────────────────────────

/// GET /v2/ - API version check
#[instrument(name = "v2_check")]
async fn v2_check() -> impl IntoResponse {
    (
        StatusCode::OK,
        [("Docker-Distribution-API-Version", "registry/2.0")],
        "{}",
    )
}

/// GET /health - Health check
#[instrument(name = "health_check")]
async fn health_check() -> impl IntoResponse {
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({"status": "healthy"})),
    )
}

/// GET /metrics - Prometheus metrics
async fn metrics_handler(State(state): State<AppState>) -> impl IntoResponse {
    (StatusCode::OK, state.prom_handle.render())
}

/// HEAD /v2/{tenant}/{project}/{name}/manifests/{reference}
#[instrument(name = "head_manifest", skip(state, claims), fields(tenant = %params.tenant, project = %params.project, name = %params.name, reference = %params.reference))]
async fn head_manifest(
    State(state): State<AppState>,
    AuthenticatedClaims(claims): AuthenticatedClaims,
    Path(params): Path<ManifestRef>,
) -> Result<Response, RegistryError> {
    authorize(
        &claims,
        &params.tenant,
        &params.project,
        &params.name,
        Action::Pull,
    )?;

    let path = resolve_manifest_path(
        &state,
        &params.tenant,
        &params.project,
        &params.name,
        &params.reference,
    )
    .await?;
    let store_path = StorePath::from(path);

    let meta = state
        .store
        .head(&store_path)
        .await
        .map_err(|_| RegistryError::ManifestUnknown {
            reference: params.reference.clone(),
        })?;

    let data = state
        .store
        .get(&store_path)
        .await
        .map_err(|_| RegistryError::ManifestUnknown {
            reference: params.reference.clone(),
        })?
        .bytes()
        .await
        .map_err(|e| RegistryError::Storage(e.to_string()))?;

    let digest = sha256_digest(&data);
    let media_type = detect_manifest_media_type(&data);

    let mut headers = HeaderMap::new();
    headers.insert(
        "Docker-Content-Digest",
        HeaderValue::from_str(&digest).unwrap(),
    );
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&media_type).unwrap(),
    );
    headers.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&meta.size.to_string()).unwrap(),
    );

    Ok((StatusCode::OK, headers).into_response())
}

/// GET /v2/{tenant}/{project}/{name}/manifests/{reference}
#[instrument(name = "get_manifest", skip(state, claims), fields(tenant = %params.tenant, project = %params.project, name = %params.name, reference = %params.reference))]
async fn get_manifest(
    State(state): State<AppState>,
    AuthenticatedClaims(claims): AuthenticatedClaims,
    Path(params): Path<ManifestRef>,
) -> Result<Response, RegistryError> {
    let op_start = Instant::now();

    authorize(
        &claims,
        &params.tenant,
        &params.project,
        &params.name,
        Action::Pull,
    )?;

    counter!("registry_pull_total",
        "tenant" => params.tenant.clone(),
        "project" => params.project.clone()
    )
    .increment(1);
    counter!("registry_manifest_pull_total").increment(1);

    let path = resolve_manifest_path(
        &state,
        &params.tenant,
        &params.project,
        &params.name,
        &params.reference,
    )
    .await?;
    let store_path = StorePath::from(path);

    let data = match state.store.get(&store_path).await {
        Ok(result) => result
            .bytes()
            .await
            .map_err(|e| RegistryError::Storage(e.to_string()))?,
        Err(_) => {
            // Try mirror fallback
            if let Some(ref mirror) = state.mirror_service {
                debug!(
                    tenant = %params.tenant,
                    reference = %params.reference,
                    "Local manifest miss, trying upstream mirror"
                );
                let result = mirror
                    .fetch_manifest(
                        &params.tenant,
                        &params.project,
                        &params.name,
                        &params.reference,
                    )
                    .await
                    .map_err(|e| RegistryError::UpstreamError(e.to_string()))?;
                result.data
            } else if let Some(ref failover) = state.failover_manager {
                // Try reading from another region
                debug!(
                    tenant = %params.tenant,
                    reference = %params.reference,
                    "Local manifest miss, trying failover region"
                );
                let path = format!(
                    "/v2/{}/{}/{}/manifests/{}",
                    params.tenant, params.project, params.name, params.reference
                );
                let proxy = failover
                    .proxy_get(&path, None)
                    .await
                    .map_err(|e| RegistryError::FailoverError(e.to_string()))?;
                proxy.body
            } else {
                return Err(RegistryError::ManifestUnknown {
                    reference: params.reference.clone(),
                });
            }
        }
    };

    let digest = sha256_digest(&data);
    let media_type = detect_manifest_media_type(&data);

    let mut headers = HeaderMap::new();
    headers.insert(
        "Docker-Content-Digest",
        HeaderValue::from_str(&digest).unwrap(),
    );
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&media_type).unwrap(),
    );
    headers.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&data.len().to_string()).unwrap(),
    );
    headers.insert(
        "Docker-Distribution-API-Version",
        HeaderValue::from_static("registry/2.0"),
    );

    let duration = op_start.elapsed();
    histogram!("registry_request_duration_seconds", "operation" => "manifest.pull")
        .record(duration.as_secs_f64());
    state
        .audit_log
        .record(audit::RegistryAuditEvent {
            timestamp: chrono::Utc::now(),
            event_type: "manifest.pull".into(),
            subject: claims.sub.clone(),
            tenant: params.tenant.clone(),
            project: params.project.clone(),
            repository: params.name.clone(),
            reference: params.reference.clone(),
            digest: digest.clone(),
            size_bytes: data.len() as u64,
            status_code: 200,
            duration_ms: duration.as_millis() as u64,
        })
        .await;

    Ok((StatusCode::OK, headers, data).into_response())
}

/// PUT /v2/{tenant}/{project}/{name}/manifests/{reference}
#[instrument(name = "put_manifest", skip(state, claims, body), fields(tenant = %params.tenant, project = %params.project, name = %params.name, reference = %params.reference))]
async fn put_manifest(
    State(state): State<AppState>,
    AuthenticatedClaims(claims): AuthenticatedClaims,
    Path(params): Path<ManifestRef>,
    body: Bytes,
) -> Result<Response, RegistryError> {
    let op_start = Instant::now();

    authorize(
        &claims,
        &params.tenant,
        &params.project,
        &params.name,
        Action::Push,
    )?;

    counter!("registry_push_total",
        "tenant" => params.tenant.clone(),
        "project" => params.project.clone()
    )
    .increment(1);
    counter!("registry_manifest_push_total").increment(1);
    counter!("registry_push_bytes_total").increment(body.len() as u64);

    // Validate JSON
    serde_json::from_slice::<serde_json::Value>(&body).map_err(|e| {
        RegistryError::ManifestInvalid {
            reason: e.to_string(),
        }
    })?;

    let digest = sha256_digest(&body);

    // Store manifest by digest
    let digest_path = manifest_path(&params.tenant, &params.project, &params.name, &digest);
    let digest_store_path = StorePath::from(digest_path);
    state
        .store
        .put(&digest_store_path, body.clone().into())
        .await
        .map_err(|e| RegistryError::Storage(e.to_string()))?;

    // If reference is a tag (not a digest), create a tag link
    if !params.reference.starts_with("sha256:") {
        let tag_p = tag_link_path(
            &params.tenant,
            &params.project,
            &params.name,
            &params.reference,
        );
        let tag_store_path = StorePath::from(tag_p);
        state
            .store
            .put(&tag_store_path, Bytes::from(digest.clone()).into())
            .await
            .map_err(|e| RegistryError::Storage(e.to_string()))?;
    }

    // Emit replication event if configured
    if let Some(ref repl) = state.replication_handle {
        let event = ReplicationEvent::manifest_push(
            params.tenant.clone(),
            params.project.clone(),
            params.name.clone(),
            params.reference.clone(),
            digest.clone(),
            body.len() as u64,
            repl.local_region().to_string(),
        );
        repl.enqueue(event).await;
    }

    // Notify webhook endpoints
    if let Some(ref wh) = state.webhook_handle {
        let source_region = state
            .replication_handle
            .as_ref()
            .map(|r| r.local_region().to_string());
        wh.notify(webhook::WebhookPayload::manifest_push(
            params.tenant.clone(),
            params.project.clone(),
            params.name.clone(),
            params.reference.clone(),
            digest.clone(),
            body.len() as u64,
            source_region,
        ))
        .await;
    }

    let location = format!(
        "/v2/{}/{}/{}/manifests/{}",
        params.tenant, params.project, params.name, digest
    );

    let mut headers = HeaderMap::new();
    headers.insert(
        "Docker-Content-Digest",
        HeaderValue::from_str(&digest).unwrap(),
    );
    headers.insert(header::LOCATION, HeaderValue::from_str(&location).unwrap());
    headers.insert(
        "Docker-Distribution-API-Version",
        HeaderValue::from_static("registry/2.0"),
    );

    let duration = op_start.elapsed();
    histogram!("registry_request_duration_seconds", "operation" => "manifest.push")
        .record(duration.as_secs_f64());
    state
        .audit_log
        .record(audit::RegistryAuditEvent {
            timestamp: chrono::Utc::now(),
            event_type: "manifest.push".into(),
            subject: claims.sub.clone(),
            tenant: params.tenant.clone(),
            project: params.project.clone(),
            repository: params.name.clone(),
            reference: params.reference.clone(),
            digest: digest.clone(),
            size_bytes: body.len() as u64,
            status_code: 201,
            duration_ms: duration.as_millis() as u64,
        })
        .await;

    Ok((StatusCode::CREATED, headers).into_response())
}

/// DELETE /v2/{tenant}/{project}/{name}/manifests/{reference}
#[instrument(name = "delete_manifest", skip(state, claims), fields(tenant = %params.tenant, project = %params.project, name = %params.name, reference = %params.reference))]
async fn delete_manifest(
    State(state): State<AppState>,
    AuthenticatedClaims(claims): AuthenticatedClaims,
    Path(params): Path<ManifestRef>,
) -> Result<Response, RegistryError> {
    let op_start = Instant::now();

    authorize(
        &claims,
        &params.tenant,
        &params.project,
        &params.name,
        Action::Delete,
    )?;

    counter!("registry_delete_total",
        "tenant" => params.tenant.clone(),
        "project" => params.project.clone()
    )
    .increment(1);

    let path = resolve_manifest_path(
        &state,
        &params.tenant,
        &params.project,
        &params.name,
        &params.reference,
    )
    .await?;
    let store_path = StorePath::from(path);

    state
        .store
        .delete(&store_path)
        .await
        .map_err(|_| RegistryError::ManifestUnknown {
            reference: params.reference.clone(),
        })?;

    // If it was a tag reference, also delete the tag link
    if !params.reference.starts_with("sha256:") {
        let tag_p = tag_link_path(
            &params.tenant,
            &params.project,
            &params.name,
            &params.reference,
        );
        let tag_store_path = StorePath::from(tag_p);
        let _ = state.store.delete(&tag_store_path).await;
    }

    // Emit replication event if configured
    if let Some(ref repl) = state.replication_handle {
        let event = ReplicationEvent::manifest_delete(
            params.tenant.clone(),
            params.project.clone(),
            params.name.clone(),
            params.reference.clone(),
            params.reference.clone(),
            repl.local_region().to_string(),
        );
        repl.enqueue(event).await;
    }

    // Notify webhook endpoints
    if let Some(ref wh) = state.webhook_handle {
        let source_region = state
            .replication_handle
            .as_ref()
            .map(|r| r.local_region().to_string());
        wh.notify(webhook::WebhookPayload::manifest_delete(
            params.tenant.clone(),
            params.project.clone(),
            params.name.clone(),
            params.reference.clone(),
            params.reference.clone(),
            source_region,
        ))
        .await;
    }

    let duration = op_start.elapsed();
    histogram!("registry_request_duration_seconds", "operation" => "manifest.delete")
        .record(duration.as_secs_f64());
    state
        .audit_log
        .record(audit::RegistryAuditEvent {
            timestamp: chrono::Utc::now(),
            event_type: "manifest.delete".into(),
            subject: claims.sub.clone(),
            tenant: params.tenant.clone(),
            project: params.project.clone(),
            repository: params.name.clone(),
            reference: params.reference.clone(),
            digest: params.reference.clone(),
            size_bytes: 0,
            status_code: 202,
            duration_ms: duration.as_millis() as u64,
        })
        .await;

    Ok(StatusCode::ACCEPTED.into_response())
}

/// HEAD /v2/{tenant}/{project}/{name}/blobs/{digest}
#[instrument(name = "head_blob", skip(state, claims), fields(tenant = %params.tenant, project = %params.project, name = %params.name, digest = %params.digest))]
async fn head_blob(
    State(state): State<AppState>,
    AuthenticatedClaims(claims): AuthenticatedClaims,
    Path(params): Path<BlobRef>,
) -> Result<Response, RegistryError> {
    authorize(
        &claims,
        &params.tenant,
        &params.project,
        &params.name,
        Action::Pull,
    )?;

    let path = blob_path(
        &params.tenant,
        &params.project,
        &params.name,
        &params.digest,
    );
    let store_path = StorePath::from(path);

    let meta = state
        .store
        .head(&store_path)
        .await
        .map_err(|_| RegistryError::BlobUnknown {
            digest: params.digest.clone(),
        })?;

    let mut headers = HeaderMap::new();
    headers.insert(
        "Docker-Content-Digest",
        HeaderValue::from_str(&params.digest).unwrap(),
    );
    headers.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&meta.size.to_string()).unwrap(),
    );
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );

    Ok((StatusCode::OK, headers).into_response())
}

/// GET /v2/{tenant}/{project}/{name}/blobs/{digest}
#[instrument(name = "get_blob", skip(state, claims), fields(tenant = %params.tenant, project = %params.project, name = %params.name, digest = %params.digest))]
async fn get_blob(
    State(state): State<AppState>,
    AuthenticatedClaims(claims): AuthenticatedClaims,
    Path(params): Path<BlobRef>,
) -> Result<Response, RegistryError> {
    let op_start = Instant::now();

    authorize(
        &claims,
        &params.tenant,
        &params.project,
        &params.name,
        Action::Pull,
    )?;

    counter!("registry_pull_total",
        "tenant" => params.tenant.clone(),
        "project" => params.project.clone()
    )
    .increment(1);
    counter!("registry_blob_pull_total").increment(1);

    let path = blob_path(
        &params.tenant,
        &params.project,
        &params.name,
        &params.digest,
    );
    let store_path = StorePath::from(path);

    let data = match state.store.get(&store_path).await {
        Ok(result) => result
            .bytes()
            .await
            .map_err(|e| RegistryError::Storage(e.to_string()))?,
        Err(_) => {
            // Try mirror fallback
            if let Some(ref mirror) = state.mirror_service {
                debug!(
                    tenant = %params.tenant,
                    digest = %params.digest,
                    "Local blob miss, trying upstream mirror"
                );
                let result = mirror
                    .fetch_blob(
                        &params.tenant,
                        &params.project,
                        &params.name,
                        &params.digest,
                    )
                    .await
                    .map_err(|e| RegistryError::UpstreamError(e.to_string()))?;
                result.data
            } else if let Some(ref failover) = state.failover_manager {
                debug!(
                    tenant = %params.tenant,
                    digest = %params.digest,
                    "Local blob miss, trying failover region"
                );
                let path = format!(
                    "/v2/{}/{}/{}/blobs/{}",
                    params.tenant, params.project, params.name, params.digest
                );
                let proxy = failover
                    .proxy_get(&path, None)
                    .await
                    .map_err(|e| RegistryError::FailoverError(e.to_string()))?;
                proxy.body
            } else {
                return Err(RegistryError::BlobUnknown {
                    digest: params.digest.clone(),
                });
            }
        }
    };

    let mut headers = HeaderMap::new();
    headers.insert(
        "Docker-Content-Digest",
        HeaderValue::from_str(&params.digest).unwrap(),
    );
    headers.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&data.len().to_string()).unwrap(),
    );
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );

    let duration = op_start.elapsed();
    histogram!("registry_request_duration_seconds", "operation" => "blob.pull")
        .record(duration.as_secs_f64());
    counter!("registry_pull_bytes_total").increment(data.len() as u64);
    state
        .audit_log
        .record(audit::RegistryAuditEvent {
            timestamp: chrono::Utc::now(),
            event_type: "blob.pull".into(),
            subject: claims.sub.clone(),
            tenant: params.tenant.clone(),
            project: params.project.clone(),
            repository: params.name.clone(),
            reference: String::new(),
            digest: params.digest.clone(),
            size_bytes: data.len() as u64,
            status_code: 200,
            duration_ms: duration.as_millis() as u64,
        })
        .await;

    Ok((StatusCode::OK, headers, data).into_response())
}

/// POST /v2/{tenant}/{project}/{name}/blobs/uploads/
#[instrument(name = "initiate_upload", skip(state, claims), fields(tenant = %params.tenant, project = %params.project, name = %params.name))]
async fn initiate_blob_upload(
    State(state): State<AppState>,
    AuthenticatedClaims(claims): AuthenticatedClaims,
    Path(params): Path<RepoPath>,
) -> Result<Response, RegistryError> {
    authorize(
        &claims,
        &params.tenant,
        &params.project,
        &params.name,
        Action::Push,
    )?;

    let upload_id = Uuid::new_v4().to_string();

    // Create an empty upload placeholder
    let path = upload_path(&params.tenant, &params.project, &params.name, &upload_id);
    let store_path = StorePath::from(path);
    state
        .store
        .put(&store_path, Bytes::new().into())
        .await
        .map_err(|e| RegistryError::Storage(e.to_string()))?;

    let location = format!(
        "/v2/{}/{}/{}/blobs/uploads/{}",
        params.tenant, params.project, params.name, upload_id
    );

    let mut headers = HeaderMap::new();
    headers.insert(header::LOCATION, HeaderValue::from_str(&location).unwrap());
    headers.insert(
        "Docker-Upload-UUID",
        HeaderValue::from_str(&upload_id).unwrap(),
    );
    headers.insert(header::RANGE, HeaderValue::from_static("0-0"));
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
    headers.insert(
        "Docker-Distribution-API-Version",
        HeaderValue::from_static("registry/2.0"),
    );

    Ok((StatusCode::ACCEPTED, headers).into_response())
}

/// PATCH /v2/{tenant}/{project}/{name}/blobs/uploads/{uuid}
#[instrument(name = "upload_chunk", skip(state, claims, body), fields(tenant = %params.tenant, project = %params.project, name = %params.name, uuid = %params.uuid))]
async fn upload_blob_chunk(
    State(state): State<AppState>,
    AuthenticatedClaims(claims): AuthenticatedClaims,
    Path(params): Path<UploadRef>,
    body: Bytes,
) -> Result<Response, RegistryError> {
    authorize(
        &claims,
        &params.tenant,
        &params.project,
        &params.name,
        Action::Push,
    )?;

    let path = upload_path(&params.tenant, &params.project, &params.name, &params.uuid);
    let store_path = StorePath::from(path);

    // Read existing upload data and append the new chunk
    let existing = match state.store.get(&store_path).await {
        Ok(result) => result
            .bytes()
            .await
            .map_err(|e| RegistryError::Storage(e.to_string()))?,
        Err(_) => return Err(RegistryError::BlobUploadInvalid),
    };

    let mut combined = existing.to_vec();
    combined.extend_from_slice(&body);
    let end = combined.len();

    counter!("registry_blob_upload_bytes_total",
        "tenant" => params.tenant.clone(),
        "project" => params.project.clone()
    )
    .increment(body.len() as u64);

    state
        .store
        .put(&store_path, Bytes::from(combined).into())
        .await
        .map_err(|e| RegistryError::Storage(e.to_string()))?;

    let location = format!(
        "/v2/{}/{}/{}/blobs/uploads/{}",
        params.tenant, params.project, params.name, params.uuid
    );

    let range_val = format!("0-{}", end.saturating_sub(1));
    let mut headers = HeaderMap::new();
    headers.insert(header::LOCATION, HeaderValue::from_str(&location).unwrap());
    headers.insert(
        "Docker-Upload-UUID",
        HeaderValue::from_str(&params.uuid).unwrap(),
    );
    headers.insert(header::RANGE, HeaderValue::from_str(&range_val).unwrap());
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
    headers.insert(
        "Docker-Distribution-API-Version",
        HeaderValue::from_static("registry/2.0"),
    );

    Ok((StatusCode::ACCEPTED, headers).into_response())
}

/// PUT /v2/{tenant}/{project}/{name}/blobs/uploads/{uuid}?digest=sha256:...
#[instrument(name = "complete_upload", skip(state, claims, body), fields(tenant = %params.tenant, project = %params.project, name = %params.name, uuid = %params.uuid))]
async fn complete_blob_upload(
    State(state): State<AppState>,
    AuthenticatedClaims(claims): AuthenticatedClaims,
    Path(params): Path<UploadRef>,
    Query(query): Query<DigestQuery>,
    body: Bytes,
) -> Result<Response, RegistryError> {
    let op_start = Instant::now();

    authorize(
        &claims,
        &params.tenant,
        &params.project,
        &params.name,
        Action::Push,
    )?;

    let expected_digest = query.digest.ok_or(RegistryError::DigestInvalid {
        expected: "sha256:...".to_string(),
        actual: "<missing>".to_string(),
    })?;

    let up_path = upload_path(&params.tenant, &params.project, &params.name, &params.uuid);
    let up_store_path = StorePath::from(up_path);

    // Read the accumulated upload data
    let existing = match state.store.get(&up_store_path).await {
        Ok(result) => result
            .bytes()
            .await
            .map_err(|e| RegistryError::Storage(e.to_string()))?,
        Err(_) => return Err(RegistryError::BlobUploadInvalid),
    };

    // Append any final chunk sent with the PUT
    let mut final_data = existing.to_vec();
    if !body.is_empty() {
        final_data.extend_from_slice(&body);
    }

    counter!("registry_blob_upload_bytes_total",
        "tenant" => params.tenant.clone(),
        "project" => params.project.clone()
    )
    .increment(body.len() as u64);

    // Verify digest
    let actual_digest = sha256_digest(&final_data);
    if actual_digest != expected_digest {
        return Err(RegistryError::DigestInvalid {
            expected: expected_digest,
            actual: actual_digest,
        });
    }

    // Store the final blob
    let final_data_len = final_data.len() as u64;
    let final_blob_path = blob_path(
        &params.tenant,
        &params.project,
        &params.name,
        &expected_digest,
    );
    let final_store_path = StorePath::from(final_blob_path);
    state
        .store
        .put(&final_store_path, Bytes::from(final_data).into())
        .await
        .map_err(|e| RegistryError::Storage(e.to_string()))?;

    // Clean up the upload session
    let _ = state.store.delete(&up_store_path).await;

    // Emit replication event if configured
    if let Some(ref repl) = state.replication_handle {
        let event = ReplicationEvent::blob_push(
            params.tenant.clone(),
            params.project.clone(),
            params.name.clone(),
            expected_digest.clone(),
            final_data_len,
            repl.local_region().to_string(),
        );
        repl.enqueue(event).await;
    }

    // Notify webhook endpoints
    if let Some(ref wh) = state.webhook_handle {
        let source_region = state
            .replication_handle
            .as_ref()
            .map(|r| r.local_region().to_string());
        wh.notify(webhook::WebhookPayload::blob_push(
            params.tenant.clone(),
            params.project.clone(),
            params.name.clone(),
            expected_digest.clone(),
            final_data_len,
            source_region,
        ))
        .await;
    }

    let location = format!(
        "/v2/{}/{}/{}/blobs/{}",
        params.tenant, params.project, params.name, expected_digest
    );

    let mut headers = HeaderMap::new();
    headers.insert(header::LOCATION, HeaderValue::from_str(&location).unwrap());
    headers.insert(
        "Docker-Content-Digest",
        HeaderValue::from_str(&expected_digest).unwrap(),
    );
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
    headers.insert(
        "Docker-Distribution-API-Version",
        HeaderValue::from_static("registry/2.0"),
    );

    let duration = op_start.elapsed();
    histogram!("registry_request_duration_seconds", "operation" => "blob.push")
        .record(duration.as_secs_f64());
    state
        .audit_log
        .record(audit::RegistryAuditEvent {
            timestamp: chrono::Utc::now(),
            event_type: "blob.push".into(),
            subject: claims.sub.clone(),
            tenant: params.tenant.clone(),
            project: params.project.clone(),
            repository: params.name.clone(),
            reference: String::new(),
            digest: expected_digest.clone(),
            size_bytes: final_data_len,
            status_code: 201,
            duration_ms: duration.as_millis() as u64,
        })
        .await;

    Ok((StatusCode::CREATED, headers).into_response())
}

/// GET /v2/{tenant}/{project}/{name}/tags/list
#[instrument(name = "list_tags", skip(state, claims), fields(tenant = %params.tenant, project = %params.project, name = %params.name))]
async fn list_tags(
    State(state): State<AppState>,
    AuthenticatedClaims(claims): AuthenticatedClaims,
    Path(params): Path<RepoPath>,
    Query(pagination): Query<PaginationQuery>,
) -> Result<Response, RegistryError> {
    authorize(
        &claims,
        &params.tenant,
        &params.project,
        &params.name,
        Action::Pull,
    )?;

    let prefix = tags_prefix(&params.tenant, &params.project, &params.name);
    let store_prefix = StorePath::from(prefix.clone());

    let mut tags: Vec<String> = Vec::new();

    let list_result: Vec<_> = state
        .store
        .list(Some(&store_prefix))
        .try_collect()
        .await
        .map_err(|e| RegistryError::Storage(e.to_string()))?;

    for meta in &list_result {
        let full_path = meta.location.to_string();
        if let Some(tag) = full_path.strip_prefix(&prefix)
            && !tag.is_empty()
        {
            tags.push(tag.to_string());
        }
    }

    tags.sort();

    // Apply pagination
    let tags = if let Some(ref last) = pagination.last {
        tags.into_iter()
            .skip_while(|t| t.as_str() <= last.as_str())
            .collect()
    } else {
        tags
    };

    let tags: Vec<String> = if let Some(n) = pagination.n {
        tags.into_iter().take(n).collect()
    } else {
        tags
    };

    let repo_name = format!("{}/{}/{}", params.tenant, params.project, params.name);
    let tag_list = nebula_common::models::TagList {
        name: repo_name,
        tags,
    };

    Ok((StatusCode::OK, axum::Json(tag_list)).into_response())
}

/// GET /v2/_catalog
#[instrument(name = "catalog", skip(state, claims))]
async fn catalog(
    State(state): State<AppState>,
    AuthenticatedClaims(claims): AuthenticatedClaims,
    Query(pagination): Query<PaginationQuery>,
) -> Result<Response, RegistryError> {
    // List repositories filtered by the tenant in the token
    let tenant_id = claims.tenant_id.to_string();
    let tenant_prefix = StorePath::from(tenant_id);

    let mut repositories: Vec<String> = Vec::new();

    let list_result = state
        .store
        .list_with_delimiter(Some(&tenant_prefix))
        .await
        .map_err(|e| RegistryError::Storage(e.to_string()))?;

    // Walk the tenant prefix to find project/repo combos
    for prefix_entry in &list_result.common_prefixes {
        let project_prefix = prefix_entry.clone();

        if let Ok(project_list) = state.store.list_with_delimiter(Some(&project_prefix)).await {
            for repo_prefix in &project_list.common_prefixes {
                let repo_path = repo_prefix.to_string();
                let repo_name = repo_path.trim_end_matches('/');
                if !repo_name.is_empty() {
                    repositories.push(repo_name.to_string());
                }
            }
        }
    }

    repositories.sort();

    // Apply pagination
    let repositories = if let Some(ref last) = pagination.last {
        repositories
            .into_iter()
            .skip_while(|r| r.as_str() <= last.as_str())
            .collect()
    } else {
        repositories
    };

    let repositories: Vec<String> = if let Some(n) = pagination.n {
        repositories.into_iter().take(n).collect()
    } else {
        repositories
    };

    let catalog_resp = nebula_common::models::Catalog { repositories };

    Ok((StatusCode::OK, axum::Json(catalog_resp)).into_response())
}

// ── Helper Functions ─────────────────────────────────────────────────────────

/// Resolve a manifest reference: if it is a tag, read the tag link to get the digest,
/// then return the manifest path by digest. If it is a digest, return the manifest path directly.
async fn resolve_manifest_path(
    state: &AppState,
    tenant: &str,
    project: &str,
    name: &str,
    reference: &str,
) -> Result<String, RegistryError> {
    if reference.starts_with("sha256:") {
        // Direct digest reference
        Ok(manifest_path(tenant, project, name, reference))
    } else {
        // Tag reference: read the tag link to get the digest
        let tag_p = tag_link_path(tenant, project, name, reference);
        let store_path = StorePath::from(tag_p);

        let result =
            state
                .store
                .get(&store_path)
                .await
                .map_err(|_| RegistryError::ManifestUnknown {
                    reference: reference.to_string(),
                })?;

        let digest_bytes = result
            .bytes()
            .await
            .map_err(|e| RegistryError::Storage(e.to_string()))?;

        let digest = String::from_utf8(digest_bytes.to_vec()).map_err(|_| {
            RegistryError::ManifestInvalid {
                reason: "tag link contains invalid UTF-8".to_string(),
            }
        })?;

        let digest = digest.trim().to_string();
        Ok(manifest_path(tenant, project, name, &digest))
    }
}

/// Detect the media type of a manifest from its JSON content.
fn detect_manifest_media_type(data: &[u8]) -> String {
    if let Ok(val) = serde_json::from_slice::<serde_json::Value>(data) {
        if let Some(mt) = val.get("mediaType").and_then(|v| v.as_str()) {
            return mt.to_string();
        }
        if let Some(sv) = val.get("schemaVersion").and_then(|v| v.as_u64())
            && sv == 2
        {
            if val.get("manifests").is_some() {
                return "application/vnd.oci.image.index.v1+json".to_string();
            }
            return "application/vnd.oci.image.manifest.v1+json".to_string();
        }
    }
    "application/vnd.oci.image.manifest.v1+json".to_string()
}

// ── Internal Replication Handlers ─────────────────────────────────────────────

/// POST /internal/replicate/manifest - Receive a replicated manifest from another region.
async fn internal_replicate_manifest(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, RegistryError> {
    let tenant = extract_header(&headers, "x-replication-tenant")?;
    let project = extract_header(&headers, "x-replication-project")?;
    let repo = extract_header(&headers, "x-replication-repo")?;
    let reference = extract_header(&headers, "x-replication-reference")?;
    let digest = extract_header(&headers, "x-replication-digest")?;

    info!(
        tenant = %tenant,
        project = %project,
        repo = %repo,
        digest = %digest,
        "Receiving replicated manifest"
    );

    // Store manifest by digest
    let digest_path = manifest_path(&tenant, &project, &repo, &digest);
    let digest_store_path = StorePath::from(digest_path);
    state
        .store
        .put(&digest_store_path, body.clone().into())
        .await
        .map_err(|e| RegistryError::Storage(e.to_string()))?;

    // If reference is a tag, create tag link
    if !reference.starts_with("sha256:") {
        let tag_p = tag_link_path(&tenant, &project, &repo, &reference);
        let tag_store_path = StorePath::from(tag_p);
        state
            .store
            .put(&tag_store_path, Bytes::from(digest.clone()).into())
            .await
            .map_err(|e| RegistryError::Storage(e.to_string()))?;
    }

    Ok(StatusCode::OK.into_response())
}

/// POST /internal/replicate/blob - Receive a replicated blob from another region.
async fn internal_replicate_blob(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, RegistryError> {
    let tenant = extract_header(&headers, "x-replication-tenant")?;
    let project = extract_header(&headers, "x-replication-project")?;
    let repo = extract_header(&headers, "x-replication-repo")?;
    let digest = extract_header(&headers, "x-replication-digest")?;

    info!(
        tenant = %tenant,
        project = %project,
        repo = %repo,
        digest = %digest,
        "Receiving replicated blob"
    );

    let store_path = StorePath::from(blob_path(&tenant, &project, &repo, &digest));
    state
        .store
        .put(&store_path, body.into())
        .await
        .map_err(|e| RegistryError::Storage(e.to_string()))?;

    Ok(StatusCode::OK.into_response())
}

/// POST /internal/replicate/delete - Receive a replicated delete from another region.
async fn internal_replicate_delete(
    State(state): State<AppState>,
    body: Bytes,
) -> Result<Response, RegistryError> {
    let event: ReplicationEvent = serde_json::from_slice(&body)
        .map_err(|e| RegistryError::Internal(format!("invalid replication event: {e}")))?;

    info!(
        tenant = %event.tenant,
        repo = %event.repo,
        reference = %event.reference,
        "Receiving replicated delete"
    );

    let path = manifest_path(&event.tenant, &event.project, &event.repo, &event.digest);
    let store_path = StorePath::from(path);
    let _ = state.store.delete(&store_path).await;

    // Delete tag link if applicable
    if !event.reference.starts_with("sha256:") {
        let tag_p = tag_link_path(&event.tenant, &event.project, &event.repo, &event.reference);
        let tag_store_path = StorePath::from(tag_p);
        let _ = state.store.delete(&tag_store_path).await;
    }

    Ok(StatusCode::OK.into_response())
}

/// GET /internal/replication/status - Get replication and failover status.
async fn internal_replication_status(
    State(state): State<AppState>,
) -> Result<Response, RegistryError> {
    let mut status = serde_json::Map::new();

    if let Some(ref failover) = state.failover_manager {
        let health = failover.all_health().await;
        status.insert(
            "regions".to_string(),
            serde_json::to_value(&health).unwrap_or_default(),
        );
        status.insert(
            "is_primary".to_string(),
            serde_json::Value::Bool(failover.is_local_primary()),
        );
    }

    Ok((
        StatusCode::OK,
        axum::Json(serde_json::Value::Object(status)),
    )
        .into_response())
}

fn extract_header(headers: &HeaderMap, name: &str) -> Result<String, RegistryError> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| RegistryError::Internal(format!("missing header: {name}")))
}

// ── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load configuration from file if --config flag provided, otherwise defaults
    let config = {
        let args: Vec<String> = std::env::args().collect();
        let config_path = args
            .iter()
            .find_map(|a| a.strip_prefix("--config=").map(String::from))
            .or_else(|| {
                args.windows(2)
                    .find(|w| w[0] == "--config")
                    .map(|w| w[1].clone())
            });
        if let Some(path) = config_path {
            match std::fs::read_to_string(&path) {
                Ok(contents) => {
                    match serde_yaml::from_str::<RegistryConfig>(&contents) {
                        Ok(cfg) => {
                            eprintln!("Config loaded from {path}, multi_region: {}", cfg.multi_region.is_some());
                            cfg
                        }
                        Err(e) => {
                            eprintln!("Warning: failed to parse config {path}: {e}, using defaults");
                            RegistryConfig::default()
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Warning: failed to read config {path}: {e}, using defaults");
                    RegistryConfig::default()
                }
            }
        } else {
            RegistryConfig::default()
        }
    };

    // Initialize tracing
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&config.observability.log_level));

    match config.observability.log_format.as_str() {
        "json" => {
            tracing_subscriber::fmt()
                .json()
                .with_env_filter(env_filter)
                .with_target(true)
                .with_thread_ids(true)
                .init();
        }
        _ => {
            tracing_subscriber::fmt()
                .with_env_filter(env_filter)
                .with_target(true)
                .init();
        }
    }

    info!("NebulaCR Registry starting up");

    // Initialize Prometheus metrics recorder and obtain the handle for rendering
    let prom_handle = PrometheusBuilder::new()
        .install_recorder()
        .expect("failed to install Prometheus recorder");

    // Pre-register all metrics so they appear in /metrics from startup
    counter!("registry_manifest_push_total").increment(0);
    counter!("registry_manifest_pull_total").increment(0);
    counter!("registry_blob_pull_total").increment(0);
    counter!("registry_delete_total", "tenant" => "", "project" => "").increment(0);
    counter!("registry_push_bytes_total").increment(0);
    counter!("registry_pull_bytes_total").increment(0);
    counter!("registry_errors_total", "type" => "storage").increment(0);
    counter!("registry_errors_total", "type" => "auth").increment(0);
    counter!("registry_errors_total", "type" => "validation").increment(0);
    histogram!("registry_request_duration_seconds", "operation" => "manifest.pull").record(0.0);
    histogram!("registry_request_duration_seconds", "operation" => "manifest.push").record(0.0);
    histogram!("registry_request_duration_seconds", "operation" => "manifest.delete").record(0.0);
    histogram!("registry_request_duration_seconds", "operation" => "blob.pull").record(0.0);
    histogram!("registry_request_duration_seconds", "operation" => "blob.push").record(0.0);

    // Initialize object store based on configured backend
    let storage_backend = config.storage.backend.as_str();
    let storage_root = &config.storage.root;

    let raw_store: Arc<dyn ObjectStore> = match storage_backend {
        "filesystem" => {
            std::fs::create_dir_all(storage_root)?;
            info!(root = %storage_root, "Initializing filesystem storage backend");
            Arc::new(LocalFileSystem::new_with_prefix(storage_root)?)
        }
        "s3" | "minio" => {
            let mut builder = AmazonS3Builder::new().with_bucket_name(storage_root);

            if let Some(ref endpoint) = config.storage.endpoint {
                builder = builder.with_endpoint(endpoint);
                // MinIO and S3-compatible stores require virtual-hosted-style to be disabled
                builder = builder.with_virtual_hosted_style_request(false);
            }
            if let Some(ref region) = config.storage.region {
                builder = builder.with_region(region);
            }
            if let Some(ref access_key) = config.storage.access_key {
                builder = builder.with_access_key_id(access_key);
            }
            if let Some(ref secret_key) = config.storage.secret_key {
                builder = builder.with_secret_access_key(secret_key);
            }

            // MinIO requires path-style access and may use HTTP
            if storage_backend == "minio" {
                builder = builder.with_virtual_hosted_style_request(false);
                builder = builder.with_allow_http(true);
            }

            let store = builder.build()?;
            info!(
                bucket = %storage_root,
                endpoint = config.storage.endpoint.as_deref().unwrap_or("default"),
                backend = %storage_backend,
                "Initializing S3-compatible storage backend"
            );
            Arc::new(store)
        }
        "gcs" => {
            let builder = GoogleCloudStorageBuilder::new().with_bucket_name(storage_root);

            let store = builder.build()?;
            info!(bucket = %storage_root, "Initializing GCS storage backend");
            Arc::new(store)
        }
        "azure" => {
            let mut builder = MicrosoftAzureBuilder::new().with_container_name(storage_root);

            if let Some(ref access_key) = config.storage.access_key {
                builder = builder.with_account(access_key);
            }
            if let Some(ref secret_key) = config.storage.secret_key {
                builder = builder.with_access_key(secret_key);
            }

            let store = builder.build()?;
            info!(container = %storage_root, "Initializing Azure Blob storage backend");
            Arc::new(store)
        }
        other => {
            anyhow::bail!(
                "Unsupported storage backend: '{}'. Supported: filesystem, s3, minio, gcs, azure",
                other
            );
        }
    };

    // Wrap with resilience layer (circuit breaker + retry)
    let store: Arc<dyn ObjectStore> = if let Some(ref resilience_cfg) = config.resilience {
        info!("Initializing resilient storage wrapper (retry + circuit breaker)");
        Arc::new(ResilientObjectStore::new(
            raw_store,
            RetryPolicy {
                max_retries: resilience_cfg.retry.max_retries,
                base_delay_ms: resilience_cfg.retry.base_delay_ms,
                max_delay_ms: resilience_cfg.retry.max_delay_ms,
                jitter: resilience_cfg.retry.jitter,
            },
            CircuitBreakerConfig {
                failure_threshold: resilience_cfg.circuit_breaker.failure_threshold,
                success_threshold: resilience_cfg.circuit_breaker.success_threshold,
                open_duration_secs: resilience_cfg.circuit_breaker.open_duration_secs,
            },
        ))
    } else {
        raw_store
    };

    info!(backend = %storage_backend, root = %storage_root, "Storage backend initialized");

    // Load JWT verification key
    let verification_key_pem =
        std::fs::read(&config.auth.verification_key_path).unwrap_or_else(|e| {
            warn!(
                path = %config.auth.verification_key_path,
                error = %e,
                "Failed to load verification key, using empty key (auth will fail)"
            );
            Vec::new()
        });

    let decoding_key = if config.auth.signing_algorithm == "EdDSA" {
        DecodingKey::from_ed_pem(&verification_key_pem)
            .unwrap_or_else(|_| DecodingKey::from_secret(b""))
    } else {
        DecodingKey::from_rsa_pem(&verification_key_pem)
            .unwrap_or_else(|_| DecodingKey::from_secret(b""))
    };

    // Rate limiter: default tenant-keyed limiter
    let default_rps = std::num::NonZeroU32::new(config.rate_limit.default_rps)
        .unwrap_or(std::num::NonZeroU32::new(100).unwrap());
    let default_rate_limiter = Arc::new(RateLimiter::keyed(Quota::per_second(default_rps)));

    // Initialize mirror service (pull-through cache)
    let mirror_service = if let Some(ref mirror_cfg) = config.mirror {
        if mirror_cfg.enabled && !mirror_cfg.upstreams.is_empty() {
            info!(
                upstreams = mirror_cfg.upstreams.len(),
                "Initializing pull-through mirror service"
            );
            let svc_config = MirrorServiceConfig {
                enabled: mirror_cfg.enabled,
                upstreams: mirror_cfg
                    .upstreams
                    .iter()
                    .map(|u| UpstreamConfig {
                        name: u.name.clone(),
                        url: u.url.clone(),
                        username: u.username.clone(),
                        password: u.password.clone(),
                        cache_ttl_secs: u.cache_ttl_secs.unwrap_or(mirror_cfg.cache_ttl_secs),
                        tenant_prefix: u.tenant_prefix.clone(),
                    })
                    .collect(),
                cache_ttl_secs: mirror_cfg.cache_ttl_secs,
            };
            Some(Arc::new(MirrorService::new(&svc_config, store.clone())))
        } else {
            None
        }
    } else {
        None
    };

    // Initialize multi-region replication and failover
    let (replication_handle, failover_manager) = if let Some(ref mr_cfg) = config.multi_region {
        if !mr_cfg.regions.is_empty() {
            info!(
                local_region = %mr_cfg.local_region,
                regions = mr_cfg.regions.len(),
                "Initializing multi-region replication"
            );

            let repl_regions: Vec<ReplicationRegionConfig> = mr_cfg
                .regions
                .iter()
                .map(|r| ReplicationRegionConfig {
                    name: r.name.clone(),
                    endpoint: r.endpoint.clone(),
                    internal_endpoint: r.internal_endpoint.clone(),
                    is_primary: r.is_primary,
                    priority: r.priority,
                })
                .collect();

            let repl_mode = if mr_cfg.replication.mode == "semi_sync" {
                ReplicationMode::SemiSync
            } else {
                ReplicationMode::Async
            };

            let repl_config = ReplicationMultiRegionConfig {
                local_region: mr_cfg.local_region.clone(),
                regions: repl_regions.clone(),
                replication: ReplicationPolicy {
                    mode: repl_mode,
                    max_lag_secs: mr_cfg.replication.max_lag_secs,
                    batch_size: mr_cfg.replication.batch_size,
                    sweep_interval_secs: mr_cfg.replication.sweep_interval_secs,
                },
            };

            let replicator = Replicator::new(&repl_config, store.clone());
            let repl_handle = replicator.handle();

            // Start the background replication loop
            tokio::spawn(async move {
                replicator.run().await;
            });

            // Initialize failover manager
            let failover_regions = repl_regions;
            let failover = Arc::new(FailoverManager::new(
                mr_cfg.local_region.clone(),
                failover_regions,
                mr_cfg.health_check_interval_secs,
            ));

            // Start the background health check loop
            let failover_clone = failover.clone();
            tokio::spawn(async move {
                failover_clone.run().await;
            });

            (Some(repl_handle), Some(failover))
        } else {
            (None, None)
        }
    } else {
        (None, None)
    };

    // Initialize webhook notifier (optional)
    let webhook_handle = if let Some(ref wh_cfg) = config.webhooks {
        if wh_cfg.enabled && !wh_cfg.endpoints.is_empty() {
            info!(
                endpoints = wh_cfg.endpoints.len(),
                "Initializing webhook notifier"
            );
            let (notifier, handle) = webhook::WebhookNotifier::new(wh_cfg.clone());
            tokio::spawn(notifier.run());
            Some(handle)
        } else {
            None
        }
    } else {
        None
    };

    let listen_addr = config.server.listen_addr.clone();
    let internal_port = config
        .multi_region
        .as_ref()
        .map(|mr| mr.internal_port)
        .unwrap_or(5002);

    let audit_log = Arc::new(audit::RegistryAuditLog::new());
    let start_time = Instant::now();

    let state = AppState {
        store,
        config: Arc::new(config),
        decoding_key: Arc::new(decoding_key),
        prom_handle: prom_handle.clone(),
        rate_limiters: Arc::new(RwLock::new(HashMap::new())),
        default_rate_limiter,
        mirror_service,
        replication_handle,
        failover_manager: failover_manager.clone(),
        webhook_handle,
        audit_log: audit_log.clone(),
        start_time,
    };

    // Dashboard state (shared with dashboard handlers)
    let dashboard_state = dashboard::DashboardState {
        audit_log: audit_log.clone(),
        start_time,
        failover_manager,
    };

    // Build the router
    // Public routes (no auth required)
    let public_routes = Router::new()
        .route("/v2/", get(v2_check))
        .route("/health", get(health_check))
        .route("/metrics", get(metrics_handler));

    // Dashboard and API routes (no auth - internal use)
    let dashboard_routes = Router::new()
        .route("/dashboard", get(dashboard::dashboard_html))
        .route("/api/stats", get(dashboard::api_stats))
        .route("/api/activity", get(dashboard::api_activity))
        .route("/api/audit", get(dashboard::api_audit))
        .route("/api/system", get(dashboard::api_system))
        .route("/api/ha-status", get(dashboard::api_ha_status))
        .with_state(dashboard_state);

    // Authenticated registry routes
    let registry_routes = Router::new()
        // Manifest operations
        .route(
            "/v2/{tenant}/{project}/{name}/manifests/{reference}",
            head(head_manifest)
                .get(get_manifest)
                .put(put_manifest)
                .delete(delete_manifest),
        )
        // Blob operations
        .route(
            "/v2/{tenant}/{project}/{name}/blobs/{digest}",
            head(head_blob).get(get_blob),
        )
        // Upload operations
        .route(
            "/v2/{tenant}/{project}/{name}/blobs/uploads/",
            post(initiate_blob_upload),
        )
        .route(
            "/v2/{tenant}/{project}/{name}/blobs/uploads/{uuid}",
            patch(upload_blob_chunk).put(complete_blob_upload),
        )
        // Tag listing
        .route("/v2/{tenant}/{project}/{name}/tags/list", get(list_tags))
        // Catalog
        .route("/v2/_catalog", get(catalog));

    let app = Router::new()
        .merge(public_routes)
        .merge(dashboard_routes)
        .merge(registry_routes)
        .layer(middleware::from_fn(request_id_middleware))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(state.clone());

    // Internal replication API (separate listener for security)
    let internal_routes = Router::new()
        .route(
            "/internal/replicate/manifest",
            post(internal_replicate_manifest),
        )
        .route("/internal/replicate/blob", post(internal_replicate_blob))
        .route(
            "/internal/replicate/delete",
            post(internal_replicate_delete),
        )
        .route(
            "/internal/replication/status",
            get(internal_replication_status),
        )
        .with_state(state);

    let internal_addr = format!("0.0.0.0:{internal_port}");

    // Start the internal replication listener in the background
    let internal_listener = tokio::net::TcpListener::bind(&internal_addr).await?;
    info!(addr = %internal_addr, "Internal replication API listening");
    tokio::spawn(async move {
        if let Err(e) = axum::serve(internal_listener, internal_routes).await {
            error!(error = %e, "Internal replication API error");
        }
    });

    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    info!(addr = %listen_addr, "NebulaCR Registry listening");

    axum::serve(listener, app).await?;

    Ok(())
}
