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
    extract::{DefaultBodyLimit, FromRequestParts, Path, Query, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header, request::Parts},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, head, patch, post},
};
use base64::Engine as _;
use bytes::Bytes;
use futures::TryStreamExt;
use governor::{Quota, RateLimiter, clock::DefaultClock, state::keyed::DefaultKeyedStateStore};
use jsonwebtoken::{DecodingKey, TokenData, Validation};
use metrics::{counter, gauge, histogram};
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
use nebula_common::models::{Action, Role};
use nebula_common::storage::{
    blob_path, manifest_path, sha256_digest, tag_link_path, tags_prefix, upload_path,
};

use nebula_mirror::service::MirrorConfig as MirrorServiceConfig;
use nebula_mirror::upstream::UpstreamConfig;
use nebula_mirror::{MirrorScope, MirrorService};
use nebula_replication::event::ReplicationEvent;
use nebula_replication::failover::FailoverManager;
use nebula_replication::region::{
    MultiRegionConfig as ReplicationMultiRegionConfig, RegionConfig as ReplicationRegionConfig,
    ReplicationMode, ReplicationPolicy,
};
use nebula_replication::replicator::{ReplicationHandle, Replicator};
use nebula_resilience::{CircuitBreakerConfig, ResilientObjectStore, RetryPolicy};
use nebula_scanner::{
    ScannerRuntime, config::ScannerConfig, model::ScanJob, queue::Queue as ScanQueue,
};

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
    /// Scanner job queue (optional). When present, successful manifest
    /// pushes enqueue a background scan job. The concrete impl is either
    /// in-process (`TokioQueue`) or durable (`PostgresQueue`) depending on
    /// `NEBULACR_SCANNER__QUEUE_BACKEND`.
    scanner_queue: Option<Arc<dyn ScanQueue>>,
    /// Online-GC refcount writer. Always present; defaults to a
    /// no-op when `[gc.online]` / `NEBULACR_GC__ONLINE` is disabled.
    /// Bumped on manifest push, decremented on manifest delete.
    gc_refcounter: Arc<dyn nebula_gc::BlobRefCounter>,
    /// Control handle for the continuous reaper. `None` when GC is
    /// disabled or the reaper task isn't running.
    gc_reaper_control: Option<Arc<nebula_gc::ReaperControl>>,
    /// Postgres pool used by GC's reconciler endpoint. `None` when GC
    /// is disabled.
    gc_pool: Option<sqlx::PgPool>,
    /// TTL reaper handle (013 slice 2). `None` when ephemeral / TTL is
    /// disabled. Lets admin endpoints flip pause/resume.
    ttl_reaper_control: Option<Arc<nebula_ephemeral::TtlReaperControl>>,
    /// Usage / cost telemetry recorder. Always present; defaults to a
    /// no-op when `[usage]` / `NEBULACR_USAGE__ENABLED` is disabled.
    /// Called from blob/manifest hot paths to seed the rollup pipeline.
    usage_recorder: Arc<dyn nebula_cost::UsageRecorder>,
    /// Typed-artifact validator registry. `None` when 016 is disabled
    /// (the default); when populated, every put_manifest dispatches to
    /// the matching ArtifactType impl and persists metadata.
    artifact_registry: Option<Arc<nebula_artifact_types::ArtifactRegistry>>,
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
            .ok_or_else(|| {
                debug!("Request missing Authorization header");
                RegistryError::Unauthorized
            })?;

        let token = auth_header.strip_prefix("Bearer ").ok_or_else(|| {
            debug!("Authorization header is not Bearer token");
            RegistryError::Unauthorized
        })?;

        let algorithm = if app_state.config.auth.signing_algorithm == "EdDSA" {
            jsonwebtoken::Algorithm::EdDSA
        } else {
            jsonwebtoken::Algorithm::RS256
        };
        let mut validation = Validation::new(algorithm);
        validation.set_audience(&[&app_state.config.auth.audience]);
        validation.set_issuer(&[&app_state.config.auth.issuer]);
        validation.validate_exp = true;

        let token_data: TokenData<TokenClaims> =
            jsonwebtoken::decode(token, &app_state.decoding_key, &validation).map_err(|e| {
                let uri = parts.uri.to_string();
                match e.kind() {
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                        debug!(uri = %uri, "Token expired");
                        RegistryError::TokenExpired
                    }
                    _ => {
                        warn!(uri = %uri, error = %e, "JWT validation failed");
                        RegistryError::TokenInvalid {
                            reason: e.to_string(),
                        }
                    }
                }
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

    // Admin role bypasses scope checks
    if claims.role == Role::Admin {
        return Ok(());
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

// ── Dashboard Auth Middleware ────────────────────────────────────────────────

/// Basic auth middleware for dashboard and API routes.
async fn dashboard_auth_middleware(
    State(config): State<Arc<nebula_common::config::DashboardAuthConfig>>,
    request: Request,
    next: Next,
) -> Response {
    if !config.enabled {
        return next.run(request).await;
    }

    // Extract Basic auth credentials
    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic "));

    let authenticated = if let Some(encoded) = auth_header {
        if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded.trim()) {
            if let Ok(cred_str) = String::from_utf8(decoded) {
                if let Some((user, pass)) = cred_str.split_once(':') {
                    let pass_hash = {
                        use sha2::{Digest, Sha256};
                        hex::encode(Sha256::digest(pass.as_bytes()))
                    };
                    user == config.username
                        && constant_time_compare(
                            pass_hash.as_bytes(),
                            config.password_hash.as_bytes(),
                        )
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        }
    } else {
        false
    };

    if authenticated {
        next.run(request).await
    } else {
        let realm = format!("Basic realm=\"{}\"", config.realm);
        let mut response = (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
        if let Ok(val) = HeaderValue::from_str(&realm) {
            response.headers_mut().insert("www-authenticate", val);
        }
        response
    }
}

/// Constant-time byte comparison to avoid timing attacks.
fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ── Request ID Middleware ────────────────────────────────────────────────────

async fn request_id_middleware(mut request: Request, next: Next) -> Response {
    let request_id = Uuid::new_v4().to_string();
    if let Ok(val) = HeaderValue::from_str(&request_id) {
        request.headers_mut().insert("x-request-id", val);
    }

    // Capture the Host header and scheme for dynamic Www-Authenticate realm
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost:5000")
        .to_string();
    let scheme = request
        .headers()
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("https")
        .to_string();

    let mut response = next.run(request).await;
    if let Ok(val) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("x-request-id", val);
    }

    // Override Www-Authenticate realm to use the request's own host/scheme.
    // The registry proxies /auth/token to the auth service, so Docker always
    // follows the realm back to the same host it connected to.
    // Skip if the response already has a Basic auth challenge (e.g., dashboard auth).
    if response.status() == StatusCode::UNAUTHORIZED {
        let existing_auth = response
            .headers()
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !existing_auth.starts_with("Basic ") {
            let service_name = std::env::var("NEBULACR_AUTH_SERVICE")
                .unwrap_or_else(|_| "nebulacr-registry".to_string());
            let realm = if let Ok(ext_url) = std::env::var("NEBULACR_EXTERNAL_URL") {
                format!("{}/auth/token", ext_url.trim_end_matches('/'))
            } else {
                format!("{scheme}://{host}/auth/token")
            };
            let header_val = format!("Bearer realm=\"{realm}\",service=\"{service_name}\"");
            if let Ok(val) = HeaderValue::from_str(&header_val) {
                response.headers_mut().insert("www-authenticate", val);
            }
        }
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
        counter!("nebulacr_rate_limit_rejected_total", "tenant" => key.clone()).increment(1);
        return Err(RegistryError::RateLimitExceeded);
    }

    Ok(next.run(request).await)
}

// ── HTTP Metrics Middleware ──────────────────────────────────────────────────

/// Map a raw URL path onto a low-cardinality route label so dashboards
/// don't blow up. Anything inside `/v2/.../{thing}/...` collapses to a
/// stable family identifier.
fn classify_route(path: &str, method: &str) -> &'static str {
    if path == "/v2/" {
        return "v2_check";
    }
    if path == "/v2/_catalog" {
        return "catalog";
    }
    if path == "/health" {
        return "health";
    }
    if path == "/metrics" {
        return "metrics";
    }
    if path.starts_with("/auth/token") {
        return "auth_token_proxy";
    }
    if path.starts_with("/internal/replicate/manifest") {
        return "internal_replicate_manifest";
    }
    if path.starts_with("/internal/replicate/blob") {
        return "internal_replicate_blob";
    }
    if path.starts_with("/internal/replicate/delete") {
        return "internal_replicate_delete";
    }
    if path.starts_with("/internal/replication/status") {
        return "internal_replication_status";
    }
    if path.starts_with("/dashboard") {
        return "dashboard";
    }
    if path.starts_with("/api/") {
        return "dashboard_api";
    }
    if path.starts_with("/v2/") {
        if path.contains("/manifests/") {
            return match method {
                "GET" => "manifest_get",
                "HEAD" => "manifest_head",
                "PUT" => "manifest_put",
                "DELETE" => "manifest_delete",
                _ => "manifest_other",
            };
        }
        if path.contains("/blobs/uploads") {
            return match method {
                "POST" => "blob_upload_initiate",
                "PATCH" => "blob_upload_chunk",
                "PUT" => "blob_upload_complete",
                _ => "blob_upload_other",
            };
        }
        if path.contains("/blobs/") {
            return match method {
                "GET" => "blob_get",
                "HEAD" => "blob_head",
                _ => "blob_other",
            };
        }
        if path.contains("/tags/list") {
            return "tags_list";
        }
        if path.contains("/status/") {
            return "image_status";
        }
        return "v2_other";
    }
    "other"
}

/// Status class — `2xx`, `3xx`, ... — used as a low-cardinality label.
fn status_class(status: u16) -> &'static str {
    match status / 100 {
        1 => "1xx",
        2 => "2xx",
        3 => "3xx",
        4 => "4xx",
        5 => "5xx",
        _ => "other",
    }
}

async fn http_metrics_middleware(request: Request, next: Next) -> Response {
    let started = Instant::now();
    let method_owned = request.method().as_str().to_string();
    let route = classify_route(request.uri().path(), &method_owned);

    gauge!("nebulacr_http_requests_in_flight", "route" => route).increment(1.0);

    let response = next.run(request).await;

    let elapsed = started.elapsed().as_secs_f64();
    let status = response.status().as_u16();
    let class = status_class(status);

    gauge!("nebulacr_http_requests_in_flight", "route" => route).decrement(1.0);
    counter!("nebulacr_http_requests_total",
        "route" => route, "method" => method_owned.clone(), "status_class" => class)
    .increment(1);
    histogram!("nebulacr_http_request_duration_seconds",
        "route" => route, "method" => method_owned)
    .record(elapsed);

    response
}

// ── Storage error classification ────────────────────────────────────────────

/// True when an object-store error means "the object is not present,"
/// as opposed to a real IO/backend failure. This matters because the
/// `get_blob`/`get_manifest` miss paths must only fall through to the
/// mirror or return 404 when the object is truly absent — real IO
/// failures must still surface as 5xx (R4).
fn is_store_not_found(err: &object_store::Error) -> bool {
    matches!(err, object_store::Error::NotFound { .. })
}

/// Translate the common-config `MirrorScopeConfig` (string-tagged,
/// forward-compatible) into the strongly-typed `MirrorScope` the
/// mirror service consumes. Unknown or missing modes fall back to
/// `DefaultTenantOnly`, which is the safe default that keeps private
/// projects out of the upstream path.
fn mirror_scope_from_config(cfg: Option<&nebula_common::config::MirrorScopeConfig>) -> MirrorScope {
    let Some(cfg) = cfg else {
        return MirrorScope::default();
    };
    let default_tenant = cfg
        .default_tenant
        .clone()
        .unwrap_or_else(|| "_".to_string());
    match cfg.mode.as_deref() {
        Some("all") => MirrorScope::All,
        Some("allowlist") => MirrorScope::Allowlist {
            tenants: cfg.tenants.clone(),
            projects: cfg.projects.clone(),
        },
        Some("denylist") => MirrorScope::Denylist {
            tenants: cfg.tenants.clone(),
            projects: cfg.projects.clone(),
        },
        Some("manifest_linked") | Some("manifest-linked") => MirrorScope::ManifestLinked,
        Some("default_tenant_only") | Some("default-tenant-only") | None => {
            MirrorScope::DefaultTenantOnly { default_tenant }
        }
        Some(other) => {
            warn!(
                mode = %other,
                "Unknown mirror.scope.mode, falling back to default_tenant_only"
            );
            MirrorScope::DefaultTenantOnly { default_tenant }
        }
    }
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

/// Default tenant used for 2-segment Docker image paths (namespace/repo).
const DEFAULT_TENANT: &str = "_";

#[derive(Debug, serde::Deserialize)]
struct RepoPath2 {
    project: String,
    name: String,
}

#[derive(Debug, serde::Deserialize)]
struct ManifestRef2 {
    project: String,
    name: String,
    reference: String,
}

#[derive(Debug, serde::Deserialize)]
struct BlobRef2 {
    project: String,
    name: String,
    digest: String,
}

#[derive(Debug, serde::Deserialize)]
struct UploadRef2 {
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

/// GET /v2/ - API version check.
///
/// Per the OCI Distribution spec, this endpoint must return 401 Unauthorized
/// with a `Www-Authenticate` challenge when the client has no credentials, so
/// that clients like `docker` and `skopeo` know to fetch a bearer token before
/// attempting push/pull. The request-id middleware rewrites the realm to the
/// request's own host. Authenticated requests (any Authorization header) get 200.
#[instrument(name = "v2_check", skip(headers))]
async fn v2_check(headers: HeaderMap) -> Response {
    if headers.get(header::AUTHORIZATION).is_some() {
        return (
            StatusCode::OK,
            [("Docker-Distribution-API-Version", "registry/2.0")],
            "{}",
        )
            .into_response();
    }
    (
        StatusCode::UNAUTHORIZED,
        [("Docker-Distribution-API-Version", "registry/2.0")],
        "{\"errors\":[{\"code\":\"UNAUTHORIZED\",\"message\":\"authentication required\"}]}",
    )
        .into_response()
}

/// GET/POST /auth/token — Proxy to the auth service.
/// When the registry is accessed directly (not via ingress), Docker follows the
/// Www-Authenticate realm to the registry's own URL. This handler proxies the
/// token request to the auth service so Docker can obtain tokens without needing
/// to know the auth service's internal address.
async fn proxy_auth_token(
    State(_state): State<AppState>,
    req: Request,
) -> Result<Response, RegistryError> {
    let auth_url = std::env::var("NEBULACR_AUTH_SERVICE_URL")
        .unwrap_or_else(|_| "http://nebulacr-auth:5001".to_string());
    let uri = req.uri();
    let query = uri.query().map(|q| format!("?{q}")).unwrap_or_default();
    let target = format!("{auth_url}/auth/token{query}");

    let client = reqwest::Client::new();
    let mut proxy_req = client.request(req.method().clone(), &target);

    // Forward auth headers (Basic auth from Docker)
    if let Some(auth) = req.headers().get(header::AUTHORIZATION) {
        proxy_req = proxy_req.header("Authorization", auth.to_str().unwrap_or(""));
    }
    if let Some(ct) = req.headers().get(header::CONTENT_TYPE) {
        proxy_req = proxy_req.header("Content-Type", ct.to_str().unwrap_or(""));
    }

    // Forward body for POST requests
    let body_bytes = axum::body::to_bytes(req.into_body(), 1024 * 64)
        .await
        .unwrap_or_default();
    if !body_bytes.is_empty() {
        proxy_req = proxy_req.body(body_bytes.to_vec());
    }

    let resp = proxy_req.send().await.map_err(|e| {
        error!(target = %target, error = %e, "Failed to proxy auth token request");
        RegistryError::Internal(format!("auth proxy error: {e}"))
    })?;

    let status =
        StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let headers = resp.headers().clone();
    let body = resp.bytes().await.unwrap_or_default();

    let mut response = (status, body).into_response();
    // Copy relevant headers from auth response
    for (name, value) in headers.iter() {
        if name == "content-type" || name == "cache-control" {
            response.headers_mut().insert(name, value.clone());
        }
    }
    Ok(response)
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

    // HEAD only checks local storage — no mirror fallback.
    // Docker will follow up with GET on miss, which has mirror fallback.
    let path = resolve_manifest_path(
        &state,
        &params.tenant,
        &params.project,
        &params.name,
        &params.reference,
    )
    .await?;
    let store_path = StorePath::from(path);

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
        HeaderValue::from_str(&data.len().to_string()).unwrap(),
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

    // Try local storage first, then upstream mirror, then failover
    let data = match resolve_manifest_path(
        &state,
        &params.tenant,
        &params.project,
        &params.name,
        &params.reference,
    )
    .await
    {
        Ok(path) => {
            let store_path = StorePath::from(path);
            state
                .store
                .get(&store_path)
                .await
                .map_err(|e| RegistryError::Storage(e.to_string()))?
                .bytes()
                .await
                .map_err(|e| RegistryError::Storage(e.to_string()))?
        }
        Err(_) => {
            // Local miss — try pull-through mirror (upstream registries)
            if let Some(ref mirror) = state.mirror_service {
                info!(
                    tenant = %params.tenant,
                    project = %params.project,
                    name = %params.name,
                    reference = %params.reference,
                    "Local manifest miss, trying upstream mirror"
                );
                match mirror
                    .fetch_manifest(
                        &params.tenant,
                        &params.project,
                        &params.name,
                        &params.reference,
                    )
                    .await
                {
                    Ok(result) => result.data,
                    Err(e) if e.is_not_found_equivalent() => {
                        return Err(RegistryError::ManifestUnknown {
                            reference: params.reference.clone(),
                        });
                    }
                    Err(e) => {
                        return Err(RegistryError::UpstreamError(e.to_string()));
                    }
                }
            } else if let Some(ref failover) = state.failover_manager {
                // Try reading from another region
                info!(
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

    record_usage(
        &state,
        &params.tenant,
        &params.project,
        &params.name,
        nebula_cost::UsageOp::ManifestGet,
        data.len() as i64,
        nebula_cost::UsageSrc::Origin,
        200,
        Some(claims.sub.clone()),
    );

    Ok((StatusCode::OK, headers, data).into_response())
}

/// PUT /v2/{tenant}/{project}/{name}/manifests/{reference}
#[instrument(name = "put_manifest", skip(state, claims, req_headers, body), fields(tenant = %params.tenant, project = %params.project, name = %params.name, reference = %params.reference))]
async fn put_manifest(
    State(state): State<AppState>,
    AuthenticatedClaims(claims): AuthenticatedClaims,
    Path(params): Path<ManifestRef>,
    req_headers: HeaderMap,
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
    let mut response_headers_extra: Vec<(String, String)> = Vec::new();
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

        // 013 TTL header — record an `expires_at` on the tag row
        // when X-NebulaCR-TTL is set. Mirrors the design's project-
        // default-TTL story: header wins; fallback comes from the
        // ephemeral_repos table (slice 2 will read it). Failures
        // never fail the push — TTL is a soft contract.
        let ttl_header = req_headers
            .get("x-nebulacr-ttl")
            .and_then(|v| v.to_str().ok());
        if let (Some(raw), Some(pool)) = (ttl_header, state.gc_pool.as_ref()) {
            let now = chrono::Utc::now();
            match nebula_ephemeral::parse_ttl_header(now, raw) {
                Ok(spec) => {
                    let expires_at = spec.expires_at;
                    let r = sqlx::query(
                        "INSERT INTO tags
                             (tenant, project, repository, tag, digest,
                              pushed_by, expires_at, ephemeral)
                         VALUES ($1, $2, $3, $4, $5, $6, $7, FALSE)
                         ON CONFLICT (tenant, project, repository, tag)
                         DO UPDATE SET digest = EXCLUDED.digest,
                                       pushed_at = NOW(),
                                       expires_at = EXCLUDED.expires_at",
                    )
                    .bind(&params.tenant)
                    .bind(&params.project)
                    .bind(&params.name)
                    .bind(&params.reference)
                    .bind(&digest)
                    .bind(&claims.sub)
                    .bind(expires_at)
                    .execute(pool)
                    .await;
                    if let Err(e) = r {
                        warn!(error = %e, tag = %params.reference, "ttl tag upsert failed");
                    } else {
                        response_headers_extra
                            .push(("X-NebulaCR-TTL-Expires-At".into(), expires_at.to_rfc3339()));
                    }
                }
                Err(e) => {
                    warn!(error = %e, raw = %raw, "ignoring invalid X-NebulaCR-TTL");
                }
            }
        }
    }

    // Online-GC refcount bookkeeping (009). When the refcounter is the
    // no-op impl the cost is a vtable call and an empty Vec build —
    // negligible. When it is the Postgres impl this is one round-trip
    // worth of UPSERTs; failures are logged but do NOT fail the push,
    // because the reconciler (slice 3) corrects drift.
    let parsed_config_digest = nebula_gc::extract_config_digest(&body);
    match nebula_gc::extract_blob_digests(&body) {
        Ok(blobs) => {
            if let Err(e) = state
                .gc_refcounter
                .add_refs(
                    &params.tenant,
                    &params.project,
                    &params.name,
                    &digest,
                    &blobs,
                )
                .await
            {
                warn!(error = %e, digest = %digest, "gc refcount add_refs failed");
            }
        }
        Err(e) => {
            // The manifest was already JSON-validated above; this branch
            // is only hit if extraction encounters an unexpected shape.
            debug!(error = %e, digest = %digest, "gc refcount skipped: manifest parse");
        }
    }

    // 016 typed-artifact validation — when the registry recognises
    // the manifest's media type as Helm/WASM/model/etc., run the
    // matching validator and persist metadata into artifact_meta.
    // Failures are logged but do NOT fail the push (slice 1 is
    // advisory; strict-mode rejection lands in slice 2 with project
    // policy plumbing).
    if let (Some(reg), Some(pool)) = (state.artifact_registry.clone(), state.gc_pool.clone()) {
        let media_type = detect_manifest_media_type(&body);
        let body_clone = body.clone();
        let digest_clone = digest.clone();
        tokio::spawn(async move {
            match reg.validate(&media_type, &body_clone).await {
                Ok(Some(meta)) => {
                    let store = nebula_artifact_types::PgArtifactStore::new(pool);
                    use nebula_artifact_types::ArtifactStore as _;
                    if let Err(e) = store.upsert(&digest_clone, &meta, None).await {
                        warn!(error = %e, digest = %digest_clone, "artifact_meta upsert failed");
                    }
                }
                Ok(None) => {
                    debug!(digest = %digest_clone, "no artifact validator matched");
                }
                Err(e) => {
                    debug!(error = %e, digest = %digest_clone, "artifact validator rejected");
                    // Slice 1: advisory only. Slice 2 will persist the
                    // failure with validation_msg and (if strict
                    // mode is on) reject the push.
                }
            }
        });
    }

    // 018 lineage capture — fetch the image config blob async and
    // record any base-image hint into image_lineage. Fire-and-forget;
    // failures are logged but never fail the push.
    if let (Some(config_digest), Some(pool)) = (parsed_config_digest, state.gc_pool.clone()) {
        let store = state.store.clone();
        let tenant = params.tenant.clone();
        let project = params.project.clone();
        let repo = params.name.clone();
        let child_digest = digest.clone();
        tokio::spawn(async move {
            let cfg_path = blob_path(&tenant, &project, &repo, &config_digest);
            let cfg_store = StorePath::from(cfg_path);
            let cfg_bytes = match store.get(&cfg_store).await {
                Ok(g) => match g.bytes().await {
                    Ok(b) => b,
                    Err(e) => {
                        debug!(error = %e, "lineage: image config read failed");
                        return;
                    }
                },
                Err(e) => {
                    // Some manifests reference configs in other repos
                    // (e.g. multi-arch indexes) — that's expected; skip.
                    debug!(error = %e, "lineage: image config not local");
                    return;
                }
            };
            let Some(hint) = nebula_rebuild::detect_lineage(&cfg_bytes) else {
                return;
            };
            let r = sqlx::query(
                "INSERT INTO image_lineage
                     (child_digest, parent_digest, confidence)
                 VALUES ($1, $2, $3)
                 ON CONFLICT (child_digest, parent_digest) DO NOTHING",
            )
            .bind(&child_digest)
            .bind(&hint.base_ref)
            .bind(hint.confidence.as_str())
            .execute(&pool)
            .await;
            match r {
                Ok(_) => debug!(
                    base = %hint.base_ref,
                    confidence = %hint.confidence.as_str(),
                    "lineage recorded"
                ),
                Err(e) => warn!(error = %e, "image_lineage insert failed"),
            }
        });
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

    // Enqueue a background vulnerability scan (fire-and-forget). The
    // enqueue call is spawned so an INSERT-backed queue (PostgresQueue)
    // never blocks the push path; scans are best-effort and can be
    // re-triggered via POST /v2/scan.
    //
    // Note on dedup: digest dedup is handled in the scanner worker, not
    // here. The worker re-emits cached findings under each push's identity
    // so every (tenant, project, repo, reference) gets its own row in
    // the `scans` audit table — preserving "every push got scanned"
    // semantics — while the heavy SBOM/vuln pipeline only runs once per
    // unique manifest digest.
    if let Some(ref q) = state.scanner_queue {
        let job = ScanJob {
            id: Uuid::new_v4(),
            digest: digest.clone(),
            tenant: params.tenant.clone(),
            project: params.project.clone(),
            repository: params.name.clone(),
            reference: params.reference.clone(),
            enqueued_at: chrono::Utc::now(),
        };
        let q = q.clone();
        let digest_copy = digest.clone();
        tokio::spawn(async move {
            match q.enqueue(job).await {
                Ok(()) => debug!(digest = %digest_copy, "scan job enqueued"),
                Err(e) => warn!(digest = %digest_copy, error = %e, "scan enqueue failed"),
            }
        });
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
    for (name, value) in &response_headers_extra {
        if let (Ok(hn), Ok(hv)) = (
            axum::http::HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            headers.insert(hn, hv);
        }
    }

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

    record_usage(
        &state,
        &params.tenant,
        &params.project,
        &params.name,
        nebula_cost::UsageOp::ManifestPut,
        body.len() as i64,
        nebula_cost::UsageSrc::Origin,
        201,
        Some(claims.sub.clone()),
    );

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
    // Pull the manifest digest out of the resolved storage path so the
    // GC refcount decrement (below) sees the same digest the writer
    // recorded under `add_refs`. Layout from `manifest_path()` is
    // `<tenant>/<project>/<repo>/manifests/<sha256:hex>`.
    let manifest_digest = path
        .rsplit_once('/')
        .map(|(_, last)| last.to_string())
        .unwrap_or_else(|| params.reference.clone());
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

    // Online-GC refcount decrement (009). Failures don't fail the
    // delete — drift is corrected by the reconciler in slice 3.
    if let Err(e) = state
        .gc_refcounter
        .remove_refs(&params.tenant, &manifest_digest)
        .await
    {
        warn!(error = %e, digest = %manifest_digest, "gc refcount remove_refs failed");
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

    record_usage(
        &state,
        &params.tenant,
        &params.project,
        &params.name,
        nebula_cost::UsageOp::Delete,
        0,
        nebula_cost::UsageSrc::Origin,
        202,
        Some(claims.sub.clone()),
    );

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

    // HEAD only checks local storage — no mirror fallback.
    // Docker will follow up with GET on miss, which has mirror fallback.
    let meta = state
        .store
        .head(&store_path)
        .await
        .map_err(|_| RegistryError::BlobUnknown {
            digest: params.digest.clone(),
        })?;
    let size = meta.size;

    let mut headers = HeaderMap::new();
    headers.insert(
        "Docker-Content-Digest",
        HeaderValue::from_str(&params.digest).unwrap(),
    );
    headers.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&size.to_string()).unwrap(),
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
        Err(store_err) => {
            // Distinguish a true "blob not present" from a genuine
            // backend failure. Only the former should fall through to
            // the mirror path or return 404; a real IO error must
            // still surface as 5xx (R4).
            if !is_store_not_found(&store_err) {
                return Err(RegistryError::Storage(store_err.to_string()));
            }

            if let Some(ref mirror) = state.mirror_service {
                // R3: scope check happens inside fetch_blob, which
                // returns MirrorError::NotInScope for private projects
                // without ever touching an upstream client.
                debug!(
                    tenant = %params.tenant,
                    digest = %params.digest,
                    "Local blob miss, trying upstream mirror"
                );
                match mirror
                    .fetch_blob(
                        &params.tenant,
                        &params.project,
                        &params.name,
                        &params.digest,
                    )
                    .await
                {
                    Ok(result) => result.data,
                    Err(e) if e.is_not_found_equivalent() => {
                        // R1/R2: domain answer is "not found," regardless
                        // of whether the mirror layer said so with a clean
                        // 404, a breaker trip, or an upstream 5xx.
                        return Err(RegistryError::BlobUnknown {
                            digest: params.digest.clone(),
                        });
                    }
                    Err(e) => {
                        // R4: genuine infrastructure failure (e.g. auth
                        // config broken). Keep the 5xx path.
                        return Err(RegistryError::UpstreamError(e.to_string()));
                    }
                }
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

    record_usage(
        &state,
        &params.tenant,
        &params.project,
        &params.name,
        nebula_cost::UsageOp::Pull,
        data.len() as i64,
        nebula_cost::UsageSrc::Origin,
        200,
        Some(claims.sub.clone()),
    );

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

    record_usage(
        &state,
        &params.tenant,
        &params.project,
        &params.name,
        nebula_cost::UsageOp::Push,
        final_data_len as i64,
        nebula_cost::UsageSrc::Origin,
        201,
        Some(claims.sub.clone()),
    );

    // 010 lazy-pull: enqueue an indexer job for this blob. The
    // worker (when present) will rewrite/extract a TOC and register
    // it as a referrer of the layer. Fire-and-forget; missing GC
    // pool or disabled feature both fall through silently.
    let lazy_enabled = std::env::var("NEBULACR_LAZY__ENABLED")
        .map(|v| matches!(v.as_str(), "true" | "1" | "yes"))
        .unwrap_or(false);
    if let Some(pool) = state.gc_pool.clone().filter(|_| lazy_enabled) {
        let format = std::env::var("NEBULACR_LAZY__FORMAT").unwrap_or_else(|_| "estargz".into());
        let layer_digest = expected_digest.clone();
        let tenant = params.tenant.clone();
        let project = params.project.clone();
        let repo = params.name.clone();
        tokio::spawn(async move {
            use nebula_lazy::LazyJobStore as _;
            let store = nebula_lazy::PgLazyJobStore::new(pool);
            if let Err(e) = store
                .enqueue(
                    &layer_digest,
                    &format,
                    Some(&tenant),
                    Some(&project),
                    Some(&repo),
                )
                .await
            {
                debug!(error = %e, %layer_digest, "lazy enqueue failed");
            }
        });
    }

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

// ── Usage telemetry helper (017 integration) ───────────────────────────────
//
// Fire-and-forget — the recorder writes to the unlogged staging table so
// failures shouldn't fail the request, but the spawned task also keeps the
// hot path entirely off the Postgres latency.
#[allow(clippy::too_many_arguments)]
fn record_usage(
    state: &AppState,
    tenant: &str,
    project: &str,
    repository: &str,
    op: nebula_cost::UsageOp,
    bytes: i64,
    src: nebula_cost::UsageSrc,
    status: i32,
    sub: Option<String>,
) {
    let recorder = state.usage_recorder.clone();
    let event = nebula_cost::UsageEvent {
        at: chrono::Utc::now(),
        tenant: tenant.to_string(),
        project: project.to_string(),
        repository: repository.to_string(),
        op,
        bytes,
        src,
        status,
        sub,
    };
    tokio::spawn(async move {
        if let Err(e) = recorder.record(&event).await {
            debug!(error = %e, "usage recorder failed");
        }
    });
}

// ── Online-GC routes (009 slice 2) ───────────────────────────────────────────

fn gc_admin_authorize(claims: &TokenClaims) -> Result<(), RegistryError> {
    if claims.role != Role::Admin {
        return Err(RegistryError::Forbidden {
            reason: "online-gc admin endpoints require Admin role".into(),
        });
    }
    Ok(())
}

/// GET /v2/_gc/status — current reaper state.
#[instrument(name = "gc_status", skip(state, claims))]
async fn gc_status(
    State(state): State<AppState>,
    AuthenticatedClaims(claims): AuthenticatedClaims,
) -> Result<Response, RegistryError> {
    gc_admin_authorize(&claims)?;
    let body = match &state.gc_reaper_control {
        Some(c) => serde_json::json!({
            "enabled": true,
            "paused": c.is_paused(),
            "stopped": c.is_stopped(),
        }),
        None => serde_json::json!({ "enabled": false }),
    };
    Ok((StatusCode::OK, axum::Json(body)).into_response())
}

/// POST /v2/_gc/pause — pause the continuous reaper. Idempotent.
#[instrument(name = "gc_pause", skip(state, claims))]
async fn gc_pause(
    State(state): State<AppState>,
    AuthenticatedClaims(claims): AuthenticatedClaims,
) -> Result<Response, RegistryError> {
    gc_admin_authorize(&claims)?;
    match &state.gc_reaper_control {
        Some(c) => {
            c.pause();
            Ok((
                StatusCode::OK,
                axum::Json(serde_json::json!({"paused": true})),
            )
                .into_response())
        }
        None => Err(RegistryError::Internal(
            "online-gc reaper not running".into(),
        )),
    }
}

/// POST /v2/_gc/resume — resume the continuous reaper. Idempotent.
#[instrument(name = "gc_resume", skip(state, claims))]
async fn gc_resume(
    State(state): State<AppState>,
    AuthenticatedClaims(claims): AuthenticatedClaims,
) -> Result<Response, RegistryError> {
    gc_admin_authorize(&claims)?;
    match &state.gc_reaper_control {
        Some(c) => {
            c.resume();
            Ok((
                StatusCode::OK,
                axum::Json(serde_json::json!({"paused": false})),
            )
                .into_response())
        }
        None => Err(RegistryError::Internal(
            "online-gc reaper not running".into(),
        )),
    }
}

/// POST /v2/_gc/reconcile — run the reconciler. Body
/// `{"apply": bool, "max": int?}`.
#[derive(Debug, serde::Deserialize, Default)]
struct GcReconcileBody {
    #[serde(default)]
    apply: bool,
    #[serde(default)]
    max: Option<i64>,
}

#[instrument(name = "gc_reconcile", skip(state, claims))]
async fn gc_reconcile(
    State(state): State<AppState>,
    AuthenticatedClaims(claims): AuthenticatedClaims,
    body: Option<axum::Json<GcReconcileBody>>,
) -> Result<Response, RegistryError> {
    gc_admin_authorize(&claims)?;
    let body = body.map(|axum::Json(b)| b).unwrap_or_default();

    let pool = state
        .gc_pool
        .clone()
        .ok_or_else(|| RegistryError::Internal("online-gc not enabled".into()))?;

    let cfg = nebula_gc::ReconcileConfig {
        apply_fix: body.apply,
        max_blobs: body.max,
    };
    let stats = nebula_gc::Reconciler::new(pool)
        .reconcile(cfg)
        .await
        .map_err(|e| RegistryError::Internal(format!("reconcile failed: {e}")))?;

    Ok((
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "examined":  stats.blobs_examined,
            "orphan":    stats.orphan_count,
            "missing":   stats.missing_count,
            "underflow": stats.underflow_count,
            "corrected": stats.corrected,
            "applied":   body.apply,
        })),
    )
        .into_response())
}

// ── TTL reaper admin routes (013 slice 2) ────────────────────────────────────

fn ttl_admin_authorize(claims: &TokenClaims) -> Result<(), RegistryError> {
    if claims.role != Role::Admin {
        return Err(RegistryError::Forbidden {
            reason: "ttl admin endpoints require Admin role".into(),
        });
    }
    Ok(())
}

#[instrument(name = "ttl_status", skip(state, claims))]
async fn ttl_status(
    State(state): State<AppState>,
    AuthenticatedClaims(claims): AuthenticatedClaims,
) -> Result<Response, RegistryError> {
    ttl_admin_authorize(&claims)?;
    let body = match &state.ttl_reaper_control {
        Some(c) => serde_json::json!({
            "enabled": true,
            "paused":  c.is_paused(),
            "stopped": c.is_stopped(),
        }),
        None => serde_json::json!({ "enabled": false }),
    };
    Ok((StatusCode::OK, axum::Json(body)).into_response())
}

#[instrument(name = "ttl_pause", skip(state, claims))]
async fn ttl_pause(
    State(state): State<AppState>,
    AuthenticatedClaims(claims): AuthenticatedClaims,
) -> Result<Response, RegistryError> {
    ttl_admin_authorize(&claims)?;
    match &state.ttl_reaper_control {
        Some(c) => {
            c.pause();
            Ok((
                StatusCode::OK,
                axum::Json(serde_json::json!({"paused": true})),
            )
                .into_response())
        }
        None => Err(RegistryError::Internal("ttl reaper not running".into())),
    }
}

#[instrument(name = "ttl_resume", skip(state, claims))]
async fn ttl_resume(
    State(state): State<AppState>,
    AuthenticatedClaims(claims): AuthenticatedClaims,
) -> Result<Response, RegistryError> {
    ttl_admin_authorize(&claims)?;
    match &state.ttl_reaper_control {
        Some(c) => {
            c.resume();
            Ok((
                StatusCode::OK,
                axum::Json(serde_json::json!({"paused": false})),
            )
                .into_response())
        }
        None => Err(RegistryError::Internal("ttl reaper not running".into())),
    }
}

// ── Usage read API (017 polish) ──────────────────────────────────────────────

fn usage_admin_authorize(claims: &TokenClaims) -> Result<(), RegistryError> {
    if claims.role != Role::Admin {
        return Err(RegistryError::Forbidden {
            reason: "usage endpoints require Admin role".into(),
        });
    }
    Ok(())
}

fn parse_since(raw: &str) -> Option<i64> {
    let raw = raw.trim();
    let (n, unit) = raw.split_at(raw.find(|c: char| !c.is_ascii_digit())?);
    let n: i64 = n.parse().ok()?;
    if n < 0 {
        return None;
    }
    let secs = match unit {
        "s" => n,
        "m" => n * 60,
        "h" => n * 3600,
        "d" => n * 86_400,
        _ => return None,
    };
    Some(secs)
}

#[derive(Debug, serde::Deserialize)]
struct TenantSeriesQuery {
    #[serde(default)]
    since: Option<String>,
    #[serde(default)]
    granularity: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct TenantSeriesPath {
    tenant: String,
}

#[instrument(name = "usage_tenant", skip(state, claims))]
async fn usage_tenant(
    State(state): State<AppState>,
    AuthenticatedClaims(claims): AuthenticatedClaims,
    Path(p): Path<TenantSeriesPath>,
    Query(q): Query<TenantSeriesQuery>,
) -> Result<Response, RegistryError> {
    usage_admin_authorize(&claims)?;
    let pool = state
        .gc_pool
        .clone()
        .ok_or_else(|| RegistryError::Internal("usage backend not configured".into()))?;
    let since_secs = q
        .since
        .as_deref()
        .and_then(parse_since)
        .unwrap_or(24 * 3600);
    let granularity = q
        .granularity
        .as_deref()
        .and_then(nebula_cost::Granularity::parse)
        .unwrap_or(nebula_cost::Granularity::Hour);

    let buckets = nebula_cost::UsageReader::new(pool)
        .tenant_series(&p.tenant, since_secs, granularity)
        .await
        .map_err(|e| RegistryError::Internal(format!("usage query failed: {e}")))?;

    Ok((
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "tenant": p.tenant,
            "since_secs": since_secs,
            "granularity": granularity.as_str(),
            "buckets": buckets,
        })),
    )
        .into_response())
}

#[derive(Debug, serde::Deserialize)]
struct TopPulledQuery {
    #[serde(default)]
    since: Option<String>,
    #[serde(default)]
    limit: Option<i64>,
}

#[instrument(name = "usage_top_pulled", skip(state, claims))]
async fn usage_top_pulled(
    State(state): State<AppState>,
    AuthenticatedClaims(claims): AuthenticatedClaims,
    Query(q): Query<TopPulledQuery>,
) -> Result<Response, RegistryError> {
    usage_admin_authorize(&claims)?;
    let pool = state
        .gc_pool
        .clone()
        .ok_or_else(|| RegistryError::Internal("usage backend not configured".into()))?;
    let since_secs = q
        .since
        .as_deref()
        .and_then(parse_since)
        .unwrap_or(7 * 86_400);
    let limit = q.limit.unwrap_or(20).clamp(1, 500);

    let rows = nebula_cost::UsageReader::new(pool)
        .top_pulled(since_secs, limit)
        .await
        .map_err(|e| RegistryError::Internal(format!("top_pulled query failed: {e}")))?;

    Ok((
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "since_secs": since_secs,
            "limit": limit,
            "rows": rows,
        })),
    )
        .into_response())
}

// ── Referrers API (010 integration) ──────────────────────────────────────────

/// GET /v2/{tenant}/{project}/{name}/referrers/{digest}
///
/// OCI 1.1 referrers API — returns artifacts that point at `digest`
/// via their `subject` field (signatures, attestations, TOC artifacts,
/// etc.). Optional `?artifactType=...` filters server-side. The
/// response is an OCI image index whose `manifests` array carries one
/// descriptor per referrer.
///
/// Reads from the shared `referrers` table populated by 010 (lazy
/// indexer), 015 (attestations), and any future producer of typed
/// OCI 1.1 referrer artifacts.
#[derive(Debug, serde::Deserialize)]
struct ReferrersQuery {
    #[serde(default, rename = "artifactType")]
    artifact_type: Option<String>,
}

#[instrument(name = "list_referrers", skip(state, claims), fields(tenant = %params.tenant, project = %params.project, name = %params.name, digest = %params.digest))]
async fn list_referrers(
    State(state): State<AppState>,
    AuthenticatedClaims(claims): AuthenticatedClaims,
    Path(params): Path<BlobRef>,
    Query(q): Query<ReferrersQuery>,
) -> Result<Response, RegistryError> {
    authorize(
        &claims,
        &params.tenant,
        &params.project,
        &params.name,
        Action::Pull,
    )?;

    let pool = state
        .gc_pool
        .clone()
        .ok_or_else(|| RegistryError::Internal("referrers backend not configured".into()))?;

    use nebula_lazy::ReferrerStore;
    let store = nebula_lazy::PgReferrerStore::new(pool);

    let rows = match q.artifact_type.as_deref() {
        Some(t) => store.list_by_type(&params.digest, t).await,
        None => store.list(&params.digest).await,
    }
    .map_err(|e| RegistryError::Internal(format!("referrers query failed: {e}")))?;

    // Build OCI image index envelope.
    let manifests: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "mediaType": r.media_type,
                "digest": r.artifact_digest,
                "size": r.size,
                "artifactType": r.artifact_type,
            })
        })
        .collect();

    let body = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": manifests,
    });

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/vnd.oci.image.index.v1+json"),
    );
    if let Some(hv) = q
        .artifact_type
        .as_deref()
        .and_then(|t| HeaderValue::from_str(t).ok())
    {
        headers.insert("OCI-Filters-Applied", hv);
    }

    Ok((StatusCode::OK, headers, axum::Json(body)).into_response())
}

// ── Attestation upload (015 slice 2) ─────────────────────────────────────────
//
// POST /v2/{tenant}/{project}/{name}/attestations
//
// Accepts a DSSE bundle (raw bytes). The body is parsed as a DSSE
// envelope; the inner in-toto statement gives us the subject digest
// (which must reference an existing manifest in this repo) plus the
// predicate type. SLSA-level inference uses the configured
// trusted-builder allowlist. We persist a row to `attestations`,
// register the bundle as an OCI 1.1 referrer of the subject, and
// store the raw bundle bytes so consumers can re-fetch them.
//
// `verified=false` for slice 2 — DSSE signature verification arrives
// with 001 (image signing). Admission policy gating in slice 3.

#[derive(Debug, serde::Deserialize, Default)]
struct AttestationQuery {
    /// Optional: pin to a specific subject digest. When omitted the
    /// bundle's first subject digest is used.
    #[serde(default)]
    subject: Option<String>,
}

#[instrument(name = "upload_attestation", skip(state, claims, body), fields(tenant = %params.tenant, project = %params.project, name = %params.name))]
async fn upload_attestation(
    State(state): State<AppState>,
    AuthenticatedClaims(claims): AuthenticatedClaims,
    Path(params): Path<RepoPath>,
    Query(q): Query<AttestationQuery>,
    body: Bytes,
) -> Result<Response, RegistryError> {
    authorize(
        &claims,
        &params.tenant,
        &params.project,
        &params.name,
        Action::Push,
    )?;

    let pool = state
        .gc_pool
        .clone()
        .ok_or_else(|| RegistryError::Internal("attestation backend not configured".into()))?;

    // 1. Parse DSSE.
    let (env, stmt) =
        nebula_attest::decode_envelope(&body).map_err(|e| RegistryError::ManifestInvalid {
            reason: format!("invalid DSSE: {e}"),
        })?;

    // 2. Resolve subject digest. Caller may pin via ?subject=...; else
    //    we use the first sha256 entry inside the in-toto statement.
    let subject_digest = q
        .subject
        .clone()
        .or_else(|| nebula_attest::dsse::first_subject_digest(&stmt));
    let subject_digest = subject_digest.ok_or_else(|| RegistryError::ManifestInvalid {
        reason: "DSSE statement has no sha256 subject digest".into(),
    })?;

    // 3. Infer SLSA level from the allowlist.
    let trusted_csv = std::env::var("NEBULACR_ATTEST__TRUSTED_BUILDERS").unwrap_or_default();
    let trusted: Vec<&str> = trusted_csv
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    let (level, builder_id) =
        nebula_attest::slsa::infer_slsa_level(&stmt.predicate_type, &stmt.predicate, &trusted);

    // 4. Persist the bundle in object storage so consumers can fetch
    //    it back via standard blob endpoints. The envelope's digest
    //    (sha256 of the raw bytes) is the storage key.
    let envelope_digest = nebula_common::storage::sha256_digest(&body);
    let env_path = nebula_common::storage::blob_path(
        &params.tenant,
        &params.project,
        &params.name,
        &envelope_digest,
    );
    state
        .store
        .put(&StorePath::from(env_path), body.clone().into())
        .await
        .map_err(|e| RegistryError::Storage(e.to_string()))?;

    // 4b. Try to verify the DSSE signature against any configured
    //     ed25519 keys. Format: comma-separated `keyid:b64key` pairs
    //     in NEBULACR_ATTEST__ED25519_KEYS. Empty / unconfigured ⇒
    //     verified=false (slice-2 advisory mode).
    let verified = {
        use base64::Engine as _;
        let raw = std::env::var("NEBULACR_ATTEST__ED25519_KEYS").unwrap_or_default();
        let mut verifiers: Vec<Box<dyn nebula_attest::Verifier>> = Vec::new();
        for spec in raw.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
            if let Some((keyid, b64)) = spec.split_once(':') {
                match base64::engine::general_purpose::STANDARD.decode(b64.as_bytes()) {
                    Ok(bytes) => match nebula_attest::Ed25519Verifier::from_bytes(keyid, &bytes) {
                        Ok(v) => verifiers.push(Box::new(v)),
                        Err(e) => warn!(keyid, error = %e, "attest: bad ed25519 key"),
                    },
                    Err(e) => warn!(keyid, error = %e, "attest: bad b64 ed25519 key"),
                }
            }
        }
        if verifiers.is_empty() {
            false
        } else {
            matches!(
                nebula_attest::verify_envelope(&env, &verifiers),
                Ok(nebula_attest::VerifyVerdict::Verified)
            )
        }
    };

    // 5. Persist the row + register a referrer.
    let attestation = nebula_attest::store::Attestation {
        id: Uuid::new_v4(),
        subject_digest: subject_digest.clone(),
        envelope_digest: envelope_digest.clone(),
        predicate_type: stmt.predicate_type.clone(),
        builder_id,
        builder_kind: None,
        slsa_level: Some(level.as_int()),
        verified,
        uploaded_at: chrono::Utc::now(),
    };
    use nebula_attest::AttestationStore as _;
    let store = nebula_attest::PgAttestationStore::new(pool.clone());
    let raw = serde_json::to_value(&env).map_err(|e| RegistryError::Internal(e.to_string()))?;
    store
        .put(&attestation, &raw)
        .await
        .map_err(|e| RegistryError::Internal(format!("attestation store: {e}")))?;

    use nebula_lazy::ReferrerStore as _;
    let r = nebula_lazy::Referrer {
        subject_digest: subject_digest.clone(),
        artifact_digest: envelope_digest.clone(),
        artifact_type: stmt.predicate_type.clone(),
        media_type: env.payload_type.clone(),
        size: body.len() as i64,
    };
    if let Err(e) = nebula_lazy::PgReferrerStore::new(pool).register(&r).await {
        warn!(error = %e, "attestation referrer register failed");
    }

    let resp = serde_json::json!({
        "id":              attestation.id,
        "subject_digest":  subject_digest,
        "envelope_digest": envelope_digest,
        "predicate_type":  stmt.predicate_type,
        "slsa_level":      level.as_int(),
    });
    Ok((StatusCode::CREATED, axum::Json(resp)).into_response())
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
    // Handle digest references: sha256:abc... or sha256-abc... (OCI dash encoding)
    let normalized_ref = if reference.starts_with("sha256-") {
        reference.replacen("sha256-", "sha256:", 1)
    } else {
        reference.to_string()
    };
    if normalized_ref.starts_with("sha256:") {
        // Direct digest reference
        Ok(manifest_path(tenant, project, name, &normalized_ref))
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

    // Record metrics and audit for replicated manifest
    let source_region = extract_header(&headers, "x-replication-source-region").unwrap_or_default();
    counter!("registry_manifest_push_total",
        "tenant" => tenant.clone(),
        "project" => project.clone()
    )
    .increment(1);
    counter!("registry_push_bytes_total").increment(body.len() as u64);
    state
        .audit_log
        .record(audit::RegistryAuditEvent {
            event_type: "manifest.replicated".into(),
            subject: format!("replication:{source_region}"),
            tenant: tenant.clone(),
            project: project.clone(),
            repository: repo.clone(),
            reference: reference.clone(),
            digest: digest.clone(),
            size_bytes: body.len() as u64,
            status_code: 200,
            duration_ms: 0,
            timestamp: chrono::Utc::now(),
        })
        .await;

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
    let blob_size = body.len() as u64;

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

    // Record metrics for replicated blob
    counter!("registry_blob_upload_bytes_total",
        "tenant" => tenant.clone(),
        "project" => project.clone()
    )
    .increment(blob_size);
    counter!("registry_push_bytes_total").increment(blob_size);

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

// ── Image Status Check ──────────────────────────────────────────────────────

/// GET /v2/{tenant}/{project}/{name}/status/{reference}
///
/// Pre-pull readiness check. Returns whether an image (manifest + all layers)
/// is fully available and pullable. Use this to verify image availability
/// before pulling, or to check if an image exists on the mirror.
///
/// Response:
/// ```json
/// {
///   "available": true,
///   "image": "demo/default/nginx:latest",
///   "manifest": { "exists": true, "digest": "sha256:...", "mediaType": "...", "size": 1234 },
///   "layers": [
///     { "digest": "sha256:...", "size": 12345, "available": true },
///     { "digest": "sha256:...", "size": 67890, "available": true }
///   ],
///   "config": { "digest": "sha256:...", "size": 5678, "available": true },
///   "missing_layers": 0,
///   "total_size": 86169
/// }
/// ```
#[instrument(name = "image_status", skip(state, claims), fields(tenant = %params.tenant, project = %params.project, name = %params.name, reference = %params.reference))]
async fn image_status(
    State(state): State<AppState>,
    AuthenticatedClaims(claims): AuthenticatedClaims,
    Path(params): Path<ManifestRef>,
) -> Result<axum::Json<serde_json::Value>, RegistryError> {
    authorize(
        &claims,
        &params.tenant,
        &params.project,
        &params.name,
        Action::Pull,
    )?;

    let image_ref = format!(
        "{}/{}/{}:{}",
        params.tenant, params.project, params.name, params.reference
    );

    // 1. Check manifest
    let manifest_path_result = resolve_manifest_path(
        &state,
        &params.tenant,
        &params.project,
        &params.name,
        &params.reference,
    )
    .await;

    let manifest_store_path = match manifest_path_result {
        Ok(p) => p,
        Err(_) => {
            return Ok(axum::Json(serde_json::json!({
                "available": false,
                "image": image_ref,
                "manifest": { "exists": false },
                "layers": [],
                "missing_layers": 0,
                "total_size": 0,
                "reason": "manifest not found"
            })));
        }
    };

    let store_path = StorePath::from(manifest_store_path);
    let manifest_data = match state.store.get(&store_path).await {
        Ok(result) => match result.bytes().await {
            Ok(bytes) => bytes,
            Err(_) => {
                return Ok(axum::Json(serde_json::json!({
                    "available": false,
                    "image": image_ref,
                    "manifest": { "exists": false },
                    "layers": [],
                    "missing_layers": 0,
                    "total_size": 0,
                    "reason": "manifest not readable"
                })));
            }
        },
        Err(_) => {
            return Ok(axum::Json(serde_json::json!({
                "available": false,
                "image": image_ref,
                "manifest": { "exists": false },
                "layers": [],
                "missing_layers": 0,
                "total_size": 0,
                "reason": "manifest not found"
            })));
        }
    };

    let digest = sha256_digest(&manifest_data);
    let media_type = detect_manifest_media_type(&manifest_data);
    let manifest_size = manifest_data.len();

    // 2. Parse manifest to find layers and config
    let manifest_json: serde_json::Value =
        serde_json::from_slice(&manifest_data).map_err(|e| RegistryError::ManifestInvalid {
            reason: e.to_string(),
        })?;

    let mut layer_statuses = Vec::new();
    let mut config_status = serde_json::json!(null);
    let mut total_size: u64 = manifest_size as u64;
    let mut missing_layers: u32 = 0;

    // Check config blob if present
    if let Some(config) = manifest_json.get("config")
        && let (Some(cfg_digest), Some(cfg_size)) = (
            config.get("digest").and_then(|d| d.as_str()),
            config.get("size").and_then(|s| s.as_u64()),
        )
    {
        let cfg_path = blob_path(&params.tenant, &params.project, &params.name, cfg_digest);
        let cfg_exists = state.store.head(&StorePath::from(cfg_path)).await.is_ok();
        if !cfg_exists {
            missing_layers += 1;
        }
        total_size += cfg_size;
        config_status = serde_json::json!({
            "digest": cfg_digest,
            "size": cfg_size,
            "available": cfg_exists
        });
    }

    // Check each layer
    if let Some(layers) = manifest_json.get("layers").and_then(|l| l.as_array()) {
        for layer in layers {
            if let (Some(layer_digest), Some(layer_size)) = (
                layer.get("digest").and_then(|d| d.as_str()),
                layer.get("size").and_then(|s| s.as_u64()),
            ) {
                let layer_store_path =
                    blob_path(&params.tenant, &params.project, &params.name, layer_digest);
                let layer_exists = state
                    .store
                    .head(&StorePath::from(layer_store_path))
                    .await
                    .is_ok();
                if !layer_exists {
                    missing_layers += 1;
                }
                total_size += layer_size;
                layer_statuses.push(serde_json::json!({
                    "digest": layer_digest,
                    "size": layer_size,
                    "available": layer_exists
                }));
            }
        }
    }

    // For manifest lists/indexes, check sub-manifests
    if let Some(manifests) = manifest_json.get("manifests").and_then(|m| m.as_array()) {
        for sub in manifests {
            if let (Some(sub_digest), Some(sub_size)) = (
                sub.get("digest").and_then(|d| d.as_str()),
                sub.get("size").and_then(|s| s.as_u64()),
            ) {
                let sub_path =
                    manifest_path(&params.tenant, &params.project, &params.name, sub_digest);
                let sub_exists = state.store.head(&StorePath::from(sub_path)).await.is_ok();
                if !sub_exists {
                    missing_layers += 1;
                }
                total_size += sub_size;
                let platform = sub
                    .get("platform")
                    .cloned()
                    .unwrap_or(serde_json::json!(null));
                layer_statuses.push(serde_json::json!({
                    "digest": sub_digest,
                    "size": sub_size,
                    "available": sub_exists,
                    "platform": platform
                }));
            }
        }
    }

    let all_available = missing_layers == 0;

    Ok(axum::Json(serde_json::json!({
        "available": all_available,
        "image": image_ref,
        "manifest": {
            "exists": true,
            "digest": digest,
            "mediaType": media_type,
            "size": manifest_size
        },
        "layers": layer_statuses,
        "config": config_status,
        "missing_layers": missing_layers,
        "total_size": total_size
    })))
}

// ── 2-segment wrapper handlers (default tenant) ────────────────────────────
//
// Standard Docker clients push with 2 path segments: {namespace}/{repo}.
// These wrappers inject the default tenant and delegate to the 3-segment handlers.

async fn head_manifest_2seg(
    state: State<AppState>,
    claims: AuthenticatedClaims,
    Path(p): Path<ManifestRef2>,
) -> Result<Response, RegistryError> {
    let params = ManifestRef {
        tenant: DEFAULT_TENANT.to_string(),
        project: p.project,
        name: p.name,
        reference: p.reference,
    };
    head_manifest(state, claims, Path(params)).await
}

async fn get_manifest_2seg(
    state: State<AppState>,
    claims: AuthenticatedClaims,
    Path(p): Path<ManifestRef2>,
) -> Result<Response, RegistryError> {
    let params = ManifestRef {
        tenant: DEFAULT_TENANT.to_string(),
        project: p.project,
        name: p.name,
        reference: p.reference,
    };
    get_manifest(state, claims, Path(params)).await
}

async fn put_manifest_2seg(
    state: State<AppState>,
    claims: AuthenticatedClaims,
    Path(p): Path<ManifestRef2>,
    req_headers: HeaderMap,
    body: Bytes,
) -> Result<Response, RegistryError> {
    let params = ManifestRef {
        tenant: DEFAULT_TENANT.to_string(),
        project: p.project,
        name: p.name,
        reference: p.reference,
    };
    put_manifest(state, claims, Path(params), req_headers, body).await
}

async fn delete_manifest_2seg(
    state: State<AppState>,
    claims: AuthenticatedClaims,
    Path(p): Path<ManifestRef2>,
) -> Result<Response, RegistryError> {
    let params = ManifestRef {
        tenant: DEFAULT_TENANT.to_string(),
        project: p.project,
        name: p.name,
        reference: p.reference,
    };
    delete_manifest(state, claims, Path(params)).await
}

async fn head_blob_2seg(
    state: State<AppState>,
    claims: AuthenticatedClaims,
    Path(p): Path<BlobRef2>,
) -> Result<Response, RegistryError> {
    let params = BlobRef {
        tenant: DEFAULT_TENANT.to_string(),
        project: p.project,
        name: p.name,
        digest: p.digest,
    };
    head_blob(state, claims, Path(params)).await
}

async fn get_blob_2seg(
    state: State<AppState>,
    claims: AuthenticatedClaims,
    Path(p): Path<BlobRef2>,
) -> Result<Response, RegistryError> {
    let params = BlobRef {
        tenant: DEFAULT_TENANT.to_string(),
        project: p.project,
        name: p.name,
        digest: p.digest,
    };
    get_blob(state, claims, Path(params)).await
}

async fn initiate_blob_upload_2seg(
    state: State<AppState>,
    claims: AuthenticatedClaims,
    Path(p): Path<RepoPath2>,
) -> Result<Response, RegistryError> {
    let params = RepoPath {
        tenant: DEFAULT_TENANT.to_string(),
        project: p.project,
        name: p.name,
    };
    initiate_blob_upload(state, claims, Path(params)).await
}

async fn upload_blob_chunk_2seg(
    state: State<AppState>,
    claims: AuthenticatedClaims,
    Path(p): Path<UploadRef2>,
    body: Bytes,
) -> Result<Response, RegistryError> {
    let params = UploadRef {
        tenant: DEFAULT_TENANT.to_string(),
        project: p.project,
        name: p.name,
        uuid: p.uuid,
    };
    upload_blob_chunk(state, claims, Path(params), body).await
}

async fn complete_blob_upload_2seg(
    state: State<AppState>,
    claims: AuthenticatedClaims,
    Path(p): Path<UploadRef2>,
    query: Query<DigestQuery>,
    body: Bytes,
) -> Result<Response, RegistryError> {
    let params = UploadRef {
        tenant: DEFAULT_TENANT.to_string(),
        project: p.project,
        name: p.name,
        uuid: p.uuid,
    };
    complete_blob_upload(state, claims, Path(params), query, body).await
}

async fn image_status_2seg(
    state: State<AppState>,
    claims: AuthenticatedClaims,
    Path(p): Path<ManifestRef2>,
) -> Result<axum::Json<serde_json::Value>, RegistryError> {
    let params = ManifestRef {
        tenant: DEFAULT_TENANT.to_string(),
        project: p.project,
        name: p.name,
        reference: p.reference,
    };
    image_status(state, claims, Path(params)).await
}

async fn list_tags_2seg(
    state: State<AppState>,
    claims: AuthenticatedClaims,
    Path(p): Path<RepoPath2>,
    pagination: Query<PaginationQuery>,
) -> Result<Response, RegistryError> {
    let params = RepoPath {
        tenant: DEFAULT_TENANT.to_string(),
        project: p.project,
        name: p.name,
    };
    list_tags(state, claims, Path(params), pagination).await
}

fn extract_header(headers: &HeaderMap, name: &str) -> Result<String, RegistryError> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| RegistryError::Internal(format!("missing header: {name}")))
}

/// Load scanner config from `NEBULACR_SCANNER__*` env vars and build the
/// runtime. Returns `Ok(None)` when `NEBULACR_SCANNER__ENABLED` is not "true".
async fn build_scanner_runtime(
    store: Arc<dyn ObjectStore>,
) -> anyhow::Result<Option<ScannerRuntime>> {
    use std::env;
    let enabled = env::var("NEBULACR_SCANNER__ENABLED")
        .map(|v| matches!(v.as_str(), "true" | "1" | "yes"))
        .unwrap_or(false);
    if !enabled {
        return Ok(None);
    }
    let postgres_url = env::var("NEBULACR_SCANNER__POSTGRES_URL").map_err(|_| {
        anyhow::anyhow!("NEBULACR_SCANNER__POSTGRES_URL required when scanner enabled")
    })?;
    let redis_url = env::var("NEBULACR_SCANNER__REDIS_URL").map_err(|_| {
        anyhow::anyhow!("NEBULACR_SCANNER__REDIS_URL required when scanner enabled")
    })?;
    let vulndb = env::var("NEBULACR_SCANNER__VULNDB").unwrap_or_else(|_| "osv".into());
    let vulndb = match vulndb.as_str() {
        "nebula" => nebula_scanner::config::VulnDbBackend::Nebula,
        _ => nebula_scanner::config::VulnDbBackend::Osv,
    };
    let ai_enabled = env::var("NEBULACR_SCANNER__AI_ENABLED")
        .map(|v| matches!(v.as_str(), "true" | "1" | "yes"))
        .unwrap_or(true);
    let ai_endpoint = env::var("NEBULACR_SCANNER__AI_ENDPOINT")
        .unwrap_or_else(|_| "http://127.0.0.1:11434".into());
    let ai_model =
        env::var("NEBULACR_SCANNER__AI_MODEL").unwrap_or_else(|_| "qwen2.5-coder:7b".into());

    let cfg = ScannerConfig {
        enabled: true,
        postgres_url,
        redis_url,
        vulndb,
        ai_enabled,
        ai_endpoint,
        ai_model,
        workers: env::var("NEBULACR_SCANNER__WORKERS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(2),
        queue_capacity: env::var("NEBULACR_SCANNER__QUEUE_CAPACITY")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(256),
        result_ttl_secs: env::var("NEBULACR_SCANNER__RESULT_TTL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3600),
        pg_max_connections: env::var("NEBULACR_SCANNER__PG_MAX_CONNECTIONS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(8),
        ingest_enabled: env::var("NEBULACR_SCANNER__INGEST_ENABLED")
            .map(|v| matches!(v.as_str(), "true" | "1" | "yes"))
            .unwrap_or(true),
        ingest_interval_secs: env::var("NEBULACR_SCANNER__INGEST_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(21_600),
        export_prefix: env::var("NEBULACR_SCANNER__EXPORT_PREFIX")
            .unwrap_or_else(|_| "scanner-exports".into()),
        nvd_enabled: env::var("NEBULACR_SCANNER__NVD_ENABLED")
            .map(|v| matches!(v.as_str(), "true" | "1" | "yes"))
            .unwrap_or(false),
        nvd_api_key: env::var("NEBULACR_SCANNER__NVD_API_KEY").ok(),
        nvd_bootstrap_window_days: env::var("NEBULACR_SCANNER__NVD_BOOTSTRAP_WINDOW_DAYS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30),
        nvd_sleep_between_pages_secs: env::var("NEBULACR_SCANNER__NVD_SLEEP_BETWEEN_PAGES_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(6),
        ghsa_enabled: env::var("NEBULACR_SCANNER__GHSA_ENABLED")
            .map(|v| matches!(v.as_str(), "true" | "1" | "yes"))
            .unwrap_or(false),
        ghsa_token: env::var("NEBULACR_SCANNER__GHSA_TOKEN").ok(),
        rate_limit_rpm: env::var("NEBULACR_SCANNER__RATE_LIMIT_RPM")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(600),
        alerts_webhook_url: env::var("NEBULACR_SCANNER__ALERTS_WEBHOOK_URL").ok(),
        alerts_format: env::var("NEBULACR_SCANNER__ALERTS_FORMAT")
            .unwrap_or_else(|_| "generic".into()),
        queue_backend: match env::var("NEBULACR_SCANNER__QUEUE_BACKEND")
            .unwrap_or_else(|_| "tokio".into())
            .to_lowercase()
            .as_str()
        {
            "postgres" => nebula_scanner::config::QueueBackend::Postgres,
            _ => nebula_scanner::config::QueueBackend::Tokio,
        },
        enqueue_only: env::var("NEBULACR_SCANNER__ENQUEUE_ONLY")
            .map(|v| matches!(v.as_str(), "true" | "1" | "yes"))
            .unwrap_or(false),
        scan_dedup_enabled: env::var("NEBULACR_SCANNER__SCAN_DEDUP_ENABLED")
            .map(|v| matches!(v.as_str(), "true" | "1" | "yes"))
            .unwrap_or(true),
    };

    let rt = ScannerRuntime::build(cfg, store).await?;
    info!(
        "scanner runtime ready (workers={})",
        rt.worker_handles.len()
    );
    Ok(Some(rt))
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
                Ok(contents) => match serde_yaml::from_str::<RegistryConfig>(&contents) {
                    Ok(cfg) => {
                        eprintln!(
                            "Config loaded from {path}, multi_region: {}",
                            cfg.multi_region.is_some()
                        );
                        cfg
                    }
                    Err(e) => {
                        eprintln!("Warning: failed to parse config {path}: {e}, using defaults");
                        RegistryConfig::default()
                    }
                },
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

    // Pre-register all metrics so they appear in /metrics from startup.
    // Existing per-operation counters & latency histogram (kept for back-compat
    // dashboards).
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

    // ── Enterprise observability (HTTP, storage, mirror, replication, webhook) ──
    // Pre-publish the build_info gauge (fixed value 1, labels carry version data
    // — same trick used by node_exporter).
    gauge!("nebulacr_build_info",
        "service" => "registry",
        "version" => env!("CARGO_PKG_VERSION"),
        "rustc" => option_env!("RUSTC_VERSION").unwrap_or("unknown"))
    .set(1.0);

    // HTTP — populated by http_metrics_middleware.
    counter!("nebulacr_http_requests_total",
        "route" => "v2_check", "method" => "GET", "status_class" => "2xx")
    .increment(0);
    histogram!("nebulacr_http_request_duration_seconds",
        "route" => "v2_check", "method" => "GET")
    .record(0.0);
    gauge!("nebulacr_http_requests_in_flight", "route" => "v2_check").set(0.0);

    // Rate limiter — populated by rate_limit_middleware.
    counter!("nebulacr_rate_limit_rejected_total", "tenant" => "anonymous").increment(0);

    // Storage backend (resilience layer).
    for op in [
        "put", "put_opts", "get", "get_opts", "head", "delete", "list",
    ] {
        counter!("nebulacr_storage_operations_total",
            "operation" => op, "outcome" => "success")
        .increment(0);
        counter!("nebulacr_storage_operations_total",
            "operation" => op, "outcome" => "error")
        .increment(0);
        counter!("nebulacr_storage_operation_errors_total", "operation" => op).increment(0);
        histogram!("nebulacr_storage_operation_duration_seconds", "operation" => op).record(0.0);
        counter!("nebulacr_retry_attempts_total",
            "operation" => op, "outcome" => "recovered")
        .increment(0);
        counter!("nebulacr_retry_attempts_total",
            "operation" => op, "outcome" => "exhausted")
        .increment(0);
    }

    // Circuit breakers — pre-publish the storage one so dashboards always have a series.
    gauge!("nebulacr_circuit_breaker_state", "breaker" => "storage").set(0.0);
    counter!("nebulacr_circuit_breaker_transitions_total",
        "breaker" => "storage", "to" => "open")
    .increment(0);
    counter!("nebulacr_circuit_breaker_rejections_total", "breaker" => "storage").increment(0);

    // Mirror.
    for kind in ["manifest", "blob"] {
        counter!("nebulacr_mirror_cache_misses_total", "kind" => kind).increment(0);
        for outcome in [
            "fetched",
            "not_found",
            "error",
            "skipped_scope",
            "skipped_unlinked",
            "no_upstreams",
        ] {
            counter!("nebulacr_mirror_fetch_total", "kind" => kind, "outcome" => outcome)
                .increment(0);
        }
    }

    // Replication.
    counter!("nebulacr_replication_enqueued_total", "kind" => "manifest").increment(0);
    counter!("nebulacr_replication_enqueued_total", "kind" => "blob").increment(0);
    counter!("nebulacr_replication_enqueued_total", "kind" => "delete").increment(0);
    counter!("nebulacr_replication_enqueue_failures_total").increment(0);
    gauge!("nebulacr_replication_queue_depth").set(0.0);

    // Webhook.
    counter!("nebulacr_webhook_enqueued_total", "event" => "manifest.push").increment(0);
    counter!("nebulacr_webhook_enqueued_total", "event" => "manifest.delete").increment(0);
    counter!("nebulacr_webhook_enqueued_total", "event" => "blob.push").increment(0);
    counter!("nebulacr_webhook_enqueue_failures_total", "event" => "manifest.push").increment(0);

    // Process start-time gauge — Prometheus convention; uptime is computed
    // by Grafana as `time() - nebulacr_process_start_time_seconds`.
    gauge!("nebulacr_process_start_time_seconds").set(chrono::Utc::now().timestamp() as f64);

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

    // Load JWT verification key — fail hard if key is missing or invalid.
    // A silent fallback to a dummy key causes all token validation to fail
    // after pod restart, making pushes return 401 with no diagnostic info.
    let verification_key_path = &config.auth.verification_key_path;
    let verification_key_pem = std::fs::read(verification_key_path).unwrap_or_else(|e| {
        error!(
            path = %verification_key_path,
            error = %e,
            "FATAL: Cannot load JWT verification key — all authenticated requests will fail"
        );
        panic!("Cannot start registry without JWT verification key: {e}");
    });

    info!(
        path = %verification_key_path,
        size = verification_key_pem.len(),
        algorithm = %config.auth.signing_algorithm,
        "JWT verification key loaded"
    );

    let decoding_key = if config.auth.signing_algorithm == "EdDSA" {
        DecodingKey::from_ed_pem(&verification_key_pem).unwrap_or_else(|e| {
            error!(error = %e, "FATAL: Invalid EdDSA verification key PEM");
            panic!("Invalid EdDSA verification key: {e}");
        })
    } else {
        DecodingKey::from_rsa_pem(&verification_key_pem).unwrap_or_else(|e| {
            error!(error = %e, "FATAL: Invalid RSA verification key PEM");
            panic!("Invalid RSA verification key: {e}");
        })
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
                scope: mirror_scope_from_config(mirror_cfg.scope.as_ref()),
            };
            info!(scope = ?svc_config.scope, "Mirror pullthrough scope");
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

    // ── Scanner runtime (optional; enabled by NEBULACR_SCANNER__ENABLED) ──
    let scanner_runtime = match build_scanner_runtime(store.clone()).await {
        Ok(Some(rt)) => Some(rt),
        Ok(None) => {
            info!("scanner disabled via config");
            None
        }
        Err(e) => {
            warn!(error = %e, "scanner runtime init failed; continuing without it");
            None
        }
    };
    let scanner_queue = scanner_runtime.as_ref().map(|rt| rt.queue.clone());
    let scanner_router = scanner_runtime.as_ref().map(|rt| rt.router.clone());

    // ── Online-GC refcounter (009 slice 1) ───────────────────────────
    // Enabled by `NEBULACR_GC__ONLINE=true`. When enabled, we reuse
    // the scanner's Postgres pool (it owns the migrations); when the
    // scanner is disabled we connect a dedicated pool. When disabled
    // entirely the no-op refcounter keeps the manifest path unchanged
    // and existing deployments are unaffected.
    let gc_online_enabled = std::env::var("NEBULACR_GC__ONLINE")
        .map(|v| matches!(v.as_str(), "true" | "1" | "yes"))
        .unwrap_or(false);
    let (gc_refcounter, gc_reaper_control, gc_pool): (
        Arc<dyn nebula_gc::BlobRefCounter>,
        Option<Arc<nebula_gc::ReaperControl>>,
        Option<sqlx::PgPool>,
    ) = if gc_online_enabled {
        let pool_opt = if let Some(rt) = scanner_runtime.as_ref() {
            Some(rt.pg.clone())
        } else if let Ok(url) = std::env::var("NEBULACR_GC__POSTGRES_URL") {
            match nebula_db::connect(&url, 4).await {
                Ok(p) => match nebula_db::migrate(&p).await {
                    Ok(()) => Some(p),
                    Err(e) => {
                        warn!(error = %e, "gc postgres migrate failed; falling back to no-op refcounter");
                        None
                    }
                },
                Err(e) => {
                    warn!(error = %e, "gc postgres connect failed; falling back to no-op refcounter");
                    None
                }
            }
        } else {
            warn!(
                "NEBULACR_GC__ONLINE=true but neither scanner nor NEBULACR_GC__POSTGRES_URL provided; using no-op refcounter"
            );
            None
        };
        match pool_opt {
            Some(pool) => {
                info!("online GC refcounter enabled (postgres-backed)");

                // Spawn the continuous reaper unless explicitly disabled.
                let reaper_enabled = std::env::var("NEBULACR_GC__REAPER_ENABLED")
                    .map(|v| matches!(v.as_str(), "true" | "1" | "yes"))
                    .unwrap_or(true);

                let control = if reaper_enabled {
                    let control = nebula_gc::ReaperControl::new();
                    let cfg = nebula_gc::ReaperConfig {
                        grace: std::time::Duration::from_secs(
                            std::env::var("NEBULACR_GC__REAPER_GRACE_SECS")
                                .ok()
                                .and_then(|v| v.parse::<u64>().ok())
                                .unwrap_or(24 * 3600),
                        ),
                        batch_size: std::env::var("NEBULACR_GC__REAPER_BATCH")
                            .ok()
                            .and_then(|v| v.parse::<i64>().ok())
                            .unwrap_or(200),
                        idle_sleep: std::time::Duration::from_secs(
                            std::env::var("NEBULACR_GC__REAPER_IDLE_SLEEP_SECS")
                                .ok()
                                .and_then(|v| v.parse::<u64>().ok())
                                .unwrap_or(30),
                        ),
                        sweep_qps: std::env::var("NEBULACR_GC__REAPER_QPS")
                            .ok()
                            .and_then(|v| v.parse::<u32>().ok())
                            .unwrap_or(100),
                    };
                    let reaper = nebula_gc::ContinuousReaper::new(
                        pool.clone(),
                        store.clone(),
                        cfg,
                        control.clone(),
                    );
                    tokio::spawn(async move {
                        let _ = reaper.run().await;
                    });
                    info!("online GC continuous reaper spawned");
                    Some(control)
                } else {
                    info!("online GC reaper disabled by config");
                    None
                };

                let rc: Arc<dyn nebula_gc::BlobRefCounter> =
                    Arc::new(nebula_gc::PgBlobRefCounter::new(pool.clone()));
                (rc, control, Some(pool))
            }
            None => (Arc::new(nebula_gc::NoopBlobRefCounter), None, None),
        }
    } else {
        (Arc::new(nebula_gc::NoopBlobRefCounter), None, None)
    };

    // ── Lazy-pull indexer worker (010 slice 2) ───────────────────────
    // Enabled by NEBULACR_LAZY__ENABLED. Spawns a worker that drains
    // the lazy_jobs queue and dispatches to a TocIndexer impl. Slice 2
    // ships a stub eStargz indexer that records metadata + referrers
    // without rewriting layer bytes — proves the queue plumbing end
    // to end so slice 3 can plug the real indexer in transparently.
    let lazy_worker_enabled = std::env::var("NEBULACR_LAZY__ENABLED")
        .map(|v| matches!(v.as_str(), "true" | "1" | "yes"))
        .unwrap_or(false);
    if let Some(pool) = gc_pool.clone().filter(|_| lazy_worker_enabled) {
        // 010 polish — real ObjectStore fetcher. Jobs now carry
        // (tenant, project, repo) so the worker can build the
        // standard `<t>/<p>/<r>/blobs/sha256/<hex>` storage key.
        let fetcher: Arc<dyn nebula_lazy::LayerFetcher> =
            Arc::new(nebula_lazy::ObjectStoreLayerFetcher {
                store: store.clone(),
            });
        let indexers: Vec<Arc<dyn nebula_lazy::TocIndexer>> =
            vec![Arc::new(nebula_lazy::StubEstargzIndexer)];
        let worker_control = nebula_lazy::WorkerControl::new();
        let worker = nebula_lazy::Worker::new(
            pool.clone(),
            fetcher,
            indexers,
            nebula_lazy::WorkerConfig::default(),
            worker_control.clone(),
        );
        tokio::spawn(async move {
            worker.run().await;
        });
        info!("lazy-pull worker spawned (stub indexer)");
        let _ = worker_control;
    }

    // ── TTL reaper (013 slice 2) ─────────────────────────────────────
    // Drains expired tag rows. Requires the GC pool + the registry's
    // storage handle. Kill-switched by NEBULACR_TTL__REAPER_ENABLED;
    // off by default so existing deployments stay no-op.
    let ttl_reaper_control: Option<Arc<nebula_ephemeral::TtlReaperControl>> = {
        let enabled = std::env::var("NEBULACR_TTL__REAPER_ENABLED")
            .map(|v| matches!(v.as_str(), "true" | "1" | "yes"))
            .unwrap_or(false);
        match (enabled, gc_pool.clone()) {
            (true, Some(pool)) => {
                let control = nebula_ephemeral::TtlReaperControl::new();
                let cfg = nebula_ephemeral::TtlReaperConfig {
                    batch_size: std::env::var("NEBULACR_TTL__REAPER_BATCH")
                        .ok()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(100),
                    idle_sleep: std::time::Duration::from_secs(
                        std::env::var("NEBULACR_TTL__REAPER_IDLE_SLEEP_SECS")
                            .ok()
                            .and_then(|v| v.parse().ok())
                            .unwrap_or(60),
                    ),
                };
                let reaper =
                    nebula_ephemeral::TtlReaper::new(pool, store.clone(), cfg, control.clone());
                tokio::spawn(async move {
                    let _ = reaper.run().await;
                });
                info!("ttl reaper spawned");
                Some(control)
            }
            (true, None) => {
                warn!(
                    "NEBULACR_TTL__REAPER_ENABLED=true but no Postgres pool; \
                     enable scanner or GC to provide one"
                );
                None
            }
            _ => None,
        }
    };

    // ── Usage recorder (017 slice 1) ─────────────────────────────────
    // Enabled by `NEBULACR_USAGE__ENABLED=true`. Reuses the GC pool
    // when present (both want the same Postgres). Defaults to a no-op
    // so existing deployments are unaffected.
    let usage_enabled = std::env::var("NEBULACR_USAGE__ENABLED")
        .map(|v| matches!(v.as_str(), "true" | "1" | "yes"))
        .unwrap_or(false);
    // ── Typed artifact validators (016) ──────────────────────────────
    // Enabled by `NEBULACR_ARTIFACT_TYPES__ENABLED=true`. Slice 1 ships
    // the Helm validator; further types (WASM/model/Terraform) plug
    // in here in subsequent slices. Default off → no-op manifest path.
    let artifact_types_enabled = std::env::var("NEBULACR_ARTIFACT_TYPES__ENABLED")
        .map(|v| matches!(v.as_str(), "true" | "1" | "yes"))
        .unwrap_or(false);
    let artifact_registry: Option<Arc<nebula_artifact_types::ArtifactRegistry>> =
        if artifact_types_enabled {
            info!("typed artifact validators enabled (helm/wasm/model/tfmodule)");
            Some(Arc::new(
                nebula_artifact_types::ArtifactRegistry::new()
                    .register(nebula_artifact_types::HelmType)
                    .register(nebula_artifact_types::WasmType)
                    .register(nebula_artifact_types::ModelType)
                    .register(nebula_artifact_types::TerraformModuleType),
            ))
        } else {
            None
        };

    let usage_recorder: Arc<dyn nebula_cost::UsageRecorder> = if usage_enabled {
        match gc_pool.clone() {
            Some(pool) => {
                info!("usage recorder enabled (postgres-backed)");

                // Spawn drainer (staging → durable). Idempotent + crash-safe.
                let drainer_control = nebula_cost::DrainerControl::new();
                let drainer_cfg = nebula_cost::DrainerConfig {
                    interval: std::time::Duration::from_secs(
                        std::env::var("NEBULACR_USAGE__DRAINER_INTERVAL_SECS")
                            .ok()
                            .and_then(|v| v.parse().ok())
                            .unwrap_or(60),
                    ),
                    batch_size: std::env::var("NEBULACR_USAGE__DRAINER_BATCH")
                        .ok()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(5000),
                };
                let drainer =
                    nebula_cost::Drainer::new(pool.clone(), drainer_cfg, drainer_control.clone());
                tokio::spawn(async move {
                    let _ = drainer.run().await;
                });
                info!("usage drainer spawned");

                // Spawn rollup loop (hourly + daily aggregations).
                let rollup_control = nebula_cost::RollupControl::new();
                let rollup_cfg = nebula_cost::RollupConfig {
                    interval: std::time::Duration::from_secs(
                        std::env::var("NEBULACR_USAGE__ROLLUP_INTERVAL_SECS")
                            .ok()
                            .and_then(|v| v.parse().ok())
                            .unwrap_or(300),
                    ),
                };
                let rollup =
                    nebula_cost::Rollup::new(pool.clone(), rollup_cfg, rollup_control.clone());
                tokio::spawn(async move {
                    let _ = rollup.run().await;
                });
                info!("usage rollup spawned");

                // Hold the controls so the drainer/rollup don't shut down
                // when their last reference goes away. Stored on AppState
                // so future admin endpoints can flip them.
                let _ = (drainer_control, rollup_control);

                Arc::new(nebula_cost::PgUsageRecorder::new(pool))
            }
            None => {
                warn!(
                    "NEBULACR_USAGE__ENABLED=true but no Postgres pool available; \
                     enable scanner or GC to provide one. Falling back to no-op."
                );
                Arc::new(nebula_cost::NoopUsageRecorder)
            }
        }
    } else {
        Arc::new(nebula_cost::NoopUsageRecorder)
    };

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
        scanner_queue,
        gc_refcounter,
        gc_reaper_control,
        gc_pool,
        ttl_reaper_control,
        usage_recorder,
        artifact_registry,
        audit_log: audit_log.clone(),
        start_time,
    };

    // Dashboard state (shared with dashboard handlers)
    let auth_service_url = format!("http://{}", state.config.server.auth_listen_addr);
    let dashboard_state = dashboard::DashboardState {
        audit_log: audit_log.clone(),
        store: state.store.clone(),
        start_time,
        failover_manager,
        auth_service_url: Some(auth_service_url),
    };

    // Build the router
    // Public routes (no auth required)
    let public_routes = Router::new()
        .route("/v2/", get(v2_check))
        .route("/health", get(health_check))
        .route("/metrics", get(metrics_handler))
        .route("/auth/token", get(proxy_auth_token).post(proxy_auth_token));

    // Dashboard and API routes (protected by Basic auth)
    let dashboard_auth_config = Arc::new(state.config.server.dashboard_auth.clone());
    let dashboard_routes = Router::new()
        .route("/dashboard", get(dashboard::dashboard_html))
        .route("/api/stats", get(dashboard::api_stats))
        .route("/api/activity", get(dashboard::api_activity))
        .route("/api/audit", get(dashboard::api_audit))
        .route("/api/system", get(dashboard::api_system))
        .route("/api/ha-status", get(dashboard::api_ha_status))
        .route("/api/images", get(dashboard::api_images))
        .route("/api/image-detail", get(dashboard::api_image_detail))
        // Identity & Access Management (proxy to auth service)
        .route("/api/users", get(dashboard::api_users))
        .route("/api/groups", get(dashboard::api_groups))
        .route("/api/robot-accounts", get(dashboard::api_robot_accounts))
        .layer(middleware::from_fn_with_state(
            dashboard_auth_config,
            dashboard_auth_middleware,
        ))
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
        // Image status check (pre-pull readiness)
        .route(
            "/v2/{tenant}/{project}/{name}/status/{reference}",
            get(image_status),
        )
        // Tag listing
        .route("/v2/{tenant}/{project}/{name}/tags/list", get(list_tags))
        // 2-segment routes (standard Docker: namespace/repo → default tenant)
        .route(
            "/v2/{project}/{name}/manifests/{reference}",
            head(head_manifest_2seg)
                .get(get_manifest_2seg)
                .put(put_manifest_2seg)
                .delete(delete_manifest_2seg),
        )
        .route(
            "/v2/{project}/{name}/blobs/{digest}",
            head(head_blob_2seg).get(get_blob_2seg),
        )
        .route(
            "/v2/{project}/{name}/blobs/uploads/",
            post(initiate_blob_upload_2seg),
        )
        .route(
            "/v2/{project}/{name}/blobs/uploads/{uuid}",
            patch(upload_blob_chunk_2seg).put(complete_blob_upload_2seg),
        )
        .route(
            "/v2/{project}/{name}/status/{reference}",
            get(image_status_2seg),
        )
        .route("/v2/{project}/{name}/tags/list", get(list_tags_2seg))
        // Referrers (OCI 1.1) — 010 integration
        .route(
            "/v2/{tenant}/{project}/{name}/referrers/{digest}",
            get(list_referrers),
        )
        // Attestations upload — 015 slice 2
        .route(
            "/v2/{tenant}/{project}/{name}/attestations",
            post(upload_attestation),
        )
        // Catalog
        .route("/v2/_catalog", get(catalog))
        // Online GC control plane (009 slice 2-3)
        .route("/v2/_gc/status", get(gc_status))
        .route("/v2/_gc/pause", post(gc_pause))
        .route("/v2/_gc/resume", post(gc_resume))
        .route("/v2/_gc/reconcile", post(gc_reconcile))
        // TTL reaper control plane (013 slice 2)
        .route("/v2/_ttl/status", get(ttl_status))
        .route("/v2/_ttl/pause", post(ttl_pause))
        .route("/v2/_ttl/resume", post(ttl_resume))
        // Usage read API (017 polish)
        .route("/v2/_usage/tenant/{tenant}", get(usage_tenant))
        .route("/v2/_usage/top-pulled", get(usage_top_pulled));

    // Internal replication routes — served on both the main port (for cross-cluster
    // access via proxy) and the dedicated internal port (for intra-cluster use).
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
        );

    let app = Router::new()
        .merge(public_routes)
        .merge(dashboard_routes)
        .merge(registry_routes)
        .merge(internal_routes.clone())
        .layer(DefaultBodyLimit::disable()) // No limit — OCI blob sizes are unbounded
        .layer(middleware::from_fn(request_id_middleware))
        .layer(middleware::from_fn(http_metrics_middleware))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(state.clone());
    // Merge the scanner router AFTER applying state to the main app — at
    // this point both are Router<()> and merge accepts them. Scanner routes
    // carry their own ScannerState internally.
    let app = match scanner_router {
        Some(sr) => app.merge(sr),
        None => app,
    };

    let internal_app = internal_routes
        .layer(DefaultBodyLimit::disable())
        .with_state(state);

    let internal_addr = format!("0.0.0.0:{internal_port}");

    // Start the internal replication listener in the background
    let internal_listener = tokio::net::TcpListener::bind(&internal_addr).await?;
    info!(addr = %internal_addr, "Internal replication API listening");
    tokio::spawn(async move {
        if let Err(e) = axum::serve(internal_listener, internal_app).await {
            error!(error = %e, "Internal replication API error");
        }
    });

    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    info!(addr = %listen_addr, "NebulaCR Registry listening");

    axum::serve(listener, app).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // T6: is_store_not_found distinguishes a true "not present" miss
    // from a real backend IO failure. Only the former must fall
    // through to the mirror or return 404; real IO errors stay 5xx.
    #[test]
    fn is_store_not_found_matches_only_not_found_variant() {
        let not_found = object_store::Error::NotFound {
            path: "tenant/project/name/blobs/sha256/abc".into(),
            source: Box::new(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "object not found",
            )),
        };
        assert!(is_store_not_found(&not_found));

        let io = object_store::Error::Generic {
            store: "mock",
            source: Box::new(std::io::Error::other("disk exploded")),
        };
        assert!(
            !is_store_not_found(&io),
            "real IO failures must NOT be flattened to 404 (R4)"
        );
    }

    #[test]
    fn mirror_scope_from_config_none_defaults_to_default_tenant_only() {
        let scope = mirror_scope_from_config(None);
        assert!(matches!(scope, MirrorScope::DefaultTenantOnly { .. }));
        assert!(scope.tenant_project_eligible("_", "library"));
        assert!(!scope.tenant_project_eligible("private", "app"));
    }

    #[test]
    fn mirror_scope_from_config_allowlist() {
        let cfg = nebula_common::config::MirrorScopeConfig {
            mode: Some("allowlist".into()),
            tenants: vec!["_".into()],
            projects: vec!["public/library".into()],
            default_tenant: None,
        };
        let scope = mirror_scope_from_config(Some(&cfg));
        assert!(matches!(scope, MirrorScope::Allowlist { .. }));
        assert!(scope.tenant_project_eligible("_", "anything"));
        assert!(scope.tenant_project_eligible("public", "library"));
        assert!(!scope.tenant_project_eligible("private", "app"));
    }

    #[test]
    fn mirror_scope_from_config_manifest_linked() {
        let cfg = nebula_common::config::MirrorScopeConfig {
            mode: Some("manifest_linked".into()),
            tenants: vec![],
            projects: vec![],
            default_tenant: None,
        };
        let scope = mirror_scope_from_config(Some(&cfg));
        assert!(matches!(scope, MirrorScope::ManifestLinked));
        assert!(!scope.decides_at_tenant_level());
    }

    #[test]
    fn mirror_scope_from_config_unknown_mode_falls_back_safely() {
        let cfg = nebula_common::config::MirrorScopeConfig {
            mode: Some("typo-mode".into()),
            tenants: vec![],
            projects: vec![],
            default_tenant: Some("__default__".into()),
        };
        let scope = mirror_scope_from_config(Some(&cfg));
        match scope {
            MirrorScope::DefaultTenantOnly { default_tenant } => {
                assert_eq!(default_tenant, "__default__");
            }
            _ => panic!("unknown mode must fall back to DefaultTenantOnly"),
        }
    }
}
