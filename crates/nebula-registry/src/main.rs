//! NebulaCR OCI Registry Service
//!
//! Implements the Docker Registry HTTP API V2 / OCI Distribution Specification
//! with multi-tenant isolation, JWT authentication, and filesystem-backed storage.

use std::collections::HashMap;
use std::sync::Arc;

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
use metrics::counter;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use object_store::{ObjectStore, local::LocalFileSystem, path::Path as StorePath};
use tokio::sync::RwLock;
use tower_http::trace::TraceLayer;
use tracing::{info, instrument, warn};
use uuid::Uuid;

use nebula_common::auth::TokenClaims;
use nebula_common::config::RegistryConfig;
use nebula_common::errors::RegistryError;
use nebula_common::models::Action;
use nebula_common::storage::{
    blob_path, manifest_path, sha256_digest, tag_link_path, tags_prefix, upload_path,
};

// ── Application State ────────────────────────────────────────────────────────

/// Shared application state available to all handlers.
#[derive(Clone)]
struct AppState {
    store: Arc<dyn ObjectStore>,
    config: Arc<RegistryConfig>,
    decoding_key: Arc<DecodingKey>,
    prom_handle: PrometheusHandle,
    #[allow(dead_code)]
    rate_limiters: Arc<
        RwLock<
            HashMap<String, Arc<RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>>>,
        >,
    >,
    default_rate_limiter: Arc<RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>>,
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
    headers.insert(
        "Docker-Distribution-API-Version",
        HeaderValue::from_static("registry/2.0"),
    );

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

    Ok((StatusCode::CREATED, headers).into_response())
}

/// DELETE /v2/{tenant}/{project}/{name}/manifests/{reference}
#[instrument(name = "delete_manifest", skip(state, claims), fields(tenant = %params.tenant, project = %params.project, name = %params.name, reference = %params.reference))]
async fn delete_manifest(
    State(state): State<AppState>,
    AuthenticatedClaims(claims): AuthenticatedClaims,
    Path(params): Path<ManifestRef>,
) -> Result<Response, RegistryError> {
    authorize(
        &claims,
        &params.tenant,
        &params.project,
        &params.name,
        Action::Delete,
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

    let path = blob_path(
        &params.tenant,
        &params.project,
        &params.name,
        &params.digest,
    );
    let store_path = StorePath::from(path);

    let result = state
        .store
        .get(&store_path)
        .await
        .map_err(|_| RegistryError::BlobUnknown {
            digest: params.digest.clone(),
        })?;

    let data = result
        .bytes()
        .await
        .map_err(|e| RegistryError::Storage(e.to_string()))?;

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
        if let Some(tag) = full_path.strip_prefix(&prefix) {
            if !tag.is_empty() {
                tags.push(tag.to_string());
            }
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
        if let Some(sv) = val.get("schemaVersion").and_then(|v| v.as_u64()) {
            if sv == 2 {
                if val.get("manifests").is_some() {
                    return "application/vnd.oci.image.index.v1+json".to_string();
                }
                return "application/vnd.oci.image.manifest.v1+json".to_string();
            }
        }
    }
    "application/vnd.oci.image.manifest.v1+json".to_string()
}

// ── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load configuration (defaults if no config file present)
    let config = RegistryConfig::default();

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

    // Initialize object store (filesystem backend)
    let storage_root = &config.storage.root;
    std::fs::create_dir_all(storage_root)?;
    let store: Arc<dyn ObjectStore> = Arc::new(LocalFileSystem::new_with_prefix(storage_root)?);

    info!(root = %storage_root, "Storage backend initialized (filesystem)");

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

    let listen_addr = config.server.listen_addr.clone();

    let state = AppState {
        store,
        config: Arc::new(config),
        decoding_key: Arc::new(decoding_key),
        prom_handle,
        rate_limiters: Arc::new(RwLock::new(HashMap::new())),
        default_rate_limiter,
    };

    // Build the router
    // Public routes (no auth required)
    let public_routes = Router::new()
        .route("/v2/", get(v2_check))
        .route("/health", get(health_check))
        .route("/metrics", get(metrics_handler));

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
        .merge(registry_routes)
        .layer(middleware::from_fn(request_id_middleware))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    info!(addr = %listen_addr, "NebulaCR Registry listening");

    axum::serve(listener, app).await?;

    Ok(())
}
