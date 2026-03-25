use std::collections::HashMap;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use base64::Engine;
use chrono::Utc;
use governor::{Quota, RateLimiter};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, encode};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use uuid::Uuid;

use nebula_common::auth::{
    DockerTokenResponse, RequestedScope, TokenClaims, TokenRequest, TokenResponse, TokenScope,
};
use nebula_common::config::{BootstrapAdmin, RegistryConfig};
use nebula_common::errors::RegistryError;
use nebula_common::models::{AccessPolicy, Action, Project, Role, Tenant, Visibility};

// ── Application state ────────────────────────────────────────────────

type KeyedRateLimiter = RateLimiter<
    String,
    governor::state::keyed::DefaultKeyedStateStore<String>,
    governor::clock::DefaultClock,
>;

#[derive(Clone)]
struct AppState {
    encoding_key: EncodingKey,
    #[allow(dead_code)]
    decoding_key: DecodingKey,
    tenants: Arc<RwLock<HashMap<String, Tenant>>>,
    projects: Arc<RwLock<HashMap<(Uuid, String), Project>>>,
    access_policies: Arc<RwLock<Vec<AccessPolicy>>>,
    config: RegistryConfig,
    rate_limiter: Arc<KeyedRateLimiter>,
    metrics_handle: metrics_exporter_prometheus::PrometheusHandle,
}

// ── Metrics counters ─────────────────────────────────────────────────

fn increment_auth_requests() {
    metrics::counter!("registry_auth_requests_total").increment(1);
}

fn increment_token_issued() {
    metrics::counter!("registry_token_issued_total").increment(1);
}

fn increment_auth_failures(reason: &str) {
    metrics::counter!("registry_auth_failures_total", "reason" => reason.to_owned()).increment(1);
}

// ── Crypto / encoding helpers ────────────────────────────────────────

/// Decode standard base64.
fn b64_standard_decode(input: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(input.trim())
        .ok()
}

/// Decode URL-safe base64 (no padding).
fn b64_url_decode(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(input)
}

/// Compute SHA-256 hex digest of a string.
fn sha256_hex(input: &str) -> String {
    hex::encode(Sha256::digest(input.as_bytes()))
}

/// Constant-time byte comparison to avoid timing attacks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ── Bootstrap admin auth ─────────────────────────────────────────────

/// Extract Basic auth credentials from the Authorization header.
fn extract_basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    let auth_header = headers.get("authorization")?.to_str().ok()?;
    let encoded = auth_header.strip_prefix("Basic ")?;
    let decoded_bytes = b64_standard_decode(encoded)?;
    let decoded = String::from_utf8(decoded_bytes).ok()?;
    let (user, pass) = decoded.split_once(':')?;
    Some((user.to_string(), pass.to_string()))
}

/// Verify a password against a stored SHA-256 hex hash.
fn verify_bootstrap_password(password: &str, password_hash: &str) -> bool {
    let computed = sha256_hex(password);
    constant_time_eq(computed.as_bytes(), password_hash.as_bytes())
}

// ── Stub OIDC token validation ───────────────────────────────────────

/// Minimal JWT claims extracted from the identity token.
#[derive(Debug, Deserialize)]
struct IdentityTokenClaims {
    sub: String,
    #[allow(dead_code)]
    #[serde(default)]
    iss: String,
    #[serde(default)]
    exp: Option<i64>,
}

/// Validate an identity token (stub implementation).
/// Decodes the JWT without signature verification — for development only.
/// In production, this will verify against the OIDC provider's JWKS.
fn validate_identity_token(token: &str) -> Result<IdentityTokenClaims, RegistryError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(RegistryError::TokenInvalid {
            reason: "identity token is not a valid JWT (expected 3 parts)".into(),
        });
    }

    // Decode header to verify it's well-formed JSON
    let header_bytes = b64_url_decode(parts[0]).map_err(|_| RegistryError::TokenInvalid {
        reason: "invalid base64 in JWT header".into(),
    })?;
    let _header: serde_json::Value =
        serde_json::from_slice(&header_bytes).map_err(|_| RegistryError::TokenInvalid {
            reason: "JWT header is not valid JSON".into(),
        })?;

    // Decode payload and extract claims
    let payload_bytes = b64_url_decode(parts[1]).map_err(|_| RegistryError::TokenInvalid {
        reason: "invalid base64 in JWT payload".into(),
    })?;
    let claims: IdentityTokenClaims =
        serde_json::from_slice(&payload_bytes).map_err(|e| RegistryError::TokenInvalid {
            reason: format!("failed to parse identity token claims: {e}"),
        })?;

    // Check expiry if present
    if let Some(exp) = claims.exp {
        if Utc::now().timestamp() > exp {
            return Err(RegistryError::TokenExpired);
        }
    }

    if claims.sub.is_empty() {
        return Err(RegistryError::TokenInvalid {
            reason: "identity token missing 'sub' claim".into(),
        });
    }

    Ok(claims)
}

// ── Docker scope parsing ─────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct DockerTokenQuery {
    #[serde(default)]
    #[allow(dead_code)]
    service: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    account: Option<String>,
}

/// Parse a Docker scope string like `repository:tenant/project/repo:pull,push`.
fn parse_docker_scope(scope: &str) -> Option<RequestedScope> {
    let parts: Vec<&str> = scope.splitn(3, ':').collect();
    if parts.len() != 3 {
        return None;
    }
    // parts[0] = resource type (e.g. "repository")
    let name = parts[1];
    let actions_str = parts[2];

    let actions: Vec<Action> = actions_str
        .split(',')
        .filter_map(|a| match a.trim() {
            "pull" => Some(Action::Pull),
            "push" => Some(Action::Push),
            "delete" => Some(Action::Delete),
            "*" => Some(Action::Pull),
            _ => None,
        })
        .collect();

    // Split name into tenant/project/repo components
    let name_parts: Vec<&str> = name.splitn(3, '/').collect();
    let (tenant, project, repository) = match name_parts.len() {
        3 => (
            name_parts[0].to_string(),
            Some(name_parts[1].to_string()),
            Some(name_parts[2].to_string()),
        ),
        2 => (
            name_parts[0].to_string(),
            Some(name_parts[1].to_string()),
            None,
        ),
        1 => ("demo".to_string(), None, Some(name_parts[0].to_string())),
        _ => return None,
    };

    Some(RequestedScope {
        tenant,
        project,
        repository,
        actions,
    })
}

// ── Authentication helpers ───────────────────────────────────────────

/// Authenticate a request: try bootstrap admin (Basic auth), then OIDC identity token.
async fn authenticate_request(
    state: &AppState,
    headers: &HeaderMap,
    identity_token: &str,
) -> Result<String, RegistryError> {
    // Try Basic auth for bootstrap admin
    if let Some((ref username, ref password)) = extract_basic_auth(headers) {
        if let Ok(subject) = authenticate_basic(state, username, password) {
            return Ok(subject);
        }
    }

    // Validate the OIDC/identity JWT
    let claims = validate_identity_token(identity_token)?;
    Ok(claims.sub)
}

/// Authenticate via Basic auth against the bootstrap admin credentials.
fn authenticate_basic(
    state: &AppState,
    username: &str,
    password: &str,
) -> Result<String, RegistryError> {
    if let Some(ref admin) = state.config.auth.bootstrap_admin {
        if username == admin.username && verify_bootstrap_password(password, &admin.password_hash) {
            info!(username = %username, "bootstrap admin authenticated");
            return Ok(username.to_string());
        }
    }
    increment_auth_failures("invalid_credentials");
    Err(RegistryError::Unauthorized)
}

/// Resolve the role for a subject within a tenant/project scope.
async fn resolve_role(
    state: &AppState,
    subject: &str,
    tenant_id: Uuid,
    project_id: Option<Uuid>,
) -> Role {
    // Bootstrap admin always gets Admin role
    if let Some(ref admin) = state.config.auth.bootstrap_admin {
        if subject == admin.username {
            return Role::Admin;
        }
    }

    let policies = state.access_policies.read().await;
    let mut best_role: Option<Role> = None;

    for policy in policies.iter() {
        if policy.subject != subject || policy.tenant_id != tenant_id {
            continue;
        }

        // Project-scoped policy takes precedence over tenant-wide
        if let Some(pid) = project_id {
            if policy.project_id == Some(pid) {
                return policy.role;
            }
        }

        // Tenant-wide policy (project_id is None)
        if policy.project_id.is_none() {
            best_role = Some(policy.role);
        }
    }

    // Authenticated users default to Reader if no explicit policy found
    best_role.unwrap_or(Role::Reader)
}

/// Build a signed JWT from the given claims.
fn sign_token(state: &AppState, claims: &TokenClaims) -> Result<String, RegistryError> {
    encode(&Header::new(Algorithm::RS256), claims, &state.encoding_key).map_err(|e| {
        error!(error = %e, "failed to encode JWT");
        RegistryError::Internal("token signing failed".into())
    })
}

// ── Handlers ─────────────────────────────────────────────────────────

/// POST /auth/token — Issue a short-lived access token.
async fn post_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<TokenRequest>,
) -> Result<Json<TokenResponse>, RegistryError> {
    increment_auth_requests();

    let request_id = Uuid::new_v4();
    let tenant_name = request.scope.tenant.clone();

    let span = tracing::info_span!(
        "post_token",
        request_id = %request_id,
        tenant = %tenant_name,
        project = ?request.scope.project,
    );
    let _guard = span.enter();

    // Rate limit by tenant name
    if state.rate_limiter.check_key(&tenant_name).is_err() {
        increment_auth_failures("rate_limited");
        return Err(RegistryError::RateLimitExceeded);
    }

    // Authenticate the caller
    let subject = authenticate_request(&state, &headers, &request.identity_token).await?;
    info!(subject = %subject, "authenticated subject");

    // Resolve tenant
    let tenants = state.tenants.read().await;
    let tenant = tenants.get(&tenant_name).ok_or_else(|| {
        increment_auth_failures("tenant_not_found");
        RegistryError::TenantNotFound {
            tenant: tenant_name.clone(),
        }
    })?;
    if !tenant.enabled {
        increment_auth_failures("tenant_disabled");
        return Err(RegistryError::Forbidden {
            reason: "tenant is disabled".into(),
        });
    }
    let tenant_id = tenant.id;
    drop(tenants);

    // Resolve project
    let project_id = if let Some(ref proj_name) = request.scope.project {
        let projects = state.projects.read().await;
        let project = projects
            .get(&(tenant_id, proj_name.clone()))
            .ok_or_else(|| {
                increment_auth_failures("project_not_found");
                RegistryError::ProjectNotFound {
                    project: proj_name.clone(),
                }
            })?;
        Some(project.id)
    } else {
        None
    };

    // Determine role and filter actions
    let role = resolve_role(&state, &subject, tenant_id, project_id).await;
    let allowed_actions: Vec<Action> = request
        .scope
        .actions
        .iter()
        .copied()
        .filter(|a| role.can(*a))
        .collect();

    if allowed_actions.is_empty() && !request.scope.actions.is_empty() {
        increment_auth_failures("insufficient_permissions");
        return Err(RegistryError::Forbidden {
            reason: format!("role '{role:?}' does not permit requested actions"),
        });
    }

    // Issue token
    let now = Utc::now();
    let ttl = state.config.auth.token_ttl_seconds;
    let claims = TokenClaims {
        iss: state.config.auth.issuer.clone(),
        sub: subject.clone(),
        aud: state.config.auth.audience.clone(),
        exp: now.timestamp() + ttl as i64,
        iat: now.timestamp(),
        jti: Uuid::new_v4().to_string(),
        tenant_id,
        project_id,
        role,
        scopes: vec![TokenScope {
            repository: request.scope.repository.unwrap_or_default(),
            actions: allowed_actions,
        }],
    };

    let token = sign_token(&state, &claims)?;
    increment_token_issued();

    info!(
        subject = %subject,
        tenant_id = %tenant_id,
        project_id = ?project_id,
        role = ?role,
        "token issued"
    );

    Ok(Json(TokenResponse {
        token,
        expires_in: ttl,
        issued_at: now,
    }))
}

/// GET /auth/token — Docker-compatible token endpoint.
async fn get_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<DockerTokenQuery>,
) -> Result<Json<DockerTokenResponse>, RegistryError> {
    increment_auth_requests();

    let request_id = Uuid::new_v4();
    let span = tracing::info_span!(
        "get_token_docker",
        request_id = %request_id,
        scope = ?query.scope,
    );
    let _guard = span.enter();

    // Docker sends credentials via Basic auth
    let subject = if let Some((ref username, ref password)) = extract_basic_auth(&headers) {
        authenticate_basic(&state, username, password).unwrap_or_else(|_| "anonymous".to_string())
    } else if let Some(ref account) = query.account {
        account.clone()
    } else {
        "anonymous".to_string()
    };

    // Parse Docker scope string
    let requested_scope = query
        .scope
        .as_deref()
        .and_then(parse_docker_scope)
        .unwrap_or(RequestedScope {
            tenant: "demo".into(),
            project: None,
            repository: None,
            actions: vec![],
        });

    // Resolve tenant
    let tenants = state.tenants.read().await;
    let tenant =
        tenants
            .get(&requested_scope.tenant)
            .ok_or_else(|| RegistryError::TenantNotFound {
                tenant: requested_scope.tenant.clone(),
            })?;
    let tenant_id = tenant.id;
    drop(tenants);

    // Resolve project
    let project_id = if let Some(ref proj_name) = requested_scope.project {
        let projects = state.projects.read().await;
        projects.get(&(tenant_id, proj_name.clone())).map(|p| p.id)
    } else {
        None
    };

    // Resolve role and filter actions
    let role = resolve_role(&state, &subject, tenant_id, project_id).await;
    let allowed_actions: Vec<Action> = requested_scope
        .actions
        .iter()
        .copied()
        .filter(|a| role.can(*a))
        .collect();

    let now = Utc::now();
    let ttl = state.config.auth.token_ttl_seconds;
    let claims = TokenClaims {
        iss: state.config.auth.issuer.clone(),
        sub: subject,
        aud: state.config.auth.audience.clone(),
        exp: now.timestamp() + ttl as i64,
        iat: now.timestamp(),
        jti: Uuid::new_v4().to_string(),
        tenant_id,
        project_id,
        role,
        scopes: vec![TokenScope {
            repository: requested_scope.repository.unwrap_or_default(),
            actions: allowed_actions,
        }],
    };

    let token = sign_token(&state, &claims)?;
    increment_token_issued();

    Ok(Json(DockerTokenResponse {
        access_token: token.clone(),
        token,
        expires_in: ttl,
        issued_at: now.to_rfc3339(),
    }))
}

/// GET /health — Health check.
async fn health() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({"status": "ok"})))
}

/// GET /metrics — Prometheus metrics.
async fn metrics_handler(State(state): State<AppState>) -> impl IntoResponse {
    (
        StatusCode::OK,
        [("content-type", "text/plain; charset=utf-8")],
        state.metrics_handle.render(),
    )
}

// ── JWT key loading ──────────────────────────────────────────────────

/// Load RSA keys from disk, falling back to embedded development keys.
fn load_jwt_keys(config: &RegistryConfig) -> (EncodingKey, DecodingKey) {
    // Try configured file paths first
    if let Ok(priv_pem) = std::fs::read(&config.auth.signing_key_path) {
        if let Ok(pub_pem) = std::fs::read(&config.auth.verification_key_path) {
            if let Ok(enc) = EncodingKey::from_rsa_pem(&priv_pem) {
                if let Ok(dec) = DecodingKey::from_rsa_pem(&pub_pem) {
                    info!("loaded JWT signing keys from configured paths");
                    return (enc, dec);
                }
            }
        }
    }

    // Fall back to embedded development keys
    warn!(
        "configured key paths not found — using embedded development RSA keys (NOT FOR PRODUCTION)"
    );
    let priv_pem = include_bytes!("dev_key.pem");
    let pub_pem = include_bytes!("dev_key.pub.pem");
    let enc = EncodingKey::from_rsa_pem(priv_pem).expect("embedded dev private key must be valid");
    let dec = DecodingKey::from_rsa_pem(pub_pem).expect("embedded dev public key must be valid");
    (enc, dec)
}

// ── Seed data ────────────────────────────────────────────────────────

fn seed_demo_data() -> (
    HashMap<String, Tenant>,
    HashMap<(Uuid, String), Project>,
    Vec<AccessPolicy>,
) {
    let now = Utc::now();

    let tenant_id = Uuid::new_v4();
    let tenant = Tenant {
        id: tenant_id,
        name: "demo".into(),
        display_name: "Demo Tenant".into(),
        enabled: true,
        storage_prefix: "demo".into(),
        rate_limit_rps: 100,
        created_at: now,
        updated_at: now,
    };

    let project_id = Uuid::new_v4();
    let project = Project {
        id: project_id,
        tenant_id,
        name: "default".into(),
        display_name: "Default Project".into(),
        visibility: Visibility::Private,
        created_at: now,
        updated_at: now,
    };

    // Seed an admin policy for the "admin" user on the demo tenant/project
    let policy = AccessPolicy {
        id: Uuid::new_v4(),
        tenant_id,
        project_id: Some(project_id),
        subject: "admin".into(),
        role: Role::Admin,
        created_at: now,
    };

    let mut tenants = HashMap::new();
    tenants.insert("demo".to_string(), tenant);

    let mut projects = HashMap::new();
    projects.insert((tenant_id, "default".to_string()), project);

    (tenants, projects, vec![policy])
}

// ── Main ─────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing with JSON output
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(true)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .init();

    info!("NebulaCR Auth Service starting");

    // Load configuration (default for now; can be replaced with file/env loading)
    let mut config = RegistryConfig::default();

    // Configure bootstrap admin for development (password: "admin")
    config.auth.bootstrap_admin = Some(BootstrapAdmin {
        username: "admin".into(),
        password_hash: sha256_hex("admin"),
    });

    // Load JWT signing keys
    let (encoding_key, decoding_key) = load_jwt_keys(&config);

    // Set up Prometheus metrics recorder
    let metrics_handle = metrics_exporter_prometheus::PrometheusBuilder::new()
        .install_recorder()
        .expect("failed to install Prometheus metrics recorder");

    // Pre-register counters so they appear in /metrics from the start
    metrics::counter!("registry_auth_requests_total").increment(0);
    metrics::counter!("registry_token_issued_total").increment(0);
    metrics::counter!("registry_auth_failures_total", "reason" => "invalid_credentials")
        .increment(0);
    metrics::counter!("registry_auth_failures_total", "reason" => "rate_limited").increment(0);
    metrics::counter!("registry_auth_failures_total", "reason" => "tenant_not_found").increment(0);
    metrics::counter!("registry_auth_failures_total", "reason" => "project_not_found").increment(0);
    metrics::counter!("registry_auth_failures_total", "reason" => "tenant_disabled").increment(0);
    metrics::counter!("registry_auth_failures_total", "reason" => "insufficient_permissions")
        .increment(0);

    // Set up keyed rate limiter (per-tenant, tokens per minute)
    let rpm = config.rate_limit.token_issue_rpm;
    let rate_limiter = Arc::new(RateLimiter::keyed(Quota::per_minute(
        NonZeroU32::new(rpm).unwrap_or(NonZeroU32::new(60).unwrap()),
    )));

    // Seed in-memory data stores with demo data
    let (tenants, projects, policies) = seed_demo_data();

    let state = AppState {
        encoding_key,
        decoding_key,
        tenants: Arc::new(RwLock::new(tenants)),
        projects: Arc::new(RwLock::new(projects)),
        access_policies: Arc::new(RwLock::new(policies)),
        config: config.clone(),
        rate_limiter,
        metrics_handle,
    };

    // Build Axum router
    let app = Router::new()
        .route("/auth/token", post(post_token))
        .route("/auth/token", get(get_token))
        .route("/health", get(health))
        .route("/metrics", get(metrics_handler))
        .layer(
            tower_http::trace::TraceLayer::new_for_http().make_span_with(
                |request: &axum::http::Request<_>| {
                    let request_id = Uuid::new_v4();
                    tracing::info_span!(
                        "http_request",
                        method = %request.method(),
                        uri = %request.uri(),
                        request_id = %request_id,
                    )
                },
            ),
        )
        .with_state(state);

    // Bind and serve
    let addr: SocketAddr = config
        .server
        .auth_listen_addr
        .parse()
        .expect("invalid auth_listen_addr in config");

    info!(listen_addr = %addr, "NebulaCR Auth Service listening");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
