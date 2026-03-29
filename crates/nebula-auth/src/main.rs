// ═══════════════════════════════════════════════════════════════════
//  NebulaCR Auth Service
//
//  Production-grade authentication service with:
//  - Real OIDC discovery & JWKS validation
//  - GitHub Actions OIDC token exchange
//  - HashiCorp Vault integration for key management
//  - Token introspection (RFC 7662)
//  - JWKS publishing
//  - Audit logging
//  - Rate limiting & Prometheus metrics
// ═══════════════════════════════════════════════════════════════════

use std::collections::HashMap;
use std::collections::VecDeque;
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
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, encode};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use uuid::Uuid;

use nebula_common::auth::{
    AuditDecision, AuditEvent, DockerTokenResponse, GitHubOidcTokenRequest, GitHubTokenClaims,
    IntrospectionResponse, Jwk, JwksResponse, OidcProviderConfig, RequestedScope, TokenClaims,
    TokenRequest, TokenResponse, TokenScope,
};
use nebula_common::config::{BootstrapAdmin, GitHubOidcConfig, RegistryConfig, VaultConfig};
use nebula_common::errors::RegistryError;
use nebula_common::models::{AccessPolicy, Action, Project, Role, Tenant, Visibility};

// ═══════════════════════════════════════════════════════════════════
//  Section 1: OIDC Provider Manager
// ═══════════════════════════════════════════════════════════════════

/// Cached JWKS data for a single OIDC provider.
#[derive(Clone)]
struct CachedProvider {
    issuer_url: String,
    client_id: String,
    #[allow(dead_code)]
    subject_claim: String,
    #[allow(dead_code)]
    tenant_claim: Option<String>,
    /// The raw JWKS keys (JSON bytes) fetched from the provider.
    jwks_keys: Vec<CachedJwk>,
    /// When this cache entry was last refreshed.
    last_refreshed: chrono::DateTime<Utc>,
}

/// A cached JWK from the provider's JWKS endpoint.
#[derive(Clone)]
struct CachedJwk {
    kid: Option<String>,
    decoding_key: DecodingKey,
    algorithm: Algorithm,
}

/// Manages multiple OIDC providers and their cached JWKS.
struct OidcProviderManager {
    providers: RwLock<HashMap<String, CachedProvider>>,
    configs: Vec<OidcProviderConfig>,
    http_client: reqwest::Client,
    /// How often to refresh JWKS (seconds).
    refresh_interval_secs: i64,
}

/// Minimal OIDC discovery document fields we need.
#[derive(Debug, Deserialize)]
struct OidcDiscoveryDocument {
    // issuer: String,
    jwks_uri: String,
}

/// JWKS response from the provider.
#[derive(Debug, Deserialize)]
struct JwksDocument {
    keys: Vec<JwkEntry>,
}

/// A single JWK entry from the provider's JWKS endpoint.
#[derive(Debug, Clone, Deserialize)]
struct JwkEntry {
    kty: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    alg: Option<String>,
    // RSA fields
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
}

impl OidcProviderManager {
    fn new(configs: Vec<OidcProviderConfig>, refresh_interval_secs: i64) -> Self {
        Self {
            providers: RwLock::new(HashMap::new()),
            configs,
            http_client: reqwest::Client::new(),
            refresh_interval_secs,
        }
    }

    /// Perform initial OIDC discovery for all configured providers.
    async fn discover_all(&self) {
        for config in &self.configs {
            if let Err(e) = self.discover_provider(config).await {
                warn!(
                    issuer = %config.issuer_url,
                    error = %e,
                    "failed to discover OIDC provider; will retry on next token validation"
                );
            }
        }
    }

    /// Discover a single OIDC provider: fetch discovery doc, then JWKS.
    async fn discover_provider(&self, config: &OidcProviderConfig) -> anyhow::Result<()> {
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            config.issuer_url.trim_end_matches('/')
        );

        info!(issuer = %config.issuer_url, "discovering OIDC provider");

        let discovery: OidcDiscoveryDocument = self
            .http_client
            .get(&discovery_url)
            .send()
            .await?
            .json()
            .await?;

        let jwks: JwksDocument = self
            .http_client
            .get(&discovery.jwks_uri)
            .send()
            .await?
            .json()
            .await?;

        let cached_keys = Self::parse_jwks_keys(&jwks);

        let cached = CachedProvider {
            issuer_url: config.issuer_url.clone(),
            client_id: config.client_id.clone(),
            subject_claim: config.subject_claim.clone(),
            tenant_claim: config.tenant_claim.clone(),
            jwks_keys: cached_keys,
            last_refreshed: Utc::now(),
        };

        let mut providers = self.providers.write().await;
        providers.insert(config.issuer_url.clone(), cached);

        info!(issuer = %config.issuer_url, "OIDC provider discovered and JWKS cached");
        Ok(())
    }

    /// Parse JWK entries into decoding keys.
    fn parse_jwks_keys(jwks: &JwksDocument) -> Vec<CachedJwk> {
        let mut keys = Vec::new();
        for entry in &jwks.keys {
            if entry.kty != "RSA" {
                continue;
            }
            let (Some(n), Some(e)) = (&entry.n, &entry.e) else {
                continue;
            };
            let Ok(decoding_key) = DecodingKey::from_rsa_components(n, e) else {
                warn!(kid = ?entry.kid, "failed to parse RSA JWK");
                continue;
            };
            let algorithm = match entry.alg.as_deref() {
                Some("RS384") => Algorithm::RS384,
                Some("RS512") => Algorithm::RS512,
                Some("PS256") => Algorithm::PS256,
                Some("PS384") => Algorithm::PS384,
                Some("PS512") => Algorithm::PS512,
                _ => Algorithm::RS256,
            };
            keys.push(CachedJwk {
                kid: entry.kid.clone(),
                decoding_key,
                algorithm,
            });
        }
        keys
    }

    /// Validate a JWT identity token against the matching OIDC provider's JWKS.
    /// Returns the subject claim value on success.
    async fn validate_token(&self, token: &str) -> Result<IdentityTokenClaims, RegistryError> {
        // Decode header to get issuer hint
        let header =
            jsonwebtoken::decode_header(token).map_err(|e| RegistryError::TokenInvalid {
                reason: format!("invalid JWT header: {e}"),
            })?;

        // Decode payload without verification to extract issuer
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(RegistryError::TokenInvalid {
                reason: "JWT must have 3 parts".into(),
            });
        }
        let payload_bytes = b64_url_decode(parts[1]).map_err(|_| RegistryError::TokenInvalid {
            reason: "invalid base64 in JWT payload".into(),
        })?;
        let unverified: IdentityTokenClaims =
            serde_json::from_slice(&payload_bytes).map_err(|e| RegistryError::TokenInvalid {
                reason: format!("failed to parse token claims: {e}"),
            })?;

        let issuer = &unverified.iss;

        // Look up the provider by issuer
        let providers = self.providers.read().await;
        let Some(provider) = providers.get(issuer) else {
            // Provider not found — maybe we need to try discovery for a matching config
            drop(providers);
            return self.validate_token_with_rediscovery(token, issuer).await;
        };

        // Check if cache needs refresh
        let needs_refresh =
            (Utc::now() - provider.last_refreshed).num_seconds() > self.refresh_interval_secs;

        if needs_refresh {
            drop(providers);
            // Try to refresh in background — but still validate with current keys
            let _ = self.refresh_provider(issuer).await;
            let providers = self.providers.read().await;
            if let Some(provider) = providers.get(issuer) {
                return Self::verify_with_provider(token, &header, provider);
            }
            return Err(RegistryError::TokenInvalid {
                reason: "OIDC provider keys unavailable after refresh".into(),
            });
        }

        Self::verify_with_provider(token, &header, provider)
    }

    /// Try to discover the provider and then validate.
    async fn validate_token_with_rediscovery(
        &self,
        token: &str,
        issuer: &str,
    ) -> Result<IdentityTokenClaims, RegistryError> {
        // Find matching config
        let matching_config = self
            .configs
            .iter()
            .find(|c| c.issuer_url == issuer)
            .cloned();

        let Some(config) = matching_config else {
            return Err(RegistryError::TokenInvalid {
                reason: format!("no OIDC provider configured for issuer: {issuer}"),
            });
        };

        self.discover_provider(&config)
            .await
            .map_err(|e| RegistryError::TokenInvalid {
                reason: format!("failed to discover OIDC provider {issuer}: {e}"),
            })?;

        let header =
            jsonwebtoken::decode_header(token).map_err(|e| RegistryError::TokenInvalid {
                reason: format!("invalid JWT header: {e}"),
            })?;

        let providers = self.providers.read().await;
        let provider = providers
            .get(issuer)
            .ok_or_else(|| RegistryError::TokenInvalid {
                reason: format!("provider {issuer} not available after discovery"),
            })?;

        Self::verify_with_provider(token, &header, provider)
    }

    /// Refresh JWKS for a specific provider.
    async fn refresh_provider(&self, issuer: &str) -> anyhow::Result<()> {
        let config = self
            .configs
            .iter()
            .find(|c| c.issuer_url == issuer)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("no config for issuer {issuer}"))?;
        self.discover_provider(&config).await
    }

    /// Verify a token against a specific provider's cached keys.
    fn verify_with_provider(
        token: &str,
        header: &jsonwebtoken::Header,
        provider: &CachedProvider,
    ) -> Result<IdentityTokenClaims, RegistryError> {
        // Find matching key by kid, or try all keys
        let keys_to_try: Vec<&CachedJwk> = if let Some(ref kid) = header.kid {
            let matched: Vec<&CachedJwk> = provider
                .jwks_keys
                .iter()
                .filter(|k| k.kid.as_ref() == Some(kid))
                .collect();
            if matched.is_empty() {
                // Fall back to trying all keys
                provider.jwks_keys.iter().collect()
            } else {
                matched
            }
        } else {
            provider.jwks_keys.iter().collect()
        };

        if keys_to_try.is_empty() {
            return Err(RegistryError::TokenInvalid {
                reason: "no matching JWKS key found for token".into(),
            });
        }

        for key in &keys_to_try {
            let mut validation = Validation::new(key.algorithm);
            validation.set_audience(&[&provider.client_id]);
            validation.set_issuer(&[&provider.issuer_url]);

            match jsonwebtoken::decode::<IdentityTokenClaims>(token, &key.decoding_key, &validation)
            {
                Ok(data) => return Ok(data.claims),
                Err(_) => continue,
            }
        }

        Err(RegistryError::TokenInvalid {
            reason: "token signature verification failed against all provider keys".into(),
        })
    }
}

// ═══════════════════════════════════════════════════════════════════
//  Section 2: Vault Client
// ═══════════════════════════════════════════════════════════════════

/// Client for HashiCorp Vault integration (Transit + KV v2).
struct VaultClient {
    http_client: reqwest::Client,
    addr: String,
    token: String,
    #[allow(dead_code)]
    transit_key_name: String,
    kv_mount_path: String,
    kv_secret_path: String,
    available: bool,
}

/// Vault KV v2 read response.
#[derive(Debug, Deserialize)]
struct VaultKvResponse {
    data: VaultKvData,
}

#[derive(Debug, Deserialize)]
struct VaultKvData {
    data: HashMap<String, String>,
}

/// Vault Transit sign response.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct VaultTransitSignResponse {
    data: VaultTransitSignData,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct VaultTransitSignData {
    signature: String,
}

impl VaultClient {
    /// Create a new Vault client from config. Returns None if Vault is not configured.
    fn new(config: Option<&VaultConfig>) -> Option<Self> {
        let config = config.filter(|c| c.enabled)?;

        let addr = std::env::var("VAULT_ADDR").unwrap_or_else(|_| config.addr.clone());
        let token = std::env::var(&config.token_env_var).unwrap_or_default();

        if token.is_empty() {
            warn!("Vault enabled but no token found; Vault integration disabled");
            return None;
        }

        info!(addr = %addr, "Vault client initialized");

        Some(Self {
            http_client: reqwest::Client::new(),
            addr,
            token,
            transit_key_name: config.transit_key_name.clone(),
            kv_mount_path: config.kv_mount_path.clone(),
            kv_secret_path: config.kv_secret_path.clone(),
            available: true,
        })
    }

    /// Check if Vault is reachable and authenticated.
    fn is_available(&self) -> bool {
        self.available
    }

    /// Read the JWT signing (private) key from Vault KV v2.
    async fn read_signing_key(&self) -> anyhow::Result<Vec<u8>> {
        let url = format!(
            "{}/v1/{}/data/{}",
            self.addr, self.kv_mount_path, self.kv_secret_path
        );

        let resp: VaultKvResponse = self
            .http_client
            .get(&url)
            .header("X-Vault-Token", &self.token)
            .send()
            .await?
            .json()
            .await?;

        let key_pem = resp
            .data
            .data
            .get("private_key")
            .ok_or_else(|| anyhow::anyhow!("'private_key' not found in Vault KV secret"))?;

        Ok(key_pem.as_bytes().to_vec())
    }

    /// Read the JWT verification (public) key from Vault KV v2.
    async fn read_verification_key(&self) -> anyhow::Result<Vec<u8>> {
        let url = format!(
            "{}/v1/{}/data/{}",
            self.addr, self.kv_mount_path, self.kv_secret_path
        );

        let resp: VaultKvResponse = self
            .http_client
            .get(&url)
            .header("X-Vault-Token", &self.token)
            .send()
            .await?
            .json()
            .await?;

        let key_pem = resp
            .data
            .data
            .get("public_key")
            .ok_or_else(|| anyhow::anyhow!("'public_key' not found in Vault KV secret"))?;

        Ok(key_pem.as_bytes().to_vec())
    }

    /// Sign a JWT payload using Vault Transit engine.
    #[allow(dead_code)]
    async fn sign_jwt(&self, payload: &str) -> anyhow::Result<String> {
        let url = format!("{}/v1/transit/sign/{}", self.addr, self.transit_key_name);

        let input_b64 = base64::engine::general_purpose::STANDARD.encode(payload.as_bytes());

        let body = serde_json::json!({
            "input": input_b64,
            "hash_algorithm": "sha2-256",
            "signature_algorithm": "pkcs1v15",
        });

        let resp: VaultTransitSignResponse = self
            .http_client
            .post(&url)
            .header("X-Vault-Token", &self.token)
            .json(&body)
            .send()
            .await?
            .json()
            .await?;

        // Vault returns "vault:v1:<base64sig>" — strip the prefix
        let sig = resp
            .data
            .signature
            .strip_prefix("vault:v1:")
            .unwrap_or(&resp.data.signature);

        Ok(sig.to_string())
    }
}

// ═══════════════════════════════════════════════════════════════════
//  Section 3: Audit Log (in-memory ring buffer)
// ═══════════════════════════════════════════════════════════════════

const MAX_AUDIT_EVENTS: usize = 1000;

struct AuditLog {
    events: RwLock<VecDeque<AuditEvent>>,
}

impl AuditLog {
    fn new() -> Self {
        Self {
            events: RwLock::new(VecDeque::with_capacity(MAX_AUDIT_EVENTS)),
        }
    }

    async fn record(&self, event: AuditEvent) {
        info!(
            subject = %event.subject,
            tenant = %event.tenant,
            action = %event.action,
            decision = ?event.decision,
            reason = %event.reason,
            request_id = %event.request_id,
            "audit_event"
        );

        let mut events = self.events.write().await;
        if events.len() >= MAX_AUDIT_EVENTS {
            events.pop_front();
        }
        events.push_back(event);
    }

    async fn recent(&self) -> Vec<AuditEvent> {
        let events = self.events.read().await;
        events.iter().cloned().collect()
    }
}

// ═══════════════════════════════════════════════════════════════════
//  Section 4: Application State
// ═══════════════════════════════════════════════════════════════════

type KeyedRateLimiter = RateLimiter<
    String,
    governor::state::keyed::DefaultKeyedStateStore<String>,
    governor::clock::DefaultClock,
>;

#[derive(Clone)]
struct AppState {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    /// Raw public key PEM bytes (for JWKS publishing).
    public_key_pem: Arc<Vec<u8>>,
    tenants: Arc<RwLock<HashMap<String, Tenant>>>,
    projects: Arc<RwLock<HashMap<(Uuid, String), Project>>>,
    access_policies: Arc<RwLock<Vec<AccessPolicy>>>,
    config: RegistryConfig,
    rate_limiter: Arc<KeyedRateLimiter>,
    metrics_handle: metrics_exporter_prometheus::PrometheusHandle,
    oidc_manager: Arc<OidcProviderManager>,
    audit_log: Arc<AuditLog>,
    github_oidc_config: Option<GitHubOidcConfig>,
}

// ═══════════════════════════════════════════════════════════════════
//  Section 5: Metrics counters
// ═══════════════════════════════════════════════════════════════════

fn increment_auth_requests() {
    metrics::counter!("registry_auth_requests_total").increment(1);
}

fn increment_token_issued() {
    metrics::counter!("registry_token_issued_total").increment(1);
}

fn increment_auth_failures(reason: &str) {
    metrics::counter!("registry_auth_failures_total", "reason" => reason.to_owned()).increment(1);
}

// ═══════════════════════════════════════════════════════════════════
//  Section 6: Crypto / encoding helpers
// ═══════════════════════════════════════════════════════════════════

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

/// Encode bytes as URL-safe base64 (no padding).
fn b64_url_encode(input: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(input)
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

// ═══════════════════════════════════════════════════════════════════
//  Section 7: Bootstrap admin auth
// ═══════════════════════════════════════════════════════════════════

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

// ═══════════════════════════════════════════════════════════════════
//  Section 8: Identity token validation (real OIDC + fallback)
// ═══════════════════════════════════════════════════════════════════

/// Minimal JWT claims extracted from the identity token.
#[derive(Debug, Deserialize)]
struct IdentityTokenClaims {
    sub: String,
    #[serde(default)]
    iss: String,
    #[serde(default)]
    exp: Option<i64>,
}

/// Validate an identity token.
///
/// If OIDC providers are configured, validates against the provider's JWKS.
/// Otherwise falls back to decoding without signature verification (dev mode).
async fn validate_identity_token(
    oidc_manager: &OidcProviderManager,
    token: &str,
) -> Result<IdentityTokenClaims, RegistryError> {
    // If we have OIDC providers configured, use real validation
    if !oidc_manager.configs.is_empty() {
        return oidc_manager.validate_token(token).await;
    }

    // Fallback: dev mode — decode without signature verification
    warn!("no OIDC providers configured; using dev-mode token validation (NO signature check)");

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
    if let Some(exp) = claims.exp
        && Utc::now().timestamp() > exp
    {
        return Err(RegistryError::TokenExpired);
    }

    if claims.sub.is_empty() {
        return Err(RegistryError::TokenInvalid {
            reason: "identity token missing 'sub' claim".into(),
        });
    }

    Ok(claims)
}

// ═══════════════════════════════════════════════════════════════════
//  Section 9: Docker scope parsing
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, Deserialize)]
struct DockerTokenQuery {
    #[serde(default)]
    #[allow(dead_code)]
    service: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    account: Option<String>,
    // OAuth2 form fields sent by Docker during Www-Authenticate challenge
    #[serde(default)]
    #[allow(dead_code)]
    grant_type: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    client_id: Option<String>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    access_type: Option<String>,
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

// ═══════════════════════════════════════════════════════════════════
//  Section 10: Authentication helpers
// ═══════════════════════════════════════════════════════════════════

/// Authenticate a request: try bootstrap admin (Basic auth), then OIDC identity token.
async fn authenticate_request(
    state: &AppState,
    headers: &HeaderMap,
    identity_token: &str,
) -> Result<String, RegistryError> {
    // Try Basic auth for bootstrap admin
    if let Some((username, password)) = extract_basic_auth(headers)
        && let Ok(subject) = authenticate_basic(state, &username, &password)
    {
        return Ok(subject);
    }

    // Validate the OIDC/identity JWT
    let claims = validate_identity_token(&state.oidc_manager, identity_token).await?;
    Ok(claims.sub)
}

/// Authenticate via Basic auth against the bootstrap admin credentials.
fn authenticate_basic(
    state: &AppState,
    username: &str,
    password: &str,
) -> Result<String, RegistryError> {
    if let Some(ref admin) = state.config.auth.bootstrap_admin
        && username == admin.username
        && verify_bootstrap_password(password, &admin.password_hash)
    {
        info!(username = %username, "bootstrap admin authenticated");
        return Ok(username.to_string());
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
    if let Some(ref admin) = state.config.auth.bootstrap_admin
        && subject == admin.username
    {
        return Role::Admin;
    }

    let policies = state.access_policies.read().await;
    let mut best_role: Option<Role> = None;

    for policy in policies.iter() {
        if policy.subject != subject || policy.tenant_id != tenant_id {
            continue;
        }

        // Project-scoped policy takes precedence over tenant-wide
        if let Some(pid) = project_id
            && policy.project_id == Some(pid)
        {
            return policy.role;
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

// ═══════════════════════════════════════════════════════════════════
//  Section 11: JWKS Publishing helpers
// ═══════════════════════════════════════════════════════════════════

/// Parse an RSA public key PEM and extract modulus (n) and exponent (e) as
/// base64url-encoded strings for JWKS publishing.
fn parse_rsa_public_key_components(pem_bytes: &[u8]) -> Option<(String, String)> {
    // Use jsonwebtoken to decode the PEM into a DecodingKey, then we parse the
    // DER manually. RSA public keys in PEM are either PKCS#1 or SPKI format.
    // We'll parse the DER from the PEM ourselves.

    let pem_str = std::str::from_utf8(pem_bytes).ok()?;

    // Strip PEM headers and decode base64
    let mut der_b64 = String::new();
    for line in pem_str.lines() {
        if line.starts_with("-----") {
            continue;
        }
        der_b64.push_str(line.trim());
    }

    let der = base64::engine::general_purpose::STANDARD
        .decode(&der_b64)
        .ok()?;

    // Try to parse as SPKI (SubjectPublicKeyInfo) — most common PEM format.
    // SPKI wraps the RSA key in a SEQUENCE { algorithm, BIT STRING { SEQUENCE { n, e } } }
    // We do a minimal ASN.1 DER parse.
    parse_spki_rsa(&der).or_else(|| parse_pkcs1_rsa(&der))
}

/// Minimal ASN.1 DER tag/length parser.
fn der_read_tag_length(data: &[u8]) -> Option<(u8, usize, usize)> {
    if data.is_empty() {
        return None;
    }
    let tag = data[0];
    if data.len() < 2 {
        return None;
    }
    let (length, header_len) = if data[1] & 0x80 == 0 {
        (data[1] as usize, 2)
    } else {
        let num_bytes = (data[1] & 0x7f) as usize;
        if data.len() < 2 + num_bytes {
            return None;
        }
        let mut length = 0usize;
        for i in 0..num_bytes {
            length = (length << 8) | (data[2 + i] as usize);
        }
        (length, 2 + num_bytes)
    };
    Some((tag, length, header_len))
}

/// Parse SPKI-wrapped RSA public key DER.
fn parse_spki_rsa(der: &[u8]) -> Option<(String, String)> {
    // SEQUENCE { SEQUENCE { OID, NULL }, BIT STRING { SEQUENCE { INTEGER n, INTEGER e } } }
    let (tag, _len, hdr) = der_read_tag_length(der)?;
    if tag != 0x30 {
        return None;
    }
    let inner = &der[hdr..];

    // Skip algorithm SEQUENCE
    let (tag, algo_len, algo_hdr) = der_read_tag_length(inner)?;
    if tag != 0x30 {
        return None;
    }
    let after_algo = &inner[algo_hdr + algo_len..];

    // BIT STRING
    let (tag, _bs_len, bs_hdr) = der_read_tag_length(after_algo)?;
    if tag != 0x03 {
        return None;
    }
    // Skip the unused-bits byte
    let rsa_der = &after_algo[bs_hdr + 1..];

    parse_pkcs1_rsa(rsa_der)
}

/// Parse PKCS#1 RSA public key DER: SEQUENCE { INTEGER n, INTEGER e }.
fn parse_pkcs1_rsa(der: &[u8]) -> Option<(String, String)> {
    let (tag, _len, hdr) = der_read_tag_length(der)?;
    if tag != 0x30 {
        return None;
    }
    let inner = &der[hdr..];

    // Read n (INTEGER)
    let (tag, n_len, n_hdr) = der_read_tag_length(inner)?;
    if tag != 0x02 {
        return None;
    }
    let mut n_bytes = &inner[n_hdr..n_hdr + n_len];
    // Strip leading zero byte (ASN.1 sign byte)
    if !n_bytes.is_empty() && n_bytes[0] == 0 {
        n_bytes = &n_bytes[1..];
    }

    let after_n = &inner[n_hdr + n_len..];

    // Read e (INTEGER)
    let (tag, e_len, e_hdr) = der_read_tag_length(after_n)?;
    if tag != 0x02 {
        return None;
    }
    let mut e_bytes = &after_n[e_hdr..e_hdr + e_len];
    if !e_bytes.is_empty() && e_bytes[0] == 0 {
        e_bytes = &e_bytes[1..];
    }

    Some((b64_url_encode(n_bytes), b64_url_encode(e_bytes)))
}

// ═══════════════════════════════════════════════════════════════════
//  Section 12: Handlers
// ═══════════════════════════════════════════════════════════════════

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
        state
            .audit_log
            .record(AuditEvent {
                timestamp: Utc::now(),
                subject: String::new(),
                tenant: tenant_name.clone(),
                project: request.scope.project.clone(),
                action: "token_request".into(),
                decision: AuditDecision::Deny,
                reason: "rate_limited".into(),
                request_id: request_id.to_string(),
                source_ip: String::new(),
            })
            .await;
        return Err(RegistryError::RateLimitExceeded);
    }

    // Authenticate the caller
    let subject = match authenticate_request(&state, &headers, &request.identity_token).await {
        Ok(sub) => sub,
        Err(e) => {
            state
                .audit_log
                .record(AuditEvent {
                    timestamp: Utc::now(),
                    subject: String::new(),
                    tenant: tenant_name.clone(),
                    project: request.scope.project.clone(),
                    action: "token_request".into(),
                    decision: AuditDecision::Deny,
                    reason: format!("auth_failed: {e}"),
                    request_id: request_id.to_string(),
                    source_ip: String::new(),
                })
                .await;
            return Err(e);
        }
    };
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
        state
            .audit_log
            .record(AuditEvent {
                timestamp: Utc::now(),
                subject: subject.clone(),
                tenant: tenant_name.clone(),
                project: request.scope.project.clone(),
                action: format!("token_request:{:?}", request.scope.actions),
                decision: AuditDecision::Deny,
                reason: format!("role '{role:?}' insufficient"),
                request_id: request_id.to_string(),
                source_ip: String::new(),
            })
            .await;
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
            actions: allowed_actions.clone(),
        }],
    };

    let token = sign_token(&state, &claims)?;
    increment_token_issued();

    state
        .audit_log
        .record(AuditEvent {
            timestamp: Utc::now(),
            subject: subject.clone(),
            tenant: tenant_name,
            project: request.scope.project,
            action: format!("token_issued:{allowed_actions:?}"),
            decision: AuditDecision::Allow,
            reason: format!("role={role:?}"),
            request_id: request_id.to_string(),
            source_ip: String::new(),
        })
        .await;

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

/// POST /auth/token — Docker OAuth2-compatible form-encoded token exchange.
/// Docker clients POST form data when using the Www-Authenticate challenge flow.
async fn post_token_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Form(form): axum::extract::Form<DockerTokenQuery>,
) -> Result<Json<DockerTokenResponse>, RegistryError> {
    // Delegate to the GET handler logic with the same query params
    get_token_inner(state, headers, form).await
}

/// GET /auth/token — Docker-compatible token endpoint.
async fn get_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<DockerTokenQuery>,
) -> Result<Json<DockerTokenResponse>, RegistryError> {
    get_token_inner(state, headers, query).await
}

/// Shared token issuance logic for GET and POST (form-encoded) flows.
async fn get_token_inner(
    state: AppState,
    headers: HeaderMap,
    query: DockerTokenQuery,
) -> Result<Json<DockerTokenResponse>, RegistryError> {
    increment_auth_requests();

    let request_id = Uuid::new_v4();
    let span = tracing::info_span!(
        "get_token_docker",
        request_id = %request_id,
        scope = ?query.scope,
    );
    let _guard = span.enter();

    // Docker sends credentials via Basic auth header or form body (OAuth2 flow)
    let subject = if let Some((username, password)) = extract_basic_auth(&headers) {
        authenticate_basic(&state, &username, &password).unwrap_or_else(|_| "anonymous".to_string())
    } else if query.username.is_some() && query.password.is_some() {
        let u = query.username.as_deref().unwrap();
        let p = query.password.as_deref().unwrap();
        authenticate_basic(&state, u, p).unwrap_or_else(|_| "anonymous".to_string())
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
        sub: subject.clone(),
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

    state
        .audit_log
        .record(AuditEvent {
            timestamp: Utc::now(),
            subject,
            tenant: requested_scope.tenant,
            project: requested_scope.project,
            action: "docker_token_issued".into(),
            decision: AuditDecision::Allow,
            reason: format!("role={role:?}"),
            request_id: request_id.to_string(),
            source_ip: String::new(),
        })
        .await;

    Ok(Json(DockerTokenResponse {
        access_token: token.clone(),
        token,
        expires_in: ttl,
        issued_at: now.to_rfc3339(),
    }))
}

// ── GitHub Actions OIDC token exchange ────────────────────────────

/// POST /auth/github-actions/token — Exchange a GitHub Actions OIDC token for a NebulaCR token.
async fn github_actions_token(
    State(state): State<AppState>,
    Json(request): Json<GitHubOidcTokenRequest>,
) -> Result<Json<TokenResponse>, RegistryError> {
    increment_auth_requests();

    let request_id = Uuid::new_v4();
    let span = tracing::info_span!(
        "github_actions_token",
        request_id = %request_id,
        tenant = %request.scope.tenant,
        project = %request.scope.project,
    );
    let _guard = span.enter();

    let github_config = state
        .github_oidc_config
        .as_ref()
        .ok_or_else(|| RegistryError::Internal("GitHub OIDC integration not configured".into()))?;

    // Validate the GitHub OIDC token
    let gh_claims = validate_github_oidc_token(
        &state.oidc_manager,
        &request.token,
        &github_config.issuer_url,
    )
    .await?;

    info!(
        repository = %gh_claims.repository,
        repository_owner = %gh_claims.repository_owner,
        actor = %gh_claims.actor,
        workflow = %gh_claims.workflow,
        "GitHub OIDC token validated"
    );

    // Check allowed orgs
    if !github_config.allowed_orgs.is_empty()
        && !github_config
            .allowed_orgs
            .contains(&gh_claims.repository_owner)
    {
        increment_auth_failures("github_org_not_allowed");
        state
            .audit_log
            .record(AuditEvent {
                timestamp: Utc::now(),
                subject: gh_claims.repository.clone(),
                tenant: request.scope.tenant.clone(),
                project: Some(request.scope.project.clone()),
                action: "github_token_exchange".into(),
                decision: AuditDecision::Deny,
                reason: format!("org '{}' not in allowed list", gh_claims.repository_owner),
                request_id: request_id.to_string(),
                source_ip: String::new(),
            })
            .await;
        return Err(RegistryError::Forbidden {
            reason: format!(
                "GitHub organization '{}' is not allowed",
                gh_claims.repository_owner
            ),
        });
    }

    // Check allowed repos
    if !github_config.allowed_repos.is_empty()
        && !github_config.allowed_repos.contains(&gh_claims.repository)
    {
        increment_auth_failures("github_repo_not_allowed");
        state
            .audit_log
            .record(AuditEvent {
                timestamp: Utc::now(),
                subject: gh_claims.repository.clone(),
                tenant: request.scope.tenant.clone(),
                project: Some(request.scope.project.clone()),
                action: "github_token_exchange".into(),
                decision: AuditDecision::Deny,
                reason: format!("repo '{}' not in allowed list", gh_claims.repository),
                request_id: request_id.to_string(),
                source_ip: String::new(),
            })
            .await;
        return Err(RegistryError::Forbidden {
            reason: format!(
                "GitHub repository '{}' is not allowed",
                gh_claims.repository
            ),
        });
    }

    // Map GitHub claims to NebulaCR subject
    let subject = format!("github:{}", gh_claims.repository);

    // Resolve tenant
    let tenants = state.tenants.read().await;
    let tenant = tenants.get(&request.scope.tenant).ok_or_else(|| {
        increment_auth_failures("tenant_not_found");
        RegistryError::TenantNotFound {
            tenant: request.scope.tenant.clone(),
        }
    })?;
    let tenant_id = tenant.id;
    drop(tenants);

    // Resolve project
    let projects = state.projects.read().await;
    let project = projects
        .get(&(tenant_id, request.scope.project.clone()))
        .ok_or_else(|| {
            increment_auth_failures("project_not_found");
            RegistryError::ProjectNotFound {
                project: request.scope.project.clone(),
            }
        })?;
    let project_id = Some(project.id);
    drop(projects);

    // Determine role — use configured default or resolve from policies
    let role = match github_config.default_role.as_str() {
        "admin" => Role::Admin,
        "maintainer" => Role::Maintainer,
        _ => Role::Reader,
    };

    // Filter requested actions by role
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

    // Issue a short-lived token (shorter TTL for CI)
    let now = Utc::now();
    let ttl = std::cmp::min(state.config.auth.token_ttl_seconds, 900); // max 15 min for CI
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
            repository: String::new(),
            actions: allowed_actions.clone(),
        }],
    };

    let token = sign_token(&state, &claims)?;
    increment_token_issued();

    state
        .audit_log
        .record(AuditEvent {
            timestamp: Utc::now(),
            subject: subject.clone(),
            tenant: request.scope.tenant,
            project: Some(request.scope.project),
            action: format!("github_token_issued:{allowed_actions:?}"),
            decision: AuditDecision::Allow,
            reason: format!(
                "repo={}, actor={}, workflow={}",
                gh_claims.repository, gh_claims.actor, gh_claims.workflow
            ),
            request_id: request_id.to_string(),
            source_ip: String::new(),
        })
        .await;

    info!(subject = %subject, "GitHub Actions token issued");

    Ok(Json(TokenResponse {
        token,
        expires_in: ttl,
        issued_at: now,
    }))
}

/// Validate a GitHub Actions OIDC token.
async fn validate_github_oidc_token(
    oidc_manager: &OidcProviderManager,
    token: &str,
    expected_issuer: &str,
) -> Result<GitHubTokenClaims, RegistryError> {
    // Check if the OIDC manager has a provider for GitHub — if so, use real validation
    let providers = oidc_manager.providers.read().await;
    let has_github_provider = providers.contains_key(expected_issuer);
    drop(providers);

    if has_github_provider
        || oidc_manager
            .configs
            .iter()
            .any(|c| c.issuer_url == expected_issuer)
    {
        // Real JWKS validation via the OIDC manager
        let _ = oidc_manager.validate_token(token).await?;
    } else {
        // No provider configured for GitHub — decode without verification but warn
        warn!(
            "GitHub OIDC provider not configured in OIDC providers; \
             falling back to unverified decode (configure the GitHub issuer for production)"
        );
    }

    // Parse GitHub-specific claims
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(RegistryError::TokenInvalid {
            reason: "GitHub OIDC token is not a valid JWT".into(),
        });
    }
    let payload_bytes = b64_url_decode(parts[1]).map_err(|_| RegistryError::TokenInvalid {
        reason: "invalid base64 in GitHub token payload".into(),
    })?;
    let claims: GitHubTokenClaims =
        serde_json::from_slice(&payload_bytes).map_err(|e| RegistryError::TokenInvalid {
            reason: format!("failed to parse GitHub token claims: {e}"),
        })?;

    // Verify issuer
    if claims.iss != expected_issuer {
        return Err(RegistryError::TokenInvalid {
            reason: format!(
                "GitHub token issuer mismatch: expected {expected_issuer}, got {}",
                claims.iss
            ),
        });
    }

    // Check expiry
    if let Some(exp) = claims.exp
        && Utc::now().timestamp() > exp
    {
        return Err(RegistryError::TokenExpired);
    }

    Ok(claims)
}

// ── Token Introspection ───────────────────────────────────────────

/// Request body for introspection.
#[derive(Debug, Deserialize)]
struct IntrospectionRequest {
    token: String,
}

/// POST /auth/introspect — RFC 7662 compatible token introspection.
async fn introspect_token(
    State(state): State<AppState>,
    Json(request): Json<IntrospectionRequest>,
) -> Json<IntrospectionResponse> {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[&state.config.auth.audience]);
    validation.set_issuer(&[&state.config.auth.issuer]);

    match jsonwebtoken::decode::<TokenClaims>(&request.token, &state.decoding_key, &validation) {
        Ok(data) => {
            let claims = data.claims;
            let scope_str = claims
                .scopes
                .iter()
                .map(|s| {
                    let actions: Vec<String> = s.actions.iter().map(|a| format!("{a:?}")).collect();
                    if s.repository.is_empty() {
                        actions.join(",")
                    } else {
                        format!("{}:{}", s.repository, actions.join(","))
                    }
                })
                .collect::<Vec<_>>()
                .join(" ");

            Json(IntrospectionResponse {
                active: true,
                sub: Some(claims.sub),
                tenant_id: Some(claims.tenant_id),
                project_id: claims.project_id,
                exp: Some(claims.exp),
                iat: Some(claims.iat),
                scope: Some(scope_str),
                iss: Some(claims.iss),
                jti: Some(claims.jti),
            })
        }
        Err(_) => Json(IntrospectionResponse {
            active: false,
            sub: None,
            tenant_id: None,
            project_id: None,
            exp: None,
            iat: None,
            scope: None,
            iss: None,
            jti: None,
        }),
    }
}

// ── JWKS Publishing ───────────────────────────────────────────────

/// GET /auth/.well-known/jwks.json — Publish NebulaCR's own public key as JWKS.
async fn jwks_endpoint(State(state): State<AppState>) -> Json<JwksResponse> {
    let components = parse_rsa_public_key_components(&state.public_key_pem);

    match components {
        Some((n, e)) => {
            // Compute a kid from the key
            let kid = {
                let digest = Sha256::digest(state.public_key_pem.as_slice());
                hex::encode(&digest[..8])
            };

            Json(JwksResponse {
                keys: vec![Jwk {
                    kty: "RSA".into(),
                    key_use: "sig".into(),
                    kid,
                    alg: "RS256".into(),
                    n,
                    e,
                }],
            })
        }
        None => {
            warn!("failed to parse public key for JWKS endpoint");
            Json(JwksResponse { keys: vec![] })
        }
    }
}

// ── Audit Log endpoint ────────────────────────────────────────────

/// GET /auth/audit — Returns recent audit events.
async fn audit_endpoint(State(state): State<AppState>) -> Json<Vec<AuditEvent>> {
    Json(state.audit_log.recent().await)
}

// ── Health & Metrics ──────────────────────────────────────────────

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

// ═══════════════════════════════════════════════════════════════════
//  Section 13: JWT key loading
// ═══════════════════════════════════════════════════════════════════

/// Load RSA keys — tries Vault first, then disk, then embedded dev keys.
/// Returns (encoding_key, decoding_key, public_key_pem_bytes).
async fn load_jwt_keys(
    config: &RegistryConfig,
    vault_client: &Option<VaultClient>,
) -> (EncodingKey, DecodingKey, Vec<u8>) {
    // Try Vault first
    if let Some(vault) = vault_client
        && vault.is_available()
    {
        info!("attempting to load JWT keys from Vault");
        match (
            vault.read_signing_key().await,
            vault.read_verification_key().await,
        ) {
            (Ok(priv_pem), Ok(pub_pem)) => {
                if let (Ok(enc), Ok(dec)) = (
                    EncodingKey::from_rsa_pem(&priv_pem),
                    DecodingKey::from_rsa_pem(&pub_pem),
                ) {
                    info!("loaded JWT signing keys from Vault");
                    return (enc, dec, pub_pem);
                }
                warn!("Vault returned keys but PEM parsing failed; falling back to file");
            }
            (Err(e1), _) => {
                warn!(error = %e1, "failed to read signing key from Vault; falling back to file");
            }
            (_, Err(e2)) => {
                warn!(error = %e2, "failed to read verification key from Vault; falling back to file");
            }
        }
    }

    // Try configured file paths
    if let Ok(priv_pem) = std::fs::read(&config.auth.signing_key_path)
        && let Ok(pub_pem) = std::fs::read(&config.auth.verification_key_path)
        && let Ok(enc) = EncodingKey::from_rsa_pem(&priv_pem)
        && let Ok(dec) = DecodingKey::from_rsa_pem(&pub_pem)
    {
        info!("loaded JWT signing keys from configured paths");
        return (enc, dec, pub_pem);
    }

    // Fall back to embedded development keys
    warn!(
        "configured key paths not found — using embedded development RSA keys (NOT FOR PRODUCTION)"
    );
    let priv_pem = include_bytes!("dev_key.pem");
    let pub_pem = include_bytes!("dev_key.pub.pem");
    let enc = EncodingKey::from_rsa_pem(priv_pem).expect("embedded dev private key must be valid");
    let dec = DecodingKey::from_rsa_pem(pub_pem).expect("embedded dev public key must be valid");
    (enc, dec, pub_pem.to_vec())
}

// ═══════════════════════════════════════════════════════════════════
//  Section 14: Seed data
// ═══════════════════════════════════════════════════════════════════

type TenantMap = HashMap<String, Tenant>;
type ProjectMap = HashMap<(Uuid, String), Project>;

fn seed_demo_data() -> (TenantMap, ProjectMap, Vec<AccessPolicy>) {
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

// ═══════════════════════════════════════════════════════════════════
//  Section 15: Main
// ═══════════════════════════════════════════════════════════════════

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

    // Load configuration from file if --config flag provided, otherwise defaults
    let mut config = {
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
                    serde_yaml::from_str::<RegistryConfig>(&contents).unwrap_or_else(|e| {
                        tracing::warn!("Failed to parse config {path}: {e}, using defaults");
                        RegistryConfig::default()
                    })
                }
                Err(e) => {
                    tracing::warn!("Failed to read config {path}: {e}, using defaults");
                    RegistryConfig::default()
                }
            }
        } else {
            RegistryConfig::default()
        }
    };

    // Configure bootstrap admin for development (password: "admin")
    config.auth.bootstrap_admin = Some(BootstrapAdmin {
        username: "admin".into(),
        password_hash: sha256_hex("admin"),
    });

    // Configure default GitHub OIDC (can be overridden by config file)
    if config.github_oidc.is_none() {
        config.github_oidc = Some(GitHubOidcConfig::default());
    }

    // Initialize Vault client (if configured)
    let vault_client = VaultClient::new(config.vault.as_ref());

    // Load JWT signing keys (Vault → file → embedded dev keys)
    let (encoding_key, decoding_key, public_key_pem) = load_jwt_keys(&config, &vault_client).await;

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
    metrics::counter!("registry_auth_failures_total", "reason" => "github_org_not_allowed")
        .increment(0);
    metrics::counter!("registry_auth_failures_total", "reason" => "github_repo_not_allowed")
        .increment(0);

    // Set up keyed rate limiter (per-tenant, tokens per minute)
    let rpm = config.rate_limit.token_issue_rpm;
    let rate_limiter = Arc::new(RateLimiter::keyed(Quota::per_minute(
        NonZeroU32::new(rpm).unwrap_or(NonZeroU32::new(60).unwrap()),
    )));

    // Initialize OIDC Provider Manager
    let oidc_manager = Arc::new(OidcProviderManager::new(
        config.auth.oidc_providers.clone(),
        3600, // refresh JWKS every hour
    ));

    // Perform initial OIDC discovery (non-blocking — failures are logged)
    oidc_manager.discover_all().await;

    // Initialize audit log
    let audit_log = Arc::new(AuditLog::new());

    // Seed in-memory data stores with demo data
    let (tenants, projects, policies) = seed_demo_data();

    let state = AppState {
        encoding_key,
        decoding_key,
        public_key_pem: Arc::new(public_key_pem),
        tenants: Arc::new(RwLock::new(tenants)),
        projects: Arc::new(RwLock::new(projects)),
        access_policies: Arc::new(RwLock::new(policies)),
        config: config.clone(),
        rate_limiter,
        metrics_handle,
        oidc_manager,
        audit_log,
        github_oidc_config: config.github_oidc.clone(),
    };

    // Build Axum router
    let app = Router::new()
        // Existing endpoints
        .route("/auth/token", post(post_token_form).get(get_token))
        // JSON token request endpoint (API clients)
        .route("/auth/token/json", post(post_token))
        // New endpoints
        .route("/auth/github-actions/token", post(github_actions_token))
        .route("/auth/introspect", post(introspect_token))
        .route("/auth/.well-known/jwks.json", get(jwks_endpoint))
        .route("/auth/audit", get(audit_endpoint))
        // Infrastructure
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
