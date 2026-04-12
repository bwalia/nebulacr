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

use std::collections::{HashMap, HashSet};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{delete, get, patch, post},
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
    AuditDecision, AuditEvent, CiTokenRequest, CredentialExchangeRequest,
    CredentialExchangeResponse, DockerTokenResponse, GitHubOidcTokenRequest, GitHubTokenClaims,
    IntrospectionResponse, Jwk, JwksResponse, OidcProviderConfig, OidcSession, OidcUserClaims,
    RefreshToken, RequestedScope, RobotAccount, ScimError, ScimGroup, ScimGroupRef,
    ScimListResponse, ScimMember, ScimMeta, ScimPatchOp, ScimUser, TokenClaims, TokenRequest,
    TokenResponse, TokenScope, UserRecord,
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
    /// Provisioned user records (auto-created on OIDC login).
    users: Arc<RwLock<HashMap<String, UserRecord>>>,
    /// Active OIDC authorization code flow sessions.
    oidc_sessions: Arc<RwLock<HashMap<String, OidcSession>>>,
    /// Robot/service accounts for machine identity.
    robot_accounts: Arc<RwLock<HashMap<String, RobotAccount>>>,
    /// Issued refresh tokens.
    refresh_tokens: Arc<RwLock<HashMap<String, RefreshToken>>>,
    /// Set of revoked token JTIs.
    revoked_tokens: Arc<RwLock<HashSet<String>>>,
    /// SCIM-managed groups (group_id -> ScimGroup).
    scim_groups: Arc<RwLock<HashMap<String, ScimGroup>>>,
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

/// Simple percent-encoding for URL query parameters.
fn url_encode(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len() * 3);
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => {
                encoded.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    encoded
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
    // 3 segments: tenant/project/repo (NebulaCR multi-tenant)
    // 2 segments: project/repo (standard Docker — uses default tenant "_")
    let name_parts: Vec<&str> = name.splitn(3, '/').collect();
    let (tenant, project, repository) = match name_parts.len() {
        3 => (
            name_parts[0].to_string(),
            Some(name_parts[1].to_string()),
            Some(name_parts[2].to_string()),
        ),
        2 => (
            "_".to_string(),
            Some(name_parts[0].to_string()),
            Some(name_parts[1].to_string()),
        ),
        1 => ("_".to_string(), None, Some(name_parts[0].to_string())),
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

/// Authenticate a request: try bootstrap admin, robot accounts (Basic auth), then OIDC identity token.
async fn authenticate_request(
    state: &AppState,
    headers: &HeaderMap,
    identity_token: &str,
) -> Result<String, RegistryError> {
    // Try Basic auth: bootstrap admin first, then robot accounts
    if let Some((username, password)) = extract_basic_auth(headers) {
        // Bootstrap admin
        if let Ok(subject) = authenticate_basic(state, &username, &password) {
            provision_user(state, &subject, None, None, vec![], "basic").await;
            return Ok(subject);
        }
        // Robot accounts: username format is "robot:{name}"
        if let Some(robot_name) = username.strip_prefix("robot:") {
            if let Ok(subject) = authenticate_robot(state, robot_name, &password).await {
                return Ok(subject);
            }
        }
    }

    // Validate the OIDC/identity JWT
    let claims = validate_identity_token(&state.oidc_manager, identity_token).await?;

    // Auto-provision user from OIDC claims
    provision_user(state, &claims.sub, None, None, vec![], "oidc").await;

    Ok(claims.sub)
}

/// Authenticate a robot account via Basic auth.
async fn authenticate_robot(
    state: &AppState,
    name: &str,
    secret: &str,
) -> Result<String, RegistryError> {
    let robots = state.robot_accounts.read().await;
    for robot in robots.values() {
        if robot.name == name && robot.enabled {
            // Check expiry
            if let Some(expires_at) = robot.expires_at {
                if Utc::now() > expires_at {
                    increment_auth_failures("robot_expired");
                    return Err(RegistryError::Unauthorized);
                }
            }
            // Verify secret (SHA-256 hash comparison)
            let secret_hash = sha256_hex(secret);
            if constant_time_eq(secret_hash.as_bytes(), robot.secret_hash.as_bytes()) {
                metrics::counter!("registry_robot_auth_total", "robot" => name.to_owned()).increment(1);
                let subject = format!("robot:{}", name);
                let robot_id = robot.id.to_string();
                info!(robot = %name, "robot account authenticated");
                // Update last_used (drop read lock, take write lock)
                drop(robots);
                let mut robots_w = state.robot_accounts.write().await;
                if let Some(r) = robots_w.get_mut(&robot_id) {
                    r.last_used = Some(Utc::now());
                }
                return Ok(subject);
            }
        }
    }
    increment_auth_failures("invalid_robot_credentials");
    Err(RegistryError::Unauthorized)
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

    // Check explicit access policies first (primary)
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
    drop(policies);

    if let Some(role) = best_role {
        return role;
    }

    // Secondary: check group-based mappings from enterprise config
    let group_role = resolve_role_from_groups(state, subject, tenant_id).await;
    if let Some(role) = group_role {
        return role;
    }

    // Authenticated users default to Reader if no explicit policy found
    Role::Reader
}

/// Check if subject's groups match any GroupRoleMapping and return the highest-privilege role.
async fn resolve_role_from_groups(
    state: &AppState,
    subject: &str,
    _tenant_id: Uuid,
) -> Option<Role> {
    let users = state.users.read().await;
    let user = users.get(subject)?;
    let user_groups = &user.groups;

    if user_groups.is_empty() {
        return None;
    }

    let mappings = &state.config.enterprise.group_role_mappings;
    if mappings.is_empty() {
        return None;
    }

    let mut best_role: Option<Role> = None;
    for mapping in mappings {
        for group in user_groups {
            if group_matches(&mapping.group, group) {
                let role = mapping.role;
                metrics::counter!("registry_group_mapping_hits_total", "group" => mapping.group.clone()).increment(1);
                best_role = Some(match best_role {
                    None => role,
                    Some(existing) => higher_privilege_role(existing, role),
                });
            }
        }
    }

    best_role
}

/// Match a group name against a pattern (exact or glob with *).
fn group_matches(pattern: &str, group: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if !pattern.contains('*') {
        return pattern == group;
    }
    // Simple glob matching
    let parts: Vec<&str> = pattern.split('*').collect();
    let mut pos = 0usize;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if let Some(found) = group[pos..].find(part) {
            if i == 0 && found != 0 && !pattern.starts_with('*') {
                return false;
            }
            pos += found + part.len();
        } else {
            return false;
        }
    }
    if !pattern.ends_with('*') {
        return pos == group.len();
    }
    true
}

/// Return the higher-privilege of two roles.
fn higher_privilege_role(a: Role, b: Role) -> Role {
    match (a, b) {
        (Role::Admin, _) | (_, Role::Admin) => Role::Admin,
        (Role::Maintainer, _) | (_, Role::Maintainer) => Role::Maintainer,
        _ => Role::Reader,
    }
}

/// Auto-provision or update a user record after OIDC authentication.
async fn provision_user(
    state: &AppState,
    subject: &str,
    email: Option<String>,
    display_name: Option<String>,
    groups: Vec<String>,
    auth_method: &str,
) {
    let now = Utc::now();
    let mut users = state.users.write().await;
    if let Some(user) = users.get_mut(subject) {
        user.last_login = now;
        user.login_count += 1;
        user.groups = groups;
        if email.is_some() {
            user.email = email;
        }
        if display_name.is_some() {
            user.display_name = display_name;
        }
    } else if state.config.enterprise.auto_provision_users {
        users.insert(
            subject.to_string(),
            UserRecord {
                subject: subject.to_string(),
                email,
                display_name,
                groups,
                auth_method: auth_method.to_string(),
                first_seen: now,
                last_login: now,
                login_count: 1,
            },
        );
        info!(subject = %subject, "auto-provisioned new user");
    }
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
                auth_method: None,
                groups: None,
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
                    auth_method: None,
                    groups: None,
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
                auth_method: None,
                groups: None,
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
            auth_method: None,
            groups: None,
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
        // Try bootstrap admin first, then robot accounts
        if let Ok(sub) = authenticate_basic(&state, &username, &password) {
            sub
        } else if let Some(robot_name) = username.strip_prefix("robot:") {
            authenticate_robot(&state, robot_name, &password).await.unwrap_or_else(|_| "anonymous".to_string())
        } else {
            "anonymous".to_string()
        }
    } else if query.username.is_some() && query.password.is_some() {
        let u = query.username.as_deref().unwrap();
        let p = query.password.as_deref().unwrap();
        if let Ok(sub) = authenticate_basic(&state, u, p) {
            sub
        } else if let Some(robot_name) = u.strip_prefix("robot:") {
            authenticate_robot(&state, robot_name, p).await.unwrap_or_else(|_| "anonymous".to_string())
        } else {
            "anonymous".to_string()
        }
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
            auth_method: None,
            groups: None,
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
                auth_method: None,
                groups: None,
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
                auth_method: None,
                groups: None,
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
            auth_method: Some("ci_oidc".into()),
            groups: None,
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

/// POST /auth/audit/export — Export all audit events as JSONL.
async fn audit_export(State(state): State<AppState>) -> impl IntoResponse {
    let events = state.audit_log.recent().await;
    let mut lines = String::new();
    for event in &events {
        if let Ok(line) = serde_json::to_string(event) {
            lines.push_str(&line);
            lines.push('\n');
        }
    }
    (
        StatusCode::OK,
        [("content-type", "application/x-ndjson")],
        lines,
    )
}

// ═══════════════════════════════════════════════════════════════════
//  Enterprise Auth Handlers
// ═══════════════════════════════════════════════════════════════════

// ── OIDC Authorization Code Flow ─────────────────────────────────

#[derive(Debug, Deserialize)]
struct OidcLoginQuery {
    /// Name of the OIDC provider (matches issuer_url or display_name).
    provider: String,
    /// URI to redirect back to after auth.
    redirect_uri: String,
}

/// GET /auth/oidc/login — Redirect to OIDC provider for login.
async fn oidc_login(
    State(state): State<AppState>,
    Query(query): Query<OidcLoginQuery>,
) -> Result<impl IntoResponse, RegistryError> {
    // Find the provider config
    let provider_config = state
        .config
        .auth
        .oidc_providers
        .iter()
        .find(|p| {
            p.issuer_url == query.provider
                || p.display_name.as_deref() == Some(&query.provider)
                || p.client_id == query.provider
        })
        .cloned()
        .ok_or_else(|| RegistryError::Internal(format!(
            "OIDC provider '{}' not configured",
            query.provider
        )))?;

    // Generate PKCE code verifier + challenge
    let pkce_verifier: String = (0..64)
        .map(|_| {
            let idx = rand::random::<u8>() % 62;
            if idx < 10 { (b'0' + idx) as char }
            else if idx < 36 { (b'a' + idx - 10) as char }
            else { (b'A' + idx - 36) as char }
        })
        .collect();

    let pkce_challenge = {
        let digest = Sha256::digest(pkce_verifier.as_bytes());
        b64_url_encode(&digest)
    };

    // Generate random state
    let state_value = Uuid::new_v4().to_string();

    // Store session
    let session = OidcSession {
        state: state_value.clone(),
        pkce_verifier,
        provider_name: provider_config.issuer_url.clone(),
        redirect_uri: query.redirect_uri.clone(),
        created_at: Utc::now(),
    };

    {
        let mut sessions = state.oidc_sessions.write().await;
        sessions.insert(state_value.clone(), session);
    }

    // Build authorization URL
    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        provider_config.issuer_url.trim_end_matches('/')
    );

    // Fetch authorization endpoint from discovery
    let auth_endpoint = match reqwest::get(&discovery_url).await {
        Ok(resp) => {
            let doc: serde_json::Value = resp.json().await.unwrap_or_default();
            doc.get("authorization_endpoint")
                .and_then(|v| v.as_str())
                .unwrap_or(&format!(
                    "{}/authorize",
                    provider_config.issuer_url.trim_end_matches('/')
                ))
                .to_string()
        }
        Err(_) => format!(
            "{}/authorize",
            provider_config.issuer_url.trim_end_matches('/')
        ),
    };

    let callback_uri = format!(
        "{}/auth/oidc/callback",
        state.config.auth.issuer.trim_end_matches('/')
    );

    let auth_url = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&state={}&scope=openid+email+profile+groups&code_challenge={}&code_challenge_method=S256",
        auth_endpoint,
        url_encode(&provider_config.client_id),
        url_encode(&callback_uri),
        url_encode(&state_value),
        url_encode(&pkce_challenge),
    );

    metrics::counter!("registry_oidc_logins_total", "provider" => provider_config.issuer_url.clone(), "status" => "initiated").increment(1);

    Ok((
        StatusCode::FOUND,
        [("location", auth_url.as_str())],
        "Redirecting to identity provider...",
    ).into_response())
}

#[derive(Debug, Deserialize)]
struct OidcCallbackQuery {
    code: String,
    state: String,
}

/// GET /auth/oidc/callback — Handle OIDC provider callback.
async fn oidc_callback(
    State(state): State<AppState>,
    Query(query): Query<OidcCallbackQuery>,
) -> Result<impl IntoResponse, RegistryError> {
    // Look up session by state
    let session = {
        let mut sessions = state.oidc_sessions.write().await;
        sessions.remove(&query.state).ok_or_else(|| {
            RegistryError::TokenInvalid {
                reason: "invalid or expired OIDC session state".into(),
            }
        })?
    };

    // Check session is not too old (10 minutes max)
    if (Utc::now() - session.created_at).num_seconds() > 600 {
        return Err(RegistryError::TokenInvalid {
            reason: "OIDC session expired".into(),
        });
    }

    // Find provider config
    let provider_config = state
        .config
        .auth
        .oidc_providers
        .iter()
        .find(|p| p.issuer_url == session.provider_name)
        .cloned()
        .ok_or_else(|| RegistryError::Internal("OIDC provider config not found".into()))?;

    // Fetch token endpoint from discovery
    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        provider_config.issuer_url.trim_end_matches('/')
    );
    let token_endpoint = match reqwest::get(&discovery_url).await {
        Ok(resp) => {
            let doc: serde_json::Value = resp.json().await.unwrap_or_default();
            doc.get("token_endpoint")
                .and_then(|v| v.as_str())
                .unwrap_or(&format!(
                    "{}/token",
                    provider_config.issuer_url.trim_end_matches('/')
                ))
                .to_string()
        }
        Err(_) => format!(
            "{}/token",
            provider_config.issuer_url.trim_end_matches('/')
        ),
    };

    let callback_uri = format!(
        "{}/auth/oidc/callback",
        state.config.auth.issuer.trim_end_matches('/')
    );

    // Exchange code for tokens
    let http_client = reqwest::Client::new();
    let mut form = HashMap::new();
    form.insert("grant_type", "authorization_code".to_string());
    form.insert("code", query.code.clone());
    form.insert("redirect_uri", callback_uri);
    form.insert("client_id", provider_config.client_id.clone());
    form.insert("code_verifier", session.pkce_verifier.clone());
    if let Some(ref secret) = provider_config.client_secret {
        form.insert("client_secret", secret.clone());
    }

    let token_resp = http_client
        .post(&token_endpoint)
        .form(&form)
        .send()
        .await
        .map_err(|e| RegistryError::Internal(format!("token exchange failed: {e}")))?;

    if !token_resp.status().is_success() {
        let body = token_resp.text().await.unwrap_or_default();
        metrics::counter!("registry_oidc_logins_total", "provider" => provider_config.issuer_url.clone(), "status" => "failure").increment(1);
        return Err(RegistryError::Internal(format!(
            "token exchange returned error: {body}"
        )));
    }

    let token_data: serde_json::Value = token_resp
        .json()
        .await
        .map_err(|e| RegistryError::Internal(format!("failed to parse token response: {e}")))?;

    let id_token = token_data
        .get("id_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| RegistryError::Internal("no id_token in token response".into()))?;

    // Extract claims from ID token (decode payload without full verification since we just exchanged it)
    let parts: Vec<&str> = id_token.split('.').collect();
    if parts.len() != 3 {
        return Err(RegistryError::TokenInvalid {
            reason: "id_token is not a valid JWT".into(),
        });
    }
    let payload_bytes = b64_url_decode(parts[1]).map_err(|_| RegistryError::TokenInvalid {
        reason: "invalid base64 in id_token payload".into(),
    })?;
    let oidc_claims: OidcUserClaims =
        serde_json::from_slice(&payload_bytes).map_err(|e| RegistryError::TokenInvalid {
            reason: format!("failed to parse OIDC claims: {e}"),
        })?;

    // Check allowed groups
    if !provider_config.allowed_groups.is_empty() {
        let has_allowed = oidc_claims
            .groups
            .iter()
            .any(|g| provider_config.allowed_groups.contains(g));
        if !has_allowed {
            metrics::counter!("registry_oidc_logins_total", "provider" => provider_config.issuer_url.clone(), "status" => "failure").increment(1);
            return Err(RegistryError::Forbidden {
                reason: "user is not a member of any allowed group".into(),
            });
        }
    }

    // Auto-provision user
    provision_user(
        &state,
        &oidc_claims.sub,
        oidc_claims.email.clone(),
        oidc_claims.name.clone().or(oidc_claims.preferred_username.clone()),
        oidc_claims.groups.clone(),
        "oidc",
    )
    .await;

    // Resolve tenant from group mappings or use default
    let tenants = state.tenants.read().await;
    let (tenant_name, tenant_id) = tenants
        .iter()
        .next()
        .map(|(name, t)| (name.clone(), t.id))
        .unwrap_or_else(|| ("demo".to_string(), Uuid::new_v4()));
    drop(tenants);

    // Resolve role from group mappings
    let role = resolve_role(&state, &oidc_claims.sub, tenant_id, None).await;

    // Issue NebulaCR JWT
    let now = Utc::now();
    let ttl = state.config.auth.token_ttl_seconds;
    let claims = TokenClaims {
        iss: state.config.auth.issuer.clone(),
        sub: oidc_claims.sub.clone(),
        aud: state.config.auth.audience.clone(),
        exp: now.timestamp() + ttl as i64,
        iat: now.timestamp(),
        jti: Uuid::new_v4().to_string(),
        tenant_id,
        project_id: None,
        role,
        scopes: vec![],
    };

    let token = sign_token(&state, &claims)?;
    increment_token_issued();

    metrics::counter!("registry_oidc_logins_total", "provider" => provider_config.issuer_url.clone(), "status" => "success").increment(1);

    state
        .audit_log
        .record(AuditEvent {
            timestamp: Utc::now(),
            subject: oidc_claims.sub.clone(),
            tenant: tenant_name,
            project: None,
            action: "oidc_login".into(),
            decision: AuditDecision::Allow,
            reason: format!("provider={}, role={role:?}", provider_config.issuer_url),
            request_id: Uuid::new_v4().to_string(),
            source_ip: String::new(),
            auth_method: Some("oidc".into()),
            groups: Some(oidc_claims.groups.clone()),
        })
        .await;

    // Redirect to redirect_uri with token
    let redirect = format!(
        "{}?token={}&expires_in={}",
        session.redirect_uri,
        url_encode(&token),
        ttl,
    );

    Ok((StatusCode::FOUND, [("location", redirect.as_str())], "").into_response())
}

// ── Generic CI OIDC Token Exchange ───────────────────────────────

/// POST /auth/ci/token — Generic CI OIDC token exchange.
async fn ci_token_exchange(
    State(state): State<AppState>,
    Json(request): Json<CiTokenRequest>,
) -> Result<Json<TokenResponse>, RegistryError> {
    increment_auth_requests();

    let request_id = Uuid::new_v4();
    let span = tracing::info_span!(
        "ci_token_exchange",
        request_id = %request_id,
        provider = %request.provider,
        tenant = %request.scope.tenant,
    );
    let _guard = span.enter();

    // Find matching CI provider config
    let ci_config = state
        .config
        .enterprise
        .ci_providers
        .iter()
        .find(|p| p.name == request.provider)
        .cloned()
        .ok_or_else(|| RegistryError::Internal(format!(
            "CI OIDC provider '{}' not configured",
            request.provider
        )))?;

    // Validate the OIDC token against the provider's JWKS
    // First check if the OIDC manager has this provider, if not try to validate generically
    let providers = state.oidc_manager.providers.read().await;
    let has_provider = providers.contains_key(&ci_config.issuer_url);
    drop(providers);

    if has_provider
        || state
            .oidc_manager
            .configs
            .iter()
            .any(|c| c.issuer_url == ci_config.issuer_url)
    {
        let _ = state.oidc_manager.validate_token(&request.token).await?;
    } else {
        warn!(
            provider = %request.provider,
            "CI OIDC provider not in OIDC manager; falling back to unverified decode"
        );
    }

    // Parse CI token claims
    let parts: Vec<&str> = request.token.split('.').collect();
    if parts.len() != 3 {
        return Err(RegistryError::TokenInvalid {
            reason: "CI OIDC token is not a valid JWT".into(),
        });
    }
    let payload_bytes = b64_url_decode(parts[1]).map_err(|_| RegistryError::TokenInvalid {
        reason: "invalid base64 in CI token payload".into(),
    })?;
    let ci_claims: serde_json::Value =
        serde_json::from_slice(&payload_bytes).map_err(|e| RegistryError::TokenInvalid {
            reason: format!("failed to parse CI token claims: {e}"),
        })?;

    // Verify issuer
    let token_issuer = ci_claims
        .get("iss")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if token_issuer != ci_config.issuer_url {
        return Err(RegistryError::TokenInvalid {
            reason: format!(
                "CI token issuer mismatch: expected {}, got {}",
                ci_config.issuer_url, token_issuer
            ),
        });
    }

    // Check expiry
    if let Some(exp) = ci_claims.get("exp").and_then(|v| v.as_i64()) {
        if Utc::now().timestamp() > exp {
            return Err(RegistryError::TokenExpired);
        }
    }

    // Check allowed claim filters
    for (claim_name, allowed_values) in &ci_config.allowed_claims {
        let claim_value = ci_claims
            .get(claim_name)
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !allowed_values.is_empty() && !allowed_values.iter().any(|v| v == claim_value) {
            increment_auth_failures("ci_claim_not_allowed");
            return Err(RegistryError::Forbidden {
                reason: format!(
                    "CI token claim '{}' value '{}' is not in allowed list",
                    claim_name, claim_value
                ),
            });
        }
    }

    // Build subject with prefix
    let sub = ci_claims
        .get("sub")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let subject = format!("{}{}", ci_config.subject_prefix, sub);

    // Resolve tenant
    let tenants = state.tenants.read().await;
    let tenant = tenants.get(&request.scope.tenant).ok_or_else(|| {
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
        .ok_or_else(|| RegistryError::ProjectNotFound {
            project: request.scope.project.clone(),
        })?;
    let project_id = Some(project.id);
    drop(projects);

    // Determine role
    let role = match ci_config.default_role.as_str() {
        "admin" => Role::Admin,
        "maintainer" => Role::Maintainer,
        _ => Role::Reader,
    };

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

    // Issue token with max TTL
    let now = Utc::now();
    let ttl = std::cmp::min(state.config.auth.token_ttl_seconds, ci_config.max_ttl_seconds);
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
            action: format!("ci_token_issued:{allowed_actions:?}"),
            decision: AuditDecision::Allow,
            reason: format!("provider={}, role={role:?}", request.provider),
            request_id: request_id.to_string(),
            source_ip: String::new(),
            auth_method: Some("ci_oidc".into()),
            groups: None,
        })
        .await;

    info!(subject = %subject, provider = %request.provider, "CI OIDC token issued");

    Ok(Json(TokenResponse {
        token,
        expires_in: ttl,
        issued_at: now,
    }))
}

// ── Refresh Token ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct RefreshTokenRequest {
    refresh_token: String,
}

/// POST /auth/token/refresh — Exchange a refresh token for a new access token.
async fn refresh_token_handler(
    State(state): State<AppState>,
    Json(request): Json<RefreshTokenRequest>,
) -> Result<Json<serde_json::Value>, RegistryError> {
    let refresh_tokens = state.refresh_tokens.read().await;
    let rt = refresh_tokens
        .get(&request.refresh_token)
        .ok_or_else(|| RegistryError::TokenInvalid {
            reason: "invalid refresh token".into(),
        })?
        .clone();
    drop(refresh_tokens);

    if rt.revoked {
        return Err(RegistryError::TokenInvalid {
            reason: "refresh token has been revoked".into(),
        });
    }

    if Utc::now() > rt.expires_at {
        return Err(RegistryError::TokenExpired);
    }

    // Issue new access token
    let now = Utc::now();
    let ttl = state.config.auth.token_ttl_seconds;
    let claims = TokenClaims {
        iss: state.config.auth.issuer.clone(),
        sub: rt.subject.clone(),
        aud: state.config.auth.audience.clone(),
        exp: now.timestamp() + ttl as i64,
        iat: now.timestamp(),
        jti: Uuid::new_v4().to_string(),
        tenant_id: rt.tenant_id,
        project_id: rt.project_id,
        role: rt.role,
        scopes: rt.scopes.clone(),
    };

    let token = sign_token(&state, &claims)?;
    increment_token_issued();
    metrics::counter!("registry_token_refresh_total").increment(1);

    Ok(Json(serde_json::json!({
        "token": token,
        "expires_in": ttl,
        "issued_at": now.to_rfc3339(),
    })))
}

// ── Token Revocation ─────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct TokenRevokeRequest {
    /// JTI of the token to revoke, or refresh_token ID.
    token_id: String,
}

/// POST /auth/token/revoke — Revoke a token by JTI.
async fn revoke_token_handler(
    State(state): State<AppState>,
    Json(request): Json<TokenRevokeRequest>,
) -> impl IntoResponse {
    // Add to revoked set
    {
        let mut revoked = state.revoked_tokens.write().await;
        revoked.insert(request.token_id.clone());
    }

    // Also revoke matching refresh token if it exists
    {
        let mut refresh_tokens = state.refresh_tokens.write().await;
        if let Some(rt) = refresh_tokens.get_mut(&request.token_id) {
            rt.revoked = true;
        }
    }

    metrics::counter!("registry_token_revocation_total").increment(1);

    (StatusCode::OK, Json(serde_json::json!({"status": "revoked"})))
}

/// GET /auth/token/revoked — Returns list of revoked token JTIs (for registry polling).
async fn revoked_tokens_handler(State(state): State<AppState>) -> Json<Vec<String>> {
    let revoked = state.revoked_tokens.read().await;
    Json(revoked.iter().cloned().collect())
}

// ── Robot Account CRUD ───────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct CreateRobotRequest {
    name: String,
    #[serde(default)]
    description: String,
    tenant: String,
    project: Option<String>,
    #[serde(default = "default_robot_role")]
    role: String,
    /// Expiry in seconds from now. None = no expiry.
    expires_in_seconds: Option<u64>,
}

fn default_robot_role() -> String {
    "reader".to_string()
}

/// POST /api/v1/robot-accounts — Create a new robot account.
async fn create_robot_account(
    State(state): State<AppState>,
    Json(request): Json<CreateRobotRequest>,
) -> Result<impl IntoResponse, RegistryError> {
    if !state.config.enterprise.robot_accounts_enabled {
        return Err(RegistryError::Forbidden {
            reason: "robot accounts are disabled".into(),
        });
    }

    // Generate a random secret
    let secret: String = (0..48)
        .map(|_| {
            let idx = rand::random::<u8>() % 62;
            if idx < 10 { (b'0' + idx) as char }
            else if idx < 36 { (b'a' + idx - 10) as char }
            else { (b'A' + idx - 36) as char }
        })
        .collect();

    let role = match request.role.as_str() {
        "admin" => Role::Admin,
        "maintainer" => Role::Maintainer,
        _ => Role::Reader,
    };

    let now = Utc::now();
    let robot = RobotAccount {
        id: Uuid::new_v4(),
        name: request.name.clone(),
        description: request.description,
        tenant: request.tenant,
        project: request.project,
        role,
        secret_hash: sha256_hex(&secret),
        created_at: now,
        expires_at: request.expires_in_seconds.map(|s| now + chrono::Duration::seconds(s as i64)),
        last_used: None,
        enabled: true,
    };

    let id = robot.id.to_string();
    let response = serde_json::json!({
        "id": robot.id,
        "name": robot.name,
        "secret": secret,
        "created_at": robot.created_at.to_rfc3339(),
        "expires_at": robot.expires_at.map(|t| t.to_rfc3339()),
    });

    {
        let mut robots = state.robot_accounts.write().await;
        robots.insert(id, robot);
    }

    info!(name = %request.name, "robot account created");
    Ok((StatusCode::CREATED, Json(response)))
}

/// GET /api/v1/robot-accounts — List all robot accounts.
async fn list_robot_accounts(
    State(state): State<AppState>,
) -> Json<Vec<serde_json::Value>> {
    let robots = state.robot_accounts.read().await;
    let list: Vec<serde_json::Value> = robots
        .values()
        .map(|r| {
            serde_json::json!({
                "id": r.id,
                "name": r.name,
                "description": r.description,
                "tenant": r.tenant,
                "project": r.project,
                "role": r.role,
                "created_at": r.created_at.to_rfc3339(),
                "expires_at": r.expires_at.map(|t| t.to_rfc3339()),
                "last_used": r.last_used.map(|t| t.to_rfc3339()),
                "enabled": r.enabled,
            })
        })
        .collect();
    Json(list)
}

/// DELETE /api/v1/robot-accounts/{id} — Delete a robot account.
async fn delete_robot_account(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let mut robots = state.robot_accounts.write().await;
    if robots.remove(&id).is_some() {
        info!(id = %id, "robot account deleted");
        (StatusCode::OK, Json(serde_json::json!({"status": "deleted"})))
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "robot account not found"})),
        )
    }
}

// ── Credential Exchange (Phase 4 stub) ──────────────────────────

/// POST /auth/credential-exchange — Exchange OIDC session for short-lived docker credentials.
async fn credential_exchange(
    State(state): State<AppState>,
    Json(request): Json<CredentialExchangeRequest>,
) -> Result<Json<CredentialExchangeResponse>, RegistryError> {
    // Validate the session token (treat as a NebulaCR JWT)
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[&state.config.auth.audience]);
    validation.set_issuer(&[&state.config.auth.issuer]);

    let token_data =
        jsonwebtoken::decode::<TokenClaims>(&request.session_token, &state.decoding_key, &validation)
            .map_err(|e| RegistryError::TokenInvalid {
                reason: format!("invalid session token: {e}"),
            })?;

    let now = Utc::now();
    let ttl_secs: i64 = 300; // 5-minute credential

    // Generate a short-lived password (actually a new JWT with short TTL)
    let cred_claims = TokenClaims {
        iss: state.config.auth.issuer.clone(),
        sub: token_data.claims.sub.clone(),
        aud: state.config.auth.audience.clone(),
        exp: now.timestamp() + ttl_secs,
        iat: now.timestamp(),
        jti: Uuid::new_v4().to_string(),
        tenant_id: token_data.claims.tenant_id,
        project_id: token_data.claims.project_id,
        role: token_data.claims.role,
        scopes: token_data.claims.scopes.clone(),
    };

    let password = sign_token(&state, &cred_claims)?;

    Ok(Json(CredentialExchangeResponse {
        username: token_data.claims.sub,
        password,
        expires_at: now + chrono::Duration::seconds(ttl_secs),
    }))
}

// ── Management API (Phase 5) ────────────────────────────────────

/// GET /api/v1/users — List all provisioned users.
async fn list_users(State(state): State<AppState>) -> Json<Vec<UserRecord>> {
    let users = state.users.read().await;
    Json(users.values().cloned().collect())
}

/// GET /api/v1/groups — List group role mappings and active memberships.
async fn list_groups(
    State(state): State<AppState>,
) -> Json<serde_json::Value> {
    let mappings = &state.config.enterprise.group_role_mappings;
    let users = state.users.read().await;

    // Collect all active groups from users
    let mut group_members: HashMap<String, Vec<String>> = HashMap::new();
    for user in users.values() {
        for group in &user.groups {
            group_members
                .entry(group.clone())
                .or_default()
                .push(user.subject.clone());
        }
    }

    let mapping_list: Vec<serde_json::Value> = mappings
        .iter()
        .map(|m| {
            let members = group_members.get(&m.group).cloned().unwrap_or_default();
            serde_json::json!({
                "group": m.group,
                "tenant": m.tenant,
                "project": m.project,
                "role": m.role,
                "member_count": members.len(),
                "members": members,
            })
        })
        .collect();

    // Also include groups from users that aren't in mappings
    let mut active_groups: Vec<serde_json::Value> = Vec::new();
    for (group, members) in &group_members {
        if !mappings.iter().any(|m| m.group == *group) {
            active_groups.push(serde_json::json!({
                "group": group,
                "tenant": null,
                "project": null,
                "role": null,
                "member_count": members.len(),
                "members": members,
            }));
        }
    }

    Json(serde_json::json!({
        "mappings": mapping_list,
        "unmapped_groups": active_groups,
    }))
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

    // Default tenant "_" for standard 2-segment Docker image paths (namespace/repo)
    let default_tenant_id = Uuid::new_v4();
    let default_tenant = Tenant {
        id: default_tenant_id,
        name: "_".into(),
        display_name: "Default Tenant".into(),
        enabled: true,
        storage_prefix: "_".into(),
        rate_limit_rps: 100,
        created_at: now,
        updated_at: now,
    };

    let default_project_id = Uuid::new_v4();
    let default_project = Project {
        id: default_project_id,
        tenant_id: default_tenant_id,
        name: "_".into(),
        display_name: "Default Project".into(),
        visibility: Visibility::Private,
        created_at: now,
        updated_at: now,
    };

    let default_policy = AccessPolicy {
        id: Uuid::new_v4(),
        tenant_id: default_tenant_id,
        project_id: None,
        subject: "admin".into(),
        role: Role::Admin,
        created_at: now,
    };

    let mut tenants = HashMap::new();
    tenants.insert("demo".to_string(), tenant);
    tenants.insert("_".to_string(), default_tenant);

    let mut projects = HashMap::new();
    projects.insert((tenant_id, "default".to_string()), project);
    projects.insert((default_tenant_id, "_".to_string()), default_project);

    (tenants, projects, vec![policy, default_policy])
}

// ═══════════════════════════════════════════════════════════════════
//  Section 15: SCIM 2.0 Provisioning (RFC 7644)
// ═══════════════════════════════════════════════════════════════════

/// Authenticate SCIM requests using the configured bearer token.
fn authenticate_scim(state: &AppState, headers: &HeaderMap) -> Result<(), (StatusCode, Json<ScimError>)> {
    let scim_config = &state.config.enterprise.scim;
    if !scim_config.enabled {
        return Err((StatusCode::NOT_FOUND, Json(ScimError::new(404, "SCIM provisioning is not enabled"))));
    }

    let Some(ref expected_token) = scim_config.bearer_token else {
        return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ScimError::new(500, "SCIM bearer token not configured"))));
    };

    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");

    if !constant_time_eq(auth_header.as_bytes(), expected_token.as_bytes()) {
        return Err((StatusCode::UNAUTHORIZED, Json(ScimError::new(401, "Invalid SCIM bearer token"))));
    }

    Ok(())
}

/// Convert a UserRecord to a SCIM User resource.
fn user_to_scim(user: &UserRecord, base_url: &str) -> ScimUser {
    let primary_email = user.email.clone().unwrap_or_default();
    let emails = if primary_email.is_empty() {
        vec![]
    } else {
        vec![nebula_common::auth::ScimMultiValue {
            value: primary_email,
            value_type: Some("work".to_string()),
            primary: true,
        }]
    };

    let groups: Vec<ScimGroupRef> = user.groups.iter().map(|g| ScimGroupRef {
        value: g.clone(),
        ref_uri: Some(format!("{}/scim/v2/Groups/{}", base_url, g)),
        display: Some(g.clone()),
    }).collect();

    ScimUser {
        schemas: vec![ScimUser::schema()],
        id: Some(user.subject.clone()),
        external_id: Some(user.subject.clone()),
        user_name: user.subject.clone(),
        display_name: user.display_name.clone(),
        active: true,
        name: user.display_name.as_ref().map(|n| nebula_common::auth::ScimName {
            formatted: Some(n.clone()),
            given_name: None,
            family_name: None,
        }),
        emails,
        groups,
        meta: Some(ScimMeta {
            resource_type: "User".to_string(),
            created: Some(user.first_seen.to_rfc3339()),
            last_modified: Some(user.last_login.to_rfc3339()),
            location: Some(format!("{}/scim/v2/Users/{}", base_url, user.subject)),
        }),
    }
}

/// GET /scim/v2/Users — List all provisioned users.
async fn scim_list_users(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ScimListResponse<ScimUser>>, (StatusCode, Json<ScimError>)> {
    authenticate_scim(&state, &headers)?;

    let users = state.users.read().await;
    let base_url = state.config.server.auth_listen_addr.clone();
    let resources: Vec<ScimUser> = users.values().map(|u| user_to_scim(u, &base_url)).collect();
    let total = resources.len();

    Ok(Json(ScimListResponse {
        schemas: vec!["urn:ietf:params:scim:api:messages:2.0:ListResponse".to_string()],
        total_results: total,
        items_per_page: total,
        start_index: 1,
        resources,
    }))
}

/// GET /scim/v2/Users/{id} — Get a single user.
async fn scim_get_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<ScimUser>, (StatusCode, Json<ScimError>)> {
    authenticate_scim(&state, &headers)?;

    let users = state.users.read().await;
    let user = users.get(&id).ok_or_else(|| {
        (StatusCode::NOT_FOUND, Json(ScimError::new(404, format!("User '{}' not found", id))))
    })?;

    let base_url = state.config.server.auth_listen_addr.clone();
    Ok(Json(user_to_scim(user, &base_url)))
}

/// POST /scim/v2/Users — Create (provision) a new user.
async fn scim_create_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(scim_user): Json<ScimUser>,
) -> Result<(StatusCode, Json<ScimUser>), (StatusCode, Json<ScimError>)> {
    authenticate_scim(&state, &headers)?;

    let subject = scim_user.user_name.clone();
    if subject.is_empty() {
        return Err((StatusCode::BAD_REQUEST, Json(ScimError::new(400, "userName is required"))));
    }

    let email = scim_user.emails.first().map(|e| e.value.clone());
    let groups: Vec<String> = scim_user.groups.iter().map(|g| g.display.clone().unwrap_or_else(|| g.value.clone())).collect();

    let now = chrono::Utc::now();
    let user = UserRecord {
        subject: subject.clone(),
        email,
        display_name: scim_user.display_name.clone(),
        groups: groups.clone(),
        auth_method: "scim".to_string(),
        first_seen: now,
        last_login: now,
        login_count: 0,
    };

    let mut users = state.users.write().await;
    users.insert(subject.clone(), user.clone());
    drop(users);

    // Apply group-role mappings for the provisioned user
    apply_group_policies(&state, &subject, &groups).await;

    metrics::counter!("registry_scim_provisions_total", "action" => "create").increment(1);
    info!(subject = %subject, groups = ?groups, "SCIM user provisioned");

    let base_url = state.config.server.auth_listen_addr.clone();
    Ok((StatusCode::CREATED, Json(user_to_scim(&user, &base_url))))
}

/// PUT /scim/v2/Users/{id} — Replace (update) a user.
async fn scim_replace_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(scim_user): Json<ScimUser>,
) -> Result<Json<ScimUser>, (StatusCode, Json<ScimError>)> {
    authenticate_scim(&state, &headers)?;

    let email = scim_user.emails.first().map(|e| e.value.clone());
    let groups: Vec<String> = scim_user.groups.iter().map(|g| g.display.clone().unwrap_or_else(|| g.value.clone())).collect();

    let mut users = state.users.write().await;
    let existing = users.get(&id);
    let now = chrono::Utc::now();

    let user = UserRecord {
        subject: id.clone(),
        email,
        display_name: scim_user.display_name.clone(),
        groups: groups.clone(),
        auth_method: "scim".to_string(),
        first_seen: existing.map(|e| e.first_seen).unwrap_or(now),
        last_login: existing.map(|e| e.last_login).unwrap_or(now),
        login_count: existing.map(|e| e.login_count).unwrap_or(0),
    };

    // Handle deactivation — if active=false, revoke all tokens and remove access policies
    if !scim_user.active && state.config.enterprise.scim.auto_deactivate {
        users.remove(&id);
        drop(users);
        // Remove access policies for this subject
        let mut policies = state.access_policies.write().await;
        policies.retain(|p| p.subject != id);
        drop(policies);
        metrics::counter!("registry_scim_provisions_total", "action" => "deactivate").increment(1);
        warn!(subject = %id, "SCIM user deactivated — access revoked immediately");
    } else {
        users.insert(id.clone(), user.clone());
        drop(users);
        apply_group_policies(&state, &id, &groups).await;
        metrics::counter!("registry_scim_provisions_total", "action" => "update").increment(1);
        info!(subject = %id, groups = ?groups, "SCIM user updated");
    }

    let base_url = state.config.server.auth_listen_addr.clone();
    let response_user = {
        let users = state.users.read().await;
        users.get(&id).map(|u| user_to_scim(u, &base_url)).unwrap_or_else(|| {
            // User was deactivated — return with active=false
            let mut u = user_to_scim(&UserRecord {
                subject: id.clone(),
                email: None,
                display_name: scim_user.display_name.clone(),
                groups: vec![],
                auth_method: "scim".to_string(),
                first_seen: now,
                last_login: now,
                login_count: 0,
            }, &base_url);
            u.active = false;
            u
        })
    };

    Ok(Json(response_user))
}

/// PATCH /scim/v2/Users/{id} — Partial update (Azure AD uses this for deactivation).
async fn scim_patch_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(patch): Json<ScimPatchOp>,
) -> Result<Json<ScimUser>, (StatusCode, Json<ScimError>)> {
    authenticate_scim(&state, &headers)?;

    for op in &patch.operations {
        match op.op.to_lowercase().as_str() {
            "replace" => {
                if op.path.as_deref() == Some("active") {
                    if let Some(serde_json::Value::Bool(false)) = &op.value {
                        // Deactivate user — instant offboarding
                        let mut users = state.users.write().await;
                        users.remove(&id);
                        drop(users);
                        let mut policies = state.access_policies.write().await;
                        policies.retain(|p| p.subject != id);
                        drop(policies);
                        metrics::counter!("registry_scim_provisions_total", "action" => "deactivate").increment(1);
                        warn!(subject = %id, "SCIM PATCH deactivated user — access revoked immediately");
                    }
                }
                // Handle other replace operations on display name, emails, etc.
                if op.path.as_deref() == Some("displayName") || op.path.as_deref() == Some("name.formatted") {
                    if let Some(serde_json::Value::String(name)) = &op.value {
                        let mut users = state.users.write().await;
                        if let Some(user) = users.get_mut(&id) {
                            user.display_name = Some(name.clone());
                        }
                    }
                }
            }
            "add" => {
                // Handle group additions
                if op.path.as_deref() == Some("members") || op.path.is_none() {
                    // Group member additions handled at group level
                }
            }
            "remove" => {
                // Handle group removals
            }
            _ => {}
        }
    }

    let users = state.users.read().await;
    let base_url = state.config.server.auth_listen_addr.clone();
    let user = users.get(&id).map(|u| user_to_scim(u, &base_url)).unwrap_or_else(|| {
        let mut u = ScimUser {
            schemas: vec![ScimUser::schema()],
            id: Some(id.clone()),
            external_id: Some(id.clone()),
            user_name: id.clone(),
            display_name: None,
            active: false,
            name: None,
            emails: vec![],
            groups: vec![],
            meta: None,
        };
        u.active = false;
        u
    });

    Ok(Json(user))
}

/// DELETE /scim/v2/Users/{id} — Deprovision a user.
async fn scim_delete_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ScimError>)> {
    authenticate_scim(&state, &headers)?;

    let mut users = state.users.write().await;
    users.remove(&id);
    drop(users);

    let mut policies = state.access_policies.write().await;
    policies.retain(|p| p.subject != id);
    drop(policies);

    metrics::counter!("registry_scim_provisions_total", "action" => "delete").increment(1);
    warn!(subject = %id, "SCIM user deprovisioned — all access removed");

    Ok(StatusCode::NO_CONTENT)
}

/// GET /scim/v2/Groups — List SCIM-managed groups.
async fn scim_list_groups(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ScimListResponse<ScimGroup>>, (StatusCode, Json<ScimError>)> {
    authenticate_scim(&state, &headers)?;

    let groups = state.scim_groups.read().await;
    let resources: Vec<ScimGroup> = groups.values().cloned().collect();
    let total = resources.len();

    Ok(Json(ScimListResponse {
        schemas: vec!["urn:ietf:params:scim:api:messages:2.0:ListResponse".to_string()],
        total_results: total,
        items_per_page: total,
        start_index: 1,
        resources,
    }))
}

/// POST /scim/v2/Groups — Create a SCIM group.
async fn scim_create_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(group): Json<ScimGroup>,
) -> Result<(StatusCode, Json<ScimGroup>), (StatusCode, Json<ScimError>)> {
    authenticate_scim(&state, &headers)?;

    let group_id = group.id.clone().unwrap_or_else(|| Uuid::new_v4().to_string());
    let mut g = group;
    g.id = Some(group_id.clone());
    g.schemas = vec![ScimGroup::schema()];

    // Sync member groups to user records
    for member in &g.members {
        let mut users = state.users.write().await;
        if let Some(user) = users.get_mut(&member.value) {
            if !user.groups.contains(&g.display_name) {
                user.groups.push(g.display_name.clone());
            }
        }
    }

    let mut groups = state.scim_groups.write().await;
    groups.insert(group_id, g.clone());

    metrics::counter!("registry_scim_provisions_total", "action" => "group_create").increment(1);
    info!(group = %g.display_name, members = g.members.len(), "SCIM group created");

    Ok((StatusCode::CREATED, Json(g)))
}

/// PATCH /scim/v2/Groups/{id} — Update group membership (Azure AD/Okta push membership changes here).
async fn scim_patch_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(patch): Json<ScimPatchOp>,
) -> Result<Json<ScimGroup>, (StatusCode, Json<ScimError>)> {
    authenticate_scim(&state, &headers)?;

    let mut groups = state.scim_groups.write().await;
    let group = groups.get_mut(&id).ok_or_else(|| {
        (StatusCode::NOT_FOUND, Json(ScimError::new(404, format!("Group '{}' not found", id))))
    })?;

    for op in &patch.operations {
        match op.op.to_lowercase().as_str() {
            "add" => {
                // Add members to the group
                if let Some(ref value) = op.value {
                    if let Ok(members) = serde_json::from_value::<Vec<ScimMember>>(value.clone()) {
                        for member in members {
                            if !group.members.iter().any(|m| m.value == member.value) {
                                // Add group to user's group list
                                let mut users = state.users.write().await;
                                if let Some(user) = users.get_mut(&member.value) {
                                    if !user.groups.contains(&group.display_name) {
                                        user.groups.push(group.display_name.clone());
                                        // Re-apply group policies
                                        let groups_clone = user.groups.clone();
                                        drop(users);
                                        apply_group_policies(&state, &member.value, &groups_clone).await;
                                    }
                                }
                                group.members.push(member);
                            }
                        }
                    }
                }
            }
            "remove" => {
                // Remove members from the group
                if let Some(ref path) = op.path {
                    // Azure AD sends: path = "members[value eq \"user-id\"]"
                    if let Some(user_id) = extract_member_id_from_path(path) {
                        group.members.retain(|m| m.value != user_id);
                        // Remove group from user's group list
                        let mut users = state.users.write().await;
                        if let Some(user) = users.get_mut(&user_id) {
                            user.groups.retain(|g| g != &group.display_name);
                            let groups_clone = user.groups.clone();
                            drop(users);
                            apply_group_policies(&state, &user_id, &groups_clone).await;
                        }
                    }
                }
            }
            "replace" => {
                // Full member list replacement
                if op.path.as_deref() == Some("members") || op.path.is_none() {
                    if let Some(ref value) = op.value {
                        if let Ok(members) = serde_json::from_value::<Vec<ScimMember>>(value.clone()) {
                            group.members = members;
                        }
                    }
                }
            }
            _ => {}
        }
    }

    metrics::counter!("registry_scim_provisions_total", "action" => "group_update").increment(1);

    Ok(Json(group.clone()))
}

/// DELETE /scim/v2/Groups/{id} — Delete a SCIM group.
async fn scim_delete_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ScimError>)> {
    authenticate_scim(&state, &headers)?;

    let mut groups = state.scim_groups.write().await;
    if let Some(group) = groups.remove(&id) {
        // Remove this group from all user records
        let mut users = state.users.write().await;
        for user in users.values_mut() {
            user.groups.retain(|g| g != &group.display_name);
        }
        metrics::counter!("registry_scim_provisions_total", "action" => "group_delete").increment(1);
        info!(group = %group.display_name, "SCIM group deleted");
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Helper: apply group-role mappings from enterprise config to create access policies.
async fn apply_group_policies(state: &AppState, subject: &str, groups: &[String]) {
    let mappings = &state.config.enterprise.group_role_mappings;
    let mut policies = state.access_policies.write().await;

    // Remove existing SCIM-generated policies for this subject
    policies.retain(|p| p.subject != subject);

    for mapping in mappings {
        let matched = groups.iter().any(|g| {
            if mapping.group.contains('*') {
                let pattern = mapping.group.replace('*', "");
                g.starts_with(&pattern) || g.ends_with(&pattern) || g.contains(&pattern)
            } else {
                g == &mapping.group
            }
        });

        if matched {
            // Find tenant ID
            let tenants = state.tenants.read().await;
            if let Some(tenant) = tenants.get(&mapping.tenant) {
                let tenant_id = tenant.id;
                drop(tenants);

                let project_id = if let Some(ref proj_name) = mapping.project {
                    let projects = state.projects.read().await;
                    projects.get(&(tenant_id, proj_name.clone())).map(|p| p.id)
                } else {
                    None
                };

                policies.push(AccessPolicy {
                    id: Uuid::new_v4(),
                    tenant_id,
                    project_id,
                    subject: subject.to_string(),
                    role: mapping.role,
                    created_at: chrono::Utc::now(),
                });

                metrics::counter!("registry_group_mapping_hits_total",
                    "group" => mapping.group.clone()
                ).increment(1);
            }
        }
    }
}

/// Extract user ID from SCIM filter path like: members[value eq "user-id"]
fn extract_member_id_from_path(path: &str) -> Option<String> {
    // Pattern: members[value eq "xxx"]
    let start = path.find("\"")? + 1;
    let end = path.rfind("\"")?;
    if start < end {
        Some(path[start..end].to_string())
    } else {
        None
    }
}

// ═══════════════════════════════════════════════════════════════════
//  Section 16: Main
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

    // Pre-register enterprise auth metrics
    metrics::counter!("registry_oidc_logins_total", "provider" => "none", "status" => "success")
        .increment(0);
    metrics::counter!("registry_oidc_logins_total", "provider" => "none", "status" => "failure")
        .increment(0);
    metrics::counter!("registry_oidc_logins_total", "provider" => "none", "status" => "initiated")
        .increment(0);
    metrics::counter!("registry_group_mapping_hits_total", "group" => "none").increment(0);
    metrics::counter!("registry_robot_auth_total", "robot" => "none").increment(0);
    metrics::counter!("registry_token_refresh_total").increment(0);
    metrics::counter!("registry_token_revocation_total").increment(0);

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
        users: Arc::new(RwLock::new(HashMap::new())),
        oidc_sessions: Arc::new(RwLock::new(HashMap::new())),
        robot_accounts: Arc::new(RwLock::new(HashMap::new())),
        refresh_tokens: Arc::new(RwLock::new(HashMap::new())),
        revoked_tokens: Arc::new(RwLock::new(HashSet::new())),
        scim_groups: Arc::new(RwLock::new(HashMap::new())),
    };

    // Build Axum router
    let app = Router::new()
        // Existing endpoints
        .route("/auth/token", post(post_token_form).get(get_token))
        // JSON token request endpoint (API clients)
        .route("/auth/token/json", post(post_token))
        // GitHub Actions OIDC
        .route("/auth/github-actions/token", post(github_actions_token))
        // Token introspection & JWKS
        .route("/auth/introspect", post(introspect_token))
        .route("/auth/.well-known/jwks.json", get(jwks_endpoint))
        // Audit
        .route("/auth/audit", get(audit_endpoint))
        .route("/auth/audit/export", post(audit_export))
        // OIDC Authorization Code Flow (Phase 1)
        .route("/auth/oidc/login", get(oidc_login))
        .route("/auth/oidc/callback", get(oidc_callback))
        // Generic CI OIDC (Phase 2)
        .route("/auth/ci/token", post(ci_token_exchange))
        // Refresh & Revocation (Phase 3)
        .route("/auth/token/refresh", post(refresh_token_handler))
        .route("/auth/token/revoke", post(revoke_token_handler))
        .route("/auth/token/revoked", get(revoked_tokens_handler))
        // Robot Account CRUD (Phase 3)
        .route("/api/v1/robot-accounts", post(create_robot_account).get(list_robot_accounts))
        .route("/api/v1/robot-accounts/{id}", delete(delete_robot_account))
        // Credential Exchange (Phase 4)
        .route("/auth/credential-exchange", post(credential_exchange))
        // Management API (Phase 5)
        .route("/api/v1/users", get(list_users))
        .route("/api/v1/groups", get(list_groups))
        // SCIM 2.0 Provisioning (RFC 7644)
        .route("/scim/v2/Users", get(scim_list_users).post(scim_create_user))
        .route("/scim/v2/Users/{id}", get(scim_get_user).put(scim_replace_user).patch(scim_patch_user).delete(scim_delete_user))
        .route("/scim/v2/Groups", get(scim_list_groups).post(scim_create_group))
        .route("/scim/v2/Groups/{id}", patch(scim_patch_group).delete(scim_delete_group))
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
