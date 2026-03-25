use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::models::{Action, Role};

// ── Token claims ──────────────────────────────────────────────────

/// JWT claims for short-lived registry access tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    /// Standard JWT fields
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub jti: String,

    /// NebulaCR-specific
    pub tenant_id: Uuid,
    pub project_id: Option<Uuid>,
    pub role: Role,
    pub scopes: Vec<TokenScope>,
}

/// A scope within a token: repository + allowed actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenScope {
    pub repository: String,
    pub actions: Vec<Action>,
}

// ── Token request / response ──────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRequest {
    /// OIDC ID token or signed identity assertion
    pub identity_token: String,
    /// Requested scope
    pub scope: RequestedScope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestedScope {
    pub tenant: String,
    pub project: Option<String>,
    pub repository: Option<String>,
    pub actions: Vec<Action>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub token: String,
    pub expires_in: u64,
    pub issued_at: DateTime<Utc>,
}

/// Docker-compatible token response for `GET /v2/token`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerTokenResponse {
    pub token: String,
    pub access_token: String,
    pub expires_in: u64,
    pub issued_at: String,
}

// ── OIDC provider config ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcProviderConfig {
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    /// Claim used to resolve the subject identity.
    pub subject_claim: String,
    /// Claim used to resolve tenant membership.
    pub tenant_claim: Option<String>,
}

// ── GitHub Actions OIDC ───────────────────────────────────────────

/// Request body for `POST /auth/github-actions/token`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubOidcTokenRequest {
    /// The GitHub Actions OIDC JWT (from ACTIONS_ID_TOKEN_REQUEST_TOKEN).
    pub token: String,
    /// Requested NebulaCR scope for the exchanged token.
    pub scope: GitHubOidcScope,
}

/// Scope requested by a GitHub Actions token exchange.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubOidcScope {
    pub tenant: String,
    pub project: String,
    pub actions: Vec<Action>,
}

/// Claims extracted from a GitHub Actions OIDC JWT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubTokenClaims {
    pub sub: String,
    pub iss: String,
    pub aud: Option<String>,
    pub exp: Option<i64>,
    pub iat: Option<i64>,
    /// e.g. "octo-org/octo-repo"
    #[serde(default)]
    pub repository: String,
    /// e.g. "octo-org"
    #[serde(default)]
    pub repository_owner: String,
    /// e.g. "build"
    #[serde(default)]
    pub workflow: String,
    /// e.g. "refs/heads/main"
    #[serde(default, rename = "ref")]
    pub git_ref: String,
    /// The GitHub user that triggered the workflow.
    #[serde(default)]
    pub actor: String,
    /// The run ID.
    #[serde(default)]
    pub run_id: String,
    /// The SHA of the commit.
    #[serde(default)]
    pub sha: String,
    /// Job workflow ref
    #[serde(default)]
    pub job_workflow_ref: String,
}

// ── Audit event ───────────────────────────────────────────────────

/// An authentication/authorization audit event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub timestamp: DateTime<Utc>,
    pub subject: String,
    pub tenant: String,
    pub project: Option<String>,
    pub action: String,
    pub decision: AuditDecision,
    pub reason: String,
    pub request_id: String,
    pub source_ip: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditDecision {
    Allow,
    Deny,
}

// ── Token introspection (RFC 7662) ────────────────────────────────

/// Response body for `POST /auth/introspect`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntrospectionResponse {
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
}

// ── JWKS publishing ───────────────────────────────────────────────

/// JWKS response for `GET /auth/.well-known/jwks.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksResponse {
    pub keys: Vec<Jwk>,
}

/// A single JSON Web Key (RSA public key).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    #[serde(rename = "use")]
    pub key_use: String,
    pub kid: String,
    pub alg: String,
    /// RSA modulus (base64url-encoded).
    pub n: String,
    /// RSA exponent (base64url-encoded).
    pub e: String,
}
