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
