use std::collections::HashMap;

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
    /// Claim name containing user groups (e.g., "groups" for Azure AD).
    #[serde(default = "default_groups_claim")]
    pub groups_claim: String,
    /// Claim name for email.
    #[serde(default = "default_email_claim")]
    pub email_claim: String,
    /// Restrict login to users in these groups. Empty = allow all.
    #[serde(default)]
    pub allowed_groups: Vec<String>,
    /// Display name for the provider (shown on login page).
    #[serde(default)]
    pub display_name: Option<String>,
}

fn default_groups_claim() -> String {
    "groups".to_string()
}
fn default_email_claim() -> String {
    "email".to_string()
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
    /// Authentication method used (basic, oidc, robot, ci_oidc).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_method: Option<String>,
    /// Groups the subject belongs to (from OIDC claims).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<String>>,
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

// ── Enterprise Auth Types ────────────────────────────────────────

/// Extended OIDC claims including groups for enterprise SSO.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcUserClaims {
    pub sub: String,
    #[serde(default)]
    pub iss: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub preferred_username: Option<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub exp: Option<i64>,
}

/// Group-to-role mapping rule for enterprise AD integration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupRoleMapping {
    /// AD/OIDC group name pattern (exact or glob with *).
    pub group: String,
    /// NebulaCR tenant to grant access to.
    pub tenant: String,
    /// Optional project restriction.
    pub project: Option<String>,
    /// Role assigned to members of this group.
    pub role: Role,
}

/// A provisioned user record (auto-created on first OIDC login).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRecord {
    pub subject: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub groups: Vec<String>,
    pub auth_method: String,
    pub first_seen: DateTime<Utc>,
    pub last_login: DateTime<Utc>,
    pub login_count: u64,
}

/// OIDC authorization code flow session state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcSession {
    pub state: String,
    pub pkce_verifier: String,
    pub provider_name: String,
    pub redirect_uri: String,
    pub created_at: DateTime<Utc>,
}

/// Robot/service account for machine identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RobotAccount {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub tenant: String,
    pub project: Option<String>,
    pub role: Role,
    pub secret_hash: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used: Option<DateTime<Utc>>,
    pub enabled: bool,
}

/// CI OIDC provider configuration (generalized for GitHub, GitLab, k8s).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiOidcProvider {
    pub name: String,
    pub issuer_url: String,
    pub audience: String,
    /// Prefix for subject identity (e.g., "github:", "gitlab:", "k8s:").
    pub subject_prefix: String,
    /// Claim filters: claim_name -> allowed values.
    #[serde(default)]
    pub allowed_claims: HashMap<String, Vec<String>>,
    pub default_role: String,
    /// Max token TTL in seconds.
    #[serde(default = "default_ci_max_ttl")]
    pub max_ttl_seconds: u64,
}

fn default_ci_max_ttl() -> u64 {
    900
}

/// Refresh token record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshToken {
    pub id: String,
    pub subject: String,
    pub tenant_id: Uuid,
    pub project_id: Option<Uuid>,
    pub role: Role,
    pub scopes: Vec<TokenScope>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked: bool,
}

// ── CI-specific token claims ─────────────────────────────────────

/// Claims extracted from a GitLab CI OIDC JWT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitLabTokenClaims {
    pub sub: String,
    #[serde(default)]
    pub iss: String,
    #[serde(default)]
    pub aud: Option<String>,
    #[serde(default)]
    pub exp: Option<i64>,
    #[serde(default)]
    pub iat: Option<i64>,
    /// e.g. "group/project"
    #[serde(default)]
    pub project_path: String,
    /// e.g. "group"
    #[serde(default)]
    pub namespace_path: String,
    /// Pipeline source (push, web, schedule, etc.)
    #[serde(default)]
    pub pipeline_source: String,
    /// Git ref (branch or tag)
    #[serde(default, rename = "ref")]
    pub git_ref: String,
    /// The user that triggered the pipeline.
    #[serde(default)]
    pub user_login: String,
    /// The pipeline ID.
    #[serde(default)]
    pub pipeline_id: String,
    /// The job ID.
    #[serde(default)]
    pub job_id: String,
}

/// Claims extracted from a Kubernetes service account OIDC JWT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubernetesTokenClaims {
    pub sub: String,
    #[serde(default)]
    pub iss: String,
    #[serde(default)]
    pub aud: Option<String>,
    #[serde(default)]
    pub exp: Option<i64>,
    #[serde(default)]
    pub iat: Option<i64>,
    /// Kubernetes namespace.
    #[serde(default)]
    pub namespace: String,
    /// Service account name.
    #[serde(default)]
    pub serviceaccount: String,
    /// Pod name.
    #[serde(default)]
    pub pod: String,
}

/// Generic CI token exchange request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiTokenRequest {
    /// The CI OIDC JWT.
    pub token: String,
    /// Provider name (e.g., "github", "gitlab", "k8s", or custom name).
    pub provider: String,
    /// Requested NebulaCR scope.
    pub scope: CiTokenScope,
}

/// Scope for CI token exchange.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiTokenScope {
    pub tenant: String,
    pub project: String,
    pub actions: Vec<Action>,
}

/// Credential exchange request for Docker credential helpers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialExchangeRequest {
    /// OIDC session token or refresh token.
    pub session_token: String,
    /// Registry host to generate credentials for.
    pub registry_host: Option<String>,
}

/// Credential exchange response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialExchangeResponse {
    pub username: String,
    pub password: String,
    pub expires_at: DateTime<Utc>,
}

// ── SCIM 2.0 Types ──────────────────────────────────────────────

/// SCIM 2.0 User resource (RFC 7643).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimUser {
    pub schemas: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    pub user_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default)]
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<ScimName>,
    #[serde(default)]
    pub emails: Vec<ScimMultiValue>,
    #[serde(default)]
    pub groups: Vec<ScimGroupRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<ScimMeta>,
}

/// SCIM 2.0 Name sub-resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimName {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formatted: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
}

/// SCIM 2.0 multi-valued attribute (emails, phone numbers, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimMultiValue {
    pub value: String,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub value_type: Option<String>,
    #[serde(default)]
    pub primary: bool,
}

/// SCIM 2.0 group reference within a user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimGroupRef {
    pub value: String,
    #[serde(rename = "$ref", skip_serializing_if = "Option::is_none")]
    pub ref_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
}

/// SCIM 2.0 Group resource (RFC 7643).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimGroup {
    pub schemas: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    pub display_name: String,
    #[serde(default)]
    pub members: Vec<ScimMember>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<ScimMeta>,
}

/// SCIM 2.0 group member.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimMember {
    pub value: String,
    #[serde(rename = "$ref", skip_serializing_if = "Option::is_none")]
    pub ref_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
}

/// SCIM 2.0 resource metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimMeta {
    pub resource_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
}

/// SCIM 2.0 ListResponse.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimListResponse<T: Serialize> {
    pub schemas: Vec<String>,
    pub total_results: usize,
    pub items_per_page: usize,
    pub start_index: usize,
    #[serde(rename = "Resources")]
    pub resources: Vec<T>,
}

/// SCIM 2.0 Error response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimError {
    pub schemas: Vec<String>,
    pub detail: String,
    pub status: u16,
}

/// SCIM 2.0 PATCH operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimPatchOp {
    pub schemas: Vec<String>,
    #[serde(rename = "Operations")]
    pub operations: Vec<ScimPatchOperation>,
}

/// A single SCIM PATCH operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimPatchOperation {
    pub op: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
}

impl ScimUser {
    pub fn schema() -> String {
        "urn:ietf:params:scim:schemas:core:2.0:User".to_string()
    }
}

impl ScimGroup {
    pub fn schema() -> String {
        "urn:ietf:params:scim:schemas:core:2.0:Group".to_string()
    }
}

impl ScimError {
    pub fn new(status: u16, detail: impl Into<String>) -> Self {
        Self {
            schemas: vec!["urn:ietf:params:scim:api:messages:2.0:Error".to_string()],
            detail: detail.into(),
            status,
        }
    }
}
