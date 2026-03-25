use serde::{Deserialize, Serialize};

use crate::auth::OidcProviderConfig;

/// Top-level registry configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryConfig {
    pub server: ServerConfig,
    pub auth: AuthConfig,
    pub storage: StorageConfig,
    pub observability: ObservabilityConfig,
    pub rate_limit: RateLimitConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Bind address for the registry API.
    pub listen_addr: String,
    /// Bind address for the auth service (if co-located).
    pub auth_listen_addr: String,
    /// Bind address for metrics endpoint.
    pub metrics_addr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// OIDC identity providers.
    pub oidc_providers: Vec<OidcProviderConfig>,
    /// JWT signing algorithm: RS256 or EdDSA.
    pub signing_algorithm: String,
    /// Path to private key (PEM) for JWT signing.
    pub signing_key_path: String,
    /// Path to public key (PEM) for JWT verification.
    pub verification_key_path: String,
    /// Token TTL in seconds (default: 300 = 5 min).
    pub token_ttl_seconds: u64,
    /// JWT issuer claim.
    pub issuer: String,
    /// JWT audience claim.
    pub audience: String,
    /// Enable bootstrap admin (initial setup only).
    pub bootstrap_admin: Option<BootstrapAdmin>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapAdmin {
    pub username: String,
    pub password_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Backend type: "filesystem", "s3", "gcs", "azure".
    pub backend: String,
    /// Root path or bucket.
    pub root: String,
    /// S3/GCS/Azure connection details.
    pub endpoint: Option<String>,
    pub region: Option<String>,
    pub access_key: Option<String>,
    pub secret_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilityConfig {
    /// Log level filter (e.g. "info", "debug").
    pub log_level: String,
    /// Log format: "json" or "pretty".
    pub log_format: String,
    /// OTLP endpoint for tracing export.
    pub otlp_endpoint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Default requests per second per tenant.
    pub default_rps: u32,
    /// Default requests per second per IP (unauthenticated).
    pub ip_rps: u32,
    /// Token issuance requests per minute.
    pub token_issue_rpm: u32,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                listen_addr: "0.0.0.0:5000".into(),
                auth_listen_addr: "0.0.0.0:5001".into(),
                metrics_addr: "0.0.0.0:9090".into(),
            },
            auth: AuthConfig {
                oidc_providers: vec![],
                signing_algorithm: "RS256".into(),
                signing_key_path: "/etc/nebulacr/keys/private.pem".into(),
                verification_key_path: "/etc/nebulacr/keys/public.pem".into(),
                token_ttl_seconds: 300,
                issuer: "nebulacr".into(),
                audience: "nebulacr-registry".into(),
                bootstrap_admin: None,
            },
            storage: StorageConfig {
                backend: "filesystem".into(),
                root: "/var/lib/nebulacr/data".into(),
                endpoint: None,
                region: None,
                access_key: None,
                secret_key: None,
            },
            observability: ObservabilityConfig {
                log_level: "info".into(),
                log_format: "json".into(),
                otlp_endpoint: None,
            },
            rate_limit: RateLimitConfig {
                default_rps: 100,
                ip_rps: 50,
                token_issue_rpm: 60,
            },
        }
    }
}
