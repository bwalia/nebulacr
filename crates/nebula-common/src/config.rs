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
    pub vault: Option<VaultConfig>,
    pub github_oidc: Option<GitHubOidcConfig>,
    pub resilience: Option<ResilienceConfig>,
    pub mirror: Option<MirrorConfig>,
    pub multi_region: Option<MultiRegionConfig>,
}

// ── Resilience configuration ─────────────────────────────────────

/// Configuration for retry and circuit breaker behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResilienceConfig {
    pub retry: RetryConfig,
    pub circuit_breaker: CircuitBreakerCfg,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum number of retry attempts.
    pub max_retries: u32,
    /// Base delay in milliseconds for exponential backoff.
    pub base_delay_ms: u64,
    /// Maximum delay in milliseconds.
    pub max_delay_ms: u64,
    /// Whether to add random jitter to delay.
    pub jitter: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerCfg {
    /// Failures before opening.
    pub failure_threshold: u32,
    /// Successes in half-open before closing.
    pub success_threshold: u32,
    /// Duration the circuit stays open (seconds).
    pub open_duration_secs: u64,
}

impl Default for ResilienceConfig {
    fn default() -> Self {
        Self {
            retry: RetryConfig {
                max_retries: 3,
                base_delay_ms: 100,
                max_delay_ms: 5000,
                jitter: true,
            },
            circuit_breaker: CircuitBreakerCfg {
                failure_threshold: 5,
                success_threshold: 3,
                open_duration_secs: 30,
            },
        }
    }
}

// ── Mirror configuration ─────────────────────────────────────────

/// Configuration for pull-through mirror/cache.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MirrorConfig {
    /// Whether mirroring is enabled.
    pub enabled: bool,
    /// Upstream registries to mirror from.
    pub upstreams: Vec<UpstreamRegistryConfig>,
    /// Default cache TTL in seconds.
    pub cache_ttl_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamRegistryConfig {
    /// Unique name for this upstream.
    pub name: String,
    /// Base URL (e.g., "https://registry-1.docker.io").
    pub url: String,
    /// Only mirror for repos matching this tenant prefix.
    pub tenant_prefix: Option<String>,
    /// Optional authentication.
    pub username: Option<String>,
    pub password: Option<String>,
    /// Cache TTL override for this upstream (seconds).
    pub cache_ttl_secs: Option<u64>,
}

impl Default for MirrorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            upstreams: vec![],
            cache_ttl_secs: 3600,
        }
    }
}

// ── Multi-region configuration ───────────────────────────────────

/// Configuration for multi-region replication and failover.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiRegionConfig {
    /// Name of the local region (e.g., "us-east-1").
    pub local_region: String,
    /// All regions in the cluster.
    pub regions: Vec<RegionCfg>,
    /// Replication policy.
    pub replication: ReplicationPolicyCfg,
    /// Health check interval in seconds.
    pub health_check_interval_secs: u64,
    /// Port for the internal replication API.
    pub internal_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionCfg {
    /// Region name (e.g., "us-east-1").
    pub name: String,
    /// Public registry API endpoint URL.
    pub endpoint: String,
    /// Internal replication endpoint URL.
    pub internal_endpoint: String,
    /// Whether this is the primary region.
    pub is_primary: bool,
    /// Failover priority (lower = higher priority).
    pub priority: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationPolicyCfg {
    /// Replication mode: "async" or "semi_sync".
    pub mode: String,
    /// Max acceptable replication lag in seconds.
    pub max_lag_secs: u64,
    /// Objects per replication batch.
    pub batch_size: usize,
    /// Interval between replication sweeps (seconds).
    pub sweep_interval_secs: u64,
}

impl Default for MultiRegionConfig {
    fn default() -> Self {
        Self {
            local_region: "us-east-1".into(),
            regions: vec![],
            replication: ReplicationPolicyCfg {
                mode: "async".into(),
                max_lag_secs: 60,
                batch_size: 50,
                sweep_interval_secs: 10,
            },
            health_check_interval_secs: 10,
            internal_port: 5002,
        }
    }
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

// ── Vault configuration ───────────────────────────────────────────

/// Configuration for HashiCorp Vault integration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultConfig {
    /// Vault server address (e.g. "https://vault.example.com:8200").
    /// Also read from VAULT_ADDR env var.
    pub addr: String,
    /// Environment variable name holding the Vault token (default: "VAULT_TOKEN").
    pub token_env_var: String,
    /// Transit secrets engine key name for JWT signing.
    pub transit_key_name: String,
    /// KV v2 mount path (e.g. "secret").
    pub kv_mount_path: String,
    /// KV v2 secret path for JWT keys (e.g. "nebulacr/jwt-keys").
    pub kv_secret_path: String,
    /// Whether Vault integration is enabled.
    pub enabled: bool,
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            addr: "http://127.0.0.1:8200".into(),
            token_env_var: "VAULT_TOKEN".into(),
            transit_key_name: "nebulacr-signing-key".into(),
            kv_mount_path: "secret".into(),
            kv_secret_path: "nebulacr/jwt-keys".into(),
            enabled: false,
        }
    }
}

// ── GitHub OIDC configuration ─────────────────────────────────────

/// Configuration for GitHub Actions OIDC token exchange.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubOidcConfig {
    /// GitHub OIDC issuer URL (default: "https://token.actions.githubusercontent.com").
    pub issuer_url: String,
    /// List of allowed GitHub organizations. Empty = allow all.
    pub allowed_orgs: Vec<String>,
    /// List of allowed repositories (e.g. "org/repo"). Empty = allow all.
    pub allowed_repos: Vec<String>,
    /// Default role assigned to GitHub Actions tokens.
    pub default_role: String,
}

impl Default for GitHubOidcConfig {
    fn default() -> Self {
        Self {
            issuer_url: "https://token.actions.githubusercontent.com".into(),
            allowed_orgs: vec![],
            allowed_repos: vec![],
            default_role: "maintainer".into(),
        }
    }
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
            vault: None,
            github_oidc: None,
            resilience: None,
            mirror: None,
            multi_region: None,
        }
    }
}
