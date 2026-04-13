use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use metrics::{counter, histogram};
use nebula_resilience::{CircuitBreaker, CircuitBreakerConfig, RetryPolicy};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

fn record_upstream_outcome(
    upstream: &str,
    kind: &'static str,
    started: Instant,
    outcome: &'static str,
    bytes_len: u64,
) {
    let elapsed = started.elapsed().as_secs_f64();
    histogram!("nebulacr_mirror_upstream_latency_seconds",
        "upstream" => upstream.to_string(), "kind" => kind)
    .record(elapsed);
    counter!("nebulacr_mirror_upstream_requests_total",
        "upstream" => upstream.to_string(), "kind" => kind, "outcome" => outcome)
    .increment(1);
    if outcome == "success" && bytes_len > 0 {
        counter!("nebulacr_mirror_upstream_bytes_total",
            "upstream" => upstream.to_string(), "kind" => kind)
        .increment(bytes_len);
    }
}

/// Configuration for an upstream registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamConfig {
    /// Unique name for this upstream.
    pub name: String,
    /// Base URL of the upstream registry (e.g., "https://registry-1.docker.io").
    pub url: String,
    /// Optional credentials for the upstream.
    pub username: Option<String>,
    pub password: Option<String>,
    /// Cache TTL in seconds for manifests from this upstream.
    pub cache_ttl_secs: u64,
    /// Only mirror for repositories matching this tenant prefix.
    pub tenant_prefix: Option<String>,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            name: "docker-hub".into(),
            url: "https://registry-1.docker.io".into(),
            username: None,
            password: None,
            cache_ttl_secs: 3600,
            tenant_prefix: None,
        }
    }
}

/// Response from an upstream registry fetch.
pub struct UpstreamResponse {
    pub data: Bytes,
    pub content_type: String,
    pub digest: Option<String>,
}

/// Token response from Docker Hub's authentication endpoint.
#[derive(Deserialize)]
struct DockerTokenResponse {
    token: String,
}

/// Client for fetching content from an upstream OCI registry.
pub struct UpstreamClient {
    http: reqwest::Client,
    config: UpstreamConfig,
    circuit_breaker: Arc<CircuitBreaker>,
    #[allow(dead_code)]
    retry_policy: RetryPolicy,
}

#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    #[error("upstream request failed: {0}")]
    Request(String),
    #[error("upstream returned {status}: {body}")]
    Http { status: u16, body: String },
    #[error("upstream authentication failed: {0}")]
    Auth(String),
    #[error("circuit breaker open for upstream '{name}'")]
    CircuitBreakerOpen { name: String },
    #[error("manifest not found on upstream: {reference}")]
    ManifestNotFound { reference: String },
    #[error("blob not found on upstream: {digest}")]
    BlobNotFound { digest: String },
}

impl UpstreamError {
    /// Returns true when this upstream-level error means "the upstream
    /// has no answer for us." From the domain perspective this
    /// collapses: explicit 404s, breaker-open, transport failures,
    /// and upstream 5xx all mean the same thing — nebulacr cannot
    /// serve this blob from this upstream, so try the next one or
    /// return 404 to the client.
    pub fn is_not_found_equivalent(&self) -> bool {
        match self {
            UpstreamError::ManifestNotFound { .. } => true,
            UpstreamError::BlobNotFound { .. } => true,
            UpstreamError::CircuitBreakerOpen { .. } => true,
            UpstreamError::Request(_) => true,
            UpstreamError::Http { status, .. } => *status >= 500 || *status == 404,
            UpstreamError::Auth(_) => false,
        }
    }
}

impl UpstreamClient {
    pub fn new(config: UpstreamConfig) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .build()
            .expect("failed to build HTTP client");

        let circuit_breaker = Arc::new(CircuitBreaker::new(
            format!("upstream-{}", config.name),
            CircuitBreakerConfig {
                failure_threshold: 5,
                success_threshold: 3,
                open_duration_secs: 30,
            },
        ));

        Self {
            http,
            config,
            circuit_breaker,
            retry_policy: RetryPolicy {
                max_retries: 2,
                base_delay_ms: 200,
                max_delay_ms: 2000,
                jitter: true,
            },
        }
    }

    /// Get an authentication token for Docker Hub (anonymous or with credentials).
    #[allow(dead_code)]
    async fn get_docker_token(&self, repo: &str) -> Result<String, UpstreamError> {
        let scope = format!("repository:{repo}:pull");
        let url = format!("https://auth.docker.io/token?service=registry.docker.io&scope={scope}");

        // If we have credentials, use basic auth
        let resp = if let (Some(user), Some(pass)) = (&self.config.username, &self.config.password)
        {
            self.http
                .get(&url)
                .basic_auth(user, Some(pass))
                .send()
                .await
        } else {
            self.http.get(&url).send().await
        };

        let resp = resp.map_err(|e| UpstreamError::Auth(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(UpstreamError::Auth(format!(
                "token endpoint returned {}",
                resp.status()
            )));
        }

        let token_resp: DockerTokenResponse = resp
            .json()
            .await
            .map_err(|e| UpstreamError::Auth(e.to_string()))?;

        Ok(token_resp.token)
    }

    /// Fetch a manifest from the upstream registry.
    pub async fn get_manifest(
        &self,
        repo: &str,
        reference: &str,
    ) -> Result<UpstreamResponse, UpstreamError> {
        info!(
            upstream = %self.config.name,
            repo = %repo,
            reference = %reference,
            "Fetching manifest from upstream"
        );

        let url = format!("{}/v2/{}/manifests/{}", self.config.url, repo, reference);
        let started = Instant::now();

        let cb = self.circuit_breaker.clone();
        let result = cb
            .call(|| {
                let url = url.clone();
                let http = self.http.clone();
                let config = self.config.clone();
                let repo = repo.to_string();
                let reference = reference.to_string();

                async move {
                    // Get token for Docker Hub
                    let token = if config.url.contains("docker.io") {
                        let scope = format!("repository:{repo}:pull");
                        let token_url = format!(
                            "https://auth.docker.io/token?service=registry.docker.io&scope={scope}"
                        );
                        let resp = if let (Some(user), Some(pass)) =
                            (&config.username, &config.password)
                        {
                            http.get(&token_url)
                                .basic_auth(user, Some(pass))
                                .send()
                                .await
                        } else {
                            http.get(&token_url).send().await
                        };

                        let resp = resp.map_err(|e| UpstreamError::Auth(e.to_string()))?;
                        let token_resp: DockerTokenResponse = resp
                            .json()
                            .await
                            .map_err(|e| UpstreamError::Auth(e.to_string()))?;
                        Some(token_resp.token)
                    } else {
                        None
                    };

                    let mut req = http.get(&url).header(
                        "Accept",
                        "application/vnd.oci.image.manifest.v1+json, \
                         application/vnd.oci.image.index.v1+json, \
                         application/vnd.docker.distribution.manifest.v2+json, \
                         application/vnd.docker.distribution.manifest.list.v2+json",
                    );

                    if let Some(ref token) = token {
                        req = req.bearer_auth(token);
                    } else if let (Some(user), Some(pass)) = (&config.username, &config.password) {
                        req = req.basic_auth(user, Some(pass));
                    }

                    let resp = req
                        .send()
                        .await
                        .map_err(|e| UpstreamError::Request(e.to_string()))?;

                    if resp.status() == reqwest::StatusCode::NOT_FOUND {
                        return Err(UpstreamError::ManifestNotFound {
                            reference: reference.to_string(),
                        });
                    }

                    if !resp.status().is_success() {
                        let status = resp.status().as_u16();
                        let body = resp.text().await.unwrap_or_default();
                        return Err(UpstreamError::Http { status, body });
                    }

                    let content_type = resp
                        .headers()
                        .get("content-type")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("application/vnd.oci.image.manifest.v1+json")
                        .to_string();

                    let digest = resp
                        .headers()
                        .get("docker-content-digest")
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_string());

                    let data = resp
                        .bytes()
                        .await
                        .map_err(|e| UpstreamError::Request(e.to_string()))?;

                    Ok(UpstreamResponse {
                        data,
                        content_type,
                        digest,
                    })
                }
            })
            .await;

        match result {
            Ok(r) => {
                let len = r.data.len() as u64;
                record_upstream_outcome(&self.config.name, "manifest", started, "success", len);
                Ok(r)
            }
            Err(nebula_resilience::circuit_breaker::CircuitBreakerCallError::BreakerOpen(_)) => {
                record_upstream_outcome(&self.config.name, "manifest", started, "breaker_open", 0);
                Err(UpstreamError::CircuitBreakerOpen {
                    name: self.config.name.clone(),
                })
            }
            Err(nebula_resilience::circuit_breaker::CircuitBreakerCallError::Inner(e)) => {
                let outcome = match &e {
                    UpstreamError::ManifestNotFound { .. } => "not_found",
                    UpstreamError::Auth(_) => "auth_error",
                    UpstreamError::Http { status, .. } if *status >= 500 => "upstream_5xx",
                    _ => "error",
                };
                record_upstream_outcome(&self.config.name, "manifest", started, outcome, 0);
                Err(e)
            }
        }
    }

    /// Fetch a blob from the upstream registry.
    pub async fn get_blob(
        &self,
        repo: &str,
        digest: &str,
    ) -> Result<UpstreamResponse, UpstreamError> {
        debug!(
            upstream = %self.config.name,
            repo = %repo,
            digest = %digest,
            "Fetching blob from upstream"
        );

        let url = format!("{}/v2/{}/blobs/{}", self.config.url, repo, digest);
        let started = Instant::now();

        let cb = self.circuit_breaker.clone();
        let result = cb
            .call(|| {
                let url = url.clone();
                let http = self.http.clone();
                let config = self.config.clone();
                let repo = repo.to_string();
                let digest = digest.to_string();

                async move {
                    let token = if config.url.contains("docker.io") {
                        let scope = format!("repository:{repo}:pull");
                        let token_url = format!(
                            "https://auth.docker.io/token?service=registry.docker.io&scope={scope}"
                        );
                        let resp = http
                            .get(&token_url)
                            .send()
                            .await
                            .map_err(|e| UpstreamError::Auth(e.to_string()))?;
                        let token_resp: DockerTokenResponse = resp
                            .json()
                            .await
                            .map_err(|e| UpstreamError::Auth(e.to_string()))?;
                        Some(token_resp.token)
                    } else {
                        None
                    };

                    let mut req = http.get(&url);

                    if let Some(ref token) = token {
                        req = req.bearer_auth(token);
                    } else if let (Some(user), Some(pass)) = (&config.username, &config.password) {
                        req = req.basic_auth(user, Some(pass));
                    }

                    let resp = req
                        .send()
                        .await
                        .map_err(|e| UpstreamError::Request(e.to_string()))?;

                    if resp.status() == reqwest::StatusCode::NOT_FOUND {
                        return Err(UpstreamError::BlobNotFound {
                            digest: digest.to_string(),
                        });
                    }

                    if !resp.status().is_success() {
                        let status = resp.status().as_u16();
                        let body = resp.text().await.unwrap_or_default();
                        return Err(UpstreamError::Http { status, body });
                    }

                    let content_type = resp
                        .headers()
                        .get("content-type")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("application/octet-stream")
                        .to_string();

                    let data = resp
                        .bytes()
                        .await
                        .map_err(|e| UpstreamError::Request(e.to_string()))?;

                    Ok(UpstreamResponse {
                        data,
                        content_type,
                        digest: Some(digest),
                    })
                }
            })
            .await;

        match result {
            Ok(r) => {
                let len = r.data.len() as u64;
                record_upstream_outcome(&self.config.name, "blob", started, "success", len);
                Ok(r)
            }
            Err(nebula_resilience::circuit_breaker::CircuitBreakerCallError::BreakerOpen(_)) => {
                record_upstream_outcome(&self.config.name, "blob", started, "breaker_open", 0);
                Err(UpstreamError::CircuitBreakerOpen {
                    name: self.config.name.clone(),
                })
            }
            Err(nebula_resilience::circuit_breaker::CircuitBreakerCallError::Inner(e)) => {
                let outcome = match &e {
                    UpstreamError::BlobNotFound { .. } => "not_found",
                    UpstreamError::Auth(_) => "auth_error",
                    UpstreamError::Http { status, .. } if *status >= 500 => "upstream_5xx",
                    _ => "error",
                };
                record_upstream_outcome(&self.config.name, "blob", started, outcome, 0);
                Err(e)
            }
        }
    }

    pub fn config(&self) -> &UpstreamConfig {
        &self.config
    }
}
