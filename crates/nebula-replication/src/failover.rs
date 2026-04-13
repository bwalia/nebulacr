use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use metrics::{counter, gauge};
use serde::Serialize;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::region::RegionConfig;

/// Health status of a region.
#[derive(Debug, Clone, Serialize)]
pub struct RegionHealth {
    pub region: String,
    pub healthy: bool,
    pub last_check: DateTime<Utc>,
    pub consecutive_failures: u32,
    pub response_time_ms: Option<u64>,
}

/// Manages automatic failover between regions.
pub struct FailoverManager {
    local_region: String,
    regions: Vec<RegionConfig>,
    health_status: Arc<RwLock<HashMap<String, RegionHealth>>>,
    http: reqwest::Client,
    health_check_interval_secs: u64,
    failure_threshold: u32,
}

impl FailoverManager {
    pub fn new(
        local_region: String,
        regions: Vec<RegionConfig>,
        health_check_interval_secs: u64,
    ) -> Self {
        let mut health_status = HashMap::new();
        for region in &regions {
            health_status.insert(
                region.name.clone(),
                RegionHealth {
                    region: region.name.clone(),
                    healthy: true,
                    last_check: Utc::now(),
                    consecutive_failures: 0,
                    response_time_ms: None,
                },
            );
        }

        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .connect_timeout(Duration::from_secs(3))
            .build()
            .expect("failed to build HTTP client");

        Self {
            local_region,
            regions,
            health_status: Arc::new(RwLock::new(health_status)),
            http,
            health_check_interval_secs,
            failure_threshold: 3,
        }
    }

    /// Start the background health check loop.
    pub async fn run(self: Arc<Self>) {
        let interval = Duration::from_secs(self.health_check_interval_secs);
        info!(
            local_region = %self.local_region,
            interval_secs = self.health_check_interval_secs,
            "Failover health check loop started"
        );

        loop {
            for region in &self.regions {
                if region.name == self.local_region {
                    continue;
                }

                let start = std::time::Instant::now();
                let health_url = format!("{}/health", region.endpoint);

                let result = self.http.get(&health_url).send().await;
                let elapsed = start.elapsed();

                let mut status = self.health_status.write().await;
                let health = status.entry(region.name.clone()).or_insert(RegionHealth {
                    region: region.name.clone(),
                    healthy: true,
                    last_check: Utc::now(),
                    consecutive_failures: 0,
                    response_time_ms: None,
                });

                match result {
                    Ok(resp) if resp.status().is_success() => {
                        if !health.healthy {
                            info!(
                                region = %region.name,
                                "Region recovered and is now healthy"
                            );
                            counter!("nebulacr_region_health_transitions_total",
                                "region" => region.name.clone(), "to" => "healthy")
                            .increment(1);
                        }
                        health.healthy = true;
                        health.consecutive_failures = 0;
                        health.response_time_ms = Some(elapsed.as_millis() as u64);
                    }
                    Ok(resp) => {
                        health.consecutive_failures += 1;
                        health.response_time_ms = Some(elapsed.as_millis() as u64);

                        if health.consecutive_failures >= self.failure_threshold {
                            if health.healthy {
                                warn!(
                                    region = %region.name,
                                    failures = health.consecutive_failures,
                                    status = %resp.status(),
                                    "Region marked as unhealthy"
                                );
                                counter!("nebulacr_region_health_transitions_total",
                                    "region" => region.name.clone(), "to" => "unhealthy")
                                .increment(1);
                            }
                            health.healthy = false;
                        }
                    }
                    Err(e) => {
                        health.consecutive_failures += 1;
                        health.response_time_ms = None;

                        if health.consecutive_failures >= self.failure_threshold {
                            if health.healthy {
                                error!(
                                    region = %region.name,
                                    failures = health.consecutive_failures,
                                    error = %e,
                                    "Region marked as unhealthy (connection failed)"
                                );
                                counter!("nebulacr_region_health_transitions_total",
                                    "region" => region.name.clone(), "to" => "unhealthy")
                                .increment(1);
                            }
                            health.healthy = false;
                        }
                    }
                }

                gauge!("nebulacr_region_healthy", "region" => region.name.clone())
                    .set(if health.healthy { 1.0 } else { 0.0 });
                if let Some(rt) = health.response_time_ms {
                    gauge!("nebulacr_region_health_check_latency_seconds",
                        "region" => region.name.clone())
                    .set(rt as f64 / 1000.0);
                }

                health.last_check = Utc::now();
            }

            tokio::time::sleep(interval).await;
        }
    }

    /// Get the next healthy region for read failover, sorted by priority.
    pub async fn next_healthy_region(&self) -> Option<RegionConfig> {
        let status = self.health_status.read().await;
        let mut candidates: Vec<&RegionConfig> = self
            .regions
            .iter()
            .filter(|r| r.name != self.local_region)
            .filter(|r| status.get(&r.name).map(|h| h.healthy).unwrap_or(false))
            .collect();

        candidates.sort_by_key(|r| r.priority);
        candidates.first().cloned().cloned()
    }

    /// Get the primary region.
    pub fn primary_region(&self) -> Option<&RegionConfig> {
        self.regions.iter().find(|r| r.is_primary)
    }

    /// Check if the local region is the primary.
    pub fn is_local_primary(&self) -> bool {
        self.regions
            .iter()
            .any(|r| r.name == self.local_region && r.is_primary)
    }

    /// Get health status for all regions.
    pub async fn all_health(&self) -> Vec<RegionHealth> {
        let status = self.health_status.read().await;
        status.values().cloned().collect()
    }

    /// Proxy a read request to a healthy remote region.
    pub async fn proxy_get(
        &self,
        path: &str,
        auth_header: Option<&str>,
    ) -> Result<ProxyResponse, FailoverError> {
        let region = self
            .next_healthy_region()
            .await
            .ok_or(FailoverError::NoHealthyRegions)?;

        let url = format!("{}{}", region.endpoint, path);
        let mut req = self.http.get(&url);
        if let Some(auth) = auth_header {
            req = req.header("authorization", auth);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| FailoverError::ProxyFailed(e.to_string()))?;

        let status = resp.status().as_u16();
        let headers: HashMap<String, String> = resp
            .headers()
            .iter()
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|v| (k.as_str().to_string(), v.to_string()))
            })
            .collect();
        let body = resp
            .bytes()
            .await
            .map_err(|e| FailoverError::ProxyFailed(e.to_string()))?;

        Ok(ProxyResponse {
            status,
            headers,
            body,
            source_region: region.name,
        })
    }
}

/// Response from a proxied request to another region.
pub struct ProxyResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: bytes::Bytes,
    pub source_region: String,
}

#[derive(Debug, thiserror::Error)]
pub enum FailoverError {
    #[error("no healthy regions available for failover")]
    NoHealthyRegions,
    #[error("proxy request failed: {0}")]
    ProxyFailed(String),
}
