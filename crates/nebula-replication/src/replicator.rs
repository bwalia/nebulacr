use nebula_resilience::{CircuitBreaker, CircuitBreakerConfig, RetryPolicy};
use object_store::{ObjectStore, path::Path as StorePath};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::event::{ReplicationEvent, ReplicationEventType};
use crate::region::{MultiRegionConfig, RegionConfig, ReplicationMode};

/// Handles replication of content to remote regions.
pub struct Replicator {
    local_region: String,
    local_store: Arc<dyn ObjectStore>,
    remote_regions: Vec<RemoteRegion>,
    mode: ReplicationMode,
    event_tx: mpsc::Sender<ReplicationEvent>,
    event_rx: Option<mpsc::Receiver<ReplicationEvent>>,
}

struct RemoteRegion {
    config: RegionConfig,
    client: reqwest::Client,
    circuit_breaker: CircuitBreaker,
    retry_policy: RetryPolicy,
}

/// Handle for enqueuing replication events from request handlers.
#[derive(Clone)]
pub struct ReplicationHandle {
    event_tx: mpsc::Sender<ReplicationEvent>,
    mode: ReplicationMode,
    local_region: String,
}

impl ReplicationHandle {
    /// Enqueue a replication event. For SemiSync mode, waits for acknowledgment.
    pub async fn enqueue(&self, event: ReplicationEvent) {
        if let Err(e) = self.event_tx.send(event).await {
            warn!(error = %e, "Failed to enqueue replication event");
        }
    }

    pub fn local_region(&self) -> &str {
        &self.local_region
    }

    pub fn mode(&self) -> ReplicationMode {
        self.mode
    }
}

/// Status of replication to a specific region.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RegionReplicationStatus {
    pub region: String,
    pub pending_events: u64,
    pub last_replicated_at: Option<chrono::DateTime<chrono::Utc>>,
    pub replication_lag_secs: Option<u64>,
    pub healthy: bool,
}

impl Replicator {
    pub fn new(config: &MultiRegionConfig, local_store: Arc<dyn ObjectStore>) -> Self {
        let (event_tx, event_rx) = mpsc::channel(1000);

        let remote_regions: Vec<RemoteRegion> = config
            .regions
            .iter()
            .filter(|r| r.name != config.local_region)
            .map(|r| {
                let client = reqwest::Client::builder()
                    .timeout(Duration::from_secs(600))
                    .connect_timeout(Duration::from_secs(30))
                    .build()
                    .expect("failed to build HTTP client");

                RemoteRegion {
                    config: r.clone(),
                    client,
                    circuit_breaker: CircuitBreaker::new(
                        format!("replication-{}", r.name),
                        CircuitBreakerConfig {
                            failure_threshold: 3,
                            success_threshold: 2,
                            open_duration_secs: 30,
                        },
                    ),
                    retry_policy: RetryPolicy {
                        max_retries: 3,
                        base_delay_ms: 500,
                        max_delay_ms: 10000,
                        jitter: true,
                    },
                }
            })
            .collect();

        Self {
            local_region: config.local_region.clone(),
            local_store,
            remote_regions,
            mode: config.replication.mode,
            event_tx,
            event_rx: Some(event_rx),
        }
    }

    /// Get a handle for enqueuing events from request handlers.
    pub fn handle(&self) -> ReplicationHandle {
        ReplicationHandle {
            event_tx: self.event_tx.clone(),
            mode: self.mode,
            local_region: self.local_region.clone(),
        }
    }

    /// Start the background replication loop. Consumes self.
    pub async fn run(mut self) {
        let mut rx = self
            .event_rx
            .take()
            .expect("Replicator::run called more than once");

        info!(
            local_region = %self.local_region,
            remote_count = self.remote_regions.len(),
            mode = ?self.mode,
            "Replication loop started"
        );

        while let Some(event) = rx.recv().await {
            debug!(
                event_id = %event.id,
                event_type = ?event.event_type,
                tenant = %event.tenant,
                "Processing replication event"
            );

            // Persist the event to local store for durability
            if let Err(e) = self.persist_event(&event).await {
                error!(error = %e, "Failed to persist replication event");
            }

            // Replicate to all remote regions
            for remote in &self.remote_regions {
                if let Err(e) = self.replicate_to_region(remote, &event).await {
                    error!(
                        region = %remote.config.name,
                        event_id = %event.id,
                        error = %e,
                        "Failed to replicate to region"
                    );
                }
            }
        }

        info!("Replication loop ended");
    }

    async fn persist_event(&self, event: &ReplicationEvent) -> Result<(), ReplicationError> {
        let path = StorePath::from(event.storage_path());
        let data = serde_json::to_vec(event)
            .map_err(|e| ReplicationError::Serialization(e.to_string()))?;
        self.local_store
            .put(&path, data.into())
            .await
            .map_err(|e| ReplicationError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn replicate_to_region(
        &self,
        remote: &RemoteRegion,
        event: &ReplicationEvent,
    ) -> Result<(), ReplicationError> {
        match event.event_type {
            ReplicationEventType::ManifestPush => self.replicate_manifest(remote, event).await,
            ReplicationEventType::BlobPush => self.replicate_blob(remote, event).await,
            ReplicationEventType::ManifestDelete => self.replicate_delete(remote, event).await,
        }
    }

    async fn replicate_manifest(
        &self,
        remote: &RemoteRegion,
        event: &ReplicationEvent,
    ) -> Result<(), ReplicationError> {
        // Read manifest from local store
        let manifest_store_path = StorePath::from(nebula_common::storage::manifest_path(
            &event.tenant,
            &event.project,
            &event.repo,
            &event.digest,
        ));

        let data = self
            .local_store
            .get(&manifest_store_path)
            .await
            .map_err(|e| ReplicationError::Storage(e.to_string()))?
            .bytes()
            .await
            .map_err(|e| ReplicationError::Storage(e.to_string()))?;

        // Push to remote region's internal replication endpoint
        let url = format!(
            "{}/internal/replicate/manifest",
            remote.config.internal_endpoint
        );

        let result = remote
            .circuit_breaker
            .call(|| {
                let client = remote.client.clone();
                let url = url.clone();
                let event = event.clone();
                let data = data.clone();
                remote.retry_policy.execute(move || {
                    let client = client.clone();
                    let url = url.clone();
                    let event = event.clone();
                    let data = data.clone();
                    async move {
                        let resp = client
                            .post(&url)
                            .header("X-Replication-Event-ID", event.id.to_string())
                            .header("X-Replication-Tenant", &event.tenant)
                            .header("X-Replication-Project", &event.project)
                            .header("X-Replication-Repo", &event.repo)
                            .header("X-Replication-Reference", &event.reference)
                            .header("X-Replication-Digest", &event.digest)
                            .header("X-Replication-Source-Region", &event.source_region)
                            .body(data.to_vec())
                            .send()
                            .await
                            .map_err(|e| ReplicationError::Network(e.to_string()))?;

                        if !resp.status().is_success() {
                            let status = resp.status().as_u16();
                            let body = resp.text().await.unwrap_or_default();
                            return Err(ReplicationError::RemoteRejected { status, body });
                        }

                        Ok(())
                    }
                })
            })
            .await;

        match result {
            Ok(r) => Ok(r),
            Err(nebula_resilience::circuit_breaker::CircuitBreakerCallError::BreakerOpen(_)) => {
                Err(ReplicationError::CircuitBreakerOpen {
                    region: remote.config.name.clone(),
                })
            }
            Err(nebula_resilience::circuit_breaker::CircuitBreakerCallError::Inner(e)) => Err(e),
        }
    }

    async fn replicate_blob(
        &self,
        remote: &RemoteRegion,
        event: &ReplicationEvent,
    ) -> Result<(), ReplicationError> {
        let blob_store_path = StorePath::from(nebula_common::storage::blob_path(
            &event.tenant,
            &event.project,
            &event.repo,
            &event.digest,
        ));

        let data = self
            .local_store
            .get(&blob_store_path)
            .await
            .map_err(|e| ReplicationError::Storage(e.to_string()))?
            .bytes()
            .await
            .map_err(|e| ReplicationError::Storage(e.to_string()))?;

        let url = format!(
            "{}/internal/replicate/blob",
            remote.config.internal_endpoint
        );

        let result = remote
            .circuit_breaker
            .call(|| {
                let client = remote.client.clone();
                let url = url.clone();
                let event = event.clone();
                let data = data.clone();
                remote.retry_policy.execute(move || {
                    let client = client.clone();
                    let url = url.clone();
                    let event = event.clone();
                    let data = data.clone();
                    async move {
                        let resp = client
                            .post(&url)
                            .header("X-Replication-Event-ID", event.id.to_string())
                            .header("X-Replication-Tenant", &event.tenant)
                            .header("X-Replication-Project", &event.project)
                            .header("X-Replication-Repo", &event.repo)
                            .header("X-Replication-Digest", &event.digest)
                            .header("X-Replication-Source-Region", &event.source_region)
                            .body(data.to_vec())
                            .send()
                            .await
                            .map_err(|e| ReplicationError::Network(e.to_string()))?;

                        if !resp.status().is_success() {
                            let status = resp.status().as_u16();
                            let body = resp.text().await.unwrap_or_default();
                            return Err(ReplicationError::RemoteRejected { status, body });
                        }

                        Ok(())
                    }
                })
            })
            .await;

        match result {
            Ok(r) => Ok(r),
            Err(nebula_resilience::circuit_breaker::CircuitBreakerCallError::BreakerOpen(_)) => {
                Err(ReplicationError::CircuitBreakerOpen {
                    region: remote.config.name.clone(),
                })
            }
            Err(nebula_resilience::circuit_breaker::CircuitBreakerCallError::Inner(e)) => Err(e),
        }
    }

    async fn replicate_delete(
        &self,
        remote: &RemoteRegion,
        event: &ReplicationEvent,
    ) -> Result<(), ReplicationError> {
        let url = format!(
            "{}/internal/replicate/delete",
            remote.config.internal_endpoint
        );

        let result = remote
            .circuit_breaker
            .call(|| {
                let client = remote.client.clone();
                let url = url.clone();
                let event = event.clone();
                remote.retry_policy.execute(move || {
                    let client = client.clone();
                    let url = url.clone();
                    let event = event.clone();
                    async move {
                        let body = serde_json::to_vec(&event)
                            .map_err(|e| ReplicationError::Serialization(e.to_string()))?;
                        let resp = client
                            .post(&url)
                            .header("content-type", "application/json")
                            .body(body)
                            .send()
                            .await
                            .map_err(|e| ReplicationError::Network(e.to_string()))?;

                        if !resp.status().is_success() {
                            let status = resp.status().as_u16();
                            let body = resp.text().await.unwrap_or_default();
                            return Err(ReplicationError::RemoteRejected { status, body });
                        }

                        Ok(())
                    }
                })
            })
            .await;

        match result {
            Ok(r) => Ok(r),
            Err(nebula_resilience::circuit_breaker::CircuitBreakerCallError::BreakerOpen(_)) => {
                Err(ReplicationError::CircuitBreakerOpen {
                    region: remote.config.name.clone(),
                })
            }
            Err(nebula_resilience::circuit_breaker::CircuitBreakerCallError::Inner(e)) => Err(e),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ReplicationError {
    #[error("storage error: {0}")]
    Storage(String),
    #[error("network error: {0}")]
    Network(String),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("remote region rejected: HTTP {status}: {body}")]
    RemoteRejected { status: u16, body: String },
    #[error("circuit breaker open for region '{region}'")]
    CircuitBreakerOpen { region: String },
}
