//! Webhook notification client for NebulaCR registry events.
//!
//! Sends JSON event payloads to configured webhook endpoints (e.g. OpsAPI)
//! when images are pushed or deleted. Supports HMAC-SHA256 signature
//! verification and configurable retry with backoff.

use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use metrics::{counter, histogram};
use reqwest::Client;
use serde::Serialize;
use sha2::Sha256;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use nebula_common::config::WebhookConfig;

type HmacSha256 = Hmac<Sha256>;

// ── Event payload ───────────────────────────────────────────────────

/// JSON payload sent to webhook endpoints.
#[derive(Debug, Clone, Serialize)]
pub struct WebhookPayload {
    /// Unique event ID.
    pub id: String,
    /// Event type: "manifest.push", "manifest.delete", "blob.push".
    pub event: String,
    /// ISO 8601 timestamp.
    pub timestamp: DateTime<Utc>,
    /// Registry event details.
    pub data: WebhookEventData,
}

#[derive(Debug, Clone, Serialize)]
pub struct WebhookEventData {
    pub tenant: String,
    pub project: String,
    pub repository: String,
    pub reference: String,
    pub digest: String,
    pub size: u64,
    /// Source region that originated the event.
    pub source_region: Option<String>,
}

impl WebhookPayload {
    pub fn manifest_push(
        tenant: String,
        project: String,
        repository: String,
        reference: String,
        digest: String,
        size: u64,
        source_region: Option<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            event: "manifest.push".into(),
            timestamp: Utc::now(),
            data: WebhookEventData {
                tenant,
                project,
                repository,
                reference,
                digest,
                size,
                source_region,
            },
        }
    }

    pub fn manifest_delete(
        tenant: String,
        project: String,
        repository: String,
        reference: String,
        digest: String,
        source_region: Option<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            event: "manifest.delete".into(),
            timestamp: Utc::now(),
            data: WebhookEventData {
                tenant,
                project,
                repository,
                reference,
                digest,
                size: 0,
                source_region,
            },
        }
    }

    pub fn blob_push(
        tenant: String,
        project: String,
        repository: String,
        digest: String,
        size: u64,
        source_region: Option<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            event: "blob.push".into(),
            timestamp: Utc::now(),
            data: WebhookEventData {
                tenant,
                project,
                repository,
                reference: String::new(),
                digest,
                size,
                source_region,
            },
        }
    }
}

// ── Webhook handle (cloneable sender) ───────────────────────────────

/// Cloneable handle for enqueuing webhook events from request handlers.
#[derive(Clone)]
pub struct WebhookHandle {
    tx: mpsc::Sender<WebhookPayload>,
}

impl WebhookHandle {
    /// Enqueue a webhook payload for async delivery.
    pub async fn notify(&self, payload: WebhookPayload) {
        let event = payload.event.clone();
        counter!("nebulacr_webhook_enqueued_total", "event" => event.clone()).increment(1);
        if let Err(e) = self.tx.send(payload).await {
            counter!("nebulacr_webhook_enqueue_failures_total", "event" => event).increment(1);
            warn!(error = %e, "Failed to enqueue webhook event (channel full or closed)");
        }
    }
}

// ── Webhook notifier (background worker) ────────────────────────────

/// Background worker that delivers webhook payloads to configured endpoints.
pub struct WebhookNotifier {
    config: Arc<WebhookConfig>,
    client: Client,
    rx: mpsc::Receiver<WebhookPayload>,
}

impl WebhookNotifier {
    /// Create a new notifier and its corresponding handle.
    ///
    /// The handle is cheaply cloneable and used by request handlers to
    /// enqueue events. The notifier should be spawned as a background task.
    pub fn new(config: WebhookConfig) -> (Self, WebhookHandle) {
        let (tx, rx) = mpsc::channel(512);

        let timeout = Duration::from_millis(config.timeout_ms);
        let client = Client::builder()
            .timeout(timeout)
            .user_agent("NebulaCR-Webhook/1.0")
            .build()
            .expect("failed to build HTTP client");

        let config = Arc::new(config);
        let notifier = Self { config, client, rx };
        let handle = WebhookHandle { tx };
        (notifier, handle)
    }

    /// Run the background delivery loop. Consumes self.
    pub async fn run(mut self) {
        info!(
            endpoints = self.config.endpoints.len(),
            "Webhook notifier started"
        );

        while let Some(payload) = self.rx.recv().await {
            self.deliver(&payload).await;
        }

        info!("Webhook notifier shutting down (channel closed)");
    }

    async fn deliver(&self, payload: &WebhookPayload) {
        let body = match serde_json::to_vec(payload) {
            Ok(b) => b,
            Err(e) => {
                error!(error = %e, event_id = %payload.id, "Failed to serialize webhook payload");
                return;
            }
        };

        for endpoint in &self.config.endpoints {
            // Filter by event type if the endpoint specifies a list
            if !endpoint.events.is_empty() && !endpoint.events.contains(&payload.event) {
                debug!(
                    endpoint = %endpoint.name,
                    event = %payload.event,
                    "Skipping endpoint (event not in filter list)"
                );
                continue;
            }

            self.deliver_to_endpoint(endpoint, payload, &body).await;
        }
    }

    async fn deliver_to_endpoint(
        &self,
        endpoint: &nebula_common::config::WebhookEndpoint,
        payload: &WebhookPayload,
        body: &[u8],
    ) {
        let max_retries = self.config.max_retries;
        let started = Instant::now();

        for attempt in 0..=max_retries {
            let mut request = self
                .client
                .post(&endpoint.url)
                .header("Content-Type", "application/json")
                .header("X-NebulaCR-Event", &payload.event)
                .header("X-NebulaCR-Event-ID", &payload.id)
                .header("X-NebulaCR-Delivery-Attempt", (attempt + 1).to_string());

            // Add HMAC-SHA256 signature if a secret is configured
            if let Some(ref secret) = endpoint.secret
                && let Ok(mut mac) = HmacSha256::new_from_slice(secret.as_bytes())
            {
                mac.update(body);
                let signature = hex::encode(mac.finalize().into_bytes());
                request = request.header("X-NebulaCR-Signature", format!("sha256={signature}"));
            }

            // Add custom headers
            if let Some(ref headers) = endpoint.headers {
                for (key, value) in headers {
                    request = request.header(key.as_str(), value.as_str());
                }
            }

            match request.body(body.to_vec()).send().await {
                Ok(resp) if resp.status().is_success() => {
                    debug!(
                        endpoint = %endpoint.name,
                        event_id = %payload.id,
                        status = %resp.status(),
                        "Webhook delivered"
                    );
                    histogram!("nebulacr_webhook_delivery_duration_seconds",
                        "endpoint" => endpoint.name.clone(), "event" => payload.event.clone())
                    .record(started.elapsed().as_secs_f64());
                    counter!("nebulacr_webhook_deliveries_total",
                        "endpoint" => endpoint.name.clone(),
                        "event" => payload.event.clone(),
                        "outcome" => "success")
                    .increment(1);
                    return;
                }
                Ok(resp) => {
                    counter!("nebulacr_webhook_delivery_attempts_total",
                        "endpoint" => endpoint.name.clone(),
                        "outcome" => "non_success_status")
                    .increment(1);
                    warn!(
                        endpoint = %endpoint.name,
                        event_id = %payload.id,
                        status = %resp.status(),
                        attempt = attempt + 1,
                        "Webhook delivery got non-success response"
                    );
                }
                Err(e) => {
                    counter!("nebulacr_webhook_delivery_attempts_total",
                        "endpoint" => endpoint.name.clone(),
                        "outcome" => "transport_error")
                    .increment(1);
                    warn!(
                        endpoint = %endpoint.name,
                        event_id = %payload.id,
                        error = %e,
                        attempt = attempt + 1,
                        "Webhook delivery failed"
                    );
                }
            }

            if attempt < max_retries {
                // Exponential backoff: 500ms, 1s, 2s, ...
                let delay = Duration::from_millis(500 * 2u64.pow(attempt));
                tokio::time::sleep(delay).await;
            }
        }

        histogram!("nebulacr_webhook_delivery_duration_seconds",
            "endpoint" => endpoint.name.clone(), "event" => payload.event.clone())
        .record(started.elapsed().as_secs_f64());
        counter!("nebulacr_webhook_deliveries_total",
            "endpoint" => endpoint.name.clone(),
            "event" => payload.event.clone(),
            "outcome" => "failed")
        .increment(1);
        error!(
            endpoint = %endpoint.name,
            event_id = %payload.id,
            "Webhook delivery failed after {} attempts",
            max_retries + 1
        );
    }
}
