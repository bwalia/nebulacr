//! Registry-side audit log for tracking image push/pull/delete activity.
//!
//! Stores a ring buffer of recent registry events with details about
//! who performed the operation, what was affected, and when.

use std::collections::VecDeque;

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::sync::RwLock;

/// Maximum number of audit events to keep in memory.
const MAX_EVENTS: usize = 10_000;

/// A registry activity audit event.
#[derive(Debug, Clone, Serialize)]
pub struct RegistryAuditEvent {
    pub timestamp: DateTime<Utc>,
    /// Event type: "manifest.push", "manifest.pull", "manifest.delete",
    /// "blob.pull", "blob.push", "tag.list", "catalog.list"
    pub event_type: String,
    /// Subject identity from JWT (e.g. user/service account).
    pub subject: String,
    /// Tenant name.
    pub tenant: String,
    /// Project name.
    pub project: String,
    /// Repository name.
    pub repository: String,
    /// Tag or digest reference (if applicable).
    pub reference: String,
    /// Content digest (if applicable).
    pub digest: String,
    /// Size in bytes (for push operations).
    pub size_bytes: u64,
    /// HTTP status code of the response.
    pub status_code: u16,
    /// Duration of the operation in milliseconds.
    pub duration_ms: u64,
}

/// Thread-safe ring buffer of audit events.
pub struct RegistryAuditLog {
    events: RwLock<VecDeque<RegistryAuditEvent>>,
}

impl RegistryAuditLog {
    pub fn new() -> Self {
        Self {
            events: RwLock::new(VecDeque::with_capacity(MAX_EVENTS)),
        }
    }

    /// Record a new audit event.
    pub async fn record(&self, event: RegistryAuditEvent) {
        let mut events = self.events.write().await;
        if events.len() >= MAX_EVENTS {
            events.pop_front();
        }
        events.push_back(event);
    }

    /// Get the most recent N audit events.
    pub async fn recent(&self, limit: usize) -> Vec<RegistryAuditEvent> {
        let events = self.events.read().await;
        events.iter().rev().take(limit).cloned().collect()
    }

    /// Get the total number of events in the buffer.
    pub async fn count(&self) -> usize {
        self.events.read().await.len()
    }

    /// Get events filtered by event type.
    pub async fn by_type(&self, event_type: &str, limit: usize) -> Vec<RegistryAuditEvent> {
        let events = self.events.read().await;
        events
            .iter()
            .rev()
            .filter(|e| e.event_type == event_type)
            .take(limit)
            .cloned()
            .collect()
    }

    /// Get events filtered by subject (who).
    pub async fn by_subject(&self, subject: &str, limit: usize) -> Vec<RegistryAuditEvent> {
        let events = self.events.read().await;
        events
            .iter()
            .rev()
            .filter(|e| e.subject == subject)
            .take(limit)
            .cloned()
            .collect()
    }

    /// Get summary statistics.
    pub async fn stats(&self) -> AuditStats {
        let events = self.events.read().await;
        let mut stats = AuditStats::default();

        for event in events.iter() {
            match event.event_type.as_str() {
                "manifest.push" | "manifest.replicated" => {
                    stats.total_pushes += 1;
                    stats.total_push_bytes += event.size_bytes;
                }
                "manifest.pull" | "blob.pull" => {
                    stats.total_pulls += 1;
                }
                "manifest.delete" => {
                    stats.total_deletes += 1;
                }
                _ => {}
            }
            stats.total_events += 1;

            if stats.latest_event.is_none() || event.timestamp > stats.latest_event.unwrap() {
                stats.latest_event = Some(event.timestamp);
            }
        }

        // Compute avg latency over last 100 events
        let recent: Vec<_> = events.iter().rev().take(100).collect();
        if !recent.is_empty() {
            let total_ms: u64 = recent.iter().map(|e| e.duration_ms).sum();
            stats.avg_latency_ms = total_ms as f64 / recent.len() as f64;
        }

        stats
    }
}

/// Summary statistics for the audit log.
#[derive(Debug, Clone, Serialize, Default)]
pub struct AuditStats {
    pub total_events: u64,
    pub total_pushes: u64,
    pub total_pulls: u64,
    pub total_deletes: u64,
    pub total_push_bytes: u64,
    pub avg_latency_ms: f64,
    pub latest_event: Option<DateTime<Utc>>,
}
