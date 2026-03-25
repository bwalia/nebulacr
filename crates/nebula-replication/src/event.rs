use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A replication event representing a write operation that needs to be replicated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationEvent {
    /// Unique event ID.
    pub id: Uuid,
    /// Type of operation.
    pub event_type: ReplicationEventType,
    /// Tenant that owns the resource.
    pub tenant: String,
    /// Project within the tenant.
    pub project: String,
    /// Repository name.
    pub repo: String,
    /// Manifest tag or digest reference.
    pub reference: String,
    /// Content digest (sha256:...).
    pub digest: String,
    /// Size of the content in bytes.
    pub size: u64,
    /// When this event was created.
    pub timestamp: DateTime<Utc>,
    /// Region where the write originated.
    pub source_region: String,
}

/// Type of replication event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplicationEventType {
    ManifestPush,
    BlobPush,
    ManifestDelete,
}

impl ReplicationEvent {
    /// Create a new event for a manifest push.
    pub fn manifest_push(
        tenant: String,
        project: String,
        repo: String,
        reference: String,
        digest: String,
        size: u64,
        source_region: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            event_type: ReplicationEventType::ManifestPush,
            tenant,
            project,
            repo,
            reference,
            digest,
            size,
            timestamp: Utc::now(),
            source_region,
        }
    }

    /// Create a new event for a blob push.
    pub fn blob_push(
        tenant: String,
        project: String,
        repo: String,
        digest: String,
        size: u64,
        source_region: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            event_type: ReplicationEventType::BlobPush,
            tenant,
            project,
            repo,
            reference: digest.clone(),
            digest,
            size,
            timestamp: Utc::now(),
            source_region,
        }
    }

    /// Create a new event for a manifest deletion.
    pub fn manifest_delete(
        tenant: String,
        project: String,
        repo: String,
        reference: String,
        digest: String,
        source_region: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            event_type: ReplicationEventType::ManifestDelete,
            tenant,
            project,
            repo,
            reference,
            digest,
            size: 0,
            timestamp: Utc::now(),
            source_region,
        }
    }

    /// Build the storage path for persisting this event.
    pub fn storage_path(&self) -> String {
        format!(
            "_replication/events/{}-{}.json",
            self.timestamp.format("%Y%m%d%H%M%S%3f"),
            self.id
        )
    }
}
