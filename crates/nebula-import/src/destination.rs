//! Destination trait + an HTTP impl that pushes through the
//! NebulaCR registry's standard OCI Distribution API.
//!
//! The runner is source-agnostic on the read side
//! (`RegistrySource`) and destination-agnostic on the write side
//! (`RegistryDestination`) — wiring is via small adapters. This
//! lets unit tests drive the runner against an in-memory
//! destination without standing up a registry.

use crate::source::ImportError;
use async_trait::async_trait;
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

#[async_trait]
pub trait RegistryDestination: Send + Sync {
    /// Upload a blob. Implementations are responsible for
    /// idempotency (HEAD before upload).
    async fn put_blob(
        &self,
        tenant: &str,
        project: &str,
        repository: &str,
        digest: &str,
        bytes: Bytes,
    ) -> Result<(), ImportError>;

    /// Upload a manifest under `tenant/project/repository:tag`.
    async fn put_manifest(
        &self,
        tenant: &str,
        project: &str,
        repository: &str,
        tag: &str,
        bytes: Bytes,
        media_type: &str,
    ) -> Result<(), ImportError>;
}

/// In-process destination — used for unit tests + dry-run runs.
/// Records every put without actually shipping bytes anywhere.
#[derive(Default, Clone)]
pub struct InMemoryDestination {
    pub blobs: Arc<RwLock<HashMap<String, Bytes>>>,
    pub manifests: Arc<RwLock<HashMap<String, (Bytes, String)>>>,
}

impl InMemoryDestination {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn blob_count(&self) -> usize {
        self.blobs.read().unwrap().len()
    }
    pub fn manifest_count(&self) -> usize {
        self.manifests.read().unwrap().len()
    }
}

#[async_trait]
impl RegistryDestination for InMemoryDestination {
    async fn put_blob(
        &self,
        tenant: &str,
        project: &str,
        repository: &str,
        digest: &str,
        bytes: Bytes,
    ) -> Result<(), ImportError> {
        let key = format!("{tenant}/{project}/{repository}/{digest}");
        self.blobs.write().unwrap().insert(key, bytes);
        Ok(())
    }

    async fn put_manifest(
        &self,
        tenant: &str,
        project: &str,
        repository: &str,
        tag: &str,
        bytes: Bytes,
        media_type: &str,
    ) -> Result<(), ImportError> {
        let key = format!("{tenant}/{project}/{repository}:{tag}");
        self.manifests
            .write()
            .unwrap()
            .insert(key, (bytes, media_type.to_string()));
        Ok(())
    }
}
