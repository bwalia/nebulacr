//! Artifact-type validator registry.

use crate::types::{ArtifactError, ArtifactMetadata, ArtifactType};
use std::sync::Arc;

#[derive(Default)]
pub struct ArtifactRegistry {
    types: Vec<Arc<dyn ArtifactType>>,
}

impl ArtifactRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register<T: ArtifactType + 'static>(mut self, t: T) -> Self {
        self.types.push(Arc::new(t));
        self
    }

    /// Find the first registered type whose `matches` returns true.
    pub fn detect(&self, media_type: &str) -> Option<Arc<dyn ArtifactType>> {
        self.types.iter().find(|t| t.matches(media_type)).cloned()
    }

    /// Detect + validate. Returns `Ok(None)` when no validator matched
    /// (caller stores the manifest unchanged), `Err` when a validator
    /// matched but the artifact is malformed under the configured
    /// strictness.
    pub async fn validate(
        &self,
        media_type: &str,
        manifest_bytes: &[u8],
    ) -> Result<Option<ArtifactMetadata>, ArtifactError> {
        match self.detect(media_type) {
            None => Ok(None),
            Some(t) => Ok(Some(t.validate(manifest_bytes).await?)),
        }
    }
}
