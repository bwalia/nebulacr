//! ArtifactType trait + shared types.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ArtifactTypeId {
    Helm,
    Wasm,
    Model,
    Tfmodule,
}

impl ArtifactTypeId {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Helm => "helm",
            Self::Wasm => "wasm",
            Self::Model => "model",
            Self::Tfmodule => "tfmodule",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactMetadata {
    pub type_id: ArtifactTypeId,
    pub fields: serde_json::Value,
    pub media_type: String,
    pub bytes: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum ArtifactError {
    #[error("media type mismatch")]
    UnsupportedMediaType,
    #[error("invalid artifact: {0}")]
    Invalid(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("serde: {0}")]
    Serde(String),
}

#[async_trait]
pub trait ArtifactType: Send + Sync {
    fn type_id(&self) -> ArtifactTypeId;

    fn matches(&self, media_type: &str) -> bool;

    /// Validate the manifest body + (when needed) any referenced blobs
    /// fetched via the supplied closure-style trait. Slice 1 supplies
    /// only the manifest bytes — slice 2 widens the signature to allow
    /// fetching referenced blobs.
    async fn validate(
        &self,
        manifest_bytes: &[u8],
    ) -> Result<ArtifactMetadata, ArtifactError>;
}
