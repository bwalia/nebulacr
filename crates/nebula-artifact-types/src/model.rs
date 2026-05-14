//! AI/ML model artifact validator.
//!
//! Recognises CNCF-spec'd model artifacts. The slice-1 contract is
//! manifest-shape only: config mediaType + at least one model-weight
//! layer. Slice 3 will fetch the config blob to extract framework /
//! parameter count / quantization.

use crate::types::{ArtifactError, ArtifactMetadata, ArtifactType, ArtifactTypeId};
use async_trait::async_trait;
use serde::Deserialize;

pub const MODEL_CONFIG_MEDIA: &str = "application/vnd.cncf.model.config.v1+json";

/// Recognised model-weight layer media types. CNCF model spec lists
/// several; we accept any that follows the model-weights naming.
fn is_weights_media_type(mt: &str) -> bool {
    mt.starts_with("application/vnd.cncf.model.weight.")
        || mt.starts_with("application/vnd.cncf.model.dataset.")
        // Hugging Face / GGUF artifacts often pick custom mt's; accept
        // anything claiming to be a model weight blob.
        || mt.contains("model.weights")
}

pub struct ModelType;

#[derive(Debug, Deserialize)]
struct OciManifest {
    config: Descriptor,
    #[serde(default)]
    layers: Vec<Descriptor>,
}

#[derive(Debug, Deserialize)]
struct Descriptor {
    #[serde(rename = "mediaType")]
    media_type: String,
    digest: String,
    #[serde(default)]
    size: i64,
}

#[async_trait]
impl ArtifactType for ModelType {
    fn type_id(&self) -> ArtifactTypeId {
        ArtifactTypeId::Model
    }

    fn matches(&self, media_type: &str) -> bool {
        media_type == "application/vnd.oci.image.manifest.v1+json"
            || media_type.starts_with("application/vnd.cncf.model.")
    }

    async fn validate(&self, manifest_bytes: &[u8]) -> Result<ArtifactMetadata, ArtifactError> {
        let m: OciManifest = serde_json::from_slice(manifest_bytes)
            .map_err(|e| ArtifactError::Serde(e.to_string()))?;

        if m.config.media_type != MODEL_CONFIG_MEDIA {
            return Err(ArtifactError::UnsupportedMediaType);
        }

        let weight_layers: Vec<&Descriptor> = m
            .layers
            .iter()
            .filter(|d| is_weights_media_type(&d.media_type))
            .collect();
        if weight_layers.is_empty() {
            return Err(ArtifactError::Invalid(
                "model artifact has no recognised weight layer".into(),
            ));
        }

        let total_bytes: i64 = weight_layers.iter().map(|d| d.size).sum();
        let layer_count = weight_layers.len();

        Ok(ArtifactMetadata {
            type_id: ArtifactTypeId::Model,
            fields: serde_json::json!({
                "config_digest":  m.config.digest,
                "weight_layers":  layer_count,
                "weight_bytes":   total_bytes,
            }),
            media_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
            bytes: manifest_bytes.len() as i64,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn validates_model_with_weights() {
        let body = serde_json::json!({
            "schemaVersion": 2,
            "config": {
                "mediaType": MODEL_CONFIG_MEDIA,
                "digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "size": 200
            },
            "layers": [
                {
                    "mediaType": "application/vnd.cncf.model.weight.v1.tar+gzip",
                    "digest": "sha256:1",
                    "size": 1_000_000_000_i64
                },
                {
                    "mediaType": "application/vnd.cncf.model.weight.v1.tar+gzip",
                    "digest": "sha256:2",
                    "size": 200_000_000_i64
                }
            ]
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        let meta = ModelType.validate(&bytes).await.unwrap();
        assert_eq!(meta.type_id, ArtifactTypeId::Model);
        assert_eq!(meta.fields["weight_layers"], 2);
        assert_eq!(meta.fields["weight_bytes"], 1_200_000_000_i64);
    }

    #[tokio::test]
    async fn rejects_model_without_weights() {
        let body = serde_json::json!({
            "schemaVersion": 2,
            "config": {
                "mediaType": MODEL_CONFIG_MEDIA,
                "digest": "sha256:c",
                "size": 1
            },
            "layers": []
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        let err = ModelType.validate(&bytes).await.unwrap_err();
        matches!(err, ArtifactError::Invalid(_));
    }
}
