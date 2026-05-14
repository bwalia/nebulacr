//! Terraform / OpenTofu module artifact validator.

use crate::types::{ArtifactError, ArtifactMetadata, ArtifactType, ArtifactTypeId};
use async_trait::async_trait;
use serde::Deserialize;

pub const TF_CONFIG_MEDIA: &str = "application/vnd.opentofu.modulepkg.config.v1+json";
pub const TF_MODULE_LAYER_MEDIA: &str = "application/vnd.opentofu.modulepkg.v1.tar+gzip";

pub struct TerraformModuleType;

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
impl ArtifactType for TerraformModuleType {
    fn type_id(&self) -> ArtifactTypeId {
        ArtifactTypeId::Tfmodule
    }

    fn matches(&self, media_type: &str) -> bool {
        media_type == "application/vnd.oci.image.manifest.v1+json"
            || media_type.starts_with("application/vnd.opentofu.")
            || media_type.starts_with("application/vnd.terraform.")
    }

    async fn validate(&self, manifest_bytes: &[u8]) -> Result<ArtifactMetadata, ArtifactError> {
        let m: OciManifest = serde_json::from_slice(manifest_bytes)
            .map_err(|e| ArtifactError::Serde(e.to_string()))?;

        if m.config.media_type != TF_CONFIG_MEDIA {
            return Err(ArtifactError::UnsupportedMediaType);
        }
        let module_layer = m
            .layers
            .iter()
            .find(|d| d.media_type == TF_MODULE_LAYER_MEDIA)
            .ok_or_else(|| {
                ArtifactError::Invalid(format!(
                    "tfmodule artifact missing layer mediaType {TF_MODULE_LAYER_MEDIA}"
                ))
            })?;

        Ok(ArtifactMetadata {
            type_id: ArtifactTypeId::Tfmodule,
            fields: serde_json::json!({
                "config_digest":   m.config.digest,
                "module_digest":   module_layer.digest,
                "module_bytes":    module_layer.size,
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
    async fn validates_tfmodule() {
        let body = serde_json::json!({
            "schemaVersion": 2,
            "config": { "mediaType": TF_CONFIG_MEDIA, "digest": "sha256:c", "size": 64 },
            "layers": [{
                "mediaType": TF_MODULE_LAYER_MEDIA,
                "digest": "sha256:1",
                "size": 4_096
            }]
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        let meta = TerraformModuleType.validate(&bytes).await.unwrap();
        assert_eq!(meta.type_id, ArtifactTypeId::Tfmodule);
        assert_eq!(meta.fields["module_bytes"], 4_096);
    }

    #[tokio::test]
    async fn rejects_tfmodule_missing_layer() {
        let body = serde_json::json!({
            "schemaVersion": 2,
            "config": { "mediaType": TF_CONFIG_MEDIA, "digest": "sha256:c", "size": 64 },
            "layers": []
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        let err = TerraformModuleType.validate(&bytes).await.unwrap_err();
        matches!(err, ArtifactError::Invalid(_));
    }
}
