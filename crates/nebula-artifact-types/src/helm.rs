//! Helm chart artifact validator.
//!
//! Slice 1: media-type detection + manifest config-blob shape check.
//! Real Chart.yaml extraction (which requires fetching the config blob
//! out of the OCI manifest) lands in slice 2 once we widen the trait.

use crate::types::{ArtifactError, ArtifactMetadata, ArtifactType, ArtifactTypeId};
use async_trait::async_trait;
use serde::Deserialize;

pub const HELM_CONFIG_MEDIA: &str = "application/vnd.cncf.helm.config.v1+json";
pub const HELM_CHART_LAYER_MEDIA: &str = "application/vnd.cncf.helm.chart.content.v1.tar+gzip";

pub struct HelmType;

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
impl ArtifactType for HelmType {
    fn type_id(&self) -> ArtifactTypeId {
        ArtifactTypeId::Helm
    }

    fn matches(&self, media_type: &str) -> bool {
        // Helm artifacts present at the OCI image-manifest level; the
        // config blob is the helm-specific media type.
        media_type == "application/vnd.oci.image.manifest.v1+json"
            || media_type.starts_with("application/vnd.cncf.helm.")
    }

    async fn validate(&self, manifest_bytes: &[u8]) -> Result<ArtifactMetadata, ArtifactError> {
        let m: OciManifest = serde_json::from_slice(manifest_bytes)
            .map_err(|e| ArtifactError::Serde(e.to_string()))?;

        if m.config.media_type != HELM_CONFIG_MEDIA {
            return Err(ArtifactError::UnsupportedMediaType);
        }

        let chart_layer = m
            .layers
            .iter()
            .find(|d| d.media_type == HELM_CHART_LAYER_MEDIA);
        if chart_layer.is_none() {
            return Err(ArtifactError::Invalid(format!(
                "helm artifact missing chart-layer mediaType {HELM_CHART_LAYER_MEDIA}"
            )));
        }

        Ok(ArtifactMetadata {
            type_id: ArtifactTypeId::Helm,
            fields: serde_json::json!({
                "config_digest": m.config.digest,
                "chart_layer_digest": chart_layer.map(|d| d.digest.clone()),
                "chart_layer_bytes": chart_layer.map(|d| d.size).unwrap_or(0),
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
    async fn validates_helm_manifest_shape() {
        let body = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": HELM_CONFIG_MEDIA,
                "digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "size": 100
            },
            "layers": [
                {
                    "mediaType": HELM_CHART_LAYER_MEDIA,
                    "digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                    "size": 4096
                }
            ]
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        let meta = HelmType.validate(&bytes).await.unwrap();
        assert_eq!(meta.type_id, ArtifactTypeId::Helm);
    }

    #[tokio::test]
    async fn rejects_non_helm_config() {
        let body = serde_json::json!({
            "schemaVersion": 2,
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": "sha256:c",
                "size": 1
            },
            "layers": []
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        let err = HelmType.validate(&bytes).await.unwrap_err();
        matches!(err, ArtifactError::UnsupportedMediaType);
    }

    #[tokio::test]
    async fn rejects_helm_without_chart_layer() {
        let body = serde_json::json!({
            "schemaVersion": 2,
            "config": {
                "mediaType": HELM_CONFIG_MEDIA,
                "digest": "sha256:c",
                "size": 1
            },
            "layers": []
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        let err = HelmType.validate(&bytes).await.unwrap_err();
        matches!(err, ArtifactError::Invalid(_));
    }
}
