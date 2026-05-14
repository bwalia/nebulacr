//! WASM artifact validator.
//!
//! Recognises OCI artifacts whose config mediaType matches the
//! WebAssembly conventions (wasm.config.v1+json, wasm-component
//! Component Model) and emits the high-level shape of the bundle.
//! Real WASM module validation (magic bytes, WIT world parse) lands
//! in slice 3 once the trait widens to fetch blobs.

use crate::types::{ArtifactError, ArtifactMetadata, ArtifactType, ArtifactTypeId};
use async_trait::async_trait;
use serde::Deserialize;

pub const WASM_CONFIG_MEDIA: &str = "application/vnd.wasm.config.v0+json";
pub const WASM_COMPONENT_CONFIG_MEDIA: &str = "application/vnd.wasm.component.config.v1+json";
pub const WASM_LAYER_MEDIA: &str = "application/vnd.wasm.content.layer.v1+wasm";

pub struct WasmType;

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
impl ArtifactType for WasmType {
    fn type_id(&self) -> ArtifactTypeId {
        ArtifactTypeId::Wasm
    }

    fn matches(&self, media_type: &str) -> bool {
        media_type == "application/vnd.oci.image.manifest.v1+json"
            || media_type.starts_with("application/vnd.wasm.")
    }

    async fn validate(&self, manifest_bytes: &[u8]) -> Result<ArtifactMetadata, ArtifactError> {
        let m: OciManifest = serde_json::from_slice(manifest_bytes)
            .map_err(|e| ArtifactError::Serde(e.to_string()))?;

        let is_component = m.config.media_type == WASM_COMPONENT_CONFIG_MEDIA;
        if m.config.media_type != WASM_CONFIG_MEDIA && !is_component {
            return Err(ArtifactError::UnsupportedMediaType);
        }

        let wasm_layer = m
            .layers
            .iter()
            .find(|d| d.media_type == WASM_LAYER_MEDIA)
            .ok_or_else(|| {
                ArtifactError::Invalid(format!(
                    "wasm artifact missing layer mediaType {WASM_LAYER_MEDIA}"
                ))
            })?;

        Ok(ArtifactMetadata {
            type_id: ArtifactTypeId::Wasm,
            fields: serde_json::json!({
                "config_digest": m.config.digest,
                "wasm_layer_digest": wasm_layer.digest,
                "wasm_layer_bytes": wasm_layer.size,
                "is_component": is_component,
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
    async fn validates_wasm_module() {
        let body = serde_json::json!({
            "schemaVersion": 2,
            "config": {
                "mediaType": WASM_CONFIG_MEDIA,
                "digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "size": 64
            },
            "layers": [{
                "mediaType": WASM_LAYER_MEDIA,
                "digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "size": 8_192
            }]
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        let meta = WasmType.validate(&bytes).await.unwrap();
        assert_eq!(meta.type_id, ArtifactTypeId::Wasm);
        assert_eq!(meta.fields["is_component"], false);
        assert_eq!(meta.fields["wasm_layer_bytes"], 8_192);
    }

    #[tokio::test]
    async fn validates_wasm_component() {
        let body = serde_json::json!({
            "schemaVersion": 2,
            "config": {
                "mediaType": WASM_COMPONENT_CONFIG_MEDIA,
                "digest": "sha256:c",
                "size": 64
            },
            "layers": [{
                "mediaType": WASM_LAYER_MEDIA,
                "digest": "sha256:1",
                "size": 1024
            }]
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        let meta = WasmType.validate(&bytes).await.unwrap();
        assert_eq!(meta.fields["is_component"], true);
    }

    #[tokio::test]
    async fn rejects_non_wasm_config() {
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
        let err = WasmType.validate(&bytes).await.unwrap_err();
        matches!(err, ArtifactError::UnsupportedMediaType);
    }
}
