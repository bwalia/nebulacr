//! Manifest parsing for refcount extraction.
//!
//! The registry already validates OCI manifests are JSON; this module
//! pulls the descriptor list out without re-validating. We support:
//! - OCI image manifests (config + layers)
//! - Docker v2.2 image manifests (config + layers)
//! - OCI image indexes / Docker manifest lists (manifests array)
//! - Generic OCI artifact manifests (config + layers + optional subject)

use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobDescriptor {
    pub digest: String,
    pub size: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum ManifestParseError {
    #[error("manifest is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Deserialize)]
struct RawDescriptor {
    digest: String,
    #[serde(default)]
    size: i64,
}

#[derive(Debug, Deserialize)]
struct RawManifest {
    #[serde(default)]
    config: Option<RawDescriptor>,
    #[serde(default)]
    layers: Vec<RawDescriptor>,
    #[serde(default)]
    manifests: Vec<RawDescriptor>,
    #[serde(default)]
    subject: Option<RawDescriptor>,
}

/// Pull just the config-blob digest from an image manifest, if any.
/// Returns `None` for image indexes (which have no config blob) and
/// for malformed JSON.
pub fn extract_config_digest(bytes: &[u8]) -> Option<String> {
    let raw: RawManifest = serde_json::from_slice(bytes).ok()?;
    raw.config.and_then(|c| {
        if c.digest.is_empty() {
            None
        } else {
            Some(c.digest)
        }
    })
}

/// Pull every blob descriptor that should bump a refcount when the
/// manifest is stored. For an image manifest this is the config blob
/// plus every layer; for an image index it is each child manifest's
/// digest (those child manifests will themselves carry their own
/// edges when they are pushed). The optional `subject` field (OCI
/// 1.1 referrers) is intentionally NOT counted — the subject relation
/// is a soft pointer; deleting the subject must not be blocked by
/// referrers.
///
/// Duplicate digests are de-duplicated; the registry stores layers
/// content-addressably so a layer referenced twice in the same
/// manifest is still one blob.
pub fn extract_blob_digests(bytes: &[u8]) -> Result<Vec<BlobDescriptor>, ManifestParseError> {
    let raw: RawManifest = serde_json::from_slice(bytes)?;

    let mut out: Vec<BlobDescriptor> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    let push = |d: RawDescriptor,
                sink: &mut Vec<BlobDescriptor>,
                seen: &mut std::collections::HashSet<String>| {
        if d.digest.is_empty() {
            return;
        }
        if seen.insert(d.digest.clone()) {
            sink.push(BlobDescriptor {
                digest: d.digest,
                size: d.size,
            });
        }
    };

    if let Some(cfg) = raw.config {
        push(cfg, &mut out, &mut seen);
    }
    for l in raw.layers {
        push(l, &mut out, &mut seen);
    }
    for m in raw.manifests {
        push(m, &mut out, &mut seen);
    }
    // `subject` deliberately NOT included — it's a soft pointer.
    let _ = raw.subject;

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_oci_image_manifest() {
        let body = br#"{
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
              "digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
              "size": 1234,
              "mediaType": "application/vnd.oci.image.config.v1+json"
            },
            "layers": [
              {"digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111", "size": 100},
              {"digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222", "size": 200}
            ]
        }"#;
        let got = extract_blob_digests(body).unwrap();
        let digests: Vec<&str> = got.iter().map(|d| d.digest.as_str()).collect();
        assert_eq!(digests.len(), 3);
        assert!(
            digests.contains(
                &"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            )
        );
        assert!(
            digests.contains(
                &"sha256:1111111111111111111111111111111111111111111111111111111111111111"
            )
        );
        assert!(
            digests.contains(
                &"sha256:2222222222222222222222222222222222222222222222222222222222222222"
            )
        );
    }

    #[test]
    fn dedupes_duplicate_layer_digest() {
        let body = br#"{
            "schemaVersion": 2,
            "config": {"digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", "size": 0},
            "layers": [
              {"digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111", "size": 100},
              {"digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111", "size": 100}
            ]
        }"#;
        let got = extract_blob_digests(body).unwrap();
        assert_eq!(got.len(), 2, "config + 1 layer (deduped)");
    }

    #[test]
    fn extracts_image_index_manifests() {
        let body = br#"{
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
              {"digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "size": 500},
              {"digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "size": 600}
            ]
        }"#;
        let got = extract_blob_digests(body).unwrap();
        assert_eq!(got.len(), 2);
    }

    #[test]
    fn does_not_count_subject_descriptor() {
        let body = br#"{
            "schemaVersion": 2,
            "config": {"digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", "size": 0},
            "layers": [],
            "subject": {"digest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", "size": 1}
        }"#;
        let got = extract_blob_digests(body).unwrap();
        let digests: Vec<&str> = got.iter().map(|d| d.digest.as_str()).collect();
        assert_eq!(digests.len(), 1);
        assert_eq!(
            digests[0],
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        );
    }

    #[test]
    fn rejects_invalid_json() {
        let body = b"not json";
        let err = extract_blob_digests(body).unwrap_err();
        matches!(err, ManifestParseError::Json(_));
    }

    #[test]
    fn empty_manifest_returns_no_digests() {
        let body = br#"{"schemaVersion": 2}"#;
        let got = extract_blob_digests(body).unwrap();
        assert!(got.is_empty());
    }

    #[test]
    fn extracts_config_digest() {
        let body = br#"{
            "schemaVersion": 2,
            "config": {"digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", "size": 0},
            "layers": []
        }"#;
        assert_eq!(
            extract_config_digest(body).as_deref(),
            Some("sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
        );
    }

    #[test]
    fn config_digest_none_for_image_index() {
        let body = br#"{
            "schemaVersion": 2,
            "manifests": [{"digest": "sha256:aaaa", "size": 1}]
        }"#;
        assert!(extract_config_digest(body).is_none());
    }
}
