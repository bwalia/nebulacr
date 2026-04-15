//! OCI image introspection.
//!
//! Given a `(tenant, project, repo, digest)` tuple, reads the manifest JSON
//! from the registry's object store, picks the right arch for index
//! manifests, then enumerates layer blobs and walks each layer's tar entries
//! invoking a visitor callback per file.
//!
//! Layers are streamed into memory one at a time (typical base-image layers
//! are tens to low-hundreds of MB — acceptable; we cap with `MAX_LAYER_BYTES`).

use std::io::Read;
use std::sync::Arc;

use bytes::Bytes;
use flate2::read::GzDecoder;
use object_store::{path::Path as StorePath, ObjectStore};
use serde::Deserialize;
use tracing::{debug, warn};

use crate::{Result, ScanError};

const MAX_LAYER_BYTES: u64 = 1024 * 1024 * 512; // 512 MiB per layer safety cap
const DEFAULT_ARCH: &str = "amd64";
const DEFAULT_OS: &str = "linux";

pub struct ImageLocator {
    pub tenant: String,
    pub project: String,
    pub repository: String,
    pub digest: String,
}

pub trait LayerVisitor: Send {
    fn visit(&mut self, layer_digest: &str, path: &str, contents: &[u8]);
}

#[derive(Deserialize)]
struct Manifest {
    #[serde(rename = "mediaType")]
    media_type: Option<String>,
    #[serde(default)]
    manifests: Vec<ManifestDescriptor>,
    #[serde(default)]
    layers: Vec<LayerDescriptor>,
}

#[derive(Deserialize)]
struct ManifestDescriptor {
    digest: String,
    #[serde(default)]
    platform: Option<Platform>,
}

#[derive(Deserialize)]
struct Platform {
    architecture: String,
    os: String,
}

#[derive(Deserialize, Clone)]
struct LayerDescriptor {
    digest: String,
    #[serde(rename = "mediaType")]
    media_type: String,
}

pub struct Puller {
    store: Arc<dyn ObjectStore>,
}

impl Puller {
    pub fn new(store: Arc<dyn ObjectStore>) -> Self {
        Self { store }
    }

    /// Read a layer blob by digest.
    async fn fetch_blob(&self, loc: &ImageLocator, digest: &str) -> Result<Bytes> {
        let path = nebula_common::storage::blob_path(
            &loc.tenant,
            &loc.project,
            &loc.repository,
            digest,
        );
        let bytes = self
            .store
            .get(&StorePath::from(path))
            .await?
            .bytes()
            .await?;
        Ok(bytes)
    }

    /// Read a manifest by digest reference. Manifests live under a separate
    /// `manifests/` prefix in the registry's object store, not `blobs/`.
    async fn fetch_manifest_bytes(&self, loc: &ImageLocator, reference: &str) -> Result<Bytes> {
        let path = nebula_common::storage::manifest_path(
            &loc.tenant,
            &loc.project,
            &loc.repository,
            reference,
        );
        let bytes = self
            .store
            .get(&StorePath::from(path))
            .await?
            .bytes()
            .await?;
        Ok(bytes)
    }

    /// Fetch the top-level manifest bytes for the image.
    pub async fn fetch_manifest(&self, loc: &ImageLocator) -> Result<Bytes> {
        self.fetch_manifest_bytes(loc, &loc.digest).await
    }

    /// Resolve the image's effective layer list, following an index manifest
    /// to the linux/amd64 manifest when necessary.
    async fn resolve_layers(&self, loc: &ImageLocator) -> Result<Vec<LayerDescriptor>> {
        let bytes = self.fetch_manifest(loc).await?;
        let manifest: Manifest = serde_json::from_slice(&bytes)?;

        let is_index = manifest
            .media_type
            .as_deref()
            .map(|mt| mt.contains("image.index") || mt.contains("manifest.list"))
            .unwrap_or(false)
            || !manifest.manifests.is_empty();

        if is_index {
            let pick = manifest
                .manifests
                .iter()
                .find(|m| {
                    m.platform
                        .as_ref()
                        .map(|p| p.os == DEFAULT_OS && p.architecture == DEFAULT_ARCH)
                        .unwrap_or(false)
                })
                .ok_or_else(|| {
                    ScanError::Image(format!(
                        "index has no {}/{} manifest",
                        DEFAULT_OS, DEFAULT_ARCH
                    ))
                })?;
            let sub = self.fetch_manifest_bytes(loc, &pick.digest).await?;
            let sub_manifest: Manifest = serde_json::from_slice(&sub)?;
            Ok(sub_manifest.layers)
        } else {
            Ok(manifest.layers)
        }
    }

    /// Walk every layer top-to-bottom, invoking `visitor.visit` for each tar
    /// entry. Supports gzip-compressed layers (the overwhelmingly common case);
    /// zstd layers are skipped with a warning until we add the decoder.
    pub async fn walk_layers<V: LayerVisitor>(
        &self,
        loc: &ImageLocator,
        visitor: &mut V,
    ) -> Result<()> {
        let layers = self.resolve_layers(loc).await?;
        debug!(digest = %loc.digest, layers = layers.len(), "walking image layers");

        for layer in layers {
            let data = self.fetch_blob(loc, &layer.digest).await?;
            if data.len() as u64 > MAX_LAYER_BYTES {
                warn!(
                    layer = %layer.digest,
                    bytes = data.len(),
                    "layer exceeds MAX_LAYER_BYTES; skipping"
                );
                continue;
            }
            walk_layer(&layer, &data, visitor)?;
        }
        Ok(())
    }
}

fn walk_layer<V: LayerVisitor>(layer: &LayerDescriptor, data: &[u8], visitor: &mut V) -> Result<()> {
    let mt = layer.media_type.as_str();
    let decoded: Box<dyn Read> = if mt.contains("gzip") || mt.contains("tar+gzip") {
        Box::new(GzDecoder::new(data))
    } else if mt.contains("zstd") {
        match zstd::stream::Decoder::new(data) {
            Ok(d) => Box::new(d),
            Err(e) => {
                warn!(layer = %layer.digest, error = %e, "zstd decoder init failed; skipping layer");
                return Ok(());
            }
        }
    } else if mt.contains("tar") {
        Box::new(data)
    } else {
        warn!(layer = %layer.digest, media_type = mt, "unknown layer media type; skipping");
        return Ok(());
    };

    let mut archive = tar::Archive::new(decoded);
    let entries = archive
        .entries()
        .map_err(|e| ScanError::Image(format!("tar entries: {e}")))?;
    for entry in entries {
        let mut entry = match entry {
            Ok(e) => e,
            Err(e) => {
                warn!(layer = %layer.digest, error = %e, "tar entry error");
                continue;
            }
        };
        // Only interested in regular files for SBOM extraction.
        if entry.header().entry_type() != tar::EntryType::Regular {
            continue;
        }
        let path = match entry.path() {
            Ok(p) => p.to_string_lossy().into_owned(),
            Err(_) => continue,
        };
        // Strip leading "./" so parsers can match on absolute-style paths.
        let path = path.trim_start_matches("./").to_string();

        // Path filter: only read bytes for files the SBOM layer cares about,
        // to avoid allocating multi-MB blobs for every binary in a layer.
        if !is_interesting(&path) {
            continue;
        }

        let mut buf = Vec::new();
        if let Err(e) = entry.read_to_end(&mut buf) {
            warn!(layer = %layer.digest, %path, error = %e, "tar read failed");
            continue;
        }
        visitor.visit(&layer.digest, &path, &buf);
    }
    Ok(())
}

/// Keep this in sync with `sbom::dispatch` — any path we match there must
/// return true here, so we don't skip reading its bytes.
fn is_interesting(path: &str) -> bool {
    path == "var/lib/dpkg/status"
        || path.ends_with("/dpkg/status")
        || path == "lib/apk/db/installed"
        || path.ends_with("/apk/db/installed")
        || path.ends_with("var/lib/rpm/Packages")
        || path.ends_with("var/lib/rpm/rpmdb.sqlite")
        || path.ends_with("package-lock.json")
        || path.ends_with("npm-shrinkwrap.json")
        || path.ends_with("Cargo.lock")
        || path.ends_with("requirements.txt")
        || path.ends_with(".dist-info/METADATA")
        || path.ends_with(".egg-info/PKG-INFO")
        || path.ends_with("go.sum")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_interesting_paths() {
        assert!(is_interesting("var/lib/dpkg/status"));
        assert!(is_interesting("lib/apk/db/installed"));
        assert!(is_interesting("app/package-lock.json"));
        assert!(is_interesting("go.sum"));
        assert!(!is_interesting("bin/bash"));
        assert!(!is_interesting("etc/hosts"));
    }
}
