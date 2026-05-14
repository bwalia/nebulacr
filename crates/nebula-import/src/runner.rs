//! ImportRunner — drives a `RegistrySource` to a
//! `RegistryDestination`. Walks repositories + tags, fetches
//! manifests, parses out blob descriptors, and pushes them in
//! dependency order (blobs before manifest).

use crate::destination::RegistryDestination;
use crate::source::{ImportError, RegistrySource};
use serde::Deserialize;
use std::sync::Arc;
use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
pub struct ImportRunnerConfig {
    pub tenant: String,
    pub project: String,
    /// Maximum concurrent (repo) walks. Slice-2 keeps the runner
    /// serial; the structured model leaves room for parallel walks
    /// in a follow-up.
    pub parallelism: u32,
    /// Optional repo prefix filter applied to the source's catalog.
    /// e.g. "myorg/" will only copy repos whose name starts with it.
    pub include_prefix: Option<String>,
}

impl Default for ImportRunnerConfig {
    fn default() -> Self {
        Self {
            tenant: "default".into(),
            project: "default".into(),
            parallelism: 1,
            include_prefix: None,
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ImportRunReport {
    pub repos_seen: u64,
    pub repos_copied: u64,
    pub tags_copied: u64,
    pub blobs_copied: u64,
    pub bytes_copied: u64,
    pub failures: u64,
}

pub struct ImportRunner {
    pub source: Arc<dyn RegistrySource>,
    pub destination: Arc<dyn RegistryDestination>,
    pub config: ImportRunnerConfig,
}

impl ImportRunner {
    pub async fn run(&self) -> Result<ImportRunReport, ImportError> {
        let mut report = ImportRunReport::default();
        info!(
            tenant = %self.config.tenant,
            project = %self.config.project,
            "import runner starting"
        );

        let repos = self.source.list_repositories().await?;
        for repo in repos {
            if let Some(prefix) = &self.config.include_prefix {
                if !repo.name.starts_with(prefix) {
                    continue;
                }
            }
            report.repos_seen += 1;
            match self.copy_repo(&repo, &mut report).await {
                Ok(()) => report.repos_copied += 1,
                Err(e) => {
                    report.failures += 1;
                    warn!(repo = %repo.name, error = %e, "import: copy failed");
                }
            }
        }
        info!(
            repos = report.repos_seen,
            tags = report.tags_copied,
            blobs = report.blobs_copied,
            bytes = report.bytes_copied,
            failures = report.failures,
            "import runner finished"
        );
        Ok(report)
    }

    async fn copy_repo(
        &self,
        repo: &crate::source::Repository,
        report: &mut ImportRunReport,
    ) -> Result<(), ImportError> {
        let tags = self.source.list_tags(repo).await?;
        for tag in tags {
            match self.copy_tag(repo, &tag.name, report).await {
                Ok(()) => {}
                Err(e) => {
                    report.failures += 1;
                    warn!(
                        repo = %repo.name, tag = %tag.name, error = %e,
                        "import: tag copy failed"
                    );
                }
            }
        }
        Ok(())
    }

    async fn copy_tag(
        &self,
        repo: &crate::source::Repository,
        tag: &str,
        report: &mut ImportRunReport,
    ) -> Result<(), ImportError> {
        let (manifest_bytes, media_type) = self.source.fetch_manifest(repo, tag).await?;
        // Translate <project>/<repo> path → destination repo name.
        let dst_repo = repo.name.as_str();

        // Parse the manifest and copy each referenced blob.
        let descriptors = parse_descriptors(&manifest_bytes);
        for d in descriptors {
            match self.source.fetch_blob(repo, &d.digest).await {
                Ok(bytes) => {
                    let bytes_len = bytes.len() as u64;
                    self.destination
                        .put_blob(
                            &self.config.tenant,
                            &self.config.project,
                            dst_repo,
                            &d.digest,
                            bytes,
                        )
                        .await?;
                    report.blobs_copied += 1;
                    report.bytes_copied += bytes_len;
                }
                Err(e) => {
                    report.failures += 1;
                    warn!(
                        repo = %repo.name, digest = %d.digest, error = %e,
                        "import: blob fetch failed"
                    );
                    // Continue copying the remaining blobs — one missing
                    // blob shouldn't sink the entire tag, but the
                    // manifest push below will fail and we'll log.
                }
            }
        }

        let manifest_bytes_len = manifest_bytes.len() as u64;
        self.destination
            .put_manifest(
                &self.config.tenant,
                &self.config.project,
                dst_repo,
                tag,
                manifest_bytes,
                &media_type,
            )
            .await?;
        report.tags_copied += 1;
        report.bytes_copied += manifest_bytes_len;
        debug!(
            repo = %repo.name, tag, "import: tag copied"
        );
        Ok(())
    }
}

#[derive(Debug)]
struct Descriptor {
    digest: String,
}

/// Parse blob descriptors out of an OCI image / index manifest. We
/// re-parse here rather than depending on nebula-gc to keep the
/// importer crate self-contained; the shapes are simple and stable.
fn parse_descriptors(bytes: &[u8]) -> Vec<Descriptor> {
    #[derive(Deserialize)]
    struct RawDesc {
        digest: String,
    }
    #[derive(Deserialize)]
    struct RawManifest {
        #[serde(default)]
        config: Option<RawDesc>,
        #[serde(default)]
        layers: Vec<RawDesc>,
        #[serde(default)]
        manifests: Vec<RawDesc>,
    }
    let Ok(m) = serde_json::from_slice::<RawManifest>(bytes) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut push = |d: RawDesc| {
        if !d.digest.is_empty() && seen.insert(d.digest.clone()) {
            out.push(Descriptor { digest: d.digest });
        }
    };
    if let Some(c) = m.config {
        push(c);
    }
    for l in m.layers {
        push(l);
    }
    for c in m.manifests {
        push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::destination::InMemoryDestination;
    use crate::source::{Repository, Tag};
    use async_trait::async_trait;
    use bytes::Bytes;

    /// Tiny in-memory source: holds one repo with one tag pointing
    /// at a manifest that references one config + one layer.
    struct MockSource {
        manifest: Bytes,
        config_bytes: Bytes,
        layer_bytes: Bytes,
        config_digest: String,
        layer_digest: String,
    }

    #[async_trait]
    impl RegistrySource for MockSource {
        fn id(&self) -> &'static str {
            "mock"
        }

        async fn list_repositories(&self) -> Result<Vec<Repository>, ImportError> {
            Ok(vec![Repository {
                name: "myorg/api".into(),
            }])
        }

        async fn list_tags(&self, _: &Repository) -> Result<Vec<Tag>, ImportError> {
            Ok(vec![Tag {
                name: "v1".into(),
                digest: String::new(),
                size: 0,
            }])
        }

        async fn fetch_manifest(
            &self,
            _: &Repository,
            _: &str,
        ) -> Result<(Bytes, String), ImportError> {
            Ok((
                self.manifest.clone(),
                "application/vnd.oci.image.manifest.v1+json".into(),
            ))
        }

        async fn fetch_blob(&self, _: &Repository, digest: &str) -> Result<Bytes, ImportError> {
            if digest == self.config_digest {
                Ok(self.config_bytes.clone())
            } else if digest == self.layer_digest {
                Ok(self.layer_bytes.clone())
            } else {
                Err(ImportError::NotFound(digest.to_string()))
            }
        }
    }

    #[tokio::test]
    async fn runner_copies_tag_with_blobs() {
        let config_digest =
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let layer_digest =
            "sha256:1111111111111111111111111111111111111111111111111111111111111111";
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "config": { "digest": config_digest, "size": 16, "mediaType": "x" },
            "layers": [
                { "digest": layer_digest, "size": 32, "mediaType": "y" }
            ]
        });
        let manifest_bytes = Bytes::from(serde_json::to_vec(&manifest).unwrap());
        let src = Arc::new(MockSource {
            manifest: manifest_bytes,
            config_bytes: Bytes::from_static(b"config-blob"),
            layer_bytes: Bytes::from_static(b"layer-blob"),
            config_digest: config_digest.into(),
            layer_digest: layer_digest.into(),
        });
        let dst = Arc::new(InMemoryDestination::new());
        let runner = ImportRunner {
            source: src,
            destination: dst.clone(),
            config: ImportRunnerConfig {
                tenant: "acme".into(),
                project: "prod".into(),
                ..Default::default()
            },
        };
        let report = runner.run().await.unwrap();
        assert_eq!(report.repos_seen, 1);
        assert_eq!(report.tags_copied, 1);
        assert_eq!(report.blobs_copied, 2);
        assert_eq!(dst.blob_count(), 2);
        assert_eq!(dst.manifest_count(), 1);
    }

    #[tokio::test]
    async fn include_prefix_filters_repos() {
        let manifest = serde_json::json!({"schemaVersion": 2});
        let manifest_bytes = Bytes::from(serde_json::to_vec(&manifest).unwrap());
        let src = Arc::new(MockSource {
            manifest: manifest_bytes,
            config_bytes: Bytes::new(),
            layer_bytes: Bytes::new(),
            config_digest: "_".into(),
            layer_digest: "_".into(),
        });
        let dst = Arc::new(InMemoryDestination::new());
        let runner = ImportRunner {
            source: src,
            destination: dst.clone(),
            config: ImportRunnerConfig {
                tenant: "t".into(),
                project: "p".into(),
                parallelism: 1,
                include_prefix: Some("nope/".into()),
            },
        };
        let report = runner.run().await.unwrap();
        assert_eq!(report.repos_seen, 0);
        assert_eq!(report.tags_copied, 0);
        assert_eq!(dst.blob_count(), 0);
    }
}
