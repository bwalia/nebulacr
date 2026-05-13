//! Vanilla OCI Distribution v2 source — the simplest adapter.
//! Used both as a real importer (for distribution-spec'd registries)
//! and as the substrate other adapters delegate to.

use crate::source::{ImportError, RegistrySource, Repository, Tag};
use async_trait::async_trait;
use bytes::Bytes;
use reqwest::header::{ACCEPT, AUTHORIZATION};
use serde::Deserialize;

pub struct DistributionSource {
    base: String,
    bearer: Option<String>,
    client: reqwest::Client,
}

impl DistributionSource {
    pub fn new(base: impl Into<String>, bearer: Option<String>) -> Self {
        Self {
            base: base.into().trim_end_matches('/').to_string(),
            bearer,
            client: reqwest::Client::new(),
        }
    }

    fn auth(&self, mut req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(t) = &self.bearer {
            req = req.header(AUTHORIZATION, format!("Bearer {t}"));
        }
        req
    }
}

#[derive(Deserialize)]
struct CatalogResp {
    repositories: Vec<String>,
}

#[derive(Deserialize)]
struct TagListResp {
    tags: Option<Vec<String>>,
}

#[async_trait]
impl RegistrySource for DistributionSource {
    fn id(&self) -> &'static str {
        "distribution"
    }

    async fn list_repositories(&self) -> Result<Vec<Repository>, ImportError> {
        let url = format!("{}/v2/_catalog?n=1000", self.base);
        let req = self.auth(self.client.get(&url));
        let body: CatalogResp = req.send().await?.error_for_status()?.json().await?;
        Ok(body.repositories.into_iter().map(|name| Repository { name }).collect())
    }

    async fn list_tags(&self, repo: &Repository) -> Result<Vec<Tag>, ImportError> {
        let url = format!("{}/v2/{}/tags/list", self.base, repo.name);
        let req = self.auth(self.client.get(&url));
        let body: TagListResp = req.send().await?.error_for_status()?.json().await?;
        Ok(body
            .tags
            .unwrap_or_default()
            .into_iter()
            .map(|name| Tag { name, digest: String::new(), size: 0 })
            .collect())
    }

    async fn fetch_manifest(
        &self,
        repo: &Repository,
        tag: &str,
    ) -> Result<(Bytes, String), ImportError> {
        let url = format!("{}/v2/{}/manifests/{}", self.base, repo.name, tag);
        let req = self.auth(self.client.get(&url)).header(
            ACCEPT,
            "application/vnd.oci.image.manifest.v1+json, \
             application/vnd.oci.image.index.v1+json, \
             application/vnd.docker.distribution.manifest.v2+json, \
             application/vnd.docker.distribution.manifest.list.v2+json",
        );
        let resp = req.send().await?.error_for_status()?;
        let media_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/vnd.oci.image.manifest.v1+json")
            .to_string();
        let bytes = resp.bytes().await?;
        Ok((bytes, media_type))
    }

    async fn fetch_blob(
        &self,
        repo: &Repository,
        digest: &str,
    ) -> Result<Bytes, ImportError> {
        let url = format!("{}/v2/{}/blobs/{}", self.base, repo.name, digest);
        let req = self.auth(self.client.get(&url));
        let resp = req.send().await?.error_for_status()?;
        Ok(resp.bytes().await?)
    }
}
