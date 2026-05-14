//! Azure Container Registry adapter.
//!
//! ACR speaks the OCI Distribution v2 API for blobs/manifests but
//! discovery uses ACR's `/acr/v1/_catalog` endpoint (Harbor-style).
//! Auth is a bearer token issued by AAD or by `az acr login` — we
//! accept it as an opaque string; operators wire `az acr login`
//! into their import job.

use crate::distribution::DistributionSource;
use crate::source::{ImportError, RegistrySource, Repository, Tag};
use async_trait::async_trait;
use bytes::Bytes;
use reqwest::header::AUTHORIZATION;
use serde::Deserialize;

pub struct AcrSource {
    pub base: String, // e.g. "https://myacr.azurecr.io"
    pub bearer: Option<String>,
    distribution: DistributionSource,
    client: reqwest::Client,
}

impl AcrSource {
    pub fn new(base: impl Into<String>, bearer: Option<String>) -> Self {
        let base = base.into().trim_end_matches('/').to_string();
        let distribution = DistributionSource::new(base.clone(), bearer.clone());
        Self {
            base,
            bearer,
            distribution,
            client: reqwest::Client::new(),
        }
    }

    fn auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(t) = &self.bearer {
            req.header(AUTHORIZATION, format!("Bearer {t}"))
        } else {
            req
        }
    }
}

#[derive(Deserialize)]
struct AcrCatalog {
    repositories: Vec<String>,
}

#[async_trait]
impl RegistrySource for AcrSource {
    fn id(&self) -> &'static str {
        "acr"
    }

    async fn list_repositories(&self) -> Result<Vec<Repository>, ImportError> {
        // Prefer ACR's richer catalog; fall back to /v2/_catalog if it
        // returns 404 (e.g. anonymous-auth limitation).
        let url = format!("{}/acr/v1/_catalog?n=2000", self.base);
        let resp = self.auth(self.client.get(&url)).send().await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return self.distribution.list_repositories().await;
        }
        let body: AcrCatalog = resp.error_for_status()?.json().await?;
        Ok(body
            .repositories
            .into_iter()
            .map(|name| Repository { name })
            .collect())
    }

    async fn list_tags(&self, repo: &Repository) -> Result<Vec<Tag>, ImportError> {
        self.distribution.list_tags(repo).await
    }

    async fn fetch_manifest(
        &self,
        repo: &Repository,
        tag: &str,
    ) -> Result<(Bytes, String), ImportError> {
        self.distribution.fetch_manifest(repo, tag).await
    }

    async fn fetch_blob(&self, repo: &Repository, digest: &str) -> Result<Bytes, ImportError> {
        self.distribution.fetch_blob(repo, digest).await
    }
}
