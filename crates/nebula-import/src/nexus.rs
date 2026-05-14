//! Nexus3 docker-hosted/proxy/group adapter.
//!
//! Nexus implements the OCI Distribution v2 API for blob + manifest
//! fetches, so we delegate those to a `DistributionSource`. The only
//! Nexus-specific call is the catalog lookup: Nexus's `/v2/_catalog`
//! exposes all docker repos under one prefix, but for typed
//! migrations operators usually want a single `docker-hosted`
//! repo as the source — captured via the `docker_repo` filter.

use crate::distribution::DistributionSource;
use crate::source::{ImportError, RegistrySource, Repository, Tag};
use async_trait::async_trait;
use bytes::Bytes;
use reqwest::header::AUTHORIZATION;
use serde::Deserialize;

pub struct NexusSource {
    pub base: String,
    /// Optional Nexus docker-hosted repo prefix to filter the catalog
    /// (e.g. "docker-prod-hosted/"). When present, only repos whose
    /// name starts with this prefix are returned.
    pub docker_repo: Option<String>,
    pub bearer: Option<String>,
    /// Underlying Distribution v2 client used for fetch_*.
    distribution: DistributionSource,
    client: reqwest::Client,
}

impl NexusSource {
    pub fn new(
        base: impl Into<String>,
        bearer: Option<String>,
        docker_repo: Option<String>,
    ) -> Self {
        let base = base.into().trim_end_matches('/').to_string();
        let distribution = DistributionSource::new(base.clone(), bearer.clone());
        Self {
            base,
            docker_repo,
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
struct CatalogResp {
    repositories: Vec<String>,
}

#[async_trait]
impl RegistrySource for NexusSource {
    fn id(&self) -> &'static str {
        "nexus"
    }

    async fn list_repositories(&self) -> Result<Vec<Repository>, ImportError> {
        let url = format!("{}/v2/_catalog?n=2000", self.base);
        let req = self.auth(self.client.get(&url));
        let body: CatalogResp = req.send().await?.error_for_status()?.json().await?;
        let names = body
            .repositories
            .into_iter()
            .filter(|n| match &self.docker_repo {
                Some(prefix) => n.starts_with(prefix),
                None => true,
            });
        Ok(names.map(|name| Repository { name }).collect())
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
