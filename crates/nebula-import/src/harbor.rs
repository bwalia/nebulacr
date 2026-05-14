//! Harbor adapter.
//!
//! Harbor exposes both the OCI Distribution v2 API and a richer
//! Harbor-native API at /api/v2.0. We use the Harbor API for catalog
//! discovery (it returns project + repository hierarchy in one call)
//! and delegate manifest/blob fetches to the Distribution path.

use crate::distribution::DistributionSource;
use crate::source::{ImportError, RegistrySource, Repository, Tag};
use async_trait::async_trait;
use bytes::Bytes;
use serde::Deserialize;

pub struct HarborSource {
    pub base: String,
    /// Optional Harbor project filter (e.g. "library", "myorg").
    pub project: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    distribution: DistributionSource,
    client: reqwest::Client,
}

impl HarborSource {
    pub fn new(
        base: impl Into<String>,
        username: Option<String>,
        password: Option<String>,
        project: Option<String>,
    ) -> Self {
        let base = base.into().trim_end_matches('/').to_string();
        // Harbor accepts basic auth on the Distribution v2 path with
        // the same credentials it uses on the API.
        let distribution = DistributionSource::new(base.clone(), None);
        Self {
            base,
            project,
            username,
            password,
            distribution,
            client: reqwest::Client::new(),
        }
    }

    fn auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match (&self.username, &self.password) {
            (Some(u), Some(p)) => req.basic_auth(u, Some(p)),
            (Some(u), None) => req.basic_auth(u, None::<&str>),
            _ => req,
        }
    }
}

#[derive(Deserialize)]
struct HarborProject {
    name: String,
}

#[derive(Deserialize)]
struct HarborRepo {
    name: String, // "<project>/<repo>"
}

#[async_trait]
impl RegistrySource for HarborSource {
    fn id(&self) -> &'static str {
        "harbor"
    }

    async fn list_repositories(&self) -> Result<Vec<Repository>, ImportError> {
        let mut out: Vec<Repository> = Vec::new();
        let projects: Vec<HarborProject> = match &self.project {
            // Single-project shortcut.
            Some(p) => vec![HarborProject { name: p.clone() }],
            // Discover all projects.
            None => {
                let url = format!("{}/api/v2.0/projects?page_size=200", self.base);
                self.auth(self.client.get(&url))
                    .send()
                    .await?
                    .error_for_status()?
                    .json()
                    .await?
            }
        };

        for proj in projects {
            let url = format!(
                "{}/api/v2.0/projects/{}/repositories?page_size=200",
                self.base, proj.name
            );
            let repos: Vec<HarborRepo> = self
                .auth(self.client.get(&url))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            for r in repos {
                out.push(Repository { name: r.name });
            }
        }
        Ok(out)
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
