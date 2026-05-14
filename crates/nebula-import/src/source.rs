//! `RegistrySource` trait — every importer adapter satisfies this.

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Repository {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tag {
    pub name: String,
    /// May be empty if the source doesn't expose digest-by-tag cheaply.
    pub digest: String,
    pub size: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("auth: {0}")]
    Auth(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("parse: {0}")]
    Parse(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

#[async_trait]
pub trait RegistrySource: Send + Sync {
    fn id(&self) -> &'static str;

    async fn list_repositories(&self) -> Result<Vec<Repository>, ImportError>;
    async fn list_tags(&self, repo: &Repository) -> Result<Vec<Tag>, ImportError>;
    async fn fetch_manifest(
        &self,
        repo: &Repository,
        tag: &str,
    ) -> Result<(Bytes, String), ImportError>;
    async fn fetch_blob(&self, repo: &Repository, digest: &str) -> Result<Bytes, ImportError>;
}
