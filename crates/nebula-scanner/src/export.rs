//! `POST /v2/export/s3` — push scan reports (JSON + HTML) to the shared
//! object store. Backends that implement the signer trait (S3, GCS, Azure)
//! return pre-signed GET URLs; local/filesystem backends return the raw
//! object path and a `signed: false` flag so callers know to fetch via
//! other means.

use std::{sync::Arc, time::Duration};

use object_store::{
    ObjectStore, PutPayload,
    path::Path as StorePath,
    signer::Signer,
};
use serde::Serialize;

use crate::model::ScanResult;
use crate::{Result, ScanError};

pub struct Exporter {
    store: Arc<dyn ObjectStore>,
    /// Optional object_store view that also implements `Signer`. Populated at
    /// construction if the backend supports it — we can't downcast a trait
    /// object at runtime, so the caller tells us explicitly.
    signer: Option<Arc<dyn Signer>>,
    prefix: String,
}

impl Exporter {
    pub fn new(store: Arc<dyn ObjectStore>, signer: Option<Arc<dyn Signer>>, prefix: String) -> Self {
        Self {
            store,
            signer,
            prefix,
        }
    }

    pub async fn export(&self, result: &ScanResult, sign_ttl: Duration) -> Result<ExportedReport> {
        let base = format!(
            "{}/{}/{}/{}",
            trim_prefix(&self.prefix),
            result.tenant,
            result.project,
            result.id
        );
        let json_path = StorePath::from(format!("{base}/report.json"));
        let html_path = StorePath::from(format!("{base}/report.html"));

        let json_body = crate::report::to_json(result)?;
        let html_body = crate::report::to_html(result);

        self.store
            .put(&json_path, PutPayload::from_bytes(json_body.into()))
            .await?;
        self.store
            .put(&html_path, PutPayload::from_bytes(html_body.into()))
            .await?;

        let (json_url, signed) = self.sign_or_path(&json_path, sign_ttl).await?;
        let (html_url, _) = self.sign_or_path(&html_path, sign_ttl).await?;

        Ok(ExportedReport {
            signed,
            expires_in_secs: if signed { sign_ttl.as_secs() } else { 0 },
            json: Artifact {
                path: json_path.to_string(),
                url: json_url,
            },
            html: Artifact {
                path: html_path.to_string(),
                url: html_url,
            },
        })
    }

    async fn sign_or_path(
        &self,
        path: &StorePath,
        ttl: Duration,
    ) -> Result<(String, bool)> {
        match &self.signer {
            Some(s) => {
                let url = s
                    .signed_url(reqwest::Method::GET, path, ttl)
                    .await
                    .map_err(|e| ScanError::Store(format!("sign: {e}")))?;
                Ok((url.to_string(), true))
            }
            None => Ok((path.to_string(), false)),
        }
    }
}

fn trim_prefix(p: &str) -> &str {
    p.trim_matches('/')
}

#[derive(Debug, Serialize)]
pub struct Artifact {
    pub path: String,
    /// Either a pre-signed HTTPS URL (when `signed=true`) or the raw object
    /// path (when the backend doesn't support signing).
    pub url: String,
}

#[derive(Debug, Serialize)]
pub struct ExportedReport {
    /// True when both URLs are pre-signed; false for filesystem/local backends.
    pub signed: bool,
    pub expires_in_secs: u64,
    pub json: Artifact,
    pub html: Artifact,
}
