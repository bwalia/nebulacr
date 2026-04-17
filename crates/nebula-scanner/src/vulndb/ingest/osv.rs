//! OSV.dev full-feed ingester.
//!
//! Downloads `https://osv-vulnerabilities.storage.googleapis.com/all.zip`
//! to a tempfile, then walks entries lazily via `zip::ZipArchive`, feeding
//! each JSON record through `normalise::normalise` and writing the result
//! via `writer::write_advisory`.
//!
//! The ~300MB zip is never held fully in memory — `tokio::fs::File` streams
//! chunks during download, and the `ZipArchive` iteration happens on a
//! `spawn_blocking` worker with `std::fs::File`.
//!
//! If the upstream ETag matches `ingest_cursor.etag`, the whole run is
//! short-circuited. Otherwise every advisory is re-ingested; incremental
//! deltas would need OSV's experimental per-ecosystem zip feeds, which we
//! skip for slice 2a.

use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use sqlx::PgPool;
use tempfile::NamedTempFile;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tracing::{info, warn};

use super::normalise::{OsvRecord, normalise};
use super::writer::{stored_etag, update_cursor, write_advisory};
use super::{IngestStats, Ingester};
use crate::{Result, ScanError};

const OSV_ZIP_URL: &str = "https://osv-vulnerabilities.storage.googleapis.com/all.zip";
const SOURCE: &str = "osv";

pub struct OsvIngester {
    http: reqwest::Client,
    url: String,
    /// Serialises `run()` so a manual admin trigger and the scheduled tick
    /// don't double-download when they collide. Contains the first-run
    /// flag as well — flipped to `false` after the inaugural warn! banner.
    state: Arc<Mutex<RunState>>,
}

struct RunState {
    first_run: bool,
}

impl OsvIngester {
    pub fn new() -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(600))
            .build()?;
        Ok(Self {
            http,
            url: OSV_ZIP_URL.into(),
            state: Arc::new(Mutex::new(RunState { first_run: true })),
        })
    }

    #[cfg(test)]
    pub fn with_url(url: String) -> Result<Self> {
        let http = reqwest::Client::new();
        Ok(Self {
            http,
            url,
            state: Arc::new(Mutex::new(RunState { first_run: true })),
        })
    }
}

#[async_trait]
impl Ingester for OsvIngester {
    fn source(&self) -> &'static str {
        SOURCE
    }

    async fn run(&self, pool: &PgPool) -> Result<IngestStats> {
        let mut state = self.state.lock().await;
        if state.first_run {
            warn!(
                url = %self.url,
                "OSV ingest first run: will download ~300MB of vuln advisories. \
                 Set NEBULACR_SCANNER__INGEST_ENABLED=false to disable."
            );
            state.first_run = false;
        }
        drop(state);

        let head = self.http.head(&self.url).send().await?.error_for_status()?;
        let upstream_etag = head
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        if let (Some(upstream), Some(stored)) = (
            upstream_etag.as_ref(),
            stored_etag(pool, SOURCE).await?.as_ref(),
        ) && upstream == stored
        {
            info!(etag = %upstream, "OSV ingest: etag unchanged, skipping");
            let stats = IngestStats::default();
            update_cursor(pool, SOURCE, Some(upstream), None, &stats, None).await?;
            return Ok(stats);
        }

        let tmp = self.download(pool, upstream_etag.as_deref()).await?;
        let path = tmp.path().to_path_buf();

        let stats = tokio::task::spawn_blocking({
            let pool = pool.clone();
            move || ingest_from_zip(path, pool)
        })
        .await
        .map_err(|e| ScanError::Other(format!("osv ingest join: {e}")))??;

        update_cursor(pool, SOURCE, upstream_etag.as_deref(), None, &stats, None).await?;
        info!(
            advisories = stats.advisories,
            skipped = stats.skipped,
            errors = stats.errors,
            "OSV ingest run complete"
        );
        Ok(stats)
    }
}

impl OsvIngester {
    async fn download(&self, pool: &PgPool, upstream_etag: Option<&str>) -> Result<NamedTempFile> {
        let tmp = NamedTempFile::new()?;
        let path = tmp.path().to_path_buf();
        info!(url = %self.url, dest = %path.display(), "OSV ingest: downloading");

        let mut resp = self.http.get(&self.url).send().await?.error_for_status()?;
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .await?;
        let mut bytes: u64 = 0;
        while let Some(chunk) = resp.chunk().await? {
            file.write_all(&chunk).await?;
            bytes += chunk.len() as u64;
        }
        file.flush().await?;
        drop(file);
        info!(bytes, "OSV ingest: download complete");

        // Record that we at least got the bytes, so subsequent crashes
        // don't lose the fact that we tried. stats are zeroed here and
        // overwritten once ingestion succeeds.
        if let Some(etag) = upstream_etag {
            let _ = update_cursor(
                pool,
                SOURCE,
                Some(etag),
                None,
                &IngestStats::default(),
                None,
            )
            .await;
        }
        Ok(tmp)
    }
}

fn ingest_from_zip(path: PathBuf, pool: PgPool) -> Result<IngestStats> {
    let file = std::fs::File::open(&path)?;
    let mut archive =
        zip::ZipArchive::new(file).map_err(|e| ScanError::Other(format!("osv zip open: {e}")))?;
    let rt = tokio::runtime::Handle::current();
    let mut stats = IngestStats::default();

    for i in 0..archive.len() {
        let mut entry = match archive.by_index(i) {
            Ok(e) => e,
            Err(e) => {
                warn!(index = i, error = %e, "osv zip entry open failed");
                stats.errors += 1;
                continue;
            }
        };
        if !entry.is_file() || !entry.name().ends_with(".json") {
            continue;
        }
        let mut buf = Vec::with_capacity(entry.size() as usize);
        if let Err(e) = entry.read_to_end(&mut buf) {
            warn!(name = entry.name(), error = %e, "osv zip entry read failed");
            stats.errors += 1;
            continue;
        }
        let rec: OsvRecord = match serde_json::from_slice(&buf) {
            Ok(r) => r,
            Err(e) => {
                warn!(name = entry.name(), error = %e, "osv record parse failed");
                stats.errors += 1;
                continue;
            }
        };
        let Some((vuln, ranges)) = normalise(&rec) else {
            stats.skipped += 1;
            continue;
        };
        match rt.block_on(write_advisory(&pool, &vuln, &ranges)) {
            Ok(()) => stats.advisories += 1,
            Err(e) => {
                warn!(id = %vuln.id, error = %e, "osv advisory write failed");
                stats.errors += 1;
            }
        }
    }
    Ok(stats)
}
