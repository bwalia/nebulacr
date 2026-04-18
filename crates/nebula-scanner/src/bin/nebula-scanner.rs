//! nebula-scanner — standalone scan-worker binary.
//!
//! Runs the same `ScannerRuntime` as the registry, but workers-only: no
//! Axum router is exposed and no enqueue handle is returned to anyone.
//! Dequeues jobs from the `scan_jobs` Postgres table (queue_backend
//! *must* be `postgres` here — tokio-mpsc can't span processes).
//!
//! Env vars:
//!   NEBULACR_SCANNER__*           — same as the registry's scanner block;
//!                                   see `ScannerConfig`. QUEUE_BACKEND is
//!                                   forced to `postgres`; WORKERS is the
//!                                   per-pod worker count (default 2).
//!   NEBULACR_STORAGE__BACKEND     — filesystem | s3 | minio | gcs | azure
//!   NEBULACR_STORAGE__ROOT        — filesystem root dir / bucket / container
//!   NEBULACR_STORAGE__ENDPOINT    — optional S3/minio endpoint
//!   NEBULACR_STORAGE__REGION      — optional S3 region
//!   NEBULACR_STORAGE__ACCESS_KEY  — S3/Azure access key
//!   NEBULACR_STORAGE__SECRET_KEY  — S3/Azure secret key

use std::env;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use object_store::aws::AmazonS3Builder;
use object_store::azure::MicrosoftAzureBuilder;
use object_store::gcp::GoogleCloudStorageBuilder;
use object_store::{ObjectStore, local::LocalFileSystem};
use tracing::info;
use tracing_subscriber::EnvFilter;

use nebula_scanner::{
    ScannerRuntime,
    config::{QueueBackend, ScannerConfig, VulnDbBackend},
};

#[tokio::main]
async fn main() -> Result<()> {
    init_logging();

    let cfg = load_scanner_config()?;
    let store = build_object_store()?;

    info!(
        workers = cfg.workers,
        vulndb = ?cfg.vulndb,
        ai_enabled = cfg.ai_enabled,
        "nebula-scanner starting"
    );

    let rt = ScannerRuntime::build(cfg, store)
        .await
        .context("scanner runtime build failed")?;
    info!(
        workers = rt.worker_handles.len(),
        ingesters = rt.ingest_handles.len(),
        "nebula-scanner runtime ready"
    );

    // Block forever on worker handles. Each worker loop is `loop { dequeue }`;
    // the first one to exit cleanly (shouldn't happen) or panic brings us
    // down, and Kubernetes restarts the pod.
    tokio::select! {
        _ = join_all(rt.worker_handles) => {
            bail!("all scan workers exited");
        }
        _ = tokio::signal::ctrl_c() => {
            info!("received Ctrl-C; shutting down");
            Ok(())
        }
    }
}

async fn join_all(handles: Vec<tokio::task::JoinHandle<()>>) {
    for h in handles {
        let _ = h.await;
    }
}

fn init_logging() {
    let filter = EnvFilter::try_from_env("NEBULACR_LOG_LEVEL")
        .or_else(|_| EnvFilter::try_from_default_env())
        .unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .with_current_span(true)
        .try_init();
}

/// Env-var loader mirroring the registry's `build_scanner_runtime` —
/// deliberately copied rather than shared so this binary has zero
/// dependency on the registry crate.
fn load_scanner_config() -> Result<ScannerConfig> {
    let postgres_url = env::var("NEBULACR_SCANNER__POSTGRES_URL")
        .context("NEBULACR_SCANNER__POSTGRES_URL is required")?;
    let redis_url = env::var("NEBULACR_SCANNER__REDIS_URL")
        .context("NEBULACR_SCANNER__REDIS_URL is required")?;
    let vulndb = match env::var("NEBULACR_SCANNER__VULNDB")
        .unwrap_or_else(|_| "osv".into())
        .as_str()
    {
        "nebula" => VulnDbBackend::Nebula,
        _ => VulnDbBackend::Osv,
    };

    // Cross-process workers can only work against a durable queue — guard
    // against a misconfiguration that'd leave the workers polling an empty
    // in-process mpsc they never enqueue to.
    let requested_backend = env::var("NEBULACR_SCANNER__QUEUE_BACKEND")
        .unwrap_or_else(|_| "postgres".into())
        .to_lowercase();
    if requested_backend != "postgres" {
        return Err(anyhow!(
            "nebula-scanner binary requires NEBULACR_SCANNER__QUEUE_BACKEND=postgres \
             (got '{}'); tokio mpsc can't span processes",
            requested_backend
        ));
    }

    Ok(ScannerConfig {
        enabled: true,
        postgres_url,
        redis_url,
        vulndb,
        ai_enabled: env_bool("NEBULACR_SCANNER__AI_ENABLED").unwrap_or(false),
        ai_endpoint: env::var("NEBULACR_SCANNER__AI_ENDPOINT")
            .unwrap_or_else(|_| "http://127.0.0.1:11434".into()),
        ai_model: env::var("NEBULACR_SCANNER__AI_MODEL")
            .unwrap_or_else(|_| "qwen2.5-coder:7b".into()),
        workers: env_usize("NEBULACR_SCANNER__WORKERS").unwrap_or(2),
        queue_capacity: env_usize("NEBULACR_SCANNER__QUEUE_CAPACITY").unwrap_or(256),
        result_ttl_secs: env_u64("NEBULACR_SCANNER__RESULT_TTL_SECS").unwrap_or(3600),
        pg_max_connections: env_u32("NEBULACR_SCANNER__PG_MAX_CONNECTIONS").unwrap_or(8),
        ingest_enabled: env_bool("NEBULACR_SCANNER__INGEST_ENABLED").unwrap_or(true),
        ingest_interval_secs: env_u64("NEBULACR_SCANNER__INGEST_INTERVAL_SECS").unwrap_or(21_600),
        export_prefix: env::var("NEBULACR_SCANNER__EXPORT_PREFIX")
            .unwrap_or_else(|_| "scanner-exports".into()),
        nvd_enabled: env_bool("NEBULACR_SCANNER__NVD_ENABLED").unwrap_or(false),
        nvd_api_key: env::var("NEBULACR_SCANNER__NVD_API_KEY").ok(),
        nvd_bootstrap_window_days: env_u32("NEBULACR_SCANNER__NVD_BOOTSTRAP_WINDOW_DAYS")
            .unwrap_or(30),
        nvd_sleep_between_pages_secs: env_u64("NEBULACR_SCANNER__NVD_SLEEP_BETWEEN_PAGES_SECS")
            .unwrap_or(6),
        ghsa_enabled: env_bool("NEBULACR_SCANNER__GHSA_ENABLED").unwrap_or(false),
        ghsa_token: env::var("NEBULACR_SCANNER__GHSA_TOKEN").ok(),
        rate_limit_rpm: env_u32("NEBULACR_SCANNER__RATE_LIMIT_RPM").unwrap_or(600),
        alerts_webhook_url: env::var("NEBULACR_SCANNER__ALERTS_WEBHOOK_URL").ok(),
        alerts_format: env::var("NEBULACR_SCANNER__ALERTS_FORMAT")
            .unwrap_or_else(|_| "generic".into()),
        queue_backend: QueueBackend::Postgres,
        enqueue_only: false,
    })
}

fn build_object_store() -> Result<Arc<dyn ObjectStore>> {
    let backend = env::var("NEBULACR_STORAGE__BACKEND").unwrap_or_else(|_| "filesystem".into());
    let root = env::var("NEBULACR_STORAGE__ROOT").context("NEBULACR_STORAGE__ROOT is required")?;

    let store: Arc<dyn ObjectStore> = match backend.as_str() {
        "filesystem" => {
            std::fs::create_dir_all(&root)?;
            info!(root = %root, "using filesystem storage");
            Arc::new(LocalFileSystem::new_with_prefix(&root)?)
        }
        "s3" | "minio" => {
            let mut b = AmazonS3Builder::new().with_bucket_name(&root);
            if let Ok(endpoint) = env::var("NEBULACR_STORAGE__ENDPOINT") {
                b = b
                    .with_endpoint(endpoint)
                    .with_virtual_hosted_style_request(false);
            }
            if let Ok(region) = env::var("NEBULACR_STORAGE__REGION") {
                b = b.with_region(region);
            }
            if let Ok(ak) = env::var("NEBULACR_STORAGE__ACCESS_KEY") {
                b = b.with_access_key_id(ak);
            }
            if let Ok(sk) = env::var("NEBULACR_STORAGE__SECRET_KEY") {
                b = b.with_secret_access_key(sk);
            }
            if backend == "minio" {
                b = b.with_allow_http(true);
            }
            info!(bucket = %root, backend = %backend, "using S3-compatible storage");
            Arc::new(b.build()?)
        }
        "gcs" => {
            info!(bucket = %root, "using GCS storage");
            Arc::new(
                GoogleCloudStorageBuilder::new()
                    .with_bucket_name(&root)
                    .build()?,
            )
        }
        "azure" => {
            let mut b = MicrosoftAzureBuilder::new().with_container_name(&root);
            if let Ok(acct) = env::var("NEBULACR_STORAGE__ACCESS_KEY") {
                b = b.with_account(acct);
            }
            if let Ok(key) = env::var("NEBULACR_STORAGE__SECRET_KEY") {
                b = b.with_access_key(key);
            }
            info!(container = %root, "using Azure Blob storage");
            Arc::new(b.build()?)
        }
        other => bail!(
            "unsupported storage backend '{}' (filesystem|s3|minio|gcs|azure)",
            other
        ),
    };
    Ok(store)
}

fn env_bool(k: &str) -> Option<bool> {
    env::var(k)
        .ok()
        .map(|v| matches!(v.as_str(), "true" | "1" | "yes"))
}
fn env_usize(k: &str) -> Option<usize> {
    env::var(k).ok().and_then(|v| v.parse().ok())
}
fn env_u32(k: &str) -> Option<u32> {
    env::var(k).ok().and_then(|v| v.parse().ok())
}
fn env_u64(k: &str) -> Option<u64> {
    env::var(k).ok().and_then(|v| v.parse().ok())
}
