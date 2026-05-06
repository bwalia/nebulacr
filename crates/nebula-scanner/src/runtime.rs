//! Runtime wiring. Builds every scanner component from a `ScannerConfig`
//! plus external handles (ObjectStore, Postgres pool). The registry binary
//! calls `ScannerRuntime::build` once at startup and holds the returned
//! handle for the lifetime of the process.

use std::sync::Arc;

use object_store::ObjectStore;
use sqlx::PgPool;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use nebula_ai::{CveAnalyzer, OllamaClient, OllamaConfig};

use crate::Result;
use crate::api::{ScannerState, router};
use crate::config::{QueueBackend, ScannerConfig, VulnDbBackend};
use crate::image::Puller;
use crate::policy::Policy;
use crate::queue::{PostgresQueue, Queue, TokioQueue};
use crate::settings::ImageSettingsStore;
use crate::store::{EphemeralStore, RedisStore};
use crate::suppress::Suppressions;
use crate::vulndb::ingest::{Ingester, OsvIngester, spawn_scheduler};
use crate::vulndb::{NebulaVulnDb, OsvClient, VulnDb};
use crate::worker::Worker;

pub struct ScannerRuntime {
    pub router: axum::Router,
    /// Enqueue handle. Producers (registry) clone this and call
    /// `queue.enqueue(job)`. Implementation is either `TokioQueue` (in-proc)
    /// or `PostgresQueue` (durable, cross-process).
    pub queue: Arc<dyn Queue>,
    pub worker_handles: Vec<JoinHandle<()>>,
    pub ingest_handles: Vec<JoinHandle<()>>,
    pub pg: PgPool,
}

impl ScannerRuntime {
    pub async fn build(config: ScannerConfig, store: Arc<dyn ObjectStore>) -> Result<Self> {
        // ── Postgres ─────────────────────────────────────────────────────
        let pg = nebula_db::connect(&config.postgres_url, config.pg_max_connections).await?;
        nebula_db::migrate(&pg).await?;
        info!("scanner postgres migrations applied");

        // ── Redis ────────────────────────────────────────────────────────
        let redis: Arc<dyn EphemeralStore> = Arc::new(RedisStore::connect(
            &config.redis_url,
            config.result_ttl_secs,
        )?);

        // ── Queue ────────────────────────────────────────────────────────
        let queue: Arc<dyn Queue> = match config.queue_backend {
            QueueBackend::Tokio => {
                info!("scanner queue backend: tokio (in-process)");
                Arc::new(TokioQueue::new(config.queue_capacity))
            }
            QueueBackend::Postgres => {
                info!("scanner queue backend: postgres (durable)");
                Arc::new(PostgresQueue::new(pg.clone()))
            }
        };

        // ── Pipeline stages ──────────────────────────────────────────────
        let puller = Arc::new(Puller::new(store.clone()));
        let vulndb: Arc<dyn VulnDb> = match config.vulndb {
            VulnDbBackend::Osv => Arc::new(OsvClient::new()?),
            VulnDbBackend::Nebula => Arc::new(NebulaVulnDb::new(pg.clone())),
        };
        let suppressions = Arc::new(Suppressions::new(pg.clone()));
        let settings = Arc::new(ImageSettingsStore::new(pg.clone()));

        // Default policy is permissive (pass-through). Per-repo policies in
        // image_settings.policy_yaml will override this once task #12 lands.
        let default_policy = Policy::default();

        let notifier = config.alerts_webhook_url.clone().map(|url| {
            Arc::new(crate::notify::Notifier::new(
                url,
                crate::notify::AlertFormat::parse(&config.alerts_format),
            ))
        });

        // ── Workers ──────────────────────────────────────────────────────
        // In `enqueue_only` mode the registry only produces work; real
        // workers run in the separate `nebula-scanner` binary, so skip
        // spawning them here.
        let worker_handles = if config.enqueue_only {
            info!("scanner workers skipped (enqueue_only=true)");
            Vec::new()
        } else {
            let mut handles = Vec::with_capacity(config.workers);
            for n in 0..config.workers {
                let worker = Arc::new(Worker {
                    queue: queue.clone(),
                    puller: puller.clone(),
                    vulndb: vulndb.clone(),
                    store: redis.clone(),
                    suppressions: suppressions.clone(),
                    settings: settings.clone(),
                    pg: pg.clone(),
                    default_policy: default_policy.clone(),
                    notifier: notifier.clone(),
                    dedup_enabled: config.scan_dedup_enabled,
                });
                let handle = tokio::spawn(async move {
                    info!(worker = n, "spawning scan worker");
                    worker.run().await;
                });
                handles.push(handle);
            }
            handles
        };

        // ── AI (optional) ────────────────────────────────────────────────
        let ai: Option<Arc<dyn CveAnalyzer>> = if config.ai_enabled {
            let oc = OllamaClient::new(OllamaConfig {
                endpoint: config.ai_endpoint.clone(),
                model: config.ai_model.clone(),
                ..Default::default()
            })?;
            Some(Arc::new(oc))
        } else {
            warn!("scanner AI disabled; /scan/live?ai=1 will return no analysis");
            None
        };

        // ── Ingesters ────────────────────────────────────────────────────
        let mut ingesters: Vec<Arc<dyn Ingester>> = vec![Arc::new(OsvIngester::new()?)];
        if config.nvd_enabled {
            ingesters.push(Arc::new(crate::vulndb::ingest::NvdIngester::new(
                crate::vulndb::ingest::NvdConfig {
                    base_url: None,
                    api_key: config.nvd_api_key.clone(),
                    bootstrap_window_days: config.nvd_bootstrap_window_days as i64,
                    sleep_between_pages_secs: config.nvd_sleep_between_pages_secs,
                },
            )?));
        }
        if config.ghsa_enabled {
            let token = config.ghsa_token.clone().ok_or_else(|| {
                crate::ScanError::Other("ghsa_enabled=true requires ghsa_token".into())
            })?;
            ingesters.push(Arc::new(crate::vulndb::ingest::GhsaIngester::new(
                crate::vulndb::ingest::GhsaConfig {
                    endpoint: None,
                    token,
                    page_size: None,
                },
            )?));
        }
        let ingesters = ingesters;
        let ingest_handles = if config.ingest_enabled && !config.enqueue_only {
            spawn_scheduler(
                ingesters.clone(),
                pg.clone(),
                std::time::Duration::from_secs(config.ingest_interval_secs),
            )
        } else {
            if config.enqueue_only {
                info!("scanner ingest scheduler skipped (enqueue_only=true)");
            } else {
                info!("scanner ingest scheduler disabled");
            }
            Vec::new()
        };

        let cve_search = Arc::new(crate::cve_search::CveSearch::new(pg.clone()));
        let api_keys = Arc::new(crate::authkey::ApiKeys::new(pg.clone()));
        let limiter = Arc::new(crate::ratelimit::ScannerLimiter::per_minute(
            config.rate_limit_rpm,
        ));
        // Signer-backed exports require a concrete backend wrapper; for now
        // we always push to the shared object store and return raw paths.
        // When operators wire up a dedicated S3 client for export, swap the
        // `None` below for `Some(Arc<AmazonS3>)`.
        let exporter = Arc::new(crate::export::Exporter::new(
            store.clone(),
            None,
            config.export_prefix.clone(),
        ));

        // ── API router ───────────────────────────────────────────────────
        let router = router(ScannerState {
            pg: pg.clone(),
            store: redis.clone(),
            queue: queue.clone(),
            suppressions: suppressions.clone(),
            settings: settings.clone(),
            ingesters,
            ai,
            cve_search,
            api_keys,
            exporter,
            limiter,
        });

        Ok(Self {
            router,
            queue,
            worker_handles,
            ingest_handles,
            pg,
        })
    }
}
