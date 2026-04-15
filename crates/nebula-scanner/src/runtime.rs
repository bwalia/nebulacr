//! Runtime wiring. Builds every scanner component from a `ScannerConfig`
//! plus external handles (ObjectStore, Postgres pool). The registry binary
//! calls `ScannerRuntime::build` once at startup and holds the returned
//! handle for the lifetime of the process.

use std::sync::Arc;

use object_store::ObjectStore;
use sqlx::PgPool;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use nebula_ai::{CveAnalyzer, OllamaClient, OllamaConfig};

use crate::api::{router, ScannerState};
use crate::config::{ScannerConfig, VulnDbBackend};
use crate::image::Puller;
use crate::model::ScanJob;
use crate::policy::Policy;
use crate::queue::{Queue, TokioQueue};
use crate::store::{EphemeralStore, RedisStore};
use crate::suppress::Suppressions;
use crate::vulndb::{NebulaVulnDb, OsvClient, VulnDb};
use crate::worker::Worker;
use crate::Result;

pub struct ScannerRuntime {
    pub router: axum::Router,
    pub queue_sender: mpsc::Sender<ScanJob>,
    pub worker_handles: Vec<JoinHandle<()>>,
    pub pg: PgPool,
}

impl ScannerRuntime {
    pub async fn build(
        config: ScannerConfig,
        store: Arc<dyn ObjectStore>,
    ) -> Result<Self> {
        // ── Postgres ─────────────────────────────────────────────────────
        let pg = nebula_db::connect(&config.postgres_url, config.pg_max_connections).await?;
        nebula_db::migrate(&pg).await?;
        info!("scanner postgres migrations applied");

        // ── Redis ────────────────────────────────────────────────────────
        let redis: Arc<dyn EphemeralStore> =
            Arc::new(RedisStore::connect(&config.redis_url, config.result_ttl_secs)?);

        // ── Queue ────────────────────────────────────────────────────────
        let tq = Arc::new(TokioQueue::new(config.queue_capacity));
        let queue: Arc<dyn Queue> = tq.clone();
        let queue_sender = tq.sender();

        // ── Pipeline stages ──────────────────────────────────────────────
        let puller = Arc::new(Puller::new(store.clone()));
        let vulndb: Arc<dyn VulnDb> = match config.vulndb {
            VulnDbBackend::Osv => Arc::new(OsvClient::new()?),
            VulnDbBackend::Nebula => Arc::new(NebulaVulnDb::new(pg.clone())),
        };
        let suppressions = Arc::new(Suppressions::new(pg.clone()));

        // Default policy is permissive (pass-through). Per-repo policies in
        // image_settings.policy_yaml will override this once task #12 lands.
        let default_policy = Policy::default();

        // ── Workers ──────────────────────────────────────────────────────
        let mut worker_handles = Vec::with_capacity(config.workers);
        for n in 0..config.workers {
            let worker = Arc::new(Worker {
                queue: queue.clone(),
                puller: puller.clone(),
                vulndb: vulndb.clone(),
                store: redis.clone(),
                suppressions: suppressions.clone(),
                pg: pg.clone(),
                default_policy: default_policy.clone(),
            });
            let handle = tokio::spawn(async move {
                info!(worker = n, "spawning scan worker");
                worker.run().await;
            });
            worker_handles.push(handle);
        }

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

        // ── API router ───────────────────────────────────────────────────
        let router = router(ScannerState {
            pg: pg.clone(),
            store: redis.clone(),
            queue: queue.clone(),
            suppressions: suppressions.clone(),
            ai,
        });

        Ok(Self {
            router,
            queue_sender,
            worker_handles,
            pg,
        })
    }
}
