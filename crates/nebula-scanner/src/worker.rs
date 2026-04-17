//! Scan worker — pulls jobs from the queue and drives the pipeline.

use std::sync::Arc;

use chrono::Utc;
use sqlx::PgPool;
use tracing::{error, info, warn};

use crate::image::{ImageLocator, LayerVisitor, Puller};
use crate::model::{ScanJob, ScanResult, ScanStatus, ScanSummary, Vulnerability};
use crate::policy::Policy;
use crate::queue::Queue;
use crate::sbom::{self, Package};
use crate::settings::ImageSettingsStore;
use crate::store::EphemeralStore;
use crate::suppress::Suppressions;
use crate::vulndb::VulnDb;
use crate::{Result, ScanError};

pub struct Worker {
    pub queue: Arc<dyn Queue>,
    pub puller: Arc<Puller>,
    pub vulndb: Arc<dyn VulnDb>,
    pub store: Arc<dyn EphemeralStore>,
    pub suppressions: Arc<Suppressions>,
    pub settings: Arc<ImageSettingsStore>,
    pub pg: PgPool,
    pub default_policy: Policy,
}

impl Worker {
    pub async fn run(self: Arc<Self>) {
        info!("scan worker started");
        loop {
            let Some(job) = self.queue.dequeue().await else {
                warn!("queue closed, worker exiting");
                return;
            };
            let digest = job.digest.clone();
            let id = job.id;
            match self.process(job).await {
                Ok(()) => info!(%digest, %id, "scan complete"),
                Err(e) => error!(%digest, %id, error = %e, "scan failed"),
            }
        }
    }

    async fn process(&self, job: ScanJob) -> Result<()> {
        // Honor per-repo scan_enabled flag (default true).
        let settings = self
            .settings
            .get(&job.tenant, &job.project, &job.repository)
            .await
            .unwrap_or_else(|e| {
                warn!(error = %e, "failed to read image_settings; using defaults");
                crate::settings::ImageSettings::default_for(
                    &job.tenant,
                    &job.project,
                    &job.repository,
                )
            });
        if !settings.scan_enabled {
            info!(
                digest = %job.digest,
                tenant = %job.tenant, project = %job.project, repo = %job.repository,
                "scan skipped: scan_enabled=false"
            );
            return Ok(());
        }

        let started = Utc::now();
        record_status(&self.pg, &job, ScanStatus::InProgress, None).await?;

        // Mark in-progress in Redis so /scan/live/:digest returns a status
        // immediately rather than 404 while the pipeline runs.
        let in_progress = ScanResult {
            id: job.id,
            digest: job.digest.clone(),
            tenant: job.tenant.clone(),
            project: job.project.clone(),
            repository: job.repository.clone(),
            reference: job.reference.clone(),
            status: ScanStatus::InProgress,
            error: None,
            started_at: started,
            completed_at: None,
            summary: ScanSummary::default(),
            vulnerabilities: vec![],
            policy_evaluation: None,
        };
        let _ = self.store.put(&in_progress).await;

        let loc = ImageLocator {
            tenant: job.tenant.clone(),
            project: job.project.clone(),
            repository: job.repository.clone(),
            digest: job.digest.clone(),
        };

        let final_result = match self.run_pipeline(&job, &loc, started, &settings).await {
            Ok(res) => res,
            Err(e) => {
                let msg = e.to_string();
                error!(error = %msg, "pipeline error");
                record_status(&self.pg, &job, ScanStatus::Failed, Some(&msg))
                    .await
                    .ok();
                ScanResult {
                    status: ScanStatus::Failed,
                    error: Some(msg),
                    completed_at: Some(Utc::now()),
                    ..in_progress
                }
            }
        };

        let _ = self.store.put(&final_result).await;
        if matches!(final_result.status, ScanStatus::Completed) {
            update_counts(&self.pg, &job, &final_result.summary).await?;
            record_status(&self.pg, &job, ScanStatus::Completed, None).await?;
        }
        Ok(())
    }

    async fn run_pipeline(
        &self,
        job: &ScanJob,
        loc: &ImageLocator,
        started: chrono::DateTime<Utc>,
        settings: &crate::settings::ImageSettings,
    ) -> Result<ScanResult> {
        // 1. SBOM extraction — per-layer, Redis-cached. Layer content is
        //    content-addressed, so a cache hit is always safe.
        let layers = self.puller.resolve_layers(loc).await?;
        let mut all_packages: Vec<Package> = Vec::new();
        let mut layers_to_walk = Vec::with_capacity(layers.len());
        let mut cache_hits = 0usize;
        for layer in &layers {
            match self.store.get_layer_sbom(&layer.digest).await {
                Ok(Some(mut cached)) => {
                    // The cached entry was stored with the real layer digest,
                    // but normalise to be defensive in case the cache schema
                    // drifts between versions.
                    for p in cached.iter_mut() {
                        if p.layer_digest.is_none() {
                            p.layer_digest = Some(layer.digest.clone());
                        }
                    }
                    all_packages.extend(cached);
                    cache_hits += 1;
                }
                _ => layers_to_walk.push(layer.clone()),
            }
        }

        if !layers_to_walk.is_empty() {
            let mut collector = PerLayerCollector::default();
            self.puller
                .walk_selected_layers(loc, &layers_to_walk, &mut collector)
                .await?;
            // Cache and merge per-layer. We group the flat packages list by
            // layer_digest because each parser emits one package at a time
            // rather than a per-layer batch.
            let mut by_layer: std::collections::HashMap<String, Vec<Package>> =
                std::collections::HashMap::new();
            for p in collector.packages {
                let k = p.layer_digest.clone().unwrap_or_default();
                by_layer.entry(k).or_default().push(p);
            }
            for layer in &layers_to_walk {
                let pkgs = by_layer.remove(&layer.digest).unwrap_or_default();
                if let Err(e) = self.store.put_layer_sbom(&layer.digest, &pkgs).await {
                    warn!(layer = %layer.digest, error = %e, "layer-sbom cache write failed");
                }
                all_packages.extend(pkgs);
            }
        }

        info!(
            digest = %loc.digest,
            layers = layers.len(),
            cached_layers = cache_hits,
            packages = all_packages.len(),
            "sbom extracted"
        );
        let collector = SbomCollector {
            packages: all_packages,
        };

        // 2. Query vuln DB.
        let mut vulns: Vec<Vulnerability> = self
            .vulndb
            .query(&collector.packages)
            .await
            .unwrap_or_else(|e| {
                warn!(error = %e, "vulndb query failed; treating as empty");
                vec![]
            });

        // 3. Apply suppressions.
        self.suppressions
            .apply(&loc.tenant, &loc.project, &loc.repository, &mut vulns)
            .await
            .map_err(|e| ScanError::Other(format!("suppress: {e}")))?;

        // 4. Summary.
        let mut summary = ScanSummary::default();
        for v in vulns.iter().filter(|v| !v.suppressed) {
            summary.add(v.severity);
        }

        // 5. Policy. Per-repo policy_yaml wins over the registry default.
        let policy = match settings.policy_yaml.as_deref() {
            Some(y) => Policy::from_yaml(y).unwrap_or_else(|e| {
                warn!(error = %e, "image_settings.policy_yaml invalid; falling back to default");
                self.default_policy.clone()
            }),
            None => self.default_policy.clone(),
        };
        let policy_eval = policy.evaluate(&vulns);

        Ok(ScanResult {
            id: job.id,
            digest: loc.digest.clone(),
            tenant: loc.tenant.clone(),
            project: loc.project.clone(),
            repository: loc.repository.clone(),
            reference: job.reference.clone(),
            status: ScanStatus::Completed,
            error: None,
            started_at: started,
            completed_at: Some(Utc::now()),
            summary,
            vulnerabilities: vulns,
            policy_evaluation: Some(policy_eval),
        })
    }
}

#[derive(Default)]
struct SbomCollector {
    packages: Vec<Package>,
}

/// Single collector re-used across the "layers we actually walk" list. The
/// per-layer `Package.layer_digest` is populated by each parser, so we can
/// regroup the flat list by layer after the walk for cache writes.
#[derive(Default)]
struct PerLayerCollector {
    packages: Vec<Package>,
}

impl LayerVisitor for PerLayerCollector {
    fn visit(&mut self, layer_digest: &str, path: &str, contents: &[u8]) {
        sbom::dispatch(layer_digest, path, contents, &mut self.packages);
    }
}

async fn record_status(
    pg: &PgPool,
    job: &ScanJob,
    status: ScanStatus,
    error: Option<&str>,
) -> Result<()> {
    let status_str = match status {
        ScanStatus::Queued => "queued",
        ScanStatus::InProgress => "in_progress",
        ScanStatus::Completed => "completed",
        ScanStatus::Failed => "failed",
    };
    sqlx::query(
        r#"INSERT INTO scans (id, digest, tenant, project, repository, reference, status, error, started_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
            ON CONFLICT (id) DO UPDATE
              SET status = EXCLUDED.status,
                  error  = COALESCE(EXCLUDED.error, scans.error),
                  completed_at = CASE
                    WHEN EXCLUDED.status IN ('completed','failed') THEN NOW()
                    ELSE scans.completed_at
                  END"#,
    )
    .bind(job.id)
    .bind(&job.digest)
    .bind(&job.tenant)
    .bind(&job.project)
    .bind(&job.repository)
    .bind(&job.reference)
    .bind(status_str)
    .bind(error)
    .execute(pg)
    .await
    .map_err(nebula_db::DbError::from)?;
    Ok(())
}

async fn update_counts(pg: &PgPool, job: &ScanJob, summary: &ScanSummary) -> Result<()> {
    sqlx::query(
        r#"UPDATE scans
            SET critical_count = $2,
                high_count = $3,
                medium_count = $4,
                low_count = $5
           WHERE id = $1"#,
    )
    .bind(job.id)
    .bind(summary.critical as i32)
    .bind(summary.high as i32)
    .bind(summary.medium as i32)
    .bind(summary.low as i32)
    .execute(pg)
    .await
    .map_err(nebula_db::DbError::from)?;
    Ok(())
}
