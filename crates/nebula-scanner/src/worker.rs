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
        // 1. Walk layers and collect packages.
        let mut collector = SbomCollector::default();
        self.puller.walk_layers(loc, &mut collector).await?;
        info!(
            digest = %loc.digest,
            packages = collector.packages.len(),
            "sbom extracted"
        );

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

impl LayerVisitor for SbomCollector {
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
