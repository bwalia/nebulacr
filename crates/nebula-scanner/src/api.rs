//! Axum router mounted into `nebula-registry`.
//!
//! Auth is intentionally *not* applied inside this module — the registry
//! binary wraps the returned router with its own `AuthenticatedClaims`
//! middleware so all scanner routes go through the same token validation
//! as the rest of the registry.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, patch, post},
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::warn;

use nebula_ai::{CveAnalysis, CveAnalyzer, CveInput};

use crate::model::{ScanResult, Vulnerability};
use crate::queue::Queue;
use crate::settings::ImageSettingsStore;
use crate::store::EphemeralStore;
use crate::suppress::{NewSuppression, Suppressions};
use crate::vulndb::ingest::Ingester;

#[derive(Clone)]
pub struct ScannerState {
    pub pg: PgPool,
    pub store: Arc<dyn EphemeralStore>,
    pub queue: Arc<dyn Queue>,
    pub suppressions: Arc<Suppressions>,
    pub settings: Arc<ImageSettingsStore>,
    pub ingesters: Vec<Arc<dyn Ingester>>,
    pub ai: Option<Arc<dyn CveAnalyzer>>,
}

pub fn router(state: ScannerState) -> Router {
    Router::new()
        .route("/v2/scan/live/{digest}", get(live_scan))
        .route("/v2/scan", post(trigger_scan))
        .route("/v2/policy/evaluate", post(evaluate_policy))
        .route(
            "/v2/cve/suppress",
            post(create_suppression).get(list_suppressions),
        )
        .route("/v2/cve/suppress/{id}", delete(revoke_suppression))
        .route("/v2/cve/search", get(search_cves))
        .route(
            "/v2/image/{tenant}/{project}/{repo}/settings",
            patch(update_image_settings).get(get_image_settings),
        )
        .route("/admin/vulndb/ingest", post(trigger_ingest))
        .with_state(state)
}

#[derive(Serialize)]
struct LiveResp {
    status: String,
    digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<ScanResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ai_analysis: Option<Vec<AiAnnotated>>,
}

#[derive(Serialize)]
struct AiAnnotated {
    cve_id: String,
    analysis: Option<CveAnalysis>,
    error: Option<String>,
}

#[derive(Deserialize, Default)]
struct LiveQuery {
    #[serde(default)]
    ai: Option<u8>,
    /// Optional cap on how many CVEs to analyse. Each call to Ollama is
    /// sequential and can take tens of seconds on contended GPUs, so callers
    /// can bound the response time with a small limit while iterating.
    #[serde(default)]
    ai_limit: Option<usize>,
}

async fn live_scan(
    State(state): State<ScannerState>,
    Path(digest): Path<String>,
    Query(q): Query<LiveQuery>,
) -> impl IntoResponse {
    let result = match state.store.get(&digest).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(LiveResp {
                    status: "not_found".into(),
                    digest,
                    result: None,
                    ai_analysis: None,
                }),
            )
                .into_response();
        }
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    let ai_analysis = if q.ai.unwrap_or(0) > 0 && state.ai.is_some() {
        let slice: &[Vulnerability] = match q.ai_limit {
            Some(n) if n < result.vulnerabilities.len() => &result.vulnerabilities[..n],
            _ => &result.vulnerabilities,
        };
        Some(analyse_all(state.ai.as_ref().unwrap(), slice).await)
    } else {
        None
    };

    let status = match result.status {
        crate::model::ScanStatus::Queued => "queued",
        crate::model::ScanStatus::InProgress => "in_progress",
        crate::model::ScanStatus::Completed => "completed",
        crate::model::ScanStatus::Failed => "failed",
    }
    .into();

    (
        StatusCode::OK,
        Json(LiveResp {
            status,
            digest,
            result: Some(result),
            ai_analysis,
        }),
    )
        .into_response()
}

async fn analyse_all(ai: &Arc<dyn CveAnalyzer>, vulns: &[Vulnerability]) -> Vec<AiAnnotated> {
    let mut out = Vec::with_capacity(vulns.len());
    for v in vulns {
        let input = CveInput {
            cve_id: v.id.clone(),
            package: v.package.clone(),
            installed_version: v.installed_version.clone(),
            fixed_version: v.fixed_version.clone(),
            severity: format!("{:?}", v.severity).to_uppercase(),
            description: v.description.clone().or_else(|| v.summary.clone()),
            ecosystem: v.ecosystem.clone(),
        };
        match ai.analyze(&input).await {
            Ok(analysis) => out.push(AiAnnotated {
                cve_id: v.id.clone(),
                analysis: Some(analysis),
                error: None,
            }),
            Err(e) => {
                warn!(cve = %v.id, error = %e, "ai analysis failed");
                out.push(AiAnnotated {
                    cve_id: v.id.clone(),
                    analysis: None,
                    error: Some(e.to_string()),
                });
            }
        }
    }
    out
}

#[derive(Deserialize)]
struct TriggerScanReq {
    tenant: String,
    project: String,
    repository: String,
    reference: String,
    digest: String,
}

async fn trigger_scan(
    State(state): State<ScannerState>,
    Json(req): Json<TriggerScanReq>,
) -> impl IntoResponse {
    let job = crate::model::ScanJob {
        id: uuid::Uuid::new_v4(),
        digest: req.digest,
        tenant: req.tenant,
        project: req.project,
        repository: req.repository,
        reference: req.reference,
        enqueued_at: chrono::Utc::now(),
    };
    match state.queue.enqueue(job.clone()).await {
        Ok(()) => (StatusCode::ACCEPTED, Json(job)).into_response(),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
struct EvalReq {
    vulnerabilities: Vec<Vulnerability>,
    #[serde(default)]
    policy_yaml: Option<String>,
}

async fn evaluate_policy(Json(req): Json<EvalReq>) -> impl IntoResponse {
    let policy = match req.policy_yaml.as_deref() {
        Some(y) => match crate::policy::Policy::from_yaml(y) {
            Ok(p) => p,
            Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
        },
        None => crate::policy::Policy::default(),
    };
    Json(policy.evaluate(&req.vulnerabilities)).into_response()
}

#[derive(Deserialize)]
struct SuppressReq {
    #[serde(flatten)]
    body: NewSuppression,
}

async fn create_suppression(
    State(state): State<ScannerState>,
    Json(req): Json<SuppressReq>,
) -> impl IntoResponse {
    // TODO: pull actor from auth middleware once wired in nebula-registry main.
    match state.suppressions.create("system", req.body).await {
        Ok(id) => (StatusCode::CREATED, Json(serde_json::json!({ "id": id }))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn search_cves() -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        "cve search — needs own-DB (slice 2)",
    )
}

#[derive(Deserialize)]
struct SettingsPatch {
    scan_enabled: Option<bool>,
    policy_yaml: Option<String>,
}

async fn get_image_settings(
    State(state): State<ScannerState>,
    Path((tenant, project, repo)): Path<(String, String, String)>,
) -> impl IntoResponse {
    match state.settings.get(&tenant, &project, &repo).await {
        Ok(s) => Json(s).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn update_image_settings(
    State(state): State<ScannerState>,
    Path((tenant, project, repo)): Path<(String, String, String)>,
    Json(patch): Json<SettingsPatch>,
) -> impl IntoResponse {
    // Merge onto current record so callers can PATCH one field at a time.
    let current = match state.settings.get(&tenant, &project, &repo).await {
        Ok(s) => s,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let scan_enabled = patch.scan_enabled.unwrap_or(current.scan_enabled);
    let policy_yaml = patch.policy_yaml.or(current.policy_yaml);
    match state
        .settings
        // TODO: use auth-derived actor once the auth middleware is wired onto scanner routes.
        .upsert(
            "system",
            &tenant,
            &project,
            &repo,
            scan_enabled,
            policy_yaml.as_deref(),
        )
        .await
    {
        Ok(s) => Json(s).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    }
}

#[derive(Deserialize, Default)]
struct ListSuppressQuery {
    cve_id: Option<String>,
    tenant: Option<String>,
    project: Option<String>,
    repository: Option<String>,
    #[serde(default)]
    include_revoked: bool,
}

async fn list_suppressions(
    State(state): State<ScannerState>,
    Query(q): Query<ListSuppressQuery>,
) -> impl IntoResponse {
    match state
        .suppressions
        .list(
            q.cve_id.as_deref(),
            q.tenant.as_deref(),
            q.project.as_deref(),
            q.repository.as_deref(),
            q.include_revoked,
        )
        .await
    {
        Ok(rows) => Json(rows).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn revoke_suppression(
    State(state): State<ScannerState>,
    Path(id): Path<uuid::Uuid>,
) -> impl IntoResponse {
    match state.suppressions.revoke("system", id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "suppression not found").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Deserialize, Default)]
struct IngestQuery {
    /// Run only the ingester with this source ID (`osv`, `nvd`, `ghsa`).
    /// Omitted → run all registered ingesters.
    source: Option<String>,
}

#[derive(Serialize)]
struct IngestReport {
    source: String,
    advisories: u64,
    skipped: u64,
    errors: u64,
    run_error: Option<String>,
}

async fn trigger_ingest(
    State(state): State<ScannerState>,
    Query(q): Query<IngestQuery>,
) -> impl IntoResponse {
    let mut reports = Vec::new();
    for ing in &state.ingesters {
        if let Some(sel) = &q.source {
            if ing.source() != sel {
                continue;
            }
        }
        match ing.run(&state.pg).await {
            Ok(stats) => reports.push(IngestReport {
                source: ing.source().into(),
                advisories: stats.advisories,
                skipped: stats.skipped,
                errors: stats.errors,
                run_error: None,
            }),
            Err(e) => reports.push(IngestReport {
                source: ing.source().into(),
                advisories: 0,
                skipped: 0,
                errors: 0,
                run_error: Some(e.to_string()),
            }),
        }
    }
    if reports.is_empty() {
        return (StatusCode::NOT_FOUND, "no matching ingester").into_response();
    }
    Json(reports).into_response()
}
