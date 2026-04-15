//! Axum router mounted into `nebula-registry`.
//!
//! Auth is intentionally *not* applied inside this module — the registry
//! binary wraps the returned router with its own `AuthenticatedClaims`
//! middleware so all scanner routes go through the same token validation
//! as the rest of the registry.

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, patch, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::warn;

use nebula_ai::{CveAnalysis, CveAnalyzer, CveInput};

use crate::model::{ScanResult, Vulnerability};
use crate::queue::Queue;
use crate::store::EphemeralStore;
use crate::suppress::{NewSuppression, Suppressions};

#[derive(Clone)]
pub struct ScannerState {
    pub pg: PgPool,
    pub store: Arc<dyn EphemeralStore>,
    pub queue: Arc<dyn Queue>,
    pub suppressions: Arc<Suppressions>,
    pub ai: Option<Arc<dyn CveAnalyzer>>,
}

pub fn router(state: ScannerState) -> Router {
    Router::new()
        .route("/v2/scan/live/{digest}", get(live_scan))
        .route("/v2/scan", post(trigger_scan))
        .route("/v2/policy/evaluate", post(evaluate_policy))
        .route("/v2/cve/suppress", post(create_suppression))
        .route("/v2/cve/search", get(search_cves))
        .route(
            "/v2/image/{tenant}/{project}/{repo}/settings",
            patch(update_image_settings),
        )
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
        Some(analyse_all(state.ai.as_ref().unwrap(), &result.vulnerabilities).await)
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
    (StatusCode::NOT_IMPLEMENTED, "cve search — needs own-DB (slice 2)")
}

async fn update_image_settings() -> impl IntoResponse {
    (StatusCode::NOT_IMPLEMENTED, "image settings — pending task")
}
