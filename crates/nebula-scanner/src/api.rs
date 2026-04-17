//! Axum router mounted into `nebula-registry`.
//!
//! Requests carrying `Authorization: Bearer nck_<secret>` are resolved to
//! a [`Principal`] with the permissions assigned to that scanner API key.
//! Requests without such a header land as a permissive `system` principal
//! for backward compatibility with pre-API-key deploys; handlers call
//! `principal.require(...)` on the perms they actually need, so only keyed
//! callers get permission-checked.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{FromRequestParts, Path, Query, State},
    http::{StatusCode, header, request::Parts},
    response::IntoResponse,
    routing::{delete, get, patch, post},
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::warn;

use nebula_ai::{CveAnalysis, CveAnalyzer, CveInput};

use crate::authkey::{ApiKeys, NewKeyRequest, Permission, Principal};
use crate::cve_search::{CveSearch, SearchQuery};
use crate::export::Exporter;
use crate::model::{ScanResult, Vulnerability};
use crate::queue::Queue;
use crate::ratelimit::{ScannerLimiter, limit_middleware};
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
    pub cve_search: Arc<CveSearch>,
    pub api_keys: Arc<ApiKeys>,
    pub exporter: Arc<Exporter>,
    pub limiter: Arc<ScannerLimiter>,
}

impl FromRequestParts<ScannerState> for Principal {
    type Rejection = (StatusCode, String);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ScannerState,
    ) -> Result<Self, Self::Rejection> {
        let bearer = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        let Some(token) = bearer else {
            return Ok(Principal::system());
        };
        if !token.starts_with("nck_") {
            return Ok(Principal::system());
        }
        match state.api_keys.lookup(token).await {
            Ok(Some(p)) => Ok(p),
            Ok(None) => Err((
                StatusCode::UNAUTHORIZED,
                "invalid or revoked api key".into(),
            )),
            Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
        }
    }
}

fn forbidden<E: ToString>(e: E) -> (StatusCode, String) {
    (StatusCode::FORBIDDEN, e.to_string())
}

pub fn router(state: ScannerState) -> Router {
    Router::new()
        .route("/v2/scan/live/{digest}", get(live_scan))
        .route("/v2/scan/{id}", get(get_scan_by_id))
        .route("/v2/scan/{id}/report", get(get_scan_report))
        .route("/v2/scan", post(trigger_scan))
        .route("/v2/policy/evaluate", post(evaluate_policy))
        .route(
            "/v2/cve/suppress",
            post(create_suppression).get(list_suppressions),
        )
        .route("/v2/cve/suppress/{id}", delete(revoke_suppression))
        .route("/v2/cve/search", get(search_cves))
        .route("/v2/cve/{id}/fix-commits", get(cve_fix_commits))
        .route(
            "/v2/image/{tenant}/{project}/{repo}/settings",
            patch(update_image_settings).get(get_image_settings),
        )
        .route("/admin/vulndb/ingest", post(trigger_ingest))
        .route(
            "/admin/scanner-keys",
            post(create_api_key).get(list_api_keys),
        )
        .route("/admin/scanner-keys/{id}", delete(revoke_api_key))
        .route("/v2/export/s3/{id}", post(export_scan))
        .route("/v2/scan/{id}/sbom", get(get_scan_sbom))
        .route(
            "/v2/scan/{id}/recommendations",
            get(get_scan_recommendations),
        )
        .route("/v2/scan/{id}/dockerfile-fix", get(get_dockerfile_fix))
        .route(
            "/v2/scan/{id}/dockerfile-patch",
            post(post_dockerfile_patch),
        )
        .route("/v2/scan/{id}/pr-comment", post(post_pr_comment))
        .route("/v2/ws/scan/{digest}", get(crate::ws::progress_ws))
        .route("/v2/vex", post(ingest_vex))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            limit_middleware,
        ))
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
    /// Optional cap on how many CVEs to analyse. Each call to Ollama can
    /// take tens of seconds on contended GPUs, so callers can bound the
    /// response time with a small limit while iterating.
    #[serde(default)]
    ai_limit: Option<usize>,
    /// Concurrent in-flight AI calls. Default 2 (see DEFAULT_AI_CONCURRENCY);
    /// set to 1 on single-GPU hosts where the model server queues anyway.
    #[serde(default)]
    ai_concurrency: Option<usize>,
}

async fn live_scan(
    State(state): State<ScannerState>,
    principal: Principal,
    Path(digest): Path<String>,
    Query(q): Query<LiveQuery>,
) -> impl IntoResponse {
    if let Err(e) = principal.require(Permission::ScanRead) {
        return forbidden(e).into_response();
    }
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

    let ai_analysis = match (q.ai.unwrap_or(0) > 0).then_some(()).and(state.ai.as_ref()) {
        Some(ai) => {
            let slice: &[Vulnerability] = match q.ai_limit {
                Some(n) if n < result.vulnerabilities.len() => &result.vulnerabilities[..n],
                _ => &result.vulnerabilities,
            };
            let concurrency = q.ai_concurrency.unwrap_or(DEFAULT_AI_CONCURRENCY);
            Some(analyse_all(ai, slice, concurrency).await)
        }
        None => None,
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

/// Per-CVE analysis cap. Default matches the typical GPU concurrency an
/// Ollama instance handles well; single-GPU hosts should run with 1 to
/// avoid queueing inside the model server. Configurable via `ai_concurrency`
/// on `LiveQuery`.
const DEFAULT_AI_CONCURRENCY: usize = 2;

async fn analyse_all(
    ai: &Arc<dyn CveAnalyzer>,
    vulns: &[Vulnerability],
    concurrency: usize,
) -> Vec<AiAnnotated> {
    use futures::stream::{FuturesOrdered, StreamExt};

    // Bounded-concurrency fan-out. `FuturesOrdered` preserves input order so
    // the response array lines up 1:1 with the vulnerabilities list the
    // caller already sees — a plain unordered fan-out would scramble that.
    let sem = Arc::new(tokio::sync::Semaphore::new(concurrency.max(1)));
    let mut pending: FuturesOrdered<_> = vulns
        .iter()
        .map(|v| {
            let ai = ai.clone();
            let sem = sem.clone();
            let input = CveInput {
                cve_id: v.id.clone(),
                package: v.package.clone(),
                installed_version: v.installed_version.clone(),
                fixed_version: v.fixed_version.clone(),
                severity: format!("{:?}", v.severity).to_uppercase(),
                description: v.description.clone().or_else(|| v.summary.clone()),
                ecosystem: v.ecosystem.clone(),
            };
            let cve_id = v.id.clone();
            async move {
                let _permit = sem.acquire().await.expect("semaphore never closed");
                match ai.analyze(&input).await {
                    Ok(analysis) => AiAnnotated {
                        cve_id,
                        analysis: Some(analysis),
                        error: None,
                    },
                    Err(e) => {
                        warn!(cve = %cve_id, error = %e, "ai analysis failed");
                        AiAnnotated {
                            cve_id,
                            analysis: None,
                            error: Some(e.to_string()),
                        }
                    }
                }
            }
        })
        .collect();

    let mut out = Vec::with_capacity(vulns.len());
    while let Some(item) = pending.next().await {
        out.push(item);
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
    principal: Principal,
    Json(req): Json<TriggerScanReq>,
) -> impl IntoResponse {
    if let Err(e) = principal.require(Permission::ScanWrite) {
        return forbidden(e).into_response();
    }
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

async fn evaluate_policy(principal: Principal, Json(req): Json<EvalReq>) -> impl IntoResponse {
    if let Err(e) = principal.require(Permission::PolicyEvaluate) {
        return forbidden(e).into_response();
    }
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
    principal: Principal,
    Json(req): Json<SuppressReq>,
) -> impl IntoResponse {
    if let Err(e) = principal.require(Permission::CveSuppress) {
        return forbidden(e).into_response();
    }
    match state.suppressions.create(&principal.actor, req.body).await {
        Ok(id) => (StatusCode::CREATED, Json(serde_json::json!({ "id": id }))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn search_cves(
    State(state): State<ScannerState>,
    principal: Principal,
    Query(q): Query<SearchQuery>,
) -> impl IntoResponse {
    if let Err(e) = principal.require(Permission::CveSearch) {
        return forbidden(e).into_response();
    }
    match state.cve_search.search(&q).await {
        Ok(resp) => Json(resp).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Deserialize, Default)]
struct FixCommitsQuery {
    /// GitHub token for the fetch — anonymous calls hit a 60/hr limit.
    /// Optional; unset falls back to unauthenticated.
    token: Option<String>,
    base_url: Option<String>,
    /// Cap on how many commits to fetch when the CVE has many. Default 5.
    limit: Option<usize>,
}

async fn cve_fix_commits(
    State(state): State<ScannerState>,
    principal: Principal,
    Path(id): Path<String>,
    Query(q): Query<FixCommitsQuery>,
) -> impl IntoResponse {
    if let Err(e) = principal.require(Permission::CveSearch) {
        return forbidden(e).into_response();
    }
    // Fetch references for the CVE directly from own DB.
    let row: Result<Option<(Vec<String>,)>, _> =
        sqlx::query_as::<_, (serde_json::Value,)>("SELECT refs FROM vulnerabilities WHERE id = $1")
            .bind(&id)
            .fetch_optional(&state.pg)
            .await
            .map(|o| {
                o.map(|(v,)| {
                    (match v {
                        serde_json::Value::Array(items) => items
                            .into_iter()
                            .filter_map(|i| i.as_str().map(String::from))
                            .collect(),
                        _ => Vec::new(),
                    },)
                })
            });
    let refs = match row {
        Ok(Some((r,))) => r,
        Ok(None) => return (StatusCode::NOT_FOUND, "cve not found").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let commits = crate::github_crawl::extract_commit_refs(&refs);
    let limit = q.limit.unwrap_or(5).min(10);
    let mut out = Vec::with_capacity(commits.len().min(limit));
    for c in commits.into_iter().take(limit) {
        match crate::github_crawl::fetch_commit(q.token.as_deref(), q.base_url.as_deref(), &c).await
        {
            Ok(fc) => out.push(fc),
            Err(e) => warn!(cve = %id, sha = %c.sha, error = %e, "fix-commit fetch failed"),
        }
    }
    Json(out).into_response()
}

#[derive(Deserialize)]
struct SettingsPatch {
    scan_enabled: Option<bool>,
    policy_yaml: Option<String>,
}

async fn get_image_settings(
    State(state): State<ScannerState>,
    principal: Principal,
    Path((tenant, project, repo)): Path<(String, String, String)>,
) -> impl IntoResponse {
    if let Err(e) = principal.require(Permission::ScanRead) {
        return forbidden(e).into_response();
    }
    match state.settings.get(&tenant, &project, &repo).await {
        Ok(s) => Json(s).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn update_image_settings(
    State(state): State<ScannerState>,
    principal: Principal,
    Path((tenant, project, repo)): Path<(String, String, String)>,
    Json(patch): Json<SettingsPatch>,
) -> impl IntoResponse {
    if let Err(e) = principal.require(Permission::SettingsWrite) {
        return forbidden(e).into_response();
    }
    // Merge onto current record so callers can PATCH one field at a time.
    let current = match state.settings.get(&tenant, &project, &repo).await {
        Ok(s) => s,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let scan_enabled = patch.scan_enabled.unwrap_or(current.scan_enabled);
    let policy_yaml = patch.policy_yaml.or(current.policy_yaml);
    match state
        .settings
        .upsert(
            &principal.actor,
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
    principal: Principal,
    Query(q): Query<ListSuppressQuery>,
) -> impl IntoResponse {
    if let Err(e) = principal.require(Permission::ScanRead) {
        return forbidden(e).into_response();
    }
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
    principal: Principal,
    Path(id): Path<uuid::Uuid>,
) -> impl IntoResponse {
    if let Err(e) = principal.require(Permission::CveSuppress) {
        return forbidden(e).into_response();
    }
    match state.suppressions.revoke(&principal.actor, id).await {
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
    principal: Principal,
    Query(q): Query<IngestQuery>,
) -> impl IntoResponse {
    if let Err(e) = principal.require(Permission::Admin) {
        return forbidden(e).into_response();
    }
    let mut reports = Vec::new();
    for ing in &state.ingesters {
        if let Some(sel) = &q.source
            && ing.source() != sel
        {
            continue;
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

// ── Scan-by-id fetch + report ───────────────────────────────────────────────

async fn digest_for_scan(state: &ScannerState, id: uuid::Uuid) -> Result<Option<String>, String> {
    sqlx::query_scalar::<_, String>("SELECT digest FROM scans WHERE id = $1")
        .bind(id)
        .fetch_optional(&state.pg)
        .await
        .map_err(|e| e.to_string())
}

async fn get_scan_by_id(
    State(state): State<ScannerState>,
    principal: Principal,
    Path(id): Path<uuid::Uuid>,
) -> impl IntoResponse {
    if let Err(e) = principal.require(Permission::ScanRead) {
        return forbidden(e).into_response();
    }
    let digest = match digest_for_scan(&state, id).await {
        Ok(Some(d)) => d,
        Ok(None) => return (StatusCode::NOT_FOUND, "scan id not found").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    };
    match state.store.get(&digest).await {
        Ok(Some(r)) => Json(r).into_response(),
        // Scan row exists but Redis TTL expired — callers can re-queue via POST /v2/scan.
        Ok(None) => (StatusCode::GONE, "scan result expired from ephemeral store").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Deserialize, Default)]
struct ReportQuery {
    /// `html` (default) or `json`. Query param wins over Accept negotiation.
    format: Option<String>,
}

async fn get_scan_report(
    State(state): State<ScannerState>,
    principal: Principal,
    Path(id): Path<uuid::Uuid>,
    Query(q): Query<ReportQuery>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = principal.require(Permission::ScanRead) {
        return forbidden(e).into_response();
    }
    let digest = match digest_for_scan(&state, id).await {
        Ok(Some(d)) => d,
        Ok(None) => return (StatusCode::NOT_FOUND, "scan id not found").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    };
    let result = match state.store.get(&digest).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return (StatusCode::GONE, "scan result expired from ephemeral store").into_response();
        }
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    let want_json = match q.format.as_deref() {
        Some("json") => true,
        Some("html") => false,
        _ => headers
            .get(axum::http::header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.contains("application/json") && !v.contains("text/html"))
            .unwrap_or(false),
    };

    if want_json {
        match crate::report::to_json(&result) {
            Ok(body) => (
                StatusCode::OK,
                [("content-type", "application/json; charset=utf-8")],
                body,
            )
                .into_response(),
            Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        }
    } else {
        let body = crate::report::to_html(&result);
        (
            StatusCode::OK,
            [("content-type", "text/html; charset=utf-8")],
            body,
        )
            .into_response()
    }
}

// ── Dockerfile patch (auto-rebuild precursor) ──────────────────────────────

#[derive(Deserialize)]
struct DockerfilePatchReq {
    dockerfile: String,
}

#[derive(Serialize)]
struct DockerfilePatchResp {
    patched_dockerfile: String,
    applied_pins: Vec<String>,
}

async fn post_dockerfile_patch(
    State(state): State<ScannerState>,
    principal: Principal,
    Path(id): Path<uuid::Uuid>,
    Json(req): Json<DockerfilePatchReq>,
) -> impl IntoResponse {
    if let Err(e) = principal.require(Permission::ScanRead) {
        return forbidden(e).into_response();
    }
    let digest = match digest_for_scan(&state, id).await {
        Ok(Some(d)) => d,
        Ok(None) => return (StatusCode::NOT_FOUND, "scan id not found").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    };
    let result = match state.store.get(&digest).await {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::GONE, "scan expired from ephemeral store").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let suggestions = crate::dockerfile::suggest(&result);
    let applied_pins: Vec<String> = suggestions
        .package_pins
        .iter()
        .filter(|p| matches!(p.ecosystem.as_str(), "deb" | "rpm" | "apk"))
        .map(|p| format!("{}={}", p.package, p.suggested_version))
        .collect();
    let patched = crate::dockerfile::patch_dockerfile(&req.dockerfile, &suggestions);
    Json(DockerfilePatchResp {
        patched_dockerfile: patched,
        applied_pins,
    })
    .into_response()
}

// ── GitHub PR comments ──────────────────────────────────────────────────────

async fn post_pr_comment(
    State(state): State<ScannerState>,
    principal: Principal,
    Path(id): Path<uuid::Uuid>,
    Json(req): Json<crate::github_pr::PrCommentRequest>,
) -> impl IntoResponse {
    if let Err(e) = principal.require(Permission::ScanRead) {
        return forbidden(e).into_response();
    }
    let digest = match digest_for_scan(&state, id).await {
        Ok(Some(d)) => d,
        Ok(None) => return (StatusCode::NOT_FOUND, "scan id not found").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    };
    let result = match state.store.get(&digest).await {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::GONE, "scan expired from ephemeral store").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let body = crate::github_pr::render_comment(&result);
    match crate::github_pr::post_comment(&req, &body).await {
        Ok(report) => (StatusCode::CREATED, Json(report)).into_response(),
        Err(e) => (StatusCode::BAD_GATEWAY, e).into_response(),
    }
}

// ── Dockerfile fix suggestions ─────────────────────────────────────────────

async fn get_dockerfile_fix(
    State(state): State<ScannerState>,
    principal: Principal,
    Path(id): Path<uuid::Uuid>,
) -> impl IntoResponse {
    if let Err(e) = principal.require(Permission::ScanRead) {
        return forbidden(e).into_response();
    }
    let digest = match digest_for_scan(&state, id).await {
        Ok(Some(d)) => d,
        Ok(None) => return (StatusCode::NOT_FOUND, "scan id not found").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    };
    let result = match state.store.get(&digest).await {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::GONE, "scan expired from ephemeral store").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    Json(crate::dockerfile::suggest(&result)).into_response()
}

// ── Base-image recommendations ──────────────────────────────────────────────

async fn get_scan_recommendations(
    State(state): State<ScannerState>,
    principal: Principal,
    Path(id): Path<uuid::Uuid>,
) -> impl IntoResponse {
    if let Err(e) = principal.require(Permission::ScanRead) {
        return forbidden(e).into_response();
    }
    let digest = match digest_for_scan(&state, id).await {
        Ok(Some(d)) => d,
        Ok(None) => return (StatusCode::NOT_FOUND, "scan id not found").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    };
    let result = match state.store.get(&digest).await {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::GONE, "scan expired from ephemeral store").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    Json(crate::recommend::recommend(&result)).into_response()
}

// ── VEX ingest ─────────────────────────────────────────────────────────────

#[derive(Deserialize, Default)]
struct VexQuery {
    /// Optional scope narrowing — a `not_affected` statement with these
    /// filters will only suppress the CVE for the given tenant/project/repo.
    tenant: Option<String>,
    project: Option<String>,
    repository: Option<String>,
}

async fn ingest_vex(
    State(state): State<ScannerState>,
    principal: Principal,
    Query(q): Query<VexQuery>,
    Json(doc): Json<crate::vex::OpenVex>,
) -> impl IntoResponse {
    if let Err(e) = principal.require(Permission::CveSuppress) {
        return forbidden(e).into_response();
    }
    match crate::vex::apply_openvex(
        &doc,
        &state.suppressions,
        Some(&principal.actor),
        q.tenant.as_deref(),
        q.project.as_deref(),
        q.repository.as_deref(),
    )
    .await
    {
        Ok(report) => (StatusCode::CREATED, Json(report)).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// ── SBOM export ─────────────────────────────────────────────────────────────

#[derive(Deserialize, Default)]
struct SbomQuery {
    /// `cyclonedx` (default) or `spdx`.
    format: Option<String>,
}

async fn get_scan_sbom(
    State(state): State<ScannerState>,
    principal: Principal,
    Path(id): Path<uuid::Uuid>,
    Query(q): Query<SbomQuery>,
) -> impl IntoResponse {
    if let Err(e) = principal.require(Permission::ScanRead) {
        return forbidden(e).into_response();
    }
    let digest = match digest_for_scan(&state, id).await {
        Ok(Some(d)) => d,
        Ok(None) => return (StatusCode::NOT_FOUND, "scan id not found").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    };
    let result = match state.store.get(&digest).await {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::GONE, "scan expired from ephemeral store").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let body = match q.format.as_deref() {
        Some("spdx") => crate::sbom_export::spdx_2_3(&result),
        _ => crate::sbom_export::cyclonedx_1_5(&result),
    };
    Json(body).into_response()
}

// ── S3 export ───────────────────────────────────────────────────────────────

#[derive(Deserialize, Default)]
struct ExportQuery {
    /// Pre-signed URL lifetime in seconds. Clamped to [60, 604800].
    /// Ignored when the configured object store backend doesn't sign
    /// (e.g. LocalFileSystem).
    sign_ttl_secs: Option<u64>,
}

async fn export_scan(
    State(state): State<ScannerState>,
    principal: Principal,
    Path(id): Path<uuid::Uuid>,
    Query(q): Query<ExportQuery>,
) -> impl IntoResponse {
    if let Err(e) = principal.require(Permission::ScanRead) {
        return forbidden(e).into_response();
    }
    let digest = match digest_for_scan(&state, id).await {
        Ok(Some(d)) => d,
        Ok(None) => return (StatusCode::NOT_FOUND, "scan id not found").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    };
    let result = match state.store.get(&digest).await {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::GONE, "scan expired from ephemeral store").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    let ttl = std::time::Duration::from_secs(q.sign_ttl_secs.unwrap_or(3600).clamp(60, 604_800));
    match state.exporter.export(&result, ttl).await {
        Ok(out) => Json(out).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// ── API key management (admin) ──────────────────────────────────────────────

async fn create_api_key(
    State(state): State<ScannerState>,
    principal: Principal,
    Json(req): Json<NewKeyRequest>,
) -> impl IntoResponse {
    if let Err(e) = principal.require(Permission::Admin) {
        return forbidden(e).into_response();
    }
    match state.api_keys.create(&principal.actor, req).await {
        Ok(issued) => (StatusCode::CREATED, Json(issued)).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Deserialize, Default)]
struct ListKeysQuery {
    #[serde(default)]
    include_revoked: bool,
}

async fn list_api_keys(
    State(state): State<ScannerState>,
    principal: Principal,
    Query(q): Query<ListKeysQuery>,
) -> impl IntoResponse {
    if let Err(e) = principal.require(Permission::Admin) {
        return forbidden(e).into_response();
    }
    match state.api_keys.list(q.include_revoked).await {
        Ok(rows) => Json(rows).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn revoke_api_key(
    State(state): State<ScannerState>,
    principal: Principal,
    Path(id): Path<uuid::Uuid>,
) -> impl IntoResponse {
    if let Err(e) = principal.require(Permission::Admin) {
        return forbidden(e).into_response();
    }
    match state.api_keys.revoke(id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "api key not found").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
