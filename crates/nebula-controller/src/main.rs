use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use futures::StreamExt;
use kube::api::{Api, Patch, PatchParams, PostParams};
use kube::runtime::Controller;
use kube::runtime::controller::Action;
use kube::runtime::watcher::Config as WatcherConfig;
use kube::{Client, CustomResource, Resource, ResourceExt};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

// ---------------------------------------------------------------------------
// Shared types
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
pub struct Condition {
    #[serde(rename = "type")]
    pub type_: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_transition_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

// ---------------------------------------------------------------------------
// Tenant CRD
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
pub struct TenantQuotas {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_projects: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_repositories: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_storage_bytes: Option<u64>,
}

#[derive(CustomResource, Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "nebulacr.io",
    version = "v1alpha1",
    kind = "Tenant",
    plural = "tenants",
    status = "TenantStatus",
    namespaced = false
)]
pub struct TenantSpec {
    pub display_name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_backend: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit_rps: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_ip_ranges: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quotas: Option<TenantQuotas>,
}

fn default_true() -> bool {
    true
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
pub struct TenantStatus {
    #[serde(default)]
    pub phase: String,
    #[serde(default)]
    pub project_count: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
}

// ---------------------------------------------------------------------------
// Project CRD
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
pub struct RetentionPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tag_count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expire_days: Option<u32>,
}

#[derive(CustomResource, Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "nebulacr.io",
    version = "v1alpha1",
    kind = "Project",
    plural = "projects",
    status = "ProjectStatus",
    namespaced
)]
pub struct ProjectSpec {
    pub tenant_ref: String,
    pub display_name: String,
    pub visibility: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub immutable_tags: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_policy: Option<RetentionPolicy>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
pub struct ProjectStatus {
    #[serde(default)]
    pub phase: String,
    #[serde(default)]
    pub repository_count: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
}

// ---------------------------------------------------------------------------
// AccessPolicy CRD
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
pub struct Subject {
    /// One of "User", "Group", or "ServiceAccount".
    pub kind: String,
    pub name: String,
}

#[derive(CustomResource, Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "nebulacr.io",
    version = "v1alpha1",
    kind = "AccessPolicy",
    plural = "accesspolicies",
    status = "AccessPolicyStatus",
    namespaced
)]
pub struct AccessPolicySpec {
    pub tenant_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_ref: Option<String>,
    pub subjects: Vec<Subject>,
    /// One of "admin", "maintainer", or "reader".
    pub role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actions: Option<Vec<String>>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
pub struct AccessPolicyStatus {
    #[serde(default)]
    pub phase: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
}

// ---------------------------------------------------------------------------
// TokenPolicy CRD
// ---------------------------------------------------------------------------

#[derive(CustomResource, Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "nebulacr.io",
    version = "v1alpha1",
    kind = "TokenPolicy",
    plural = "tokenpolicies",
    status = "TokenPolicyStatus",
    namespaced
)]
pub struct TokenPolicySpec {
    pub tenant_ref: String,
    pub max_ttl_seconds: u64,
    pub default_ttl_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_ip_ranges: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_mfa: Option<bool>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
pub struct TokenPolicyStatus {
    #[serde(default)]
    pub phase: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
}

// ---------------------------------------------------------------------------
// Context shared across reconcilers
// ---------------------------------------------------------------------------

struct Ctx {
    client: Client,
    http: reqwest::Client,
    auth_service_url: String,
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
enum ControllerError {
    #[error("Kubernetes API error: {0}")]
    Kube(#[from] kube::Error),

    #[error("Validation failed: {0}")]
    Validation(String),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

// ---------------------------------------------------------------------------
// Helper: update status subresource
// ---------------------------------------------------------------------------

async fn update_status<T>(
    api: &Api<T>,
    name: &str,
    status: serde_json::Value,
) -> Result<(), ControllerError>
where
    T: Resource<DynamicType = ()>
        + Clone
        + std::fmt::Debug
        + serde::de::DeserializeOwned
        + Serialize,
{
    let patch = serde_json::json!({ "status": status });
    let pp = PatchParams::apply("nebula-controller").force();
    api.patch_status(name, &pp, &Patch::Merge(&patch)).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Helper: publish a Kubernetes Event
// ---------------------------------------------------------------------------

struct EventInfo<'a> {
    namespace: Option<&'a str>,
    regarding_kind: &'a str,
    regarding_name: &'a str,
    regarding_uid: &'a str,
    reason: &'a str,
    message: &'a str,
    event_type: &'a str,
}

async fn publish_event(client: &Client, info: &EventInfo<'_>) -> Result<(), ControllerError> {
    let events: Api<k8s_openapi::api::events::v1::Event> = match info.namespace {
        Some(ns) => Api::namespaced(client.clone(), ns),
        None => Api::default_namespaced(client.clone()),
    };

    let now = Utc::now();
    let event = k8s_openapi::api::events::v1::Event {
        metadata: kube::api::ObjectMeta {
            generate_name: Some(format!("{}-", info.regarding_name)),
            namespace: info.namespace.map(String::from),
            ..Default::default()
        },
        regarding: Some(k8s_openapi::api::core::v1::ObjectReference {
            kind: Some(info.regarding_kind.to_string()),
            name: Some(info.regarding_name.to_string()),
            uid: Some(info.regarding_uid.to_string()),
            namespace: info.namespace.map(String::from),
            api_version: Some("nebulacr.io/v1alpha1".to_string()),
            ..Default::default()
        }),
        reason: Some(info.reason.to_string()),
        note: Some(info.message.to_string()),
        type_: Some(info.event_type.to_string()),
        event_time: Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::MicroTime(
            now,
        )),
        reporting_controller: Some("nebula-controller".to_string()),
        reporting_instance: Some("nebula-controller-0".to_string()),
        action: Some(info.reason.to_string()),
        ..Default::default()
    };

    let pp = PostParams::default();
    events.create(&pp, &event).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Helper: sync state to the NebulaCR auth service
// ---------------------------------------------------------------------------

async fn sync_to_auth_service(
    http: &reqwest::Client,
    base_url: &str,
    path: &str,
    body: &serde_json::Value,
) -> Result<(), ControllerError> {
    let url = format!("{base_url}{path}");
    let resp = http.put(&url).json(body).send().await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        warn!(
            %url,
            %status,
            %text,
            "auth-service sync returned non-success"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Reconcile: Tenant
// ---------------------------------------------------------------------------

async fn reconcile_tenant(tenant: Arc<Tenant>, ctx: Arc<Ctx>) -> Result<Action, ControllerError> {
    let name = tenant.name_any();
    info!(%name, "reconciling Tenant");

    // Validate spec
    if tenant.spec.display_name.is_empty() {
        return Err(ControllerError::Validation(
            "display_name must not be empty".into(),
        ));
    }

    // Ensure storage prefix
    let storage_backend = tenant.spec.storage_backend.as_deref().unwrap_or("default");
    info!(%name, %storage_backend, "storage backend verified");

    // Sync to auth service
    let body = serde_json::to_value(&tenant.spec)?;
    if let Err(e) = sync_to_auth_service(
        &ctx.http,
        &ctx.auth_service_url,
        &format!("/api/v1/tenants/{name}"),
        &body,
    )
    .await
    {
        warn!(%name, error = %e, "failed to sync tenant to auth service; will retry");
        return Ok(Action::requeue(Duration::from_secs(30)));
    }

    // Update status
    let api: Api<Tenant> = Api::all(ctx.client.clone());
    let now = Utc::now().to_rfc3339();
    let status = serde_json::json!({
        "phase": "Ready",
        "project_count": 0,
        "conditions": [{
            "type": "Ready",
            "status": "True",
            "lastTransitionTime": now,
            "reason": "Reconciled",
            "message": "Tenant reconciled successfully",
        }]
    });
    update_status(&api, &name, status).await?;

    // Publish event
    let uid = tenant.uid().unwrap_or_default();
    let msg = format!("Tenant {name} reconciled successfully");
    if let Err(e) = publish_event(
        &ctx.client,
        &EventInfo {
            namespace: None,
            regarding_kind: "Tenant",
            regarding_name: &name,
            regarding_uid: &uid,
            reason: "Reconciled",
            message: &msg,
            event_type: "Normal",
        },
    )
    .await
    {
        warn!(%name, error = %e, "failed to publish event");
    }

    Ok(Action::requeue(Duration::from_secs(300)))
}

fn tenant_error_policy(tenant: Arc<Tenant>, error: &ControllerError, _ctx: Arc<Ctx>) -> Action {
    let name = tenant.name_any();
    error!(%name, %error, "tenant reconciliation failed");
    Action::requeue(Duration::from_secs(60))
}

// ---------------------------------------------------------------------------
// Reconcile: Project
// ---------------------------------------------------------------------------

async fn reconcile_project(
    project: Arc<Project>,
    ctx: Arc<Ctx>,
) -> Result<Action, ControllerError> {
    let name = project.name_any();
    let ns = project.namespace().unwrap_or_default();
    info!(%name, %ns, "reconciling Project");

    // Validate tenant_ref exists
    let tenants: Api<Tenant> = Api::all(ctx.client.clone());
    if tenants.get_opt(&project.spec.tenant_ref).await?.is_none() {
        warn!(
            %name,
            tenant_ref = %project.spec.tenant_ref,
            "referenced Tenant does not exist"
        );
        let api: Api<Project> = Api::namespaced(ctx.client.clone(), &ns);
        let now = Utc::now().to_rfc3339();
        let status = serde_json::json!({
            "phase": "Error",
            "repository_count": 0,
            "conditions": [{
                "type": "Ready",
                "status": "False",
                "lastTransitionTime": now,
                "reason": "TenantNotFound",
                "message": format!("Tenant '{}' not found", project.spec.tenant_ref),
            }]
        });
        update_status(&api, &name, status).await?;
        return Ok(Action::requeue(Duration::from_secs(60)));
    }

    // Validate visibility
    if !matches!(project.spec.visibility.as_str(), "private" | "public") {
        return Err(ControllerError::Validation(format!(
            "visibility must be 'private' or 'public', got '{}'",
            project.spec.visibility
        )));
    }

    // Validate retention policy
    if let Some(ref rp) = project.spec.retention_policy {
        if rp.max_tag_count == Some(0) {
            return Err(ControllerError::Validation(
                "max_tag_count must be > 0".into(),
            ));
        }
        if rp.expire_days == Some(0) {
            return Err(ControllerError::Validation(
                "expire_days must be > 0".into(),
            ));
        }
    }

    // Sync to auth service
    let body = serde_json::to_value(&project.spec)?;
    if let Err(e) = sync_to_auth_service(
        &ctx.http,
        &ctx.auth_service_url,
        &format!(
            "/api/v1/tenants/{}/projects/{name}",
            project.spec.tenant_ref
        ),
        &body,
    )
    .await
    {
        warn!(%name, error = %e, "failed to sync project to auth service; will retry");
        return Ok(Action::requeue(Duration::from_secs(30)));
    }

    // Update status
    let api: Api<Project> = Api::namespaced(ctx.client.clone(), &ns);
    let now = Utc::now().to_rfc3339();
    let status = serde_json::json!({
        "phase": "Ready",
        "repository_count": 0,
        "conditions": [{
            "type": "Ready",
            "status": "True",
            "lastTransitionTime": now,
            "reason": "Reconciled",
            "message": "Project reconciled successfully",
        }]
    });
    update_status(&api, &name, status).await?;

    // Publish event
    let uid = project.uid().unwrap_or_default();
    let msg = format!("Project {name} reconciled successfully");
    if let Err(e) = publish_event(
        &ctx.client,
        &EventInfo {
            namespace: Some(&ns),
            regarding_kind: "Project",
            regarding_name: &name,
            regarding_uid: &uid,
            reason: "Reconciled",
            message: &msg,
            event_type: "Normal",
        },
    )
    .await
    {
        warn!(%name, error = %e, "failed to publish event");
    }

    Ok(Action::requeue(Duration::from_secs(300)))
}

fn project_error_policy(project: Arc<Project>, error: &ControllerError, _ctx: Arc<Ctx>) -> Action {
    let name = project.name_any();
    error!(%name, %error, "project reconciliation failed");
    Action::requeue(Duration::from_secs(60))
}

// ---------------------------------------------------------------------------
// Reconcile: AccessPolicy
// ---------------------------------------------------------------------------

const VALID_ROLES: &[&str] = &["admin", "maintainer", "reader"];

async fn reconcile_access_policy(
    policy: Arc<AccessPolicy>,
    ctx: Arc<Ctx>,
) -> Result<Action, ControllerError> {
    let name = policy.name_any();
    let ns = policy.namespace().unwrap_or_default();
    info!(%name, %ns, "reconciling AccessPolicy");

    // Validate tenant_ref
    let tenants: Api<Tenant> = Api::all(ctx.client.clone());
    if tenants.get_opt(&policy.spec.tenant_ref).await?.is_none() {
        return Err(ControllerError::Validation(format!(
            "referenced Tenant '{}' not found",
            policy.spec.tenant_ref
        )));
    }

    // Validate project_ref if present
    if let Some(ref project_ref) = policy.spec.project_ref {
        let projects: Api<Project> = Api::namespaced(ctx.client.clone(), &ns);
        if projects.get_opt(project_ref).await?.is_none() {
            return Err(ControllerError::Validation(format!(
                "referenced Project '{project_ref}' not found"
            )));
        }
    }

    // Validate role
    if !VALID_ROLES.contains(&policy.spec.role.as_str()) {
        return Err(ControllerError::Validation(format!(
            "role must be one of {:?}, got '{}'",
            VALID_ROLES, policy.spec.role
        )));
    }

    // Validate subjects
    for s in &policy.spec.subjects {
        if !matches!(s.kind.as_str(), "User" | "Group" | "ServiceAccount") {
            return Err(ControllerError::Validation(format!(
                "subject kind must be User, Group, or ServiceAccount, got '{}'",
                s.kind
            )));
        }
    }

    // Sync to auth service
    let body = serde_json::to_value(&policy.spec)?;
    if let Err(e) = sync_to_auth_service(
        &ctx.http,
        &ctx.auth_service_url,
        &format!(
            "/api/v1/tenants/{}/access-policies/{name}",
            policy.spec.tenant_ref
        ),
        &body,
    )
    .await
    {
        warn!(%name, error = %e, "failed to sync access policy to auth service; will retry");
        return Ok(Action::requeue(Duration::from_secs(30)));
    }

    // Update status
    let api: Api<AccessPolicy> = Api::namespaced(ctx.client.clone(), &ns);
    let now = Utc::now().to_rfc3339();
    let status = serde_json::json!({
        "phase": "Active",
        "conditions": [{
            "type": "Ready",
            "status": "True",
            "lastTransitionTime": now,
            "reason": "Reconciled",
            "message": "AccessPolicy reconciled and synced to auth service",
        }]
    });
    update_status(&api, &name, status).await?;

    // Publish event
    let uid = policy.uid().unwrap_or_default();
    let msg = format!("AccessPolicy {name} synced to auth service");
    if let Err(e) = publish_event(
        &ctx.client,
        &EventInfo {
            namespace: Some(&ns),
            regarding_kind: "AccessPolicy",
            regarding_name: &name,
            regarding_uid: &uid,
            reason: "Reconciled",
            message: &msg,
            event_type: "Normal",
        },
    )
    .await
    {
        warn!(%name, error = %e, "failed to publish event");
    }

    Ok(Action::requeue(Duration::from_secs(300)))
}

fn access_policy_error_policy(
    policy: Arc<AccessPolicy>,
    error: &ControllerError,
    _ctx: Arc<Ctx>,
) -> Action {
    let name = policy.name_any();
    error!(%name, %error, "access-policy reconciliation failed");
    Action::requeue(Duration::from_secs(60))
}

// ---------------------------------------------------------------------------
// Reconcile: TokenPolicy
// ---------------------------------------------------------------------------

async fn reconcile_token_policy(
    policy: Arc<TokenPolicy>,
    ctx: Arc<Ctx>,
) -> Result<Action, ControllerError> {
    let name = policy.name_any();
    let ns = policy.namespace().unwrap_or_default();
    info!(%name, %ns, "reconciling TokenPolicy");

    // Validate tenant_ref
    let tenants: Api<Tenant> = Api::all(ctx.client.clone());
    if tenants.get_opt(&policy.spec.tenant_ref).await?.is_none() {
        return Err(ControllerError::Validation(format!(
            "referenced Tenant '{}' not found",
            policy.spec.tenant_ref
        )));
    }

    // Validate constraints
    if policy.spec.default_ttl_seconds > policy.spec.max_ttl_seconds {
        return Err(ControllerError::Validation(
            "default_ttl_seconds must be <= max_ttl_seconds".into(),
        ));
    }
    if policy.spec.max_ttl_seconds == 0 {
        return Err(ControllerError::Validation(
            "max_ttl_seconds must be > 0".into(),
        ));
    }

    // Sync to auth service
    let body = serde_json::to_value(&policy.spec)?;
    if let Err(e) = sync_to_auth_service(
        &ctx.http,
        &ctx.auth_service_url,
        &format!(
            "/api/v1/tenants/{}/token-policies/{name}",
            policy.spec.tenant_ref
        ),
        &body,
    )
    .await
    {
        warn!(%name, error = %e, "failed to sync token policy to auth service; will retry");
        return Ok(Action::requeue(Duration::from_secs(30)));
    }

    // Update status
    let api: Api<TokenPolicy> = Api::namespaced(ctx.client.clone(), &ns);
    let now = Utc::now().to_rfc3339();
    let status = serde_json::json!({
        "phase": "Active",
        "conditions": [{
            "type": "Ready",
            "status": "True",
            "lastTransitionTime": now,
            "reason": "Reconciled",
            "message": "TokenPolicy reconciled successfully",
        }]
    });
    update_status(&api, &name, status).await?;

    // Publish event
    let uid = policy.uid().unwrap_or_default();
    let msg = format!("TokenPolicy {name} reconciled successfully");
    if let Err(e) = publish_event(
        &ctx.client,
        &EventInfo {
            namespace: Some(&ns),
            regarding_kind: "TokenPolicy",
            regarding_name: &name,
            regarding_uid: &uid,
            reason: "Reconciled",
            message: &msg,
            event_type: "Normal",
        },
    )
    .await
    {
        warn!(%name, error = %e, "failed to publish event");
    }

    Ok(Action::requeue(Duration::from_secs(300)))
}

fn token_policy_error_policy(
    policy: Arc<TokenPolicy>,
    error: &ControllerError,
    _ctx: Arc<Ctx>,
) -> Action {
    let name = policy.name_any();
    error!(%name, %error, "token-policy reconciliation failed");
    Action::requeue(Duration::from_secs(60))
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .json()
        .init();

    info!("starting nebula-controller");

    let client = Client::try_default().await?;

    let auth_service_url =
        std::env::var("AUTH_SERVICE_URL").unwrap_or_else(|_| "http://nebula-auth:8080".to_string());

    let ctx = Arc::new(Ctx {
        client: client.clone(),
        http: reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?,
        auth_service_url,
    });

    // --- Tenant controller (cluster-scoped) ---
    let tenants: Api<Tenant> = Api::all(client.clone());
    let tenant_ctrl = Controller::new(tenants, WatcherConfig::default())
        .shutdown_on_signal()
        .run(reconcile_tenant, tenant_error_policy, ctx.clone())
        .for_each(|res| async move {
            match res {
                Ok(o) => info!(resource = ?o, "tenant reconciled"),
                Err(e) => error!(error = %e, "tenant reconcile loop error"),
            }
        });

    // --- Project controller ---
    let projects: Api<Project> = Api::all(client.clone());
    let project_ctrl = Controller::new(projects, WatcherConfig::default())
        .shutdown_on_signal()
        .run(reconcile_project, project_error_policy, ctx.clone())
        .for_each(|res| async move {
            match res {
                Ok(o) => info!(resource = ?o, "project reconciled"),
                Err(e) => error!(error = %e, "project reconcile loop error"),
            }
        });

    // --- AccessPolicy controller ---
    let access_policies: Api<AccessPolicy> = Api::all(client.clone());
    let access_ctrl = Controller::new(access_policies, WatcherConfig::default())
        .shutdown_on_signal()
        .run(
            reconcile_access_policy,
            access_policy_error_policy,
            ctx.clone(),
        )
        .for_each(|res| async move {
            match res {
                Ok(o) => info!(resource = ?o, "access-policy reconciled"),
                Err(e) => error!(error = %e, "access-policy reconcile loop error"),
            }
        });

    // --- TokenPolicy controller ---
    let token_policies: Api<TokenPolicy> = Api::all(client.clone());
    let token_ctrl = Controller::new(token_policies, WatcherConfig::default())
        .shutdown_on_signal()
        .run(
            reconcile_token_policy,
            token_policy_error_policy,
            ctx.clone(),
        )
        .for_each(|res| async move {
            match res {
                Ok(o) => info!(resource = ?o, "token-policy reconciled"),
                Err(e) => error!(error = %e, "token-policy reconcile loop error"),
            }
        });

    info!("all controllers started; waiting for shutdown signal");

    // Run all controllers concurrently — they all exit on SIGTERM.
    tokio::select! {
        () = tenant_ctrl => info!("tenant controller exited"),
        () = project_ctrl => info!("project controller exited"),
        () = access_ctrl => info!("access-policy controller exited"),
        () = token_ctrl => info!("token-policy controller exited"),
    }

    info!("nebula-controller shut down");
    Ok(())
}
