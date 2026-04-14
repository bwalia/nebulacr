//! Embedded metrics dashboard and JSON API endpoints.
//!
//! Serves:
//!   GET /dashboard         - HTML dashboard with live metrics
//!   GET /api/stats         - Summary statistics JSON
//!   GET /api/activity      - Recent activity feed JSON
//!   GET /api/audit         - Audit log with filtering JSON
//!   GET /api/system        - System metrics (CPU, RAM, disk) JSON
//!   GET /api/ha-status     - HA peer region health status JSON

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Response},
};
use futures::TryStreamExt;
use object_store::{ObjectStore, path::Path as StorePath};
use serde::{Deserialize, Serialize};
use sysinfo::{Disks, System};

use crate::audit::{AuditStats, RegistryAuditLog};
use nebula_replication::failover::FailoverManager;

/// State shared with dashboard handlers.
#[derive(Clone)]
pub struct DashboardState {
    pub audit_log: Arc<RegistryAuditLog>,
    pub store: Arc<dyn ObjectStore>,
    pub start_time: std::time::Instant,
    pub failover_manager: Option<Arc<FailoverManager>>,
    /// Optional auth service URL for proxying identity/access management requests.
    pub auth_service_url: Option<String>,
}

// ── JSON API ────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct StatsResponse {
    uptime_seconds: u64,
    #[serde(flatten)]
    audit: AuditStats,
}

pub async fn api_stats(State(state): State<DashboardState>) -> Json<StatsResponse> {
    let audit = state.audit_log.stats().await;
    Json(StatsResponse {
        uptime_seconds: state.start_time.elapsed().as_secs(),
        audit,
    })
}

#[derive(Deserialize)]
pub struct ActivityQuery {
    pub limit: Option<usize>,
    #[serde(rename = "type")]
    pub event_type: Option<String>,
    pub subject: Option<String>,
}

pub async fn api_activity(
    State(state): State<DashboardState>,
    Query(query): Query<ActivityQuery>,
) -> impl IntoResponse {
    let limit = query.limit.unwrap_or(50).min(500);

    let events = if let Some(ref event_type) = query.event_type {
        state.audit_log.by_type(event_type, limit).await
    } else if let Some(ref subject) = query.subject {
        state.audit_log.by_subject(subject, limit).await
    } else {
        state.audit_log.recent(limit).await
    };

    Json(serde_json::json!({
        "events": events,
        "count": events.len(),
    }))
}

pub async fn api_audit(
    State(state): State<DashboardState>,
    Query(query): Query<ActivityQuery>,
) -> impl IntoResponse {
    let limit = query.limit.unwrap_or(100).min(1000);

    let events = if let Some(ref event_type) = query.event_type {
        state.audit_log.by_type(event_type, limit).await
    } else if let Some(ref subject) = query.subject {
        state.audit_log.by_subject(subject, limit).await
    } else {
        state.audit_log.recent(limit).await
    };

    Json(serde_json::json!({
        "audit_events": events,
        "total_in_buffer": state.audit_log.count().await,
    }))
}

// ── System Metrics API ──────────────────────────────────────────────────

#[derive(Serialize)]
pub struct SystemMetrics {
    cpu_usage_percent: f32,
    cpu_count: usize,
    memory_total_bytes: u64,
    memory_used_bytes: u64,
    memory_available_bytes: u64,
    memory_usage_percent: f32,
    disks: Vec<DiskInfo>,
}

#[derive(Serialize)]
pub struct DiskInfo {
    mount_point: String,
    total_bytes: u64,
    available_bytes: u64,
    usage_percent: f32,
}

pub async fn api_system(_state: State<DashboardState>) -> Json<SystemMetrics> {
    let metrics = collect_system_metrics();
    Json(metrics)
}

fn collect_system_metrics() -> SystemMetrics {
    let mut sys = System::new();
    sys.refresh_cpu_all();
    sys.refresh_memory();

    // Brief pause for CPU measurement accuracy
    std::thread::sleep(std::time::Duration::from_millis(200));
    sys.refresh_cpu_all();

    let cpu_usage = sys.global_cpu_usage();
    let cpu_count = sys.cpus().len();
    let memory_total = sys.total_memory();
    let memory_used = sys.used_memory();
    let memory_available = sys.available_memory();
    let memory_usage_pct = if memory_total > 0 {
        (memory_used as f32 / memory_total as f32) * 100.0
    } else {
        0.0
    };

    let disk_list = Disks::new_with_refreshed_list();
    let disks: Vec<DiskInfo> = disk_list
        .iter()
        .filter(|d| {
            let mp = d.mount_point().to_string_lossy();
            // Filter to meaningful mount points
            mp == "/"
                || mp.starts_with("/var")
                || mp.starts_with("/data")
                || mp.starts_with("/home")
        })
        .map(|d| {
            let total = d.total_space();
            let available = d.available_space();
            let used = total.saturating_sub(available);
            let usage_pct = if total > 0 {
                (used as f32 / total as f32) * 100.0
            } else {
                0.0
            };
            DiskInfo {
                mount_point: d.mount_point().to_string_lossy().to_string(),
                total_bytes: total,
                available_bytes: available,
                usage_percent: usage_pct,
            }
        })
        .collect();

    SystemMetrics {
        cpu_usage_percent: cpu_usage,
        cpu_count,
        memory_total_bytes: memory_total,
        memory_used_bytes: memory_used,
        memory_available_bytes: memory_available,
        memory_usage_percent: memory_usage_pct,
        disks,
    }
}

// ── HA Status API ───────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct HaStatusResponse {
    ha_enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    local_is_primary: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    regions: Option<Vec<RegionStatus>>,
}

#[derive(Serialize)]
pub struct RegionStatus {
    region: String,
    healthy: bool,
    last_check: String,
    consecutive_failures: u32,
    response_time_ms: Option<u64>,
}

pub async fn api_ha_status(State(state): State<DashboardState>) -> Json<HaStatusResponse> {
    match &state.failover_manager {
        Some(fm) => {
            let health = fm.all_health().await;
            let regions: Vec<RegionStatus> = health
                .into_iter()
                .map(|h| RegionStatus {
                    region: h.region,
                    healthy: h.healthy,
                    last_check: h.last_check.to_rfc3339(),
                    consecutive_failures: h.consecutive_failures,
                    response_time_ms: h.response_time_ms,
                })
                .collect();
            Json(HaStatusResponse {
                ha_enabled: true,
                local_is_primary: Some(fm.is_local_primary()),
                regions: Some(regions),
            })
        }
        None => Json(HaStatusResponse {
            ha_enabled: false,
            local_is_primary: None,
            regions: None,
        }),
    }
}

// ── Image Browser API ──────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ImageQuery {
    /// Search term — supports substring and wildcard (*) matching.
    pub q: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Serialize)]
pub struct ImageEntry {
    pub repository: String,
    pub tenant: String,
    pub project: String,
    pub name: String,
    pub tags: Vec<String>,
    pub tag_count: usize,
    /// Total size of all blobs in bytes.
    pub total_size_bytes: u64,
    /// Human-readable total size.
    pub total_size: String,
    /// Number of blob objects.
    pub blob_count: usize,
    /// Number of manifests.
    pub manifest_count: usize,
    /// Last modified timestamp (most recent blob or manifest).
    pub last_pushed: Option<String>,
}

#[derive(Serialize)]
pub struct ImageListResponse {
    pub images: Vec<ImageEntry>,
    pub total: usize,
}

/// GET /api/images?q=search&limit=100 — List all repositories from storage with optional search.
pub async fn api_images(
    State(state): State<DashboardState>,
    Query(query): Query<ImageQuery>,
) -> Json<ImageListResponse> {
    let limit = query.limit.unwrap_or(200).min(1000);
    let search = query.q.unwrap_or_default().to_lowercase();

    // Walk the store to discover tenant/project/repo structures by finding tags/ prefixes.
    let mut images: Vec<ImageEntry> = Vec::new();

    // List top-level tenant prefixes
    let tenants = state
        .store
        .list_with_delimiter(None)
        .await
        .ok()
        .unwrap_or_else(|| object_store::ListResult {
            common_prefixes: vec![],
            objects: vec![],
        });

    for tenant_prefix in &tenants.common_prefixes {
        let tenant = tenant_prefix.as_ref().trim_end_matches('/').to_string();
        // Skip internal prefixes (allow "_" default tenant, skip _replication etc)
        if tenant.starts_with("_replication") {
            continue;
        }

        // List project prefixes under tenant
        let projects = state
            .store
            .list_with_delimiter(Some(tenant_prefix))
            .await
            .ok()
            .unwrap_or_else(|| object_store::ListResult {
                common_prefixes: vec![],
                objects: vec![],
            });

        for project_prefix in &projects.common_prefixes {
            let project_path = project_prefix.as_ref().trim_end_matches('/');
            let project = project_path
                .strip_prefix(&format!("{tenant}/"))
                .unwrap_or(project_path)
                .to_string();

            // List repo prefixes under project
            let repos = state
                .store
                .list_with_delimiter(Some(project_prefix))
                .await
                .ok()
                .unwrap_or_else(|| object_store::ListResult {
                    common_prefixes: vec![],
                    objects: vec![],
                });

            for repo_prefix in &repos.common_prefixes {
                let repo_path = repo_prefix.as_ref().trim_end_matches('/');
                let name = repo_path
                    .strip_prefix(&format!("{tenant}/{project}/"))
                    .unwrap_or(repo_path)
                    .to_string();

                let repository = format!("{tenant}/{project}/{name}");

                // Apply search filter
                if !search.is_empty() && !matches_search(&repository, &search) {
                    continue;
                }

                // List tags for this repo
                let tags_path = StorePath::from(format!("{tenant}/{project}/{name}/tags/"));
                let tag_objects: Vec<_> = state
                    .store
                    .list(Some(&tags_path))
                    .try_collect()
                    .await
                    .unwrap_or_default();

                let tags: Vec<String> = tag_objects
                    .iter()
                    .filter_map(|meta| {
                        let full = meta.location.to_string();
                        let prefix = format!("{tenant}/{project}/{name}/tags/");
                        full.strip_prefix(&prefix)
                            .filter(|t| !t.is_empty())
                            .map(|t| t.to_string())
                    })
                    .collect();

                let tag_count = tags.len();

                // Calculate blob sizes
                let blobs_path = StorePath::from(format!("{tenant}/{project}/{name}/blobs/"));
                let blob_objects: Vec<_> = state
                    .store
                    .list(Some(&blobs_path))
                    .try_collect()
                    .await
                    .unwrap_or_default();
                let total_size_bytes: u64 = blob_objects.iter().map(|m| m.size as u64).sum();
                let blob_count = blob_objects.len();

                // Count manifests
                let manifests_path =
                    StorePath::from(format!("{tenant}/{project}/{name}/manifests/"));
                let manifest_objects: Vec<_> = state
                    .store
                    .list(Some(&manifests_path))
                    .try_collect()
                    .await
                    .unwrap_or_default();
                let manifest_count = manifest_objects.len();

                // Find the most recent modification time across blobs and manifests
                let last_pushed = blob_objects
                    .iter()
                    .chain(manifest_objects.iter())
                    .map(|m| m.last_modified)
                    .max()
                    .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string());

                images.push(ImageEntry {
                    repository,
                    tenant: tenant.clone(),
                    project: project.clone(),
                    name,
                    tags,
                    tag_count,
                    total_size_bytes,
                    total_size: format_bytes(total_size_bytes),
                    blob_count,
                    manifest_count,
                    last_pushed,
                });

                if images.len() >= limit {
                    break;
                }
            }
            if images.len() >= limit {
                break;
            }
        }
        if images.len() >= limit {
            break;
        }
    }

    images.sort_by(|a, b| a.repository.cmp(&b.repository));
    let total = images.len();

    Json(ImageListResponse { images, total })
}

// ── Image Detail API ───────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ImageDetailQuery {
    /// Repository in `tenant/project/name` form.
    pub repo: String,
}

#[derive(Serialize)]
pub struct ImageDetailResponse {
    pub repository: String,
    pub tenant: String,
    pub project: String,
    pub name: String,

    /// Sum of every blob file actually stored on disk for this repo.
    /// This is what the repo really costs you.
    pub on_disk_bytes: u64,
    pub on_disk: String,

    /// What you would pay if every tag stored its own private copy of every
    /// layer. Always >= on_disk_bytes; the gap is dedup savings.
    pub naive_total_bytes: u64,
    pub naive_total: String,

    pub savings_bytes: u64,
    pub savings: String,
    pub savings_percent: f32,

    pub tag_count: usize,
    pub unique_layer_count: usize,
    pub orphan_blob_count: usize,
    pub orphan_blob_bytes: u64,
    pub orphan_blob_size: String,

    pub tags: Vec<TagDetail>,
    pub layers: Vec<LayerDetail>,
    pub orphans: Vec<OrphanBlob>,

    /// Plain-English summary suitable for non-Docker users.
    pub explanation: String,
}

#[derive(Serialize)]
pub struct TagDetail {
    pub tag: String,
    pub display_name: String,
    pub manifest_digest: String,
    pub media_type: String,
    pub platform: Option<String>,
    pub config_size_bytes: u64,
    pub layer_count: usize,
    /// Total bytes a `docker pull` of this tag would download
    /// (config + all layers for this platform).
    pub image_size_bytes: u64,
    pub image_size: String,
    pub layer_digests: Vec<String>,
}

#[derive(Serialize)]
pub struct LayerDetail {
    pub digest: String,
    pub short_digest: String,
    pub size_bytes: u64,
    pub size: String,
    pub used_by_tags: Vec<String>,
    /// True if more than one tag references this layer.
    pub shared: bool,
}

#[derive(Serialize)]
pub struct OrphanBlob {
    pub digest: String,
    pub short_digest: String,
    pub size_bytes: u64,
    pub size: String,
}

/// GET /api/image-detail?repo=tenant/project/name
///
/// Returns a deep breakdown of a repository: every tag's on-the-wire size,
/// every unique layer with its sharing fan-out, and any orphaned blobs.
pub async fn api_image_detail(
    State(state): State<DashboardState>,
    Query(query): Query<ImageDetailQuery>,
) -> Response {
    let parts: Vec<&str> = query.repo.split('/').collect();
    if parts.len() != 3 || parts.iter().any(|p| p.is_empty()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "repo must be tenant/project/name"})),
        )
            .into_response();
    }
    let (tenant, project, name) = (parts[0], parts[1], parts[2]);

    // ── Step 1: list every blob file (digest -> on-disk size) ──────────
    let blobs_path = StorePath::from(format!("{tenant}/{project}/{name}/blobs/"));
    let blob_objects: Vec<_> = state
        .store
        .list(Some(&blobs_path))
        .try_collect()
        .await
        .unwrap_or_default();

    let mut blob_sizes: HashMap<String, u64> = HashMap::new();
    for obj in &blob_objects {
        let full = obj.location.to_string();
        if let Some(hex) = full.rsplit('/').next()
            && hex.len() == 64
        {
            blob_sizes.insert(format!("sha256:{hex}"), obj.size as u64);
        }
    }
    let on_disk_bytes: u64 = blob_sizes.values().sum();

    // ── Step 2: walk tags, fetch each manifest, parse layers ───────────
    let tags_path = StorePath::from(format!("{tenant}/{project}/{name}/tags/"));
    let tag_objects: Vec<_> = state
        .store
        .list(Some(&tags_path))
        .try_collect()
        .await
        .unwrap_or_default();

    let mut tags: Vec<TagDetail> = Vec::new();
    let mut layer_to_tags: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut referenced_blobs: BTreeSet<String> = BTreeSet::new();

    for tag_obj in &tag_objects {
        let full = tag_obj.location.to_string();
        let prefix = format!("{tenant}/{project}/{name}/tags/");
        let tag_name = match full.strip_prefix(&prefix) {
            Some(t) if !t.is_empty() => t.to_string(),
            _ => continue,
        };

        // Tag link file content is the manifest digest as raw bytes.
        let manifest_digest = match read_object_string(&*state.store, &tag_obj.location).await {
            Some(s) => s.trim().to_string(),
            None => continue,
        };
        if manifest_digest.is_empty() {
            continue;
        }

        let manifest_path = StorePath::from(format!(
            "{tenant}/{project}/{name}/manifests/{manifest_digest}"
        ));
        let manifest_bytes = match read_object_bytes(&*state.store, &manifest_path).await {
            Some(b) => b,
            None => continue,
        };

        collect_tag_details(
            &*state.store,
            tenant,
            project,
            name,
            &tag_name,
            &manifest_digest,
            &manifest_bytes,
            &blob_sizes,
            &mut tags,
            &mut layer_to_tags,
            &mut referenced_blobs,
        )
        .await;
    }

    // ── Step 3: build unique-layer view sorted by size ─────────────────
    let mut layers: Vec<LayerDetail> = layer_to_tags
        .iter()
        .map(|(digest, used_by)| {
            let size = *blob_sizes.get(digest).unwrap_or(&0);
            let used_by_vec: Vec<String> = used_by.iter().cloned().collect();
            let shared = used_by_vec.len() > 1;
            LayerDetail {
                digest: digest.clone(),
                short_digest: short_digest(digest),
                size_bytes: size,
                size: format_bytes(size),
                used_by_tags: used_by_vec,
                shared,
            }
        })
        .collect();
    layers.sort_by(|a, b| b.size_bytes.cmp(&a.size_bytes));

    // ── Step 4: orphan blobs (on disk but unreferenced by any tag) ─────
    let mut orphans: Vec<OrphanBlob> = blob_sizes
        .iter()
        .filter(|(d, _)| !referenced_blobs.contains(*d))
        .map(|(digest, size)| OrphanBlob {
            digest: digest.clone(),
            short_digest: short_digest(digest),
            size_bytes: *size,
            size: format_bytes(*size),
        })
        .collect();
    orphans.sort_by(|a, b| b.size_bytes.cmp(&a.size_bytes));
    let orphan_blob_bytes: u64 = orphans.iter().map(|o| o.size_bytes).sum();
    let orphan_blob_count = orphans.len();

    // ── Step 5: summary numbers ────────────────────────────────────────
    let naive_total_bytes: u64 = tags.iter().map(|t| t.image_size_bytes).sum();
    let savings_bytes = naive_total_bytes.saturating_sub(on_disk_bytes);
    let savings_percent = if naive_total_bytes > 0 {
        (savings_bytes as f64 / naive_total_bytes as f64 * 100.0) as f32
    } else {
        0.0
    };

    let unique_layer_count = layers.len();
    let tag_count = tags.len();

    let explanation = build_explanation(
        tag_count,
        unique_layer_count,
        on_disk_bytes,
        naive_total_bytes,
        savings_bytes,
        orphan_blob_count,
        orphan_blob_bytes,
    );

    tags.sort_by(|a, b| b.image_size_bytes.cmp(&a.image_size_bytes));

    let resp = ImageDetailResponse {
        repository: format!("{tenant}/{project}/{name}"),
        tenant: tenant.to_string(),
        project: project.to_string(),
        name: name.to_string(),
        on_disk_bytes,
        on_disk: format_bytes(on_disk_bytes),
        naive_total_bytes,
        naive_total: format_bytes(naive_total_bytes),
        savings_bytes,
        savings: format_bytes(savings_bytes),
        savings_percent,
        tag_count,
        unique_layer_count,
        orphan_blob_count,
        orphan_blob_bytes,
        orphan_blob_size: format_bytes(orphan_blob_bytes),
        tags,
        layers,
        orphans,
        explanation,
    };

    Json(resp).into_response()
}

async fn read_object_bytes(store: &dyn ObjectStore, path: &StorePath) -> Option<bytes::Bytes> {
    match store.get(path).await {
        Ok(g) => g.bytes().await.ok(),
        Err(_) => None,
    }
}

async fn read_object_string(store: &dyn ObjectStore, path: &StorePath) -> Option<String> {
    let bytes = read_object_bytes(store, path).await?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// Walks one tag's manifest. If it's a manifest list/index, fetches each
/// platform-specific child manifest and emits one `TagDetail` per platform.
#[allow(clippy::too_many_arguments)]
async fn collect_tag_details(
    store: &dyn ObjectStore,
    tenant: &str,
    project: &str,
    name: &str,
    tag_name: &str,
    manifest_digest: &str,
    manifest_bytes: &[u8],
    blob_sizes: &HashMap<String, u64>,
    tags: &mut Vec<TagDetail>,
    layer_to_tags: &mut BTreeMap<String, BTreeSet<String>>,
    referenced_blobs: &mut BTreeSet<String>,
) {
    let json: serde_json::Value = match serde_json::from_slice(manifest_bytes) {
        Ok(v) => v,
        Err(_) => return,
    };

    // Manifest list / OCI index — recurse one level.
    if let Some(child_manifests) = json.get("manifests").and_then(|v| v.as_array()) {
        for entry in child_manifests {
            let child_digest = match entry.get("digest").and_then(|v| v.as_str()) {
                Some(d) => d.to_string(),
                None => continue,
            };
            let platform = entry.get("platform").map(|p| {
                let arch = p.get("architecture").and_then(|v| v.as_str()).unwrap_or("");
                let os = p.get("os").and_then(|v| v.as_str()).unwrap_or("");
                if arch.is_empty() && os.is_empty() {
                    "unknown".to_string()
                } else {
                    format!("{os}/{arch}")
                }
            });
            let display_name = match &platform {
                Some(p) => format!("{tag_name} [{p}]"),
                None => tag_name.to_string(),
            };
            let child_path = StorePath::from(format!(
                "{tenant}/{project}/{name}/manifests/{child_digest}"
            ));
            let Some(child_bytes) = read_object_bytes(store, &child_path).await else {
                continue;
            };
            parse_single_manifest(
                tag_name,
                &display_name,
                &child_digest,
                &child_bytes,
                platform,
                blob_sizes,
                tags,
                layer_to_tags,
                referenced_blobs,
            );
        }
        return;
    }

    parse_single_manifest(
        tag_name,
        tag_name,
        manifest_digest,
        manifest_bytes,
        None,
        blob_sizes,
        tags,
        layer_to_tags,
        referenced_blobs,
    );
}

#[allow(clippy::too_many_arguments)]
fn parse_single_manifest(
    tag_name: &str,
    display_name: &str,
    manifest_digest: &str,
    manifest_bytes: &[u8],
    platform: Option<String>,
    blob_sizes: &HashMap<String, u64>,
    tags: &mut Vec<TagDetail>,
    layer_to_tags: &mut BTreeMap<String, BTreeSet<String>>,
    referenced_blobs: &mut BTreeSet<String>,
) {
    let json: serde_json::Value = match serde_json::from_slice(manifest_bytes) {
        Ok(v) => v,
        Err(_) => return,
    };
    let media_type = json
        .get("mediaType")
        .and_then(|v| v.as_str())
        .unwrap_or("application/vnd.oci.image.manifest.v1+json")
        .to_string();

    let config_digest = json
        .get("config")
        .and_then(|c| c.get("digest"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let config_size: u64 = json
        .get("config")
        .and_then(|c| c.get("size"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    if let Some(d) = &config_digest {
        referenced_blobs.insert(d.clone());
    }

    let mut layer_digests: Vec<String> = Vec::new();
    let mut layer_total: u64 = 0;
    if let Some(layers) = json.get("layers").and_then(|v| v.as_array()) {
        for layer in layers {
            let Some(digest) = layer.get("digest").and_then(|v| v.as_str()) else {
                continue;
            };
            // Prefer on-disk size if we have it (authoritative); fall back to
            // the size declared in the manifest.
            let size = blob_sizes.get(digest).copied().unwrap_or_else(|| {
                layer.get("size").and_then(|v| v.as_u64()).unwrap_or(0)
            });
            layer_total += size;
            layer_digests.push(digest.to_string());
            referenced_blobs.insert(digest.to_string());
            layer_to_tags
                .entry(digest.to_string())
                .or_default()
                .insert(display_name.to_string());
        }
    }

    let image_size_bytes = config_size + layer_total;

    tags.push(TagDetail {
        tag: tag_name.to_string(),
        display_name: display_name.to_string(),
        manifest_digest: manifest_digest.to_string(),
        media_type,
        platform,
        config_size_bytes: config_size,
        layer_count: layer_digests.len(),
        image_size_bytes,
        image_size: format_bytes(image_size_bytes),
        layer_digests,
    });
}

fn short_digest(digest: &str) -> String {
    let hex = digest.strip_prefix("sha256:").unwrap_or(digest);
    let take = hex.len().min(12);
    format!("sha256:{}", &hex[..take])
}

fn build_explanation(
    tag_count: usize,
    unique_layers: usize,
    on_disk: u64,
    naive_total: u64,
    savings: u64,
    orphan_count: usize,
    orphan_bytes: u64,
) -> String {
    if tag_count == 0 {
        return "This repository has no tags. Any storage you see is from blobs that were uploaded but never referenced by a manifest — usually leftovers from an interrupted push.".to_string();
    }

    let tag_word = if tag_count == 1 { "tag" } else { "tags" };
    let layer_word = if unique_layers == 1 { "layer" } else { "layers" };
    let mut s = format!(
        "A container image is built from a stack of read-only filesystem slices called \"layers\". \
This repository has {tag_count} {tag_word} sharing {unique_layers} unique {layer_word}. \
The repository takes {on_disk} on disk because identical layers are stored once even when many tags reference them — \
if every tag had its own private copy, the same content would take {naive}, so deduplication is saving you {savings}.",
        on_disk = format_bytes(on_disk),
        naive = format_bytes(naive_total),
        savings = format_bytes(savings),
    );
    if savings > 0 && naive_total > 0 {
        let pct = (savings as f64 / naive_total as f64 * 100.0).round() as u64;
        s.push_str(&format!(" ({pct}% smaller than the naive total.)"));
    }
    s.push_str(" When someone runs `docker pull`, they only download the layers for the one tag they asked for — not the whole repository.");
    if orphan_count > 0 {
        s.push_str(&format!(
            " ⚠ {orphan_count} blob(s) totalling {orphans} are on disk but no tag references them. These are usually leftovers from interrupted pushes or deleted tags and can be reclaimed by garbage collection.",
            orphans = format_bytes(orphan_bytes),
        ));
    }
    s
}

// ── Identity & Access Management API (proxies to auth service) ─────────

/// GET /api/users — Proxy to auth service /api/v1/users.
pub async fn api_users(State(state): State<DashboardState>) -> impl IntoResponse {
    proxy_to_auth(&state, "/api/v1/users").await
}

/// GET /api/groups — Proxy to auth service /api/v1/groups.
pub async fn api_groups(State(state): State<DashboardState>) -> impl IntoResponse {
    proxy_to_auth(&state, "/api/v1/groups").await
}

/// GET /api/robot-accounts — Proxy to auth service /api/v1/robot-accounts.
pub async fn api_robot_accounts(State(state): State<DashboardState>) -> impl IntoResponse {
    proxy_to_auth(&state, "/api/v1/robot-accounts").await
}

/// Proxy a GET request to the auth service.
async fn proxy_to_auth(state: &DashboardState, path: &str) -> Response {
    let Some(ref auth_url) = state.auth_service_url else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "auth service URL not configured"})),
        )
            .into_response();
    };

    let url = format!("{}{}", auth_url.trim_end_matches('/'), path);
    match reqwest::get(&url).await {
        Ok(resp) => {
            let status = StatusCode::from_u16(resp.status().as_u16())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            let body = resp.text().await.unwrap_or_default();
            (
                status,
                [(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                )],
                body,
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error": format!("failed to proxy to auth service: {e}")})),
        )
            .into_response(),
    }
}

/// Match a repository name against a search term supporting wildcards (*).
fn matches_search(repo: &str, search: &str) -> bool {
    let repo_lower = repo.to_lowercase();

    if search.contains('*') {
        // Convert wildcard pattern to simple matching
        let parts: Vec<&str> = search.split('*').collect();
        if parts.len() == 1 {
            return repo_lower.contains(parts[0]);
        }
        // Check that all parts appear in order
        let mut pos = 0;
        for (i, part) in parts.iter().enumerate() {
            if part.is_empty() {
                continue;
            }
            if let Some(found) = repo_lower[pos..].find(part) {
                if i == 0 && found != 0 {
                    // First segment must be at start if pattern doesn't start with *
                    if !search.starts_with('*') {
                        return false;
                    }
                }
                pos += found + part.len();
            } else {
                return false;
            }
        }
        // If pattern doesn't end with *, last segment must be at end
        if !search.ends_with('*')
            && let Some(last) = parts.last()
            && !last.is_empty()
        {
            return repo_lower.ends_with(last);
        }
        true
    } else {
        // Simple substring match
        repo_lower.contains(search)
    }
}

// ── HTML Dashboard ──────────────────────────────────────────────────────

pub async fn dashboard_html(State(state): State<DashboardState>) -> Response {
    let stats = state.audit_log.stats().await;
    let recent = state.audit_log.recent(20).await;
    let uptime = state.start_time.elapsed().as_secs();
    let sys_metrics = collect_system_metrics();

    // Collect HA status
    let (ha_enabled, ha_local_primary, ha_regions) = match &state.failover_manager {
        Some(fm) => {
            let health = fm.all_health().await;
            (true, fm.is_local_primary(), health)
        }
        None => (false, false, vec![]),
    };

    // Build recent activity rows
    let mut rows = String::new();
    for e in &recent {
        let size_display = if e.size_bytes > 0 {
            format_bytes(e.size_bytes)
        } else {
            "-".to_string()
        };
        rows.push_str(&format!(
            "<tr><td>{}</td><td><span class=\"badge badge-{}\">{}</span></td><td>{}</td><td>{}/{}/{}</td><td>{}</td><td>{}</td><td>{}ms</td></tr>\n",
            e.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
            event_badge_class(&e.event_type),
            e.event_type,
            e.subject,
            e.tenant, e.project, e.repository,
            e.reference,
            size_display,
            e.duration_ms,
        ));
    }

    // Build disk info for the primary disk
    let primary_disk = sys_metrics.disks.first();
    let disk_avail_display = primary_disk
        .map(|d| format_bytes(d.available_bytes))
        .unwrap_or_else(|| "N/A".to_string());
    let disk_usage_pct = primary_disk.map(|d| d.usage_percent).unwrap_or(0.0);

    // Build HA status section
    let ha_section = if ha_enabled {
        let mut region_rows = String::new();
        for r in &ha_regions {
            let status_class = if r.healthy { "green" } else { "red" };
            let status_label = if r.healthy { "Healthy" } else { "Unhealthy" };
            let latency = r
                .response_time_ms
                .map(|ms| format!("{ms}ms"))
                .unwrap_or_else(|| "-".to_string());
            region_rows.push_str(&format!(
                "<tr><td>{region}</td><td><span class=\"badge badge-{status_class}\">{status_label}</span></td><td>{latency}</td><td>{failures}</td><td>{last_check}</td></tr>\n",
                region = r.region,
                status_class = status_class,
                status_label = status_label,
                latency = latency,
                failures = r.consecutive_failures,
                last_check = r.last_check.format("%Y-%m-%d %H:%M:%S UTC"),
            ));
        }

        let role = if ha_local_primary {
            "Primary"
        } else {
            "Secondary"
        };
        let healthy_count = ha_regions.iter().filter(|r| r.healthy).count();
        let total_count = ha_regions.len();

        format!(
            r#"<div class="section">
        <div class="section-header">
            <h2>HA Multi-Region Status</h2>
            <div class="controls">
                <span class="badge badge-green" style="font-size:13px;">Local Role: {role}</span>
                <span style="color:var(--text-muted);font-size:13px;">{healthy_count}/{total_count} regions healthy</span>
            </div>
        </div>
        <table>
            <thead>
                <tr>
                    <th>Region</th>
                    <th>Status</th>
                    <th>Latency</th>
                    <th>Failures</th>
                    <th>Last Check</th>
                </tr>
            </thead>
            <tbody>
                {region_rows}
            </tbody>
        </table>
    </div>"#,
        )
    } else {
        r#"<div class="section">
        <div class="section-header">
            <h2>HA Multi-Region Status</h2>
        </div>
        <div class="empty">Multi-region HA is not configured. Enable it in <code>[multi_region]</code> config to see peer status.</div>
    </div>"#
            .to_string()
    };

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NebulaCR Dashboard</title>
<style>
:root {{
    --bg: #0f172a;
    --surface: #1e293b;
    --surface2: #334155;
    --border: #475569;
    --text: #e2e8f0;
    --text-muted: #94a3b8;
    --accent: #38bdf8;
    --green: #4ade80;
    --yellow: #fbbf24;
    --red: #f87171;
    --purple: #a78bfa;
    --orange: #fb923c;
    --teal: #2dd4bf;
}}
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace; background: var(--bg); color: var(--text); min-height:100vh; }}
.header {{ background: var(--surface); border-bottom: 1px solid var(--border); padding: 16px 24px; display:flex; align-items:center; justify-content:space-between; }}
.header h1 {{ font-size: 20px; font-weight: 600; }}
.header h1 span {{ color: var(--accent); }}
.header .status {{ color: var(--green); font-size: 14px; }}
.container {{ max-width: 1400px; margin: 0 auto; padding: 24px; }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 24px; }}
.card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 20px; }}
.card .label {{ font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); margin-bottom: 4px; }}
.card .value {{ font-size: 28px; font-weight: 700; }}
.card .sub {{ font-size: 11px; color: var(--text-muted); margin-top: 4px; }}
.card .value.green {{ color: var(--green); }}
.card .value.accent {{ color: var(--accent); }}
.card .value.yellow {{ color: var(--yellow); }}
.card .value.red {{ color: var(--red); }}
.card .value.purple {{ color: var(--purple); }}
.card .value.orange {{ color: var(--orange); }}
.card .value.teal {{ color: var(--teal); }}
.progress-bar {{ height: 6px; background: var(--surface2); border-radius: 3px; margin-top: 8px; overflow: hidden; }}
.progress-bar .fill {{ height: 100%; border-radius: 3px; transition: width 0.3s; }}
.fill-green {{ background: var(--green); }}
.fill-yellow {{ background: var(--yellow); }}
.fill-red {{ background: var(--red); }}
.fill-accent {{ background: var(--accent); }}
.fill-orange {{ background: var(--orange); }}
.section {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 24px; }}
.section-header {{ padding: 16px 20px; border-bottom: 1px solid var(--border); display:flex; justify-content:space-between; align-items:center; }}
.section-header h2 {{ font-size: 16px; font-weight: 600; }}
.section-header .controls {{ display:flex; gap:8px; align-items:center; }}
.section-header select, .section-header input {{ background: var(--surface2); border: 1px solid var(--border); color: var(--text); padding: 6px 10px; border-radius: 4px; font-size: 13px; }}
table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
th {{ text-align: left; padding: 10px 16px; color: var(--text-muted); font-weight: 500; font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid var(--border); }}
td {{ padding: 10px 16px; border-bottom: 1px solid var(--surface2); }}
tr:hover {{ background: var(--surface2); }}
.badge {{ padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }}
.badge-push {{ background: rgba(74,222,128,0.15); color: var(--green); }}
.badge-pull {{ background: rgba(56,189,248,0.15); color: var(--accent); }}
.badge-delete {{ background: rgba(248,113,113,0.15); color: var(--red); }}
.badge-other {{ background: rgba(167,139,250,0.15); color: var(--purple); }}
.badge-green {{ background: rgba(74,222,128,0.15); color: var(--green); }}
.badge-red {{ background: rgba(248,113,113,0.15); color: var(--red); }}
.footer {{ text-align: center; color: var(--text-muted); font-size: 12px; padding: 16px; }}
.refresh-btn {{ background: var(--accent); color: var(--bg); border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; font-size: 13px; font-weight: 600; }}
.refresh-btn:hover {{ opacity: 0.8; }}
.empty {{ text-align: center; padding: 40px; color: var(--text-muted); }}
.clickable-row {{ cursor: pointer; }}
.clickable-row:hover {{ background: var(--surface2); }}
.clickable-row td:first-child::before {{ content: '▸ '; color: var(--accent); font-size: 11px; }}
.modal-backdrop {{ position: fixed; inset: 0; background: rgba(0,0,0,0.7); display: none; align-items: flex-start; justify-content: center; z-index: 1000; padding: 40px 20px; overflow-y: auto; }}
.modal-backdrop.open {{ display: flex; }}
.modal {{ background: var(--bg); border: 1px solid var(--border); border-radius: 8px; max-width: 1200px; width: 100%; box-shadow: 0 20px 60px rgba(0,0,0,0.5); }}
.modal-header {{ padding: 20px 24px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; position: sticky; top: 0; background: var(--bg); border-radius: 8px 8px 0 0; z-index: 1; }}
.modal-header h2 {{ font-size: 18px; }}
.modal-header h2 small {{ display: block; font-size: 12px; color: var(--text-muted); font-weight: 400; margin-top: 2px; }}
.modal-close {{ background: var(--surface2); border: 1px solid var(--border); color: var(--text); width: 32px; height: 32px; border-radius: 4px; cursor: pointer; font-size: 18px; line-height: 1; }}
.modal-close:hover {{ background: var(--red); color: var(--bg); }}
.modal-body {{ padding: 20px 24px; }}
.explainer {{ background: var(--surface); border-left: 3px solid var(--accent); padding: 14px 18px; border-radius: 4px; margin-bottom: 20px; font-size: 13px; line-height: 1.6; color: var(--text); }}
.detail-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-bottom: 24px; }}
.detail-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 14px 16px; }}
.detail-card .label {{ font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); margin-bottom: 4px; }}
.detail-card .value {{ font-size: 22px; font-weight: 700; }}
.detail-card .sub {{ font-size: 11px; color: var(--text-muted); margin-top: 4px; }}
.topology {{ background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 16px; margin-bottom: 20px; overflow-x: auto; }}
.topology h3 {{ font-size: 13px; margin-bottom: 4px; }}
.topology .topology-help {{ font-size: 11px; color: var(--text-muted); margin-bottom: 12px; }}
.layer-bar {{ margin-bottom: 8px; }}
.layer-bar .layer-meta {{ display: flex; justify-content: space-between; font-size: 11px; margin-bottom: 3px; color: var(--text-muted); }}
.layer-bar .layer-meta strong {{ color: var(--text); font-family: monospace; }}
.layer-bar .layer-track {{ height: 18px; background: var(--surface2); border-radius: 3px; overflow: hidden; position: relative; }}
.layer-bar .layer-fill {{ height: 100%; border-radius: 3px; }}
.layer-bar .layer-fill.shared {{ background: linear-gradient(90deg, var(--green), var(--teal)); }}
.layer-bar .layer-fill.unique {{ background: var(--accent); }}
.layer-bar .layer-tags {{ font-size: 10px; margin-top: 4px; display: flex; flex-wrap: wrap; gap: 3px; }}
.matrix {{ overflow-x: auto; }}
.matrix table {{ font-size: 11px; }}
.matrix th, .matrix td {{ padding: 4px 6px; text-align: center; border: 1px solid var(--surface2); }}
.matrix th.tag-header {{ writing-mode: vertical-rl; transform: rotate(180deg); white-space: nowrap; vertical-align: bottom; min-height: 80px; padding: 6px 2px; }}
.matrix th.layer-header {{ text-align: left; font-family: monospace; font-weight: normal; color: var(--text-muted); white-space: nowrap; padding-right: 12px; }}
.matrix td.cell-on {{ background: var(--green); color: var(--bg); font-weight: 700; }}
.matrix td.cell-off {{ background: var(--surface); color: var(--surface2); }}
.matrix td.size-col {{ text-align: right; font-family: monospace; color: var(--text-muted); padding-right: 8px; }}
.warn-box {{ background: rgba(251,191,36,0.1); border: 1px solid var(--yellow); border-radius: 4px; padding: 12px 14px; margin-bottom: 16px; font-size: 12px; color: var(--yellow); }}
</style>
</head>
<body>

<div class="header">
    <h1><span>Nebula</span>CR Registry Dashboard</h1>
    <div class="status">Healthy &bull; Uptime: {uptime_display}</div>
</div>

<div class="container">
    <div class="grid">
        <div class="card">
            <div class="label">CPU Usage</div>
            <div class="value {cpu_color}">{cpu_usage:.1}%</div>
            <div class="sub">{cpu_count} cores</div>
            <div class="progress-bar"><div class="fill {cpu_bar_color}" style="width:{cpu_usage:.0}%"></div></div>
        </div>
        <div class="card">
            <div class="label">RAM Usage</div>
            <div class="value {ram_color}">{ram_used}</div>
            <div class="sub">{ram_usage_pct:.1}% of {ram_total}</div>
            <div class="progress-bar"><div class="fill {ram_bar_color}" style="width:{ram_usage_pct:.0}%"></div></div>
        </div>
        <div class="card">
            <div class="label">Disk Available</div>
            <div class="value {disk_color}">{disk_avail}</div>
            <div class="sub">{disk_usage_pct:.1}% used</div>
            <div class="progress-bar"><div class="fill {disk_bar_color}" style="width:{disk_usage_pct:.0}%"></div></div>
        </div>
        <div class="card">
            <div class="label">HA Status</div>
            <div class="value {ha_color}">{ha_display}</div>
            <div class="sub">{ha_sub}</div>
        </div>
        <div class="card">
            <div class="label">Total Pushes</div>
            <div class="value green">{total_pushes}</div>
        </div>
        <div class="card">
            <div class="label">Total Pulls</div>
            <div class="value accent">{total_pulls}</div>
        </div>
        <div class="card">
            <div class="label">Total Deletes</div>
            <div class="value red">{total_deletes}</div>
        </div>
        <div class="card">
            <div class="label">Data Pushed</div>
            <div class="value yellow">{total_push_bytes}</div>
        </div>
        <div class="card">
            <div class="label">Avg Latency</div>
            <div class="value purple">{avg_latency:.1}ms</div>
        </div>
        <div class="card">
            <div class="label">Events Logged</div>
            <div class="value">{total_events}</div>
        </div>
    </div>

    {ha_section}

    <div class="section">
        <div class="section-header">
            <h2>Image Browser</h2>
            <div class="controls">
                <input type="text" id="image-search" placeholder="Search images... (e.g. fastapi or _/diy*)" oninput="searchImages()" style="width:300px;">
                <button class="refresh-btn" onclick="searchImages()">Search</button>
            </div>
        </div>
        <div id="image-results">
            <div class="empty" id="image-loading">Loading images...</div>
        </div>
    </div>

    <div class="section">
        <div class="section-header">
            <h2>Identity &amp; Access</h2>
            <div class="controls">
                <button class="refresh-btn" onclick="loadIAM()" style="font-size:12px;">Refresh</button>
            </div>
        </div>
        <div style="padding:10px 16px;">
            <div class="controls" style="margin-bottom:12px;">
                <button class="refresh-btn" onclick="showIAMTab('users')" id="tab-users" style="font-size:12px;">Users</button>
                <button class="refresh-btn" onclick="showIAMTab('groups')" id="tab-groups" style="font-size:12px;opacity:0.6;">Groups</button>
                <button class="refresh-btn" onclick="showIAMTab('robots')" id="tab-robots" style="font-size:12px;opacity:0.6;">Service Accounts</button>
            </div>
            <div id="iam-content"><div class="empty">Loading identity data...</div></div>
        </div>
    </div>

    <div class="section">
        <div class="section-header">
            <h2>Recent Activity &amp; Audit Log</h2>
            <div class="controls">
                <select id="filter-type" onchange="filterTable()">
                    <option value="">All Events</option>
                    <option value="manifest.push">Pushes</option>
                    <option value="manifest.pull">Pulls</option>
                    <option value="manifest.delete">Deletes</option>
                    <option value="blob.push">Blob Push</option>
                    <option value="blob.pull">Blob Pull</option>
                </select>
                <input type="text" id="filter-user" placeholder="Filter by user..." oninput="filterTable()">
                <button class="refresh-btn" onclick="location.reload()">Refresh</button>
            </div>
        </div>
        <table id="audit-table">
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Event</th>
                    <th>User</th>
                    <th>Repository</th>
                    <th>Reference</th>
                    <th>Size</th>
                    <th>Latency</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
        {empty_msg}
    </div>

    <div class="section">
        <div class="section-header">
            <h2>API Endpoints</h2>
        </div>
        <table>
            <thead><tr><th>Endpoint</th><th>Description</th></tr></thead>
            <tbody>
                <tr><td><code>/metrics</code></td><td>Prometheus metrics (scrape target)</td></tr>
                <tr><td><code>/api/stats</code></td><td>Summary statistics JSON</td></tr>
                <tr><td><code>/api/system</code></td><td>System metrics (CPU, RAM, disk) JSON</td></tr>
                <tr><td><code>/api/ha-status</code></td><td>HA multi-region peer health JSON</td></tr>
                <tr><td><code>/api/images?q=search&amp;limit=200</code></td><td>Image browser with wildcard search</td></tr>
                <tr><td><code>/api/activity?limit=50&amp;type=manifest.push</code></td><td>Recent activity feed (filterable)</td></tr>
                <tr><td><code>/api/audit?limit=100&amp;subject=user</code></td><td>Full audit log (filterable)</td></tr>
                <tr><td><code>/api/users</code></td><td>Provisioned users (proxied from auth service)</td></tr>
                <tr><td><code>/api/groups</code></td><td>Group role mappings and active memberships</td></tr>
                <tr><td><code>/api/robot-accounts</code></td><td>Robot/service accounts list</td></tr>
                <tr><td><code>/dashboard</code></td><td>This dashboard</td></tr>
                <tr><td colspan="2" style="color:var(--text-muted);font-size:11px;padding-top:12px;"><strong>Auth Service Endpoints</strong></td></tr>
                <tr><td><code>POST /auth/credential-exchange</code></td><td>Exchange OIDC session for short-lived docker login credentials (for credential helpers)</td></tr>
                <tr><td><code>GET /auth/oidc/login</code></td><td>OIDC authorization code flow login redirect</td></tr>
                <tr><td><code>POST /auth/ci/token</code></td><td>Generic CI OIDC token exchange (GitHub, GitLab, k8s)</td></tr>
                <tr><td><code>POST /auth/token/refresh</code></td><td>Exchange refresh token for new access token</td></tr>
                <tr><td><code>POST /auth/token/revoke</code></td><td>Revoke a token by JTI</td></tr>
                <tr><td><code>POST /api/v1/robot-accounts</code></td><td>Create robot/service account</td></tr>
                <tr><td><code>POST /auth/audit/export</code></td><td>Export all audit events as JSONL</td></tr>
            </tbody>
        </table>
    </div>
</div>

<div class="modal-backdrop" id="image-modal" onclick="if(event.target===this)closeImageDetail()">
    <div class="modal" id="image-modal-content">
        <div class="modal-header">
            <h2 id="modal-title">Loading…<small id="modal-subtitle"></small></h2>
            <button class="modal-close" onclick="closeImageDetail()" title="Close (Esc)">×</button>
        </div>
        <div class="modal-body" id="modal-body">
            <div class="empty">Loading image details…</div>
        </div>
    </div>
</div>

<div class="footer">
    NebulaCR Registry v{version} (build {build_hash})
    &mdash; Prometheus endpoint at <a href="/metrics" style="color:var(--accent)">/metrics</a>
    &bull; Auto-refresh: <select onchange="setupAutoRefresh(this.value)" style="background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:4px;padding:2px;">
        <option value="0">Off</option>
        <option value="5">5s</option>
        <option value="15">15s</option>
        <option value="30" selected>30s</option>
        <option value="60">60s</option>
    </select>
</div>

<script>
let refreshTimer;
function setupAutoRefresh(sec) {{
    clearInterval(refreshTimer);
    if (sec > 0) refreshTimer = setInterval(() => location.reload(), sec * 1000);
}}
setupAutoRefresh(30);

// Image browser
let searchTimeout;
function searchImages() {{
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(doSearch, 300);
}}

async function doSearch() {{
    const q = document.getElementById('image-search').value.trim();
    const container = document.getElementById('image-results');
    container.innerHTML = '<div class="empty">Searching...</div>';
    try {{
        const url = q ? `/api/images?q=${{encodeURIComponent(q)}}&limit=200` : '/api/images?limit=200';
        const resp = await fetch(url);
        const data = await resp.json();
        if (data.total === 0) {{
            container.innerHTML = '<div class="empty">No images found.</div>';
            return;
        }}
        let totalSize = 0;
        data.images.forEach(img => totalSize += img.total_size_bytes);
        let html = `<table><thead><tr><th>Repository</th><th>Size</th><th>Blobs</th><th>Manifests</th><th>Tags</th><th>Last Pushed</th><th>Tag Names</th></tr></thead><tbody>`;
        for (const img of data.images) {{
            const tagBadges = img.tags.slice(0, 8).map(t =>
                `<span class="badge badge-push">${{t}}</span>`
            ).join(' ');
            const more = img.tags.length > 8 ? ` <span class="badge badge-other">+${{img.tags.length - 8}} more</span>` : '';
            const sizeClass = img.total_size_bytes > 1073741824 ? 'red' : img.total_size_bytes > 104857600 ? 'yellow' : 'green';
            const pushed = img.last_pushed || '-';
            const repoAttr = img.repository.replace(/"/g, '&quot;');
            html += `<tr class="clickable-row" onclick="openImageDetail('${{repoAttr}}')" title="Click to see all layers and per-tag breakdown"><td><strong>${{img.repository}}</strong><br><span style="font-size:11px;color:var(--text-muted)">${{img.tenant}} / ${{img.project}} / ${{img.name}}</span></td><td><span class="value ${{sizeClass}}" style="font-size:13px;font-weight:600">${{img.total_size}}</span></td><td>${{img.blob_count}}</td><td>${{img.manifest_count}}</td><td>${{img.tag_count}}</td><td style="font-size:12px;color:var(--text-muted);white-space:nowrap">${{pushed}}</td><td>${{tagBadges}}${{more}}</td></tr>`;
        }}
        html += `</tbody></table>`;
        const totalFormatted = totalSize >= 1073741824 ? (totalSize/1073741824).toFixed(1)+' GB' : totalSize >= 1048576 ? (totalSize/1048576).toFixed(1)+' MB' : totalSize >= 1024 ? (totalSize/1024).toFixed(1)+' KB' : totalSize+' B';
        html += `<div style="padding:10px 16px;color:var(--text-muted);font-size:12px;">Showing ${{data.total}} repositor${{data.total === 1 ? 'y' : 'ies'}} &middot; Total storage: ${{totalFormatted}}</div>`;
        container.innerHTML = html;
    }} catch(e) {{
        container.innerHTML = `<div class="empty">Error loading images: ${{e.message}}</div>`;
    }}
}}
// Load images on page load
doSearch();

// Identity & Access Management tabs
let currentIAMTab = 'users';
let iamData = {{}};

function showIAMTab(tab) {{
    currentIAMTab = tab;
    document.querySelectorAll('[id^=tab-]').forEach(b => b.style.opacity = '0.6');
    const btn = document.getElementById('tab-' + tab);
    if (btn) btn.style.opacity = '1';
    renderIAMTab();
}}

async function loadIAM() {{
    try {{
        const [usersResp, groupsResp, robotsResp] = await Promise.all([
            fetch('/api/users').then(r => r.json()).catch(() => []),
            fetch('/api/groups').then(r => r.json()).catch(() => ({{mappings:[], unmapped_groups:[]}})),
            fetch('/api/robot-accounts').then(r => r.json()).catch(() => []),
        ]);
        iamData.users = usersResp;
        iamData.groups = groupsResp;
        iamData.robots = robotsResp;
        renderIAMTab();
    }} catch(e) {{
        document.getElementById('iam-content').innerHTML = '<div class="empty">Failed to load identity data.</div>';
    }}
}}

function renderIAMTab() {{
    const container = document.getElementById('iam-content');
    if (currentIAMTab === 'users') {{
        const users = iamData.users || [];
        if (users.length === 0) {{
            container.innerHTML = '<div class="empty">No provisioned users yet. Users appear after OIDC login.</div>';
            return;
        }}
        let html = '<table><thead><tr><th>Subject</th><th>Email</th><th>Groups</th><th>Auth Method</th><th>Last Login</th><th>Logins</th></tr></thead><tbody>';
        for (const u of users) {{
            const groups = (u.groups || []).map(g => '<span class="badge badge-push">' + g + '</span>').join(' ');
            html += '<tr><td>' + u.subject + '</td><td>' + (u.email || '-') + '</td><td>' + (groups || '-') + '</td><td>' + u.auth_method + '</td><td>' + (u.last_login || '-') + '</td><td>' + u.login_count + '</td></tr>';
        }}
        html += '</tbody></table>';
        container.innerHTML = html;
    }} else if (currentIAMTab === 'groups') {{
        const data = iamData.groups || {{}};
        const mappings = data.mappings || [];
        const unmapped = data.unmapped_groups || [];
        if (mappings.length === 0 && unmapped.length === 0) {{
            container.innerHTML = '<div class="empty">No group mappings configured. Add group_role_mappings to enterprise config.</div>';
            return;
        }}
        let html = '<table><thead><tr><th>Group</th><th>Role</th><th>Tenant</th><th>Project</th><th>Members</th></tr></thead><tbody>';
        for (const m of mappings) {{
            html += '<tr><td>' + m.group + '</td><td><span class="badge badge-push">' + (m.role || 'N/A') + '</span></td><td>' + (m.tenant || '-') + '</td><td>' + (m.project || '*') + '</td><td>' + m.member_count + '</td></tr>';
        }}
        for (const m of unmapped) {{
            html += '<tr><td>' + m.group + '</td><td><span class="badge badge-other">unmapped</span></td><td>-</td><td>-</td><td>' + m.member_count + '</td></tr>';
        }}
        html += '</tbody></table>';
        container.innerHTML = html;
    }} else if (currentIAMTab === 'robots') {{
        const robots = iamData.robots || [];
        if (robots.length === 0) {{
            container.innerHTML = '<div class="empty">No service accounts. Create via POST /api/v1/robot-accounts.</div>';
            return;
        }}
        let html = '<table><thead><tr><th>Name</th><th>Tenant</th><th>Role</th><th>Last Used</th><th>Status</th><th>Expires</th></tr></thead><tbody>';
        for (const r of robots) {{
            const status = r.enabled ? '<span class="badge badge-green">Active</span>' : '<span class="badge badge-red">Disabled</span>';
            html += '<tr><td>' + r.name + '</td><td>' + r.tenant + '</td><td>' + JSON.stringify(r.role) + '</td><td>' + (r.last_used || 'Never') + '</td><td>' + status + '</td><td>' + (r.expires_at || 'Never') + '</td></tr>';
        }}
        html += '</tbody></table>';
        container.innerHTML = html;
    }}
}}

loadIAM();

// ── Image detail modal ──────────────────────────────────────────────
function escapeHtml(s) {{
    if (s == null) return '';
    return String(s)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}}
function fmtBytes(n) {{
    if (!n || n < 0) return '0 B';
    if (n >= 1099511627776) return (n/1099511627776).toFixed(1)+' TB';
    if (n >= 1073741824) return (n/1073741824).toFixed(1)+' GB';
    if (n >= 1048576) return (n/1048576).toFixed(1)+' MB';
    if (n >= 1024) return (n/1024).toFixed(1)+' KB';
    return n+' B';
}}

async function openImageDetail(repo) {{
    const modal = document.getElementById('image-modal');
    const body = document.getElementById('modal-body');
    const title = document.getElementById('modal-title');
    const subtitle = document.getElementById('modal-subtitle');
    title.textContent = repo;
    subtitle.textContent = 'Loading layer breakdown…';
    body.innerHTML = '<div class="empty">Reading manifests and computing layer topology…</div>';
    modal.classList.add('open');
    document.body.style.overflow = 'hidden';
    try {{
        const resp = await fetch('/api/image-detail?repo=' + encodeURIComponent(repo));
        if (!resp.ok) throw new Error('HTTP ' + resp.status);
        const d = await resp.json();
        renderImageDetail(d);
    }} catch (e) {{
        body.innerHTML = '<div class="empty">Failed to load details: ' + escapeHtml(e.message) + '</div>';
    }}
}}

function closeImageDetail() {{
    document.getElementById('image-modal').classList.remove('open');
    document.body.style.overflow = '';
}}

document.addEventListener('keydown', (e) => {{
    if (e.key === 'Escape') closeImageDetail();
}});

function renderImageDetail(d) {{
    document.getElementById('modal-title').innerHTML =
        escapeHtml(d.repository) + '<small>' + d.tag_count + ' tag(s) · ' + d.unique_layer_count + ' unique layer(s)</small>';
    document.getElementById('modal-subtitle').textContent = '';

    let html = '';

    // Plain-English explainer
    html += '<div class="explainer">' + escapeHtml(d.explanation) + '</div>';

    // Summary cards
    const savingsColor = d.savings_bytes > 0 ? 'green' : 'text-muted';
    html += '<div class="detail-grid">';
    html += '<div class="detail-card"><div class="label">On Disk (real cost)</div><div class="value yellow">' + escapeHtml(d.on_disk) + '</div><div class="sub">unique blobs only</div></div>';
    html += '<div class="detail-card"><div class="label">Naive Total</div><div class="value">' + escapeHtml(d.naive_total) + '</div><div class="sub">if every tag had its own copies</div></div>';
    html += '<div class="detail-card"><div class="label">Saved by Dedup</div><div class="value ' + savingsColor + '">' + escapeHtml(d.savings) + '</div><div class="sub">' + d.savings_percent.toFixed(1) + '% smaller</div></div>';
    html += '<div class="detail-card"><div class="label">Tags</div><div class="value accent">' + d.tag_count + '</div><div class="sub">click any to see its layers below</div></div>';
    html += '<div class="detail-card"><div class="label">Unique Layers</div><div class="value purple">' + d.unique_layer_count + '</div><div class="sub">de-duplicated count</div></div>';
    if (d.orphan_blob_count > 0) {{
        html += '<div class="detail-card"><div class="label">Orphan Blobs</div><div class="value red">' + d.orphan_blob_count + '</div><div class="sub">' + escapeHtml(d.orphan_blob_size) + ' reclaimable</div></div>';
    }}
    html += '</div>';

    // Tags table
    if (d.tags && d.tags.length > 0) {{
        html += '<h3 style="font-size:14px;margin:18px 0 8px;">Tags &mdash; what one <code>docker pull</code> would actually download</h3>';
        html += '<div class="topology" style="padding:0;"><table><thead><tr><th>Tag</th><th>Platform</th><th>Pull Size</th><th>Layers</th><th>Manifest Digest</th></tr></thead><tbody>';
        for (const t of d.tags) {{
            const sizeColor = t.image_size_bytes > 1073741824 ? 'red' : t.image_size_bytes > 104857600 ? 'yellow' : 'green';
            html += '<tr><td><strong>' + escapeHtml(t.display_name) + '</strong></td>'
                  + '<td style="color:var(--text-muted);font-size:12px;">' + escapeHtml(t.platform || '-') + '</td>'
                  + '<td><span class="value ' + sizeColor + '" style="font-size:13px;font-weight:600">' + escapeHtml(t.image_size) + '</span></td>'
                  + '<td>' + t.layer_count + '</td>'
                  + '<td style="font-family:monospace;font-size:11px;color:var(--text-muted);">' + escapeHtml(t.manifest_digest.substring(0, 19)) + '…</td></tr>';
        }}
        html += '</tbody></table></div>';
    }}

    // Layer bars (sorted by size, biggest first)
    if (d.layers && d.layers.length > 0) {{
        const maxSize = Math.max.apply(null, d.layers.map(l => l.size_bytes || 1));
        html += '<div class="topology"><h3>Layer Stack &mdash; biggest first</h3>'
              + '<div class="topology-help">Each bar is one unique layer in this repo. Width = relative size. <span style="color:var(--green)">Green</span> = shared by multiple tags (efficient). <span style="color:var(--accent)">Blue</span> = used by only one tag.</div>';
        for (const l of d.layers) {{
            const pct = maxSize > 0 ? Math.max(2, (l.size_bytes / maxSize) * 100) : 2;
            const cls = l.shared ? 'shared' : 'unique';
            const tagBadges = l.used_by_tags.map(t =>
                '<span class="badge badge-' + (l.shared ? 'green' : 'pull') + '">' + escapeHtml(t) + '</span>'
            ).join(' ');
            html += '<div class="layer-bar">'
                  + '<div class="layer-meta"><strong>' + escapeHtml(l.short_digest) + '</strong><span>' + escapeHtml(l.size) + ' &middot; used by ' + l.used_by_tags.length + ' tag(s)</span></div>'
                  + '<div class="layer-track"><div class="layer-fill ' + cls + '" style="width:' + pct.toFixed(1) + '%"></div></div>'
                  + '<div class="layer-tags">' + tagBadges + '</div></div>';
        }}
        html += '</div>';
    }}

    // Layer × Tag matrix (true topology view)
    if (d.layers && d.layers.length > 0 && d.tags && d.tags.length > 0 && d.tags.length <= 30) {{
        html += '<div class="topology"><h3>Layer ✕ Tag Topology</h3>'
              + '<div class="topology-help">Rows are unique layers, columns are tags. A filled cell means that tag uses that layer. Look for layers that span many columns &mdash; those are your dedup wins.</div>'
              + '<div class="matrix"><table><thead><tr><th class="layer-header">Layer</th><th class="size-col">Size</th>';
        for (const t of d.tags) {{
            html += '<th class="tag-header" title="' + escapeHtml(t.display_name) + '">' + escapeHtml(t.display_name) + '</th>';
        }}
        html += '</tr></thead><tbody>';
        for (const l of d.layers) {{
            const usedSet = new Set(l.used_by_tags);
            html += '<tr><td class="layer-header">' + escapeHtml(l.short_digest) + '</td><td class="size-col">' + escapeHtml(l.size) + '</td>';
            for (const t of d.tags) {{
                if (usedSet.has(t.display_name)) {{
                    html += '<td class="cell-on" title="' + escapeHtml(t.display_name) + ' uses this layer">●</td>';
                }} else {{
                    html += '<td class="cell-off">·</td>';
                }}
            }}
            html += '</tr>';
        }}
        html += '</tbody></table></div></div>';
    }} else if (d.tags && d.tags.length > 30) {{
        html += '<div class="warn-box">Layer ✕ Tag matrix hidden (too many tags to display compactly &mdash; ' + d.tags.length + ' columns).</div>';
    }}

    // Orphans
    if (d.orphans && d.orphans.length > 0) {{
        html += '<div class="warn-box"><strong>⚠ ' + d.orphan_blob_count + ' orphan blob(s) totalling ' + escapeHtml(d.orphan_blob_size) + '</strong> &mdash; these blobs exist on disk but no tag references them. They can be reclaimed by garbage collection.</div>';
        html += '<div class="topology" style="padding:0;"><table><thead><tr><th>Digest</th><th>Size</th></tr></thead><tbody>';
        for (const o of d.orphans.slice(0, 50)) {{
            html += '<tr><td style="font-family:monospace;font-size:11px;">' + escapeHtml(o.short_digest) + '</td><td>' + escapeHtml(o.size) + '</td></tr>';
        }}
        if (d.orphans.length > 50) {{
            html += '<tr><td colspan="2" style="text-align:center;color:var(--text-muted);font-size:11px;">… and ' + (d.orphans.length - 50) + ' more orphans</td></tr>';
        }}
        html += '</tbody></table></div>';
    }}

    document.getElementById('modal-body').innerHTML = html;
}}

function filterTable() {{
    const typeFilter = document.getElementById('filter-type').value.toLowerCase();
    const userFilter = document.getElementById('filter-user').value.toLowerCase();
    const rows = document.querySelectorAll('#audit-table tbody tr');
    rows.forEach(row => {{
        const eventType = row.cells[1]?.textContent.toLowerCase() || '';
        const user = row.cells[2]?.textContent.toLowerCase() || '';
        const showType = !typeFilter || eventType.includes(typeFilter);
        const showUser = !userFilter || user.includes(userFilter);
        row.style.display = (showType && showUser) ? '' : 'none';
    }});
}}
</script>
</body>
</html>"#,
        uptime_display = format_uptime(uptime),
        // System metrics
        cpu_usage = sys_metrics.cpu_usage_percent,
        cpu_count = sys_metrics.cpu_count,
        cpu_color = usage_color_class(sys_metrics.cpu_usage_percent),
        cpu_bar_color = usage_bar_color(sys_metrics.cpu_usage_percent),
        ram_used = format_bytes(sys_metrics.memory_used_bytes),
        ram_total = format_bytes(sys_metrics.memory_total_bytes),
        ram_usage_pct = sys_metrics.memory_usage_percent,
        ram_color = usage_color_class(sys_metrics.memory_usage_percent),
        ram_bar_color = usage_bar_color(sys_metrics.memory_usage_percent),
        disk_avail = disk_avail_display,
        disk_usage_pct = disk_usage_pct,
        disk_color = usage_color_class(disk_usage_pct),
        disk_bar_color = usage_bar_color(disk_usage_pct),
        // HA status
        ha_color = if !ha_enabled {
            "text-muted"
        } else if ha_regions.iter().all(|r| r.healthy) {
            "green"
        } else if ha_regions.iter().any(|r| r.healthy) {
            "yellow"
        } else {
            "red"
        },
        ha_display = if !ha_enabled {
            "N/A".to_string()
        } else {
            let healthy = ha_regions.iter().filter(|r| r.healthy).count();
            let total = ha_regions.len();
            format!("{healthy}/{total}")
        },
        ha_sub = if !ha_enabled {
            "Not configured".to_string()
        } else if ha_local_primary {
            "Primary node".to_string()
        } else {
            "Secondary node".to_string()
        },
        ha_section = ha_section,
        // Registry stats
        total_pushes = stats.total_pushes,
        total_pulls = stats.total_pulls,
        total_deletes = stats.total_deletes,
        total_push_bytes = format_bytes(stats.total_push_bytes),
        avg_latency = stats.avg_latency_ms,
        total_events = stats.total_events,
        rows = rows,
        empty_msg = if recent.is_empty() {
            r#"<div class="empty">No activity yet. Push an image to see it here.</div>"#
        } else {
            ""
        },
        version = env!("CARGO_PKG_VERSION"),
        build_hash = option_env!("NEBULACR_BUILD_HASH").unwrap_or("dev"),
    );

    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        )],
        Html(html),
    )
        .into_response()
}

fn usage_color_class(pct: f32) -> &'static str {
    if pct >= 90.0 {
        "red"
    } else if pct >= 70.0 {
        "yellow"
    } else {
        "green"
    }
}

fn usage_bar_color(pct: f32) -> &'static str {
    if pct >= 90.0 {
        "fill-red"
    } else if pct >= 70.0 {
        "fill-yellow"
    } else {
        "fill-green"
    }
}

fn event_badge_class(event_type: &str) -> &'static str {
    if event_type.contains("push") {
        "push"
    } else if event_type.contains("pull") {
        "pull"
    } else if event_type.contains("delete") {
        "delete"
    } else {
        "other"
    }
}

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    const TB: u64 = 1024 * GB;

    if bytes >= TB {
        format!("{:.1} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

fn format_uptime(secs: u64) -> String {
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let minutes = (secs % 3600) / 60;
    if days > 0 {
        format!("{days}d {hours}h {minutes}m")
    } else if hours > 0 {
        format!("{hours}h {minutes}m")
    } else {
        format!("{minutes}m")
    }
}

#[cfg(test)]
mod image_detail_tests {
    use super::*;

    #[test]
    fn short_digest_truncates_long_hex() {
        let d = short_digest(
            "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        );
        assert_eq!(d, "sha256:abcdef123456");
    }

    #[test]
    fn short_digest_handles_missing_prefix() {
        let d = short_digest(
            "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        );
        assert_eq!(d, "sha256:abcdef123456");
    }

    #[test]
    fn short_digest_handles_input_shorter_than_12() {
        assert_eq!(short_digest("sha256:abc"), "sha256:abc");
        assert_eq!(short_digest(""), "sha256:");
    }

    #[test]
    fn build_explanation_empty_repo_mentions_no_tags() {
        let s = build_explanation(0, 0, 0, 0, 0, 0, 0);
        assert!(s.contains("no tags"));
    }

    #[test]
    fn build_explanation_singular_grammar() {
        let s = build_explanation(1, 1, 10, 10, 0, 0, 0);
        assert!(s.contains("1 tag sharing"));
        assert!(s.contains("1 unique layer."));
        assert!(!s.contains("smaller than the naive total"));
    }

    #[test]
    fn build_explanation_reports_savings_and_orphans() {
        let mb = 1024 * 1024;
        let s = build_explanation(3, 5, 100 * mb, 300 * mb, 200 * mb, 2, 50 * mb);
        assert!(s.contains("3 tags"));
        assert!(s.contains("5 unique layers"));
        assert!(s.contains("100.0 MB"));
        assert!(s.contains("300.0 MB"));
        assert!(s.contains("200.0 MB"));
        // 200/300 rounds to 67
        assert!(s.contains("(67% smaller"));
        assert!(s.contains("2 blob(s)"));
        assert!(s.contains("50.0 MB"));
    }

    #[test]
    fn parse_single_manifest_extracts_config_and_layers() {
        let cfg = "sha256:cfgcfgcfgcfgcfgcfgcfgcfgcfgcfgcfgcfgcfgcfgcfgcfgcfgcfgcfgcfgcf01";
        let l1 = "sha256:layer1layer1layer1layer1layer1layer1layer1layer1layer1layer1aa";
        let l2 = "sha256:layer2layer2layer2layer2layer2layer2layer2layer2layer2layer2bb";

        let manifest = serde_json::json!({
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": { "digest": cfg, "size": 1500 },
            "layers": [
                { "digest": l1, "size": 1_000_000 },
                { "digest": l2, "size": 2_000_000 }
            ]
        });
        let bytes = serde_json::to_vec(&manifest).unwrap();

        // On-disk size for l1 differs from manifest-declared size; l2 missing
        // from blob_sizes so code should fall back to the manifest number.
        let mut blob_sizes: HashMap<String, u64> = HashMap::new();
        blob_sizes.insert(l1.to_string(), 1_100_000);

        let mut tags: Vec<TagDetail> = Vec::new();
        let mut layer_to_tags: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut referenced: BTreeSet<String> = BTreeSet::new();

        parse_single_manifest(
            "latest",
            "latest",
            "sha256:manifestdigest",
            &bytes,
            None,
            &blob_sizes,
            &mut tags,
            &mut layer_to_tags,
            &mut referenced,
        );

        assert_eq!(tags.len(), 1);
        let tag = &tags[0];
        assert_eq!(tag.tag, "latest");
        assert_eq!(tag.layer_count, 2);
        assert_eq!(tag.config_size_bytes, 1500);
        // authoritative l1 + manifest-declared l2 + config
        assert_eq!(tag.image_size_bytes, 1_100_000 + 2_000_000 + 1500);

        assert_eq!(referenced.len(), 3, "config + two layers should be referenced");
        assert!(referenced.contains(cfg));
        assert!(referenced.contains(l1));
        assert!(referenced.contains(l2));

        assert_eq!(layer_to_tags.len(), 2);
        assert!(layer_to_tags[l1].contains("latest"));
        assert!(layer_to_tags[l2].contains("latest"));
    }

    #[test]
    fn parse_single_manifest_records_fan_out_across_tags() {
        let shared_layer =
            "sha256:sharedsharedsharedsharedsharedsharedsharedsharedsharedsharedaa";
        let make_manifest = |cfg_digest: &str| {
            serde_json::to_vec(&serde_json::json!({
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": { "digest": cfg_digest, "size": 100 },
                "layers": [{ "digest": shared_layer, "size": 500 }]
            }))
            .unwrap()
        };

        let mut tags: Vec<TagDetail> = Vec::new();
        let mut layer_to_tags: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut referenced: BTreeSet<String> = BTreeSet::new();
        let blob_sizes: HashMap<String, u64> = HashMap::new();

        for tag in ["v1", "v2", "latest"] {
            let bytes = make_manifest("sha256:cfgcfgcfgcfgcfgcfgcfgcfgcfgcfgcfgcfgcfgcfgcfgcfgcfgcfgcfgcfgcf01");
            parse_single_manifest(
                tag,
                tag,
                "sha256:mdigest",
                &bytes,
                None,
                &blob_sizes,
                &mut tags,
                &mut layer_to_tags,
                &mut referenced,
            );
        }

        assert_eq!(tags.len(), 3);
        let used_by = &layer_to_tags[shared_layer];
        assert_eq!(used_by.len(), 3);
        assert!(used_by.contains("v1"));
        assert!(used_by.contains("v2"));
        assert!(used_by.contains("latest"));
    }

    #[test]
    fn parse_single_manifest_ignores_invalid_json() {
        let mut tags: Vec<TagDetail> = Vec::new();
        let mut layer_to_tags: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut referenced: BTreeSet<String> = BTreeSet::new();

        parse_single_manifest(
            "broken",
            "broken",
            "sha256:x",
            b"this is not json",
            None,
            &HashMap::new(),
            &mut tags,
            &mut layer_to_tags,
            &mut referenced,
        );

        assert!(tags.is_empty());
        assert!(layer_to_tags.is_empty());
        assert!(referenced.is_empty());
    }
}
