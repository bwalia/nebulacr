//! Tests for the mirror isolation fix.
//!
//! These cover the behaviour matrix described in R1–R7 of the fix:
//!
//!   T1: local-hit pull returns Ok with content (regression guard).
//!   T2: miss on a private project NEVER touches the upstream path.
//!   T3: miss on a mirror-eligible scope, all upstreams 404 -> NotFound.
//!   T4: miss on a mirror-eligible scope, all upstreams 5xx     -> NotFound
//!       (i.e. domain-level "not present anywhere," NOT a bubbled 502).
//!   T5: miss on a mirror-eligible scope, breaker pre-opened    -> NotFound.
//!   T6: real storage IO errors still surface (tested at the handler
//!       level — see the is_store_not_found helper in nebula-registry).
//!   T7: miss on a mirror-eligible scope with a reachable upstream
//!       returns Ok and populates the local cache.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use bytes::Bytes;
use nebula_common::storage::blob_path;
use nebula_mirror::service::{MirrorConfig, MirrorScope};
use nebula_mirror::upstream::{UpstreamConfig, UpstreamError};
use nebula_mirror::{MirrorError, MirrorService};
use object_store::memory::InMemory;
use object_store::{ObjectStore, path::Path as StorePath};

// ── Scope-level unit tests ──────────────────────────────────────────────────

#[test]
fn scope_default_tenant_only_rejects_private_projects() {
    let scope = MirrorScope::DefaultTenantOnly {
        default_tenant: "_".to_string(),
    };
    assert!(scope.tenant_project_eligible("_", "library"));
    assert!(!scope.tenant_project_eligible("diytaxreturn", "diy-tax-return-frontend"));
    assert!(!scope.tenant_project_eligible("acme", "web"));
}

#[test]
fn scope_allowlist_matches_tenant_or_tenant_project() {
    let scope = MirrorScope::Allowlist {
        tenants: vec!["_".to_string()],
        projects: vec!["public-proxy/library".to_string()],
    };
    assert!(scope.tenant_project_eligible("_", "anything"));
    assert!(scope.tenant_project_eligible("public-proxy", "library"));
    assert!(!scope.tenant_project_eligible("public-proxy", "other"));
    assert!(!scope.tenant_project_eligible("private", "app"));
}

#[test]
fn scope_denylist_excludes_listed_tenants() {
    let scope = MirrorScope::Denylist {
        tenants: vec!["private-a".to_string()],
        projects: vec!["shared/secret-app".to_string()],
    };
    assert!(scope.tenant_project_eligible("_", "library"));
    assert!(!scope.tenant_project_eligible("private-a", "whatever"));
    assert!(!scope.tenant_project_eligible("shared", "secret-app"));
    assert!(scope.tenant_project_eligible("shared", "other-app"));
}

#[test]
fn scope_all_accepts_everything() {
    let scope = MirrorScope::All;
    assert!(scope.tenant_project_eligible("_", "library"));
    assert!(scope.tenant_project_eligible("private", "whatever"));
}

// ── Error-classification unit tests ─────────────────────────────────────────

#[test]
fn mirror_error_breaker_open_is_not_found_equivalent() {
    let err = MirrorError::Upstream(UpstreamError::CircuitBreakerOpen {
        name: "docker.io".into(),
    });
    assert!(
        err.is_not_found_equivalent(),
        "breaker-open must collapse to NotFound at the HTTP layer (R2)"
    );
}

#[test]
fn mirror_error_upstream_5xx_is_not_found_equivalent() {
    let err = MirrorError::Upstream(UpstreamError::Http {
        status: 503,
        body: "svc unavailable".into(),
    });
    assert!(
        err.is_not_found_equivalent(),
        "upstream 5xx must not bubble up as a 502 on the blob miss path (R4)"
    );
}

#[test]
fn mirror_error_upstream_blob_not_found_is_not_found_equivalent() {
    let err = MirrorError::Upstream(UpstreamError::BlobNotFound {
        digest: "sha256:0".into(),
    });
    assert!(err.is_not_found_equivalent());
}

#[test]
fn mirror_error_not_in_scope_is_not_found_equivalent() {
    assert!(MirrorError::NotInScope.is_not_found_equivalent());
}

#[test]
fn mirror_error_not_found_on_any_upstream_is_not_found_equivalent() {
    assert!(MirrorError::NotFoundOnAnyUpstream.is_not_found_equivalent());
}

#[test]
fn mirror_error_auth_failure_is_not_collapsed() {
    let err = MirrorError::Upstream(UpstreamError::Auth("bad token".into()));
    assert!(
        !err.is_not_found_equivalent(),
        "auth failures are real backend errors and must remain 5xx"
    );
}

// ── Integration tests against a mock upstream ──────────────────────────────

#[derive(Clone)]
struct MockState {
    behaviour: MockBehaviour,
    hits: Arc<AtomicUsize>,
}

#[derive(Copy, Clone)]
enum MockBehaviour {
    NotFound,
    ServerError,
    Ok(&'static [u8]),
}

async fn mock_blob_handler(State(state): State<MockState>) -> axum::response::Response {
    state.hits.fetch_add(1, Ordering::SeqCst);
    match state.behaviour {
        MockBehaviour::NotFound => (StatusCode::NOT_FOUND, "not found").into_response(),
        MockBehaviour::ServerError => (StatusCode::BAD_GATEWAY, "upstream down").into_response(),
        MockBehaviour::Ok(bytes) => (StatusCode::OK, bytes).into_response(),
    }
}

/// Spawn a minimal axum server that serves OCI blob responses with a
/// configurable behaviour. Returns the base URL and a shared counter
/// of the number of requests received — used to assert that the
/// upstream path was NEVER called for private-project requests.
async fn spawn_upstream(behaviour: MockBehaviour) -> (String, Arc<AtomicUsize>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let state = MockState {
        behaviour,
        hits: hits.clone(),
    };

    let app: Router = Router::new()
        .route("/v2/{project}/{name}/blobs/{digest}", get(mock_blob_handler))
        .route("/v2/", get(|| async { StatusCode::OK }))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (format!("http://{}", addr), hits)
}

fn mirror_config_with(
    upstream_url: &str,
    scope: MirrorScope,
) -> (MirrorConfig, Arc<dyn ObjectStore>) {
    let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
    let cfg = MirrorConfig {
        enabled: true,
        upstreams: vec![UpstreamConfig {
            name: "mock".into(),
            url: upstream_url.into(),
            username: None,
            password: None,
            cache_ttl_secs: 60,
            tenant_prefix: None,
        }],
        cache_ttl_secs: 60,
        scope,
    };
    (cfg, store)
}

// T1 (regression): happy pull through the mirror returns Ok and
// populates the local cache.
#[tokio::test]
async fn t7_pullthrough_success_caches_locally() {
    let payload: &'static [u8] = b"hello world blob";
    let (url, hits) = spawn_upstream(MockBehaviour::Ok(payload)).await;

    // Default scope is DefaultTenantOnly{_} so tenant="_" is eligible.
    let (cfg, store) = mirror_config_with(&url, MirrorScope::default());
    let svc = MirrorService::new(&cfg, store.clone());

    let result = svc
        .fetch_blob("_", "library", "alpine", "sha256:abc")
        .await
        .expect("pullthrough should succeed");
    assert_eq!(result.data.as_ref(), payload);
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    // Local cache populated at the correct path.
    let cached = store
        .get(&StorePath::from(blob_path(
            "_", "library", "alpine", "sha256:abc",
        )))
        .await
        .expect("blob must be cached locally")
        .bytes()
        .await
        .unwrap();
    assert_eq!(cached, Bytes::from_static(payload));
}

// T2: private-project miss MUST NOT touch the upstream path at all.
#[tokio::test]
async fn t2_private_project_skips_upstream_entirely() {
    // An upstream that WOULD return 404 if called — but it must not be called.
    let (url, hits) = spawn_upstream(MockBehaviour::NotFound).await;

    let (cfg, store) = mirror_config_with(
        &url,
        MirrorScope::DefaultTenantOnly {
            default_tenant: "_".into(),
        },
    );
    let svc = MirrorService::new(&cfg, store);

    let err = svc
        .fetch_blob(
            "diytaxreturn",
            "diy-tax-return-frontend",
            "latest",
            "sha256:b984351d",
        )
        .await
        .expect_err("private project must not hit upstream");

    assert!(matches!(err, MirrorError::NotInScope));
    assert!(err.is_not_found_equivalent());
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "upstream must NEVER be contacted for private-project blob probes"
    );
}

// T3: mirror-eligible project, every upstream returns 404 -> NotFound.
#[tokio::test]
async fn t3_eligible_all_upstreams_404_returns_not_found() {
    let (url, hits) = spawn_upstream(MockBehaviour::NotFound).await;

    let (cfg, store) = mirror_config_with(&url, MirrorScope::default());
    let svc = MirrorService::new(&cfg, store);

    let err = svc
        .fetch_blob("_", "library", "alpine", "sha256:missing")
        .await
        .expect_err("should fail");

    assert!(
        err.is_not_found_equivalent(),
        "all-upstreams-404 must collapse to NotFound, not bubble as 5xx"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

// T4: mirror-eligible project, upstream returns 5xx (network-level
// failure) -> domain is still NotFound, NOT 502.
#[tokio::test]
async fn t4_eligible_upstream_5xx_returns_not_found() {
    let (url, hits) = spawn_upstream(MockBehaviour::ServerError).await;

    let (cfg, store) = mirror_config_with(&url, MirrorScope::default());
    let svc = MirrorService::new(&cfg, store);

    let err = svc
        .fetch_blob("_", "library", "alpine", "sha256:crash")
        .await
        .expect_err("should fail");

    assert!(
        err.is_not_found_equivalent(),
        "upstream 5xx must not bubble as UpstreamError; breaker state is internal (R2/R4)"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

// T5: mirror-eligible project, circuit breaker forcibly pre-opened for
// every upstream -> returns NotFound. This is the exact production
// regression scenario.
#[tokio::test]
async fn t5_eligible_breaker_open_returns_not_found() {
    // Upstream would serve 200 if called, but we pre-open the breaker
    // by giving it a bogus URL and then invoking fetch_blob 5 times.
    // To keep the test deterministic, point at an unused TCP port —
    // every attempt will fail quickly and trip the 5-failure breaker.
    let unused_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = unused_listener.local_addr().unwrap();
    drop(unused_listener); // port is now free; nothing listening
    let dead_url = format!("http://{}", addr);

    let (cfg, store) = mirror_config_with(&dead_url, MirrorScope::default());
    let svc = MirrorService::new(&cfg, store);

    // Trip the breaker. Five consecutive failures is the configured
    // threshold in UpstreamClient::new. After the 5th call the breaker
    // is open, and the 6th call gets rejected internally with
    // CircuitBreakerOpen — which is_not_found_equivalent()==true.
    for _ in 0..5 {
        let _ = svc
            .fetch_blob("_", "library", "alpine", "sha256:xxx")
            .await;
    }

    let err = svc
        .fetch_blob("_", "library", "alpine", "sha256:xxx")
        .await
        .expect_err("breaker should be open");

    assert!(
        err.is_not_found_equivalent(),
        "breaker-open MUST collapse to NotFound — this is the production 502 regression"
    );
}
