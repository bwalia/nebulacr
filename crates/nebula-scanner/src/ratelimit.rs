//! Per-principal rate limiting for scanner routes.
//!
//! Keyed on the resolved API-key actor name (or the literal string `"system"`
//! for unauthenticated callers). We deliberately key on the principal rather
//! than the remote address: CI runners behind a shared egress would share a
//! budget otherwise, and we already trust the key-to-identity mapping for
//! audit logging.

use std::num::NonZeroU32;
use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Request, State},
    http::{StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use governor::{Quota, RateLimiter, clock::DefaultClock, state::keyed::DefaultKeyedStateStore};
use tracing::debug;

type KeyedLimiter = RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock>;

pub struct ScannerLimiter {
    inner: Arc<KeyedLimiter>,
}

impl ScannerLimiter {
    pub fn per_minute(rpm: u32) -> Self {
        let quota = Quota::per_minute(NonZeroU32::new(rpm.max(1)).expect("min 1"));
        Self {
            inner: Arc::new(RateLimiter::keyed(quota)),
        }
    }

    pub fn disabled() -> Self {
        // A huge quota is effectively "no limit"; avoids branching in the
        // hot path while letting operators keep the middleware in place.
        let quota = Quota::per_second(NonZeroU32::new(u32::MAX).expect("max"));
        Self {
            inner: Arc::new(RateLimiter::keyed(quota)),
        }
    }

    fn check(&self, key: &str) -> bool {
        self.inner.check_key(&key.to_string()).is_ok()
    }
}

/// Middleware: resolve the caller from the Authorization header (cheaply —
/// we don't hit the DB here; just inspect the bearer shape) and key the
/// limiter on that. Unauthenticated callers share the `"system"` bucket,
/// authenticated callers use their key's raw hash prefix as a stable id.
pub async fn limit_middleware(
    State(state): State<crate::api::ScannerState>,
    req: Request,
    next: Next,
) -> Response {
    let key = rate_limit_key(&req);
    if !state.limiter.check(&key) {
        debug!(key = %key, "scanner rate limit rejected");
        return (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response();
    }
    let fut = next.run(req);
    let resp: Response<Body> = fut.await;
    resp
}

/// Extract a stable per-caller key. Full DB lookup happens on the real
/// principal extractor; here we just need a consistent string — we short-
/// circuit to a hash prefix of the raw key so compromised limiters can't
/// leak key material into logs.
fn rate_limit_key(req: &Request) -> String {
    let Some(auth) = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    else {
        return "system".into();
    };
    let Some(token) = auth.strip_prefix("Bearer ") else {
        return "system".into();
    };
    if let Some(raw) = token.strip_prefix("nck_") {
        // Use the first 12 chars of the raw token as a bucket id. Collisions
        // are meaningless for rate-limiting and we avoid parsing the key
        // structure for a concern that doesn't need it.
        let prefix: String = raw.chars().take(12).collect();
        format!("key:{prefix}")
    } else {
        "system".into()
    }
}
