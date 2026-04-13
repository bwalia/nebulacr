use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use futures::stream::BoxStream;
use metrics::{counter, histogram};
use object_store::{
    GetOptions, GetResult, ListResult, MultipartUpload, ObjectMeta, ObjectStore, PutMultipartOpts,
    PutOptions, PutPayload, PutResult, Result as OsResult, path::Path as StorePath,
};
use tracing::debug;

use crate::circuit_breaker::{CircuitBreaker, CircuitBreakerCallError, CircuitBreakerConfig};
use crate::retry::RetryPolicy;

fn record_storage_outcome(operation: &'static str, started: Instant, ok: bool) {
    let elapsed = started.elapsed().as_secs_f64();
    histogram!("nebulacr_storage_operation_duration_seconds", "operation" => operation)
        .record(elapsed);
    if ok {
        counter!("nebulacr_storage_operations_total",
            "operation" => operation, "outcome" => "success")
        .increment(1);
    } else {
        counter!("nebulacr_storage_operations_total",
            "operation" => operation, "outcome" => "error")
        .increment(1);
        counter!("nebulacr_storage_operation_errors_total", "operation" => operation).increment(1);
    }
}

/// An ObjectStore wrapper that adds retry logic and circuit breaker protection.
pub struct ResilientObjectStore {
    inner: Arc<dyn ObjectStore>,
    retry_policy: RetryPolicy,
    circuit_breaker: CircuitBreaker,
}

impl std::fmt::Debug for ResilientObjectStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResilientObjectStore").finish()
    }
}

impl ResilientObjectStore {
    pub fn new(
        inner: Arc<dyn ObjectStore>,
        retry_policy: RetryPolicy,
        circuit_breaker_config: CircuitBreakerConfig,
    ) -> Self {
        Self {
            inner,
            retry_policy,
            circuit_breaker: CircuitBreaker::new("storage", circuit_breaker_config),
        }
    }

    fn map_cb_err(err: CircuitBreakerCallError<object_store::Error>) -> object_store::Error {
        match err {
            CircuitBreakerCallError::BreakerOpen(e) => object_store::Error::Generic {
                store: "resilient",
                source: Box::new(e),
            },
            CircuitBreakerCallError::Inner(e) => e,
        }
    }
}

impl std::fmt::Display for ResilientObjectStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ResilientObjectStore({})", self.inner)
    }
}

#[async_trait::async_trait]
impl ObjectStore for ResilientObjectStore {
    async fn put(&self, location: &StorePath, payload: PutPayload) -> OsResult<PutResult> {
        let started = Instant::now();
        let location = location.clone();
        let inner = self.inner.clone();
        let payload_bytes: Bytes = payload.into();

        let result = self
            .circuit_breaker
            .call(|| {
                let inner = inner.clone();
                let loc = location.clone();
                let data = payload_bytes.clone();
                self.retry_policy.execute_labeled("put", move || {
                    let inner = inner.clone();
                    let loc = loc.clone();
                    let data = data.clone();
                    async move { inner.put(&loc, PutPayload::from(data)).await }
                })
            })
            .await;

        record_storage_outcome("put", started, result.is_ok());
        match result {
            Ok(inner_result) => Ok(inner_result),
            Err(e) => Err(Self::map_cb_err(e)),
        }
    }

    async fn put_opts(
        &self,
        location: &StorePath,
        payload: PutPayload,
        opts: PutOptions,
    ) -> OsResult<PutResult> {
        let started = Instant::now();
        let location = location.clone();
        let inner = self.inner.clone();
        let payload_bytes: Bytes = payload.into();

        let result = self
            .circuit_breaker
            .call(|| {
                let inner = inner.clone();
                let loc = location.clone();
                let data = payload_bytes.clone();
                let opts = opts.clone();
                self.retry_policy.execute_labeled("put_opts", move || {
                    let inner = inner.clone();
                    let loc = loc.clone();
                    let data = data.clone();
                    let opts = opts.clone();
                    async move { inner.put_opts(&loc, PutPayload::from(data), opts).await }
                })
            })
            .await;

        record_storage_outcome("put_opts", started, result.is_ok());
        match result {
            Ok(inner_result) => Ok(inner_result),
            Err(e) => Err(Self::map_cb_err(e)),
        }
    }

    async fn put_multipart(&self, location: &StorePath) -> OsResult<Box<dyn MultipartUpload>> {
        debug!(location = %location, "Delegating multipart upload (no retry)");
        self.inner.put_multipart(location).await
    }

    async fn put_multipart_opts(
        &self,
        location: &StorePath,
        opts: PutMultipartOpts,
    ) -> OsResult<Box<dyn MultipartUpload>> {
        debug!(location = %location, "Delegating multipart upload with opts (no retry)");
        self.inner.put_multipart_opts(location, opts).await
    }

    async fn get(&self, location: &StorePath) -> OsResult<GetResult> {
        let started = Instant::now();
        let location = location.clone();
        let inner = self.inner.clone();

        let result = self
            .circuit_breaker
            .call(|| {
                let inner = inner.clone();
                let loc = location.clone();
                self.retry_policy.execute_labeled("get", move || {
                    let inner = inner.clone();
                    let loc = loc.clone();
                    async move { inner.get(&loc).await }
                })
            })
            .await;

        record_storage_outcome("get", started, result.is_ok());
        match result {
            Ok(inner_result) => Ok(inner_result),
            Err(e) => Err(Self::map_cb_err(e)),
        }
    }

    async fn get_opts(&self, location: &StorePath, options: GetOptions) -> OsResult<GetResult> {
        let started = Instant::now();
        let location = location.clone();
        let inner = self.inner.clone();

        let result = self
            .circuit_breaker
            .call(|| {
                let inner = inner.clone();
                let loc = location.clone();
                let opts = options.clone();
                self.retry_policy.execute_labeled("get_opts", move || {
                    let inner = inner.clone();
                    let loc = loc.clone();
                    let opts = opts.clone();
                    async move { inner.get_opts(&loc, opts).await }
                })
            })
            .await;

        record_storage_outcome("get_opts", started, result.is_ok());
        match result {
            Ok(inner_result) => Ok(inner_result),
            Err(e) => Err(Self::map_cb_err(e)),
        }
    }

    async fn head(&self, location: &StorePath) -> OsResult<ObjectMeta> {
        let started = Instant::now();
        let location = location.clone();
        let inner = self.inner.clone();

        let result = self
            .circuit_breaker
            .call(|| {
                let inner = inner.clone();
                let loc = location.clone();
                self.retry_policy.execute_labeled("head", move || {
                    let inner = inner.clone();
                    let loc = loc.clone();
                    async move { inner.head(&loc).await }
                })
            })
            .await;

        record_storage_outcome("head", started, result.is_ok());
        match result {
            Ok(inner_result) => Ok(inner_result),
            Err(e) => Err(Self::map_cb_err(e)),
        }
    }

    async fn delete(&self, location: &StorePath) -> OsResult<()> {
        let started = Instant::now();
        let location = location.clone();
        let inner = self.inner.clone();

        let result = self
            .circuit_breaker
            .call(|| {
                let inner = inner.clone();
                let loc = location.clone();
                self.retry_policy.execute_labeled("delete", move || {
                    let inner = inner.clone();
                    let loc = loc.clone();
                    async move { inner.delete(&loc).await }
                })
            })
            .await;

        record_storage_outcome("delete", started, result.is_ok());
        match result {
            Ok(inner_result) => Ok(inner_result),
            Err(e) => Err(Self::map_cb_err(e)),
        }
    }

    fn list(&self, prefix: Option<&StorePath>) -> BoxStream<'_, OsResult<ObjectMeta>> {
        self.inner.list(prefix)
    }

    async fn list_with_delimiter(&self, prefix: Option<&StorePath>) -> OsResult<ListResult> {
        let started = Instant::now();
        let prefix_owned = prefix.cloned();
        let inner = self.inner.clone();

        let result = self
            .circuit_breaker
            .call(|| {
                let inner = inner.clone();
                let p = prefix_owned.clone();
                self.retry_policy.execute_labeled("list", move || {
                    let inner = inner.clone();
                    let p = p.clone();
                    async move { inner.list_with_delimiter(p.as_ref()).await }
                })
            })
            .await;

        record_storage_outcome("list", started, result.is_ok());
        match result {
            Ok(inner_result) => Ok(inner_result),
            Err(e) => Err(Self::map_cb_err(e)),
        }
    }

    async fn copy(&self, from: &StorePath, to: &StorePath) -> OsResult<()> {
        self.inner.copy(from, to).await
    }

    async fn copy_if_not_exists(&self, from: &StorePath, to: &StorePath) -> OsResult<()> {
        self.inner.copy_if_not_exists(from, to).await
    }
}
