use std::sync::Arc;

use bytes::Bytes;
use futures::stream::BoxStream;
use object_store::{
    GetOptions, GetResult, ListResult, MultipartUpload, ObjectMeta, ObjectStore, PutMultipartOpts,
    PutOptions, PutPayload, PutResult, Result as OsResult, path::Path as StorePath,
};
use tracing::debug;

use crate::circuit_breaker::{CircuitBreaker, CircuitBreakerCallError, CircuitBreakerConfig};
use crate::retry::RetryPolicy;

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
        let location = location.clone();
        let inner = self.inner.clone();
        let payload_bytes: Bytes = payload.into();

        let result = self
            .circuit_breaker
            .call(|| {
                let inner = inner.clone();
                let loc = location.clone();
                let data = payload_bytes.clone();
                self.retry_policy.execute(move || {
                    let inner = inner.clone();
                    let loc = loc.clone();
                    let data = data.clone();
                    async move { inner.put(&loc, PutPayload::from(data)).await }
                })
            })
            .await;

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
                self.retry_policy.execute(move || {
                    let inner = inner.clone();
                    let loc = loc.clone();
                    let data = data.clone();
                    let opts = opts.clone();
                    async move { inner.put_opts(&loc, PutPayload::from(data), opts).await }
                })
            })
            .await;

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
        let location = location.clone();
        let inner = self.inner.clone();

        let result = self
            .circuit_breaker
            .call(|| {
                let inner = inner.clone();
                let loc = location.clone();
                self.retry_policy.execute(move || {
                    let inner = inner.clone();
                    let loc = loc.clone();
                    async move { inner.get(&loc).await }
                })
            })
            .await;

        match result {
            Ok(inner_result) => Ok(inner_result),
            Err(e) => Err(Self::map_cb_err(e)),
        }
    }

    async fn get_opts(&self, location: &StorePath, options: GetOptions) -> OsResult<GetResult> {
        let location = location.clone();
        let inner = self.inner.clone();

        let result = self
            .circuit_breaker
            .call(|| {
                let inner = inner.clone();
                let loc = location.clone();
                let opts = options.clone();
                self.retry_policy.execute(move || {
                    let inner = inner.clone();
                    let loc = loc.clone();
                    let opts = opts.clone();
                    async move { inner.get_opts(&loc, opts).await }
                })
            })
            .await;

        match result {
            Ok(inner_result) => Ok(inner_result),
            Err(e) => Err(Self::map_cb_err(e)),
        }
    }

    async fn head(&self, location: &StorePath) -> OsResult<ObjectMeta> {
        let location = location.clone();
        let inner = self.inner.clone();

        let result = self
            .circuit_breaker
            .call(|| {
                let inner = inner.clone();
                let loc = location.clone();
                self.retry_policy.execute(move || {
                    let inner = inner.clone();
                    let loc = loc.clone();
                    async move { inner.head(&loc).await }
                })
            })
            .await;

        match result {
            Ok(inner_result) => Ok(inner_result),
            Err(e) => Err(Self::map_cb_err(e)),
        }
    }

    async fn delete(&self, location: &StorePath) -> OsResult<()> {
        let location = location.clone();
        let inner = self.inner.clone();

        let result = self
            .circuit_breaker
            .call(|| {
                let inner = inner.clone();
                let loc = location.clone();
                self.retry_policy.execute(move || {
                    let inner = inner.clone();
                    let loc = loc.clone();
                    async move { inner.delete(&loc).await }
                })
            })
            .await;

        match result {
            Ok(inner_result) => Ok(inner_result),
            Err(e) => Err(Self::map_cb_err(e)),
        }
    }

    fn list(&self, prefix: Option<&StorePath>) -> BoxStream<'_, OsResult<ObjectMeta>> {
        self.inner.list(prefix)
    }

    async fn list_with_delimiter(&self, prefix: Option<&StorePath>) -> OsResult<ListResult> {
        let prefix_owned = prefix.cloned();
        let inner = self.inner.clone();

        let result = self
            .circuit_breaker
            .call(|| {
                let inner = inner.clone();
                let p = prefix_owned.clone();
                self.retry_policy.execute(move || {
                    let inner = inner.clone();
                    let p = p.clone();
                    async move { inner.list_with_delimiter(p.as_ref()).await }
                })
            })
            .await;

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
