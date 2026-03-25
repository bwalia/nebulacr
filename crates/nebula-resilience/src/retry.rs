use std::time::Duration;

use rand::Rng;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

/// Configuration for retry behavior with exponential backoff.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryPolicy {
    /// Maximum number of retry attempts (0 = no retries).
    pub max_retries: u32,
    /// Base delay in milliseconds for exponential backoff.
    pub base_delay_ms: u64,
    /// Maximum delay in milliseconds (caps the exponential growth).
    pub max_delay_ms: u64,
    /// Whether to add random jitter to the delay.
    pub jitter: bool,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_delay_ms: 100,
            max_delay_ms: 5000,
            jitter: true,
        }
    }
}

impl RetryPolicy {
    /// Execute an async operation with retry logic and exponential backoff.
    pub async fn execute<F, Fut, T, E>(&self, mut f: F) -> Result<T, E>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T, E>>,
        E: std::fmt::Display,
    {
        let mut attempt = 0u32;

        loop {
            match f().await {
                Ok(val) => return Ok(val),
                Err(e) => {
                    if attempt >= self.max_retries {
                        warn!(
                            attempts = attempt + 1,
                            error = %e,
                            "All retry attempts exhausted"
                        );
                        return Err(e);
                    }

                    let delay = self.compute_delay(attempt);
                    debug!(
                        attempt = attempt + 1,
                        max_retries = self.max_retries,
                        delay_ms = delay.as_millis() as u64,
                        error = %e,
                        "Retrying after error"
                    );

                    tokio::time::sleep(delay).await;
                    attempt += 1;
                }
            }
        }
    }

    /// Compute the delay for a given attempt using exponential backoff with optional jitter.
    fn compute_delay(&self, attempt: u32) -> Duration {
        let base = self
            .base_delay_ms
            .saturating_mul(2u64.saturating_pow(attempt));
        let capped = base.min(self.max_delay_ms);

        let delay_ms = if self.jitter {
            let mut rng = rand::rng();
            rng.random_range(0..=capped)
        } else {
            capped
        };

        Duration::from_millis(delay_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[tokio::test]
    async fn test_retry_succeeds_immediately() {
        let policy = RetryPolicy {
            max_retries: 3,
            base_delay_ms: 10,
            max_delay_ms: 100,
            jitter: false,
        };

        let result: Result<i32, String> = policy.execute(|| async { Ok(42) }).await;
        assert_eq!(result.unwrap(), 42);
    }

    #[tokio::test]
    async fn test_retry_succeeds_after_failures() {
        let policy = RetryPolicy {
            max_retries: 3,
            base_delay_ms: 1,
            max_delay_ms: 10,
            jitter: false,
        };

        let counter = AtomicU32::new(0);
        let result: Result<i32, String> = policy
            .execute(|| {
                let count = counter.fetch_add(1, Ordering::SeqCst);
                async move {
                    if count < 2 {
                        Err("not yet".to_string())
                    } else {
                        Ok(42)
                    }
                }
            })
            .await;

        assert_eq!(result.unwrap(), 42);
        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_retry_exhausted() {
        let policy = RetryPolicy {
            max_retries: 2,
            base_delay_ms: 1,
            max_delay_ms: 10,
            jitter: false,
        };

        let counter = AtomicU32::new(0);
        let result: Result<i32, String> = policy
            .execute(|| {
                counter.fetch_add(1, Ordering::SeqCst);
                async { Err("always fails".to_string()) }
            })
            .await;

        assert!(result.is_err());
        // 1 initial + 2 retries = 3 attempts
        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn test_delay_capped() {
        let policy = RetryPolicy {
            max_retries: 10,
            base_delay_ms: 100,
            max_delay_ms: 500,
            jitter: false,
        };

        let delay = policy.compute_delay(10);
        assert!(delay.as_millis() <= 500);
    }
}
