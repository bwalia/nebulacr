use std::fmt;
use std::time::{Duration, Instant};

use metrics::{counter, gauge};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, warn};

// State encoding for the `nebulacr_circuit_breaker_state` gauge.
// Kept stable so dashboards and alerts can match on numeric value.
const STATE_CLOSED: f64 = 0.0;
const STATE_HALF_OPEN: f64 = 1.0;
const STATE_OPEN: f64 = 2.0;

/// Configuration for the circuit breaker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    /// Number of consecutive failures before opening the circuit.
    pub failure_threshold: u32,
    /// Number of consecutive successes in half-open state before closing.
    pub success_threshold: u32,
    /// Duration the circuit stays open before transitioning to half-open.
    pub open_duration_secs: u64,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            success_threshold: 3,
            open_duration_secs: 30,
        }
    }
}

#[derive(Debug)]
enum BreakerState {
    Closed { consecutive_failures: u32 },
    Open { opened_at: Instant },
    HalfOpen { consecutive_successes: u32 },
}

impl fmt::Display for BreakerState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BreakerState::Closed {
                consecutive_failures,
            } => {
                write!(f, "Closed(failures={})", consecutive_failures)
            }
            BreakerState::Open { .. } => write!(f, "Open"),
            BreakerState::HalfOpen {
                consecutive_successes,
            } => {
                write!(f, "HalfOpen(successes={})", consecutive_successes)
            }
        }
    }
}

/// A circuit breaker that prevents cascading failures by short-circuiting
/// requests when a target is unhealthy.
pub struct CircuitBreaker {
    state: RwLock<BreakerState>,
    config: CircuitBreakerConfig,
    name: String,
}

#[derive(Debug, thiserror::Error)]
pub enum CircuitBreakerError {
    #[error("circuit breaker '{name}' is open")]
    Open { name: String },
}

impl CircuitBreaker {
    pub fn new(name: impl Into<String>, config: CircuitBreakerConfig) -> Self {
        let name = name.into();
        // Pre-publish the gauge so the metric exists from startup.
        gauge!("nebulacr_circuit_breaker_state", "breaker" => name.clone()).set(STATE_CLOSED);
        counter!("nebulacr_circuit_breaker_transitions_total",
            "breaker" => name.clone(), "to" => "closed")
        .increment(0);
        counter!("nebulacr_circuit_breaker_rejections_total", "breaker" => name.clone())
            .increment(0);
        Self {
            state: RwLock::new(BreakerState::Closed {
                consecutive_failures: 0,
            }),
            config,
            name,
        }
    }

    fn set_state_gauge(&self, value: f64) {
        gauge!("nebulacr_circuit_breaker_state", "breaker" => self.name.clone()).set(value);
    }

    fn record_transition(&self, to: &'static str) {
        counter!("nebulacr_circuit_breaker_transitions_total",
            "breaker" => self.name.clone(), "to" => to)
        .increment(1);
    }

    /// Execute an async operation through the circuit breaker.
    /// Returns `Err(CircuitBreakerError::Open)` if the circuit is open.
    pub async fn call<F, Fut, T, E>(&self, f: F) -> Result<T, CircuitBreakerCallError<E>>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T, E>>,
    {
        // Check if we should allow the call
        {
            let state = self.state.read().await;
            match &*state {
                BreakerState::Open { opened_at } => {
                    let elapsed = opened_at.elapsed();
                    let open_duration = Duration::from_secs(self.config.open_duration_secs);
                    if elapsed < open_duration {
                        debug!(
                            breaker = %self.name,
                            remaining_secs = (open_duration - elapsed).as_secs(),
                            "Circuit breaker is open, rejecting call"
                        );
                        counter!("nebulacr_circuit_breaker_rejections_total",
                            "breaker" => self.name.clone())
                        .increment(1);
                        return Err(CircuitBreakerCallError::BreakerOpen(
                            CircuitBreakerError::Open {
                                name: self.name.clone(),
                            },
                        ));
                    }
                    // Transition to half-open will happen below
                }
                BreakerState::Closed { .. } | BreakerState::HalfOpen { .. } => {
                    // Allow the call
                }
            }
        }

        // If we were open and enough time passed, transition to half-open
        {
            let mut state = self.state.write().await;
            if let BreakerState::Open { opened_at } = &*state {
                let elapsed = opened_at.elapsed();
                let open_duration = Duration::from_secs(self.config.open_duration_secs);
                if elapsed >= open_duration {
                    debug!(breaker = %self.name, "Transitioning from Open to HalfOpen");
                    *state = BreakerState::HalfOpen {
                        consecutive_successes: 0,
                    };
                    self.set_state_gauge(STATE_HALF_OPEN);
                    self.record_transition("half_open");
                }
            }
        }

        // Execute the operation
        let result = f().await;

        // Update state based on result
        match &result {
            Ok(_) => self.record_success().await,
            Err(_) => self.record_failure().await,
        }

        result.map_err(CircuitBreakerCallError::Inner)
    }

    async fn record_success(&self) {
        let mut state = self.state.write().await;
        match &*state {
            BreakerState::Closed { .. } => {
                *state = BreakerState::Closed {
                    consecutive_failures: 0,
                };
            }
            BreakerState::HalfOpen {
                consecutive_successes,
            } => {
                let new_successes = consecutive_successes + 1;
                if new_successes >= self.config.success_threshold {
                    debug!(breaker = %self.name, "Circuit breaker closing after recovery");
                    *state = BreakerState::Closed {
                        consecutive_failures: 0,
                    };
                    self.set_state_gauge(STATE_CLOSED);
                    self.record_transition("closed");
                } else {
                    *state = BreakerState::HalfOpen {
                        consecutive_successes: new_successes,
                    };
                }
            }
            BreakerState::Open { .. } => {
                // Shouldn't happen, but reset to closed
                *state = BreakerState::Closed {
                    consecutive_failures: 0,
                };
                self.set_state_gauge(STATE_CLOSED);
                self.record_transition("closed");
            }
        }
    }

    async fn record_failure(&self) {
        let mut state = self.state.write().await;
        match &*state {
            BreakerState::Closed {
                consecutive_failures,
            } => {
                let new_failures = consecutive_failures + 1;
                if new_failures >= self.config.failure_threshold {
                    warn!(
                        breaker = %self.name,
                        failures = new_failures,
                        "Circuit breaker opening after {} failures",
                        new_failures
                    );
                    *state = BreakerState::Open {
                        opened_at: Instant::now(),
                    };
                    self.set_state_gauge(STATE_OPEN);
                    self.record_transition("open");
                } else {
                    *state = BreakerState::Closed {
                        consecutive_failures: new_failures,
                    };
                }
            }
            BreakerState::HalfOpen { .. } => {
                warn!(breaker = %self.name, "Failure in half-open state, re-opening circuit");
                *state = BreakerState::Open {
                    opened_at: Instant::now(),
                };
                self.set_state_gauge(STATE_OPEN);
                self.record_transition("open");
            }
            BreakerState::Open { .. } => {
                // Already open, nothing to do
            }
        }
    }

    /// Check if the circuit breaker is currently open.
    pub async fn is_open(&self) -> bool {
        let state = self.state.read().await;
        matches!(&*state, BreakerState::Open { .. })
    }

    /// Get the current state as a string for metrics/debugging.
    pub async fn state_name(&self) -> String {
        let state = self.state.read().await;
        state.to_string()
    }
}

/// Error type that wraps both circuit breaker errors and inner operation errors.
#[derive(Debug, thiserror::Error)]
pub enum CircuitBreakerCallError<E> {
    #[error(transparent)]
    BreakerOpen(CircuitBreakerError),
    #[error(transparent)]
    Inner(E),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_circuit_breaker_stays_closed_on_success() {
        let cb = CircuitBreaker::new(
            "test",
            CircuitBreakerConfig {
                failure_threshold: 3,
                success_threshold: 2,
                open_duration_secs: 1,
            },
        );

        let result: Result<i32, CircuitBreakerCallError<String>> =
            cb.call(|| async { Ok::<i32, String>(42) }).await;
        assert!(result.is_ok());
        assert!(!cb.is_open().await);
    }

    #[tokio::test]
    async fn test_circuit_breaker_opens_after_threshold() {
        let cb = CircuitBreaker::new(
            "test",
            CircuitBreakerConfig {
                failure_threshold: 2,
                success_threshold: 1,
                open_duration_secs: 60,
            },
        );

        // Two failures should open the circuit
        let _: Result<i32, _> = cb
            .call(|| async { Err::<i32, String>("fail".into()) })
            .await;
        let _: Result<i32, _> = cb
            .call(|| async { Err::<i32, String>("fail".into()) })
            .await;

        assert!(cb.is_open().await);

        // Next call should be rejected
        let result: Result<i32, _> = cb.call(|| async { Ok::<i32, String>(42) }).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_circuit_breaker_recovers() {
        let cb = CircuitBreaker::new(
            "test",
            CircuitBreakerConfig {
                failure_threshold: 1,
                success_threshold: 1,
                open_duration_secs: 0, // Immediate transition to half-open
            },
        );

        // Open the circuit
        let _: Result<i32, _> = cb
            .call(|| async { Err::<i32, String>("fail".into()) })
            .await;
        assert!(cb.is_open().await);

        // Wait for open duration (0 seconds)
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Should transition to half-open and allow the call
        let result: Result<i32, CircuitBreakerCallError<String>> =
            cb.call(|| async { Ok::<i32, String>(42) }).await;
        assert!(result.is_ok());
        assert!(!cb.is_open().await);
    }
}
