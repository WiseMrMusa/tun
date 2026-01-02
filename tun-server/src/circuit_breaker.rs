//! Circuit breaker pattern for tunnel requests.
//!
//! Prevents cascading failures by temporarily stopping requests to unhealthy tunnels.
//! States:
//! - Closed: Normal operation, requests pass through
//! - Open: Failure threshold exceeded, requests fail immediately
//! - HalfOpen: Testing if tunnel has recovered

use dashmap::DashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Circuit breaker states.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Normal operation - requests pass through
    Closed = 0,
    /// Circuit tripped - requests fail immediately
    Open = 1,
    /// Testing recovery - limited requests allowed
    HalfOpen = 2,
}

impl From<u8> for CircuitState {
    fn from(v: u8) -> Self {
        match v {
            0 => CircuitState::Closed,
            1 => CircuitState::Open,
            2 => CircuitState::HalfOpen,
            _ => CircuitState::Closed,
        }
    }
}

/// Configuration for circuit breaker behavior.
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of failures before tripping the circuit
    pub failure_threshold: u32,
    /// Duration the circuit stays open before testing recovery
    pub open_duration: Duration,
    /// Number of successful requests in half-open state to close circuit
    pub success_threshold: u32,
    /// Time window for counting failures (failures outside this window are forgotten)
    pub failure_window: Duration,
    /// Maximum concurrent requests in half-open state
    pub half_open_max_requests: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            open_duration: Duration::from_secs(30),
            success_threshold: 3,
            failure_window: Duration::from_secs(60),
            half_open_max_requests: 1,
        }
    }
}

impl CircuitBreakerConfig {
    /// Create a lenient config (more tolerant of failures).
    pub fn lenient() -> Self {
        Self {
            failure_threshold: 10,
            open_duration: Duration::from_secs(60),
            success_threshold: 5,
            failure_window: Duration::from_secs(120),
            half_open_max_requests: 2,
        }
    }

    /// Create a strict config (trips quickly on failures).
    pub fn strict() -> Self {
        Self {
            failure_threshold: 3,
            open_duration: Duration::from_secs(15),
            success_threshold: 2,
            failure_window: Duration::from_secs(30),
            half_open_max_requests: 1,
        }
    }
}

/// A circuit breaker for a single tunnel.
pub struct CircuitBreaker {
    /// Current state (Closed=0, Open=1, HalfOpen=2)
    state: AtomicU8,
    /// Consecutive failure count
    failure_count: AtomicU32,
    /// Consecutive success count in half-open state
    success_count: AtomicU32,
    /// Timestamp when circuit was opened (millis since UNIX_EPOCH)
    opened_at: AtomicU64,
    /// Current in-flight requests in half-open state
    half_open_requests: AtomicU32,
    /// Configuration
    config: CircuitBreakerConfig,
    /// Tunnel identifier for logging
    tunnel_id: String,
}

impl CircuitBreaker {
    /// Create a new circuit breaker for a tunnel.
    pub fn new(tunnel_id: &str, config: CircuitBreakerConfig) -> Self {
        Self {
            state: AtomicU8::new(CircuitState::Closed as u8),
            failure_count: AtomicU32::new(0),
            success_count: AtomicU32::new(0),
            opened_at: AtomicU64::new(0),
            half_open_requests: AtomicU32::new(0),
            config,
            tunnel_id: tunnel_id.to_string(),
        }
    }

    /// Check if a request can be executed.
    /// Returns true if the circuit allows the request.
    pub fn can_execute(&self) -> bool {
        let state = CircuitState::from(self.state.load(Ordering::SeqCst));

        match state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                // Check if we should transition to half-open
                let opened_at = self.opened_at.load(Ordering::SeqCst);
                let now = current_time_millis();
                let elapsed = Duration::from_millis(now.saturating_sub(opened_at));

                if elapsed >= self.config.open_duration {
                    // Transition to half-open
                    self.transition_to_half_open();
                    self.try_half_open_request()
                } else {
                    debug!(
                        "Circuit breaker OPEN for tunnel {}, retry in {:?}",
                        self.tunnel_id,
                        self.config.open_duration - elapsed
                    );
                    false
                }
            }
            CircuitState::HalfOpen => self.try_half_open_request(),
        }
    }

    /// Record a successful request.
    pub fn record_success(&self) {
        let state = CircuitState::from(self.state.load(Ordering::SeqCst));

        match state {
            CircuitState::Closed => {
                // Reset failure count on success
                self.failure_count.store(0, Ordering::SeqCst);
            }
            CircuitState::HalfOpen => {
                // Decrement in-flight counter
                self.half_open_requests.fetch_sub(1, Ordering::SeqCst);
                
                // Increment success count
                let successes = self.success_count.fetch_add(1, Ordering::SeqCst) + 1;

                if successes >= self.config.success_threshold {
                    // Transition to closed
                    self.transition_to_closed();
                }
            }
            CircuitState::Open => {
                // Shouldn't happen, but treat as recovery
                self.transition_to_closed();
            }
        }
    }

    /// Record a failed request.
    pub fn record_failure(&self) {
        let state = CircuitState::from(self.state.load(Ordering::SeqCst));

        match state {
            CircuitState::Closed => {
                let failures = self.failure_count.fetch_add(1, Ordering::SeqCst) + 1;

                if failures >= self.config.failure_threshold {
                    self.transition_to_open();
                }
            }
            CircuitState::HalfOpen => {
                // Decrement in-flight counter
                self.half_open_requests.fetch_sub(1, Ordering::SeqCst);
                // Single failure in half-open state re-opens the circuit
                self.transition_to_open();
            }
            CircuitState::Open => {
                // Already open, nothing to do
            }
        }
    }

    /// Get the current state.
    pub fn state(&self) -> CircuitState {
        CircuitState::from(self.state.load(Ordering::SeqCst))
    }

    /// Get the current failure count.
    pub fn failure_count(&self) -> u32 {
        self.failure_count.load(Ordering::SeqCst)
    }

    /// Force the circuit open (for manual intervention).
    pub fn force_open(&self) {
        self.transition_to_open();
    }

    /// Force the circuit closed (for manual intervention).
    pub fn force_close(&self) {
        self.transition_to_closed();
    }

    /// Reset the circuit breaker to initial state.
    pub fn reset(&self) {
        self.state.store(CircuitState::Closed as u8, Ordering::SeqCst);
        self.failure_count.store(0, Ordering::SeqCst);
        self.success_count.store(0, Ordering::SeqCst);
        self.half_open_requests.store(0, Ordering::SeqCst);
        self.opened_at.store(0, Ordering::SeqCst);
        info!("Circuit breaker RESET for tunnel {}", self.tunnel_id);
    }

    // === Private methods ===

    fn transition_to_open(&self) {
        self.state.store(CircuitState::Open as u8, Ordering::SeqCst);
        self.opened_at
            .store(current_time_millis(), Ordering::SeqCst);
        warn!(
            "Circuit breaker OPENED for tunnel {} after {} failures",
            self.tunnel_id,
            self.failure_count.load(Ordering::SeqCst)
        );
        crate::metrics::record_circuit_breaker_trip(&self.tunnel_id);
    }

    fn transition_to_half_open(&self) {
        self.state
            .store(CircuitState::HalfOpen as u8, Ordering::SeqCst);
        self.success_count.store(0, Ordering::SeqCst);
        self.half_open_requests.store(0, Ordering::SeqCst);
        debug!(
            "Circuit breaker HALF-OPEN for tunnel {}, testing recovery",
            self.tunnel_id
        );
    }

    fn transition_to_closed(&self) {
        self.state
            .store(CircuitState::Closed as u8, Ordering::SeqCst);
        self.failure_count.store(0, Ordering::SeqCst);
        self.success_count.store(0, Ordering::SeqCst);
        self.half_open_requests.store(0, Ordering::SeqCst);
        info!("Circuit breaker CLOSED for tunnel {}", self.tunnel_id);
    }

    fn try_half_open_request(&self) -> bool {
        let current = self.half_open_requests.load(Ordering::SeqCst);
        if current >= self.config.half_open_max_requests {
            debug!(
                "Circuit breaker HALF-OPEN for tunnel {}, max requests reached",
                self.tunnel_id
            );
            return false;
        }

        // Try to increment, fail if we exceed the limit
        let result = self.half_open_requests.compare_exchange(
            current,
            current + 1,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );

        result.is_ok()
    }
}

/// Get current time in milliseconds since UNIX_EPOCH.
fn current_time_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Manager for circuit breakers across all tunnels.
pub struct CircuitBreakerManager {
    /// Circuit breakers by tunnel ID
    breakers: DashMap<String, CircuitBreaker>,
    /// Default configuration
    default_config: CircuitBreakerConfig,
}

impl CircuitBreakerManager {
    /// Create a new circuit breaker manager.
    pub fn new(default_config: CircuitBreakerConfig) -> Self {
        Self {
            breakers: DashMap::new(),
            default_config,
        }
    }

    /// Get or create a circuit breaker for a tunnel.
    pub fn get_or_create(&self, tunnel_id: &str) -> dashmap::mapref::one::Ref<'_, String, CircuitBreaker> {
        if !self.breakers.contains_key(tunnel_id) {
            self.breakers.insert(
                tunnel_id.to_string(),
                CircuitBreaker::new(tunnel_id, self.default_config.clone()),
            );
        }
        self.breakers.get(tunnel_id).unwrap()
    }

    /// Check if a request can be executed for a tunnel.
    pub fn can_execute(&self, tunnel_id: &str) -> bool {
        self.get_or_create(tunnel_id).can_execute()
    }

    /// Record a successful request for a tunnel.
    pub fn record_success(&self, tunnel_id: &str) {
        self.get_or_create(tunnel_id).record_success();
    }

    /// Record a failed request for a tunnel.
    pub fn record_failure(&self, tunnel_id: &str) {
        self.get_or_create(tunnel_id).record_failure();
    }

    /// Get the state of a tunnel's circuit breaker.
    pub fn state(&self, tunnel_id: &str) -> CircuitState {
        self.get_or_create(tunnel_id).state()
    }

    /// Remove circuit breaker for a disconnected tunnel.
    pub fn remove(&self, tunnel_id: &str) {
        self.breakers.remove(tunnel_id);
    }

    /// Get statistics about all circuit breakers.
    pub fn stats(&self) -> CircuitBreakerStats {
        let mut closed = 0;
        let mut open = 0;
        let mut half_open = 0;

        for breaker in self.breakers.iter() {
            match breaker.state() {
                CircuitState::Closed => closed += 1,
                CircuitState::Open => open += 1,
                CircuitState::HalfOpen => half_open += 1,
            }
        }

        CircuitBreakerStats {
            total: self.breakers.len(),
            closed,
            open,
            half_open,
        }
    }
}

/// Statistics about circuit breakers.
#[derive(Debug, Clone)]
pub struct CircuitBreakerStats {
    pub total: usize,
    pub closed: usize,
    pub open: usize,
    pub half_open: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_breaker_closed() {
        let cb = CircuitBreaker::new("test", CircuitBreakerConfig::default());
        assert_eq!(cb.state(), CircuitState::Closed);
        assert!(cb.can_execute());
    }

    #[test]
    fn test_circuit_breaker_trips() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            ..Default::default()
        };
        let cb = CircuitBreaker::new("test", config);

        // Record failures
        for _ in 0..3 {
            assert!(cb.can_execute());
            cb.record_failure();
        }

        // Circuit should be open
        assert_eq!(cb.state(), CircuitState::Open);
        assert!(!cb.can_execute());
    }

    #[test]
    fn test_circuit_breaker_recovery() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            success_threshold: 2,
            open_duration: Duration::from_millis(10),
            half_open_max_requests: 2,
            ..Default::default()
        };
        let cb = CircuitBreaker::new("test", config);

        // Trip the circuit
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);

        // Wait for open duration
        std::thread::sleep(Duration::from_millis(15));

        // Should transition to half-open
        assert!(cb.can_execute());
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        // Record successes
        cb.record_success();
        cb.record_success();

        // Should be closed now
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn test_success_resets_failures() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            ..Default::default()
        };
        let cb = CircuitBreaker::new("test", config);

        // Record some failures
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.failure_count(), 2);

        // Success resets count
        cb.record_success();
        assert_eq!(cb.failure_count(), 0);
    }
}

