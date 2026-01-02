//! Graceful shutdown handling with connection draining.
//!
//! This module provides mechanisms for gracefully shutting down the server
//! while ensuring in-flight requests are completed.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tokio::time::timeout;
use tracing::{debug, info, warn};

/// Default shutdown timeout in seconds.
pub const DEFAULT_SHUTDOWN_TIMEOUT_SECS: u64 = 30;

/// Shutdown signal that can be shared across tasks.
#[derive(Clone)]
pub struct ShutdownSignal {
    /// Flag indicating shutdown has been initiated.
    is_shutting_down: Arc<AtomicBool>,
    /// Broadcast sender for shutdown notification.
    notify: broadcast::Sender<()>,
    /// Counter for active connections.
    active_connections: Arc<AtomicUsize>,
    /// Timeout for graceful shutdown.
    timeout: Duration,
}

impl ShutdownSignal {
    /// Create a new shutdown signal.
    pub fn new(timeout_secs: u64) -> Self {
        let (notify, _) = broadcast::channel(1);
        Self {
            is_shutting_down: Arc::new(AtomicBool::new(false)),
            notify,
            active_connections: Arc::new(AtomicUsize::new(0)),
            timeout: Duration::from_secs(timeout_secs),
        }
    }

    /// Check if shutdown has been initiated.
    pub fn is_shutting_down(&self) -> bool {
        self.is_shutting_down.load(Ordering::SeqCst)
    }

    /// Initiate shutdown.
    pub fn initiate_shutdown(&self) {
        self.is_shutting_down.store(true, Ordering::SeqCst);
        let _ = self.notify.send(());
        info!("Shutdown initiated");
    }

    /// Subscribe to shutdown notifications.
    pub fn subscribe(&self) -> broadcast::Receiver<()> {
        self.notify.subscribe()
    }

    /// Register a new active connection.
    pub fn register_connection(&self) -> ConnectionGuard {
        self.active_connections.fetch_add(1, Ordering::SeqCst);
        debug!(
            "Connection registered, active: {}",
            self.active_connections.load(Ordering::SeqCst)
        );
        ConnectionGuard {
            counter: self.active_connections.clone(),
        }
    }

    /// Get the number of active connections.
    pub fn active_connection_count(&self) -> usize {
        self.active_connections.load(Ordering::SeqCst)
    }

    /// Wait for all connections to drain with timeout.
    pub async fn wait_for_drain(&self) -> bool {
        info!(
            "Waiting for {} active connections to drain (timeout: {:?})",
            self.active_connection_count(),
            self.timeout
        );

        let drain_future = async {
            loop {
                let count = self.active_connection_count();
                if count == 0 {
                    info!("All connections drained successfully");
                    return true;
                }
                debug!("Waiting for {} connections to drain", count);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        };

        match timeout(self.timeout, drain_future).await {
            Ok(result) => result,
            Err(_) => {
                warn!(
                    "Shutdown timeout reached with {} connections still active",
                    self.active_connection_count()
                );
                false
            }
        }
    }
}

/// Guard that decrements the connection counter when dropped.
pub struct ConnectionGuard {
    counter: Arc<AtomicUsize>,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        let prev = self.counter.fetch_sub(1, Ordering::SeqCst);
        debug!("Connection closed, active: {}", prev - 1);
    }
}

/// In-flight request tracker for a single tunnel.
#[derive(Clone)]
pub struct RequestTracker {
    active_requests: Arc<AtomicUsize>,
    shutdown_signal: ShutdownSignal,
}

impl RequestTracker {
    /// Create a new request tracker.
    pub fn new(shutdown_signal: ShutdownSignal) -> Self {
        Self {
            active_requests: Arc::new(AtomicUsize::new(0)),
            shutdown_signal,
        }
    }

    /// Check if we should accept new requests.
    pub fn should_accept_requests(&self) -> bool {
        !self.shutdown_signal.is_shutting_down()
    }

    /// Register a new request.
    pub fn register_request(&self) -> Option<RequestGuard> {
        if self.shutdown_signal.is_shutting_down() {
            debug!("Rejecting new request during shutdown");
            return None;
        }
        self.active_requests.fetch_add(1, Ordering::SeqCst);
        Some(RequestGuard {
            counter: self.active_requests.clone(),
        })
    }

    /// Get the number of active requests.
    pub fn active_request_count(&self) -> usize {
        self.active_requests.load(Ordering::SeqCst)
    }

    /// Wait for all requests to complete.
    pub async fn wait_for_requests(&self, timeout_secs: u64) -> bool {
        let drain_future = async {
            loop {
                let count = self.active_request_count();
                if count == 0 {
                    return true;
                }
                debug!("Waiting for {} requests to complete", count);
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        };

        match timeout(Duration::from_secs(timeout_secs), drain_future).await {
            Ok(result) => result,
            Err(_) => {
                warn!(
                    "Request drain timeout with {} requests still active",
                    self.active_request_count()
                );
                false
            }
        }
    }
}

/// Guard that decrements the request counter when dropped.
pub struct RequestGuard {
    counter: Arc<AtomicUsize>,
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Graceful shutdown coordinator.
pub struct GracefulShutdown {
    signal: ShutdownSignal,
}

impl GracefulShutdown {
    /// Create a new graceful shutdown coordinator.
    pub fn new(timeout_secs: u64) -> Self {
        Self {
            signal: ShutdownSignal::new(timeout_secs),
        }
    }

    /// Get the shutdown signal for sharing with tasks.
    pub fn signal(&self) -> ShutdownSignal {
        self.signal.clone()
    }

    /// Wait for shutdown signal (Ctrl+C or SIGTERM).
    pub async fn wait_for_signal(&self) {
        let ctrl_c = async {
            tokio::signal::ctrl_c()
                .await
                .expect("Failed to install Ctrl+C handler");
        };

        #[cfg(unix)]
        let terminate = async {
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("Failed to install SIGTERM handler")
                .recv()
                .await;
        };

        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::select! {
            _ = ctrl_c => {
                info!("Received Ctrl+C, initiating graceful shutdown");
            }
            _ = terminate => {
                info!("Received SIGTERM, initiating graceful shutdown");
            }
        }

        self.signal.initiate_shutdown();
    }

    /// Perform graceful shutdown.
    pub async fn shutdown(&self) -> bool {
        self.signal.wait_for_drain().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_shutdown_signal() {
        let signal = ShutdownSignal::new(5);
        assert!(!signal.is_shutting_down());

        // Register a connection
        let _guard = signal.register_connection();
        assert_eq!(signal.active_connection_count(), 1);

        // Initiate shutdown
        signal.initiate_shutdown();
        assert!(signal.is_shutting_down());

        // Drop the guard
        drop(_guard);
        assert_eq!(signal.active_connection_count(), 0);
    }

    #[tokio::test]
    async fn test_request_tracker() {
        let signal = ShutdownSignal::new(5);
        let tracker = RequestTracker::new(signal.clone());

        assert!(tracker.should_accept_requests());

        let guard = tracker.register_request();
        assert!(guard.is_some());
        assert_eq!(tracker.active_request_count(), 1);

        signal.initiate_shutdown();
        assert!(!tracker.should_accept_requests());
        assert!(tracker.register_request().is_none());

        drop(guard);
        assert_eq!(tracker.active_request_count(), 0);
    }
}

