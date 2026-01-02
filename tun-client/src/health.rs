//! Upstream health check module.
//!
//! Provides health checking capabilities for the local service that the tunnel
//! is forwarding traffic to. This helps detect connectivity issues early and
//! can be used for periodic monitoring.

use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::{interval, timeout};
use tracing::{debug, error, info, warn};

/// Health check configuration.
#[derive(Debug, Clone)]
pub struct HealthCheckConfig {
    /// The address to check (local service address).
    pub addr: String,
    /// Connection timeout for health checks.
    pub timeout: Duration,
    /// Interval between periodic health checks.
    pub interval: Duration,
    /// Number of consecutive failures before considering unhealthy.
    pub failure_threshold: u32,
    /// Number of consecutive successes before considering healthy again.
    pub success_threshold: u32,
    /// Optional HTTP health check path.
    pub http_path: Option<String>,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            addr: "127.0.0.1:8080".to_string(),
            timeout: Duration::from_secs(5),
            interval: Duration::from_secs(30),
            failure_threshold: 3,
            success_threshold: 1,
            http_path: None,
        }
    }
}

impl HealthCheckConfig {
    /// Create a new health check config for a given address.
    pub fn new(addr: &str) -> Self {
        Self {
            addr: addr.to_string(),
            ..Default::default()
        }
    }

    /// Set the connection timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the check interval.
    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// Set the failure threshold.
    pub fn with_failure_threshold(mut self, threshold: u32) -> Self {
        self.failure_threshold = threshold;
        self
    }

    /// Set an HTTP health check path.
    pub fn with_http_path(mut self, path: &str) -> Self {
        self.http_path = Some(path.to_string());
        self
    }
}

/// Health check result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    /// Service is healthy and accepting connections.
    Healthy,
    /// Service is unhealthy.
    Unhealthy,
    /// Health status is unknown (not checked yet).
    Unknown,
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HealthStatus::Healthy => write!(f, "healthy"),
            HealthStatus::Unhealthy => write!(f, "unhealthy"),
            HealthStatus::Unknown => write!(f, "unknown"),
        }
    }
}

/// Result of a single health check.
#[derive(Debug, Clone)]
pub struct HealthCheckResult {
    pub status: HealthStatus,
    pub latency: Option<Duration>,
    pub error: Option<String>,
}

/// Upstream health checker.
pub struct HealthChecker {
    config: HealthCheckConfig,
    consecutive_failures: u32,
    consecutive_successes: u32,
    current_status: HealthStatus,
}

impl HealthChecker {
    /// Create a new health checker.
    pub fn new(config: HealthCheckConfig) -> Self {
        Self {
            config,
            consecutive_failures: 0,
            consecutive_successes: 0,
            current_status: HealthStatus::Unknown,
        }
    }

    /// Get the current health status.
    pub fn status(&self) -> HealthStatus {
        self.current_status
    }

    /// Perform a single health check.
    pub async fn check(&mut self) -> HealthCheckResult {
        let start = std::time::Instant::now();

        // First try TCP connection
        let tcp_result = self.check_tcp().await;

        match tcp_result {
            Ok(()) => {
                let latency = start.elapsed();
                self.consecutive_failures = 0;
                self.consecutive_successes += 1;

                if self.consecutive_successes >= self.config.success_threshold {
                    if self.current_status != HealthStatus::Healthy {
                        info!(
                            "Upstream {} is now healthy (latency: {:?})",
                            self.config.addr, latency
                        );
                    }
                    self.current_status = HealthStatus::Healthy;
                }

                debug!(
                    "Health check passed for {} (latency: {:?})",
                    self.config.addr, latency
                );

                HealthCheckResult {
                    status: self.current_status,
                    latency: Some(latency),
                    error: None,
                }
            }
            Err(e) => {
                self.consecutive_successes = 0;
                self.consecutive_failures += 1;

                if self.consecutive_failures >= self.config.failure_threshold {
                    if self.current_status != HealthStatus::Unhealthy {
                        warn!(
                            "Upstream {} is now unhealthy after {} consecutive failures: {}",
                            self.config.addr, self.consecutive_failures, e
                        );
                    }
                    self.current_status = HealthStatus::Unhealthy;
                }

                debug!("Health check failed for {}: {}", self.config.addr, e);

                HealthCheckResult {
                    status: self.current_status,
                    latency: None,
                    error: Some(e),
                }
            }
        }
    }

    /// Perform a TCP connection check.
    async fn check_tcp(&self) -> Result<(), String> {
        let addr: SocketAddr = self
            .config
            .addr
            .parse()
            .map_err(|e| format!("Invalid address: {}", e))?;

        match timeout(self.config.timeout, TcpStream::connect(addr)).await {
            Ok(Ok(_stream)) => Ok(()),
            Ok(Err(e)) => Err(format!("Connection failed: {}", e)),
            Err(_) => Err("Connection timeout".to_string()),
        }
    }

    /// Perform an optional HTTP health check.
    #[allow(dead_code)]
    async fn check_http(&self) -> Result<(), String> {
        let path = match &self.config.http_path {
            Some(p) => p,
            None => return Ok(()),
        };

        let url = format!("http://{}{}", self.config.addr, path);

        // Simple HTTP health check using raw TCP
        // In a production system, you might use reqwest or hyper
        let stream = timeout(
            self.config.timeout,
            TcpStream::connect(&self.config.addr),
        )
        .await
        .map_err(|_| "Connection timeout")?
        .map_err(|e| format!("Connection failed: {}", e))?;

        // Send a simple HTTP GET request
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            path, self.config.addr
        );

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut reader, mut writer) = stream.into_split();

        writer
            .write_all(request.as_bytes())
            .await
            .map_err(|e| format!("Write failed: {}", e))?;

        let mut response = [0u8; 1024];
        let n = reader
            .read(&mut response)
            .await
            .map_err(|e| format!("Read failed: {}", e))?;

        let response_str = String::from_utf8_lossy(&response[..n]);

        // Check for 2xx status code
        if response_str.starts_with("HTTP/1.") {
            let status_line = response_str.lines().next().unwrap_or("");
            if status_line.contains(" 2") {
                return Ok(());
            } else {
                return Err(format!("HTTP check failed: {}", status_line));
            }
        }

        Err("Invalid HTTP response".to_string())
    }
}

/// Start a background health check task.
pub fn start_health_check_task(
    config: HealthCheckConfig,
    status_tx: tokio::sync::watch::Sender<HealthStatus>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut checker = HealthChecker::new(config.clone());
        let mut interval = interval(config.interval);

        loop {
            interval.tick().await;

            let result = checker.check().await;
            if status_tx.send(result.status).is_err() {
                // Receiver dropped, stop the task
                break;
            }
        }
    })
}

/// Verify upstream connectivity before starting the tunnel.
pub async fn verify_upstream(addr: &str, timeout_secs: u64) -> Result<Duration, String> {
    info!("Verifying upstream connectivity to {}...", addr);

    let config = HealthCheckConfig::new(addr)
        .with_timeout(Duration::from_secs(timeout_secs));

    let mut checker = HealthChecker::new(config);
    let result = checker.check().await;

    match result.status {
        HealthStatus::Healthy | HealthStatus::Unknown => {
            let latency = result.latency.unwrap_or_default();
            info!("Upstream {} is reachable (latency: {:?})", addr, latency);
            Ok(latency)
        }
        HealthStatus::Unhealthy => {
            let err = result.error.unwrap_or_else(|| "Unknown error".to_string());
            error!("Upstream {} is not reachable: {}", addr, err);
            Err(err)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_checker_unknown_initial_status() {
        let config = HealthCheckConfig::new("127.0.0.1:12345"); // Non-existent port
        let checker = HealthChecker::new(config);
        assert_eq!(checker.status(), HealthStatus::Unknown);
    }

    #[tokio::test]
    async fn test_health_status_display() {
        assert_eq!(HealthStatus::Healthy.to_string(), "healthy");
        assert_eq!(HealthStatus::Unhealthy.to_string(), "unhealthy");
        assert_eq!(HealthStatus::Unknown.to_string(), "unknown");
    }
}

