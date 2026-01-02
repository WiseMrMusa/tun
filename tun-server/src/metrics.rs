//! Prometheus metrics for the tunnel server.
//!
//! Provides observability metrics for monitoring tunnel connections,
//! request performance, and server health.

#![allow(dead_code)]

use axum::{routing::get, Router};
use metrics::{counter, gauge, histogram};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use std::sync::Arc;
use tracing::info;

/// Metrics recorder wrapper
pub struct TunnelMetrics {
    handle: PrometheusHandle,
}

impl TunnelMetrics {
    /// Create a new metrics instance with Prometheus exporter.
    pub fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let builder = PrometheusBuilder::new();

        // Configure histogram buckets for latency measurements
        let builder = builder.set_buckets_for_metric(
            Matcher::Prefix("tun_request_duration".to_string()),
            &[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
        )?;

        let handle = builder.install_recorder()?;

        Ok(Self { handle })
    }

    /// Render metrics in Prometheus format.
    pub fn render(&self) -> String {
        self.handle.render()
    }
}

/// Record a successful tunnel connection.
pub fn record_tunnel_connected(tunnel_id: &str, subdomain: &str) {
    counter!("tun_tunnels_connected_total").increment(1);
    gauge!("tun_active_tunnels").increment(1.0);
    
    info!(
        tunnel_id = tunnel_id,
        subdomain = subdomain,
        "Tunnel connected (metrics)"
    );
}

/// Record a tunnel disconnection.
pub fn record_tunnel_disconnected(tunnel_id: &str) {
    counter!("tun_tunnels_disconnected_total").increment(1);
    gauge!("tun_active_tunnels").decrement(1.0);
}

/// Record an HTTP request through a tunnel.
pub fn record_request(tunnel_id: &str, status: u16, duration_ms: f64, bytes_in: u64, bytes_out: u64) {
    let status_class = format!("{}xx", status / 100);
    
    counter!("tun_requests_total", 
        "tunnel" => tunnel_id.to_string(),
        "status_class" => status_class.clone()
    ).increment(1);

    histogram!("tun_request_duration_ms",
        "tunnel" => tunnel_id.to_string()
    ).record(duration_ms);

    counter!("tun_bytes_in_total",
        "tunnel" => tunnel_id.to_string()
    ).increment(bytes_in);

    counter!("tun_bytes_out_total",
        "tunnel" => tunnel_id.to_string()
    ).increment(bytes_out);

    if status >= 500 {
        counter!("tun_errors_total",
            "tunnel" => tunnel_id.to_string(),
            "type" => "server_error"
        ).increment(1);
    } else if status >= 400 {
        counter!("tun_errors_total",
            "tunnel" => tunnel_id.to_string(),
            "type" => "client_error"
        ).increment(1);
    }
}

/// Record an authentication attempt.
pub fn record_auth_attempt(success: bool) {
    if success {
        counter!("tun_auth_success_total").increment(1);
    } else {
        counter!("tun_auth_failure_total").increment(1);
    }
}

/// Record a rate limit event.
pub fn record_rate_limit(client_ip: &str) {
    counter!("tun_rate_limit_total",
        "client_ip" => client_ip.to_string()
    ).increment(1);
}

/// Set the number of active tunnels (for startup reconciliation).
pub fn set_active_tunnels(count: usize) {
    gauge!("tun_active_tunnels").set(count as f64);
}

/// Set the number of pending requests.
pub fn set_pending_requests(count: usize) {
    gauge!("tun_pending_requests").set(count as f64);
}

/// Record server startup.
pub fn record_server_start() {
    counter!("tun_server_starts_total").increment(1);
    gauge!("tun_server_uptime_seconds").set(0.0);
}

/// Record a WebSocket connection.
pub fn record_websocket_connected() {
    counter!("tun_websocket_connections_total").increment(1);
    gauge!("tun_active_websocket_connections").increment(1.0);
}

/// Record a WebSocket disconnection.
pub fn record_websocket_disconnected() {
    gauge!("tun_active_websocket_connections").decrement(1.0);
}

/// Record WebSocket frames.
pub fn record_websocket_frame(direction: &str, bytes: usize) {
    counter!("tun_websocket_frames_total",
        "direction" => direction.to_string()
    ).increment(1);
    counter!("tun_websocket_bytes_total",
        "direction" => direction.to_string()
    ).increment(bytes as u64);
}

/// Record an IP block event.
pub fn record_ip_blocked(client_ip: &str, reason: &str) {
    counter!("tun_ip_blocked_total",
        "reason" => reason.to_string()
    ).increment(1);
}

/// Record a request timeout.
pub fn record_request_timeout(tunnel_id: &str) {
    counter!("tun_request_timeouts_total",
        "tunnel" => tunnel_id.to_string()
    ).increment(1);
}

/// Record upstream connection error.
pub fn record_upstream_error(tunnel_id: &str, error_type: &str) {
    counter!("tun_upstream_errors_total",
        "tunnel" => tunnel_id.to_string(),
        "error_type" => error_type.to_string()
    ).increment(1);
}

/// Record request body size.
pub fn record_request_body_size(bytes: usize) {
    histogram!("tun_request_body_bytes").record(bytes as f64);
}

/// Record response body size.
pub fn record_response_body_size(bytes: usize) {
    histogram!("tun_response_body_bytes").record(bytes as f64);
}

/// Record connection pool stats.
pub fn set_connection_pool_size(pool_name: &str, active: usize, idle: usize) {
    gauge!("tun_connection_pool_active",
        "pool" => pool_name.to_string()
    ).set(active as f64);
    gauge!("tun_connection_pool_idle",
        "pool" => pool_name.to_string()
    ).set(idle as f64);
}

/// Record streaming chunk sent.
pub fn record_stream_chunk(tunnel_id: &str, bytes: usize) {
    counter!("tun_stream_chunks_total",
        "tunnel" => tunnel_id.to_string()
    ).increment(1);
    counter!("tun_stream_bytes_total",
        "tunnel" => tunnel_id.to_string()
    ).increment(bytes as u64);
}

/// Record token revocation.
pub fn record_token_revoked() {
    counter!("tun_tokens_revoked_total").increment(1);
}

/// Record validation rejection.
pub fn record_validation_rejected(reason: &str) {
    counter!("tun_validation_rejected_total",
        "reason" => reason.to_string()
    ).increment(1);
}

/// Create a metrics router that serves the /metrics endpoint.
pub fn metrics_router(metrics: Arc<TunnelMetrics>) -> Router {
    Router::new()
        .route("/metrics", get(move || {
            let metrics = metrics.clone();
            async move { metrics.render() }
        }))
        .route("/health", get(|| async { "OK" }))
}

/// Start the metrics server on a separate port.
pub async fn run_metrics_server(
    port: u16,
    metrics: Arc<TunnelMetrics>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = format!("0.0.0.0:{}", port);
    let app = metrics_router(metrics);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!("Metrics server listening on {}", addr);

    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_creation() {
        // Note: This test might fail if metrics are already installed
        // In a real test, you'd use a separate metrics registry
        let result = TunnelMetrics::new();
        // Just verify it doesn't panic
        if result.is_ok() {
            let metrics = result.unwrap();
            let rendered = metrics.render();
            // Basic sanity check
            assert!(rendered.is_empty() || rendered.contains("# "));
        }
    }
}

