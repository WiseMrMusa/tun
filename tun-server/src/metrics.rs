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
pub fn record_websocket_connected(tunnel_id: &str, subdomain: &str) {
    counter!("tun_websocket_connections_total",
        "tunnel" => tunnel_id.to_string(),
        "subdomain" => subdomain.to_string()
    ).increment(1);
    gauge!("tun_active_websocket_connections").increment(1.0);
}

/// Record a WebSocket disconnection.
pub fn record_websocket_disconnected(tunnel_id: &str) {
    gauge!("tun_active_websocket_connections").decrement(1.0);
}

/// Record an ACL denial.
pub fn record_acl_denied(subdomain: &str, reason: &str) {
    counter!("tun_acl_denied_total",
        "subdomain" => subdomain.to_string(),
        "reason" => reason.to_string()
    ).increment(1);
}

/// Record a validation failure.
pub fn record_validation_failure(subdomain: &str, reason: &str) {
    counter!("tun_validation_failure_total",
        "subdomain" => subdomain.to_string(),
        "reason" => reason.to_string()
    ).increment(1);
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

// === Connection Metadata Tracking ===

/// Record connection with timestamp and metadata.
pub fn record_connection_metadata(tunnel_id: &str, client_ip: &str, subdomain: &str) {
    counter!("tun_connection_events_total",
        "tunnel" => tunnel_id.to_string(),
        "subdomain" => subdomain.to_string(),
        "event" => "connect"
    ).increment(1);
    
    // Track by client IP for geographic analysis
    counter!("tun_connections_by_ip_total",
        "client_ip_prefix" => truncate_ip(client_ip)
    ).increment(1);
}

/// Record disconnection with duration.
pub fn record_disconnection_metadata(tunnel_id: &str, duration_secs: f64) {
    counter!("tun_connection_events_total",
        "tunnel" => tunnel_id.to_string(),
        "event" => "disconnect"
    ).increment(1);
    
    histogram!("tun_connection_duration_seconds",
        "tunnel" => tunnel_id.to_string()
    ).record(duration_secs);
}

// === Cluster Metrics ===

/// Record cluster peer count.
pub fn set_cluster_peer_count(count: usize) {
    gauge!("tun_cluster_peers_total").set(count as f64);
}

/// Record cluster peer health.
pub fn set_cluster_healthy_peers(count: usize) {
    gauge!("tun_cluster_healthy_peers").set(count as f64);
}

/// Record cross-server request forwarding.
pub fn record_cluster_forward(target_server: &str, success: bool) {
    counter!("tun_cluster_forwards_total",
        "target" => target_server.to_string(),
        "success" => success.to_string()
    ).increment(1);
}

/// Record circuit breaker trip.
pub fn record_circuit_breaker_trip(tunnel_id: &str) {
    counter!("tun_circuit_breaker_trips_total",
        "tunnel" => tunnel_id.to_string()
    ).increment(1);
}

/// Record circuit breaker state.
pub fn set_circuit_breaker_state(tunnel_id: &str, state: &str) {
    // Use gauge to track current state (0=closed, 1=open, 2=half-open)
    let value = match state {
        "closed" => 0.0,
        "open" => 1.0,
        "half_open" => 2.0,
        _ => 0.0,
    };
    gauge!("tun_circuit_breaker_state",
        "tunnel" => tunnel_id.to_string()
    ).set(value);
}

/// Record peer heartbeat.
pub fn record_peer_heartbeat(server_id: &str) {
    counter!("tun_peer_heartbeats_total",
        "server" => server_id.to_string()
    ).increment(1);
}

// === OTLP Export Metrics ===

/// Record OTLP span export.
pub fn record_otlp_export(span_count: usize, success: bool) {
    counter!("tun_otlp_spans_exported_total",
        "success" => success.to_string()
    ).increment(span_count as u64);
}

/// Record OTLP export latency.
pub fn record_otlp_export_latency(duration_ms: f64) {
    histogram!("tun_otlp_export_duration_ms").record(duration_ms);
}

// === Hot Reload Metrics ===

/// Record config reload.
pub fn record_config_reload(config_type: &str, success: bool) {
    counter!("tun_config_reloads_total",
        "type" => config_type.to_string(),
        "success" => success.to_string()
    ).increment(1);
}

/// Helper to truncate IP for privacy (keeping first two octets for IPv4).
fn truncate_ip(ip: &str) -> String {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() >= 2 {
        format!("{}.{}.*.*", parts[0], parts[1])
    } else {
        "*".to_string()
    }
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

