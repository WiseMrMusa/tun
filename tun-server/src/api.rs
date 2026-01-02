//! Introspection REST API for tunnel management.
//!
//! Provides endpoints for monitoring and managing tunnels.

use crate::ratelimit::IpRateLimiter;
use crate::tunnel::TunnelRegistry;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::info;

/// API response for tunnel information.
#[derive(Debug, Serialize)]
pub struct TunnelInfo {
    pub id: String,
    pub subdomain: String,
    pub connected_at: String,
    pub pending_requests: usize,
}

/// API response for server health.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub active_tunnels: usize,
    pub uptime_seconds: u64,
}

/// API response for server statistics.
#[derive(Debug, Serialize)]
pub struct ServerStats {
    pub active_tunnels: usize,
    pub total_connections: u64,
    pub rate_limited_requests: u64,
    pub tracked_ips: usize,
}

/// API response for list of tunnels.
#[derive(Debug, Serialize)]
pub struct TunnelListResponse {
    pub tunnels: Vec<TunnelInfo>,
    pub total: usize,
}

/// API response for errors.
#[derive(Debug, Serialize)]
pub struct ApiError {
    pub error: String,
    pub code: u16,
}

/// State for the API server.
#[derive(Clone)]
pub struct ApiState {
    pub registry: Arc<TunnelRegistry>,
    pub rate_limiter: Arc<IpRateLimiter>,
    pub start_time: std::time::Instant,
}

/// Create the API router.
pub fn create_api_router(state: ApiState) -> Router {
    Router::new()
        .route("/api/health", get(health_handler))
        .route("/api/stats", get(stats_handler))
        .route("/api/tunnels", get(list_tunnels_handler))
        .route("/api/tunnels/:subdomain", get(get_tunnel_handler))
        .route(
            "/api/tunnels/:subdomain/disconnect",
            post(disconnect_tunnel_handler),
        )
        .with_state(state)
}

/// Health check endpoint.
async fn health_handler(State(state): State<ApiState>) -> impl IntoResponse {
    let response = HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        active_tunnels: state.registry.count(),
        uptime_seconds: state.start_time.elapsed().as_secs(),
    };

    Json(response)
}

/// Server statistics endpoint.
async fn stats_handler(State(state): State<ApiState>) -> impl IntoResponse {
    let response = ServerStats {
        active_tunnels: state.registry.count(),
        total_connections: 0, // TODO: Track this
        rate_limited_requests: state.rate_limiter.rate_limited_count(),
        tracked_ips: state.rate_limiter.tracked_ips(),
    };

    Json(response)
}

/// List all active tunnels.
async fn list_tunnels_handler(State(state): State<ApiState>) -> impl IntoResponse {
    let tunnels: Vec<TunnelInfo> = state
        .registry
        .list_tunnels()
        .into_iter()
        .map(|(id, subdomain, pending)| TunnelInfo {
            id: id.to_string(),
            subdomain,
            connected_at: "unknown".to_string(), // TODO: Track connection time
            pending_requests: pending,
        })
        .collect();

    let total = tunnels.len();
    Json(TunnelListResponse { tunnels, total })
}

/// Get a specific tunnel by subdomain.
async fn get_tunnel_handler(
    State(state): State<ApiState>,
    Path(subdomain): Path<String>,
) -> impl IntoResponse {
    match state.registry.get_by_subdomain(&subdomain) {
        Some(tunnel) => {
            let info = TunnelInfo {
                id: tunnel.id.to_string(),
                subdomain: tunnel.subdomain.clone(),
                connected_at: "unknown".to_string(),
                pending_requests: tunnel.pending_requests.len(),
            };
            Json(info).into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(ApiError {
                error: format!("Tunnel '{}' not found", subdomain),
                code: 404,
            }),
        )
            .into_response(),
    }
}

/// Disconnect a tunnel by subdomain.
async fn disconnect_tunnel_handler(
    State(state): State<ApiState>,
    Path(subdomain): Path<String>,
) -> impl IntoResponse {
    match state.registry.get_by_subdomain(&subdomain) {
        Some(tunnel) => {
            let tunnel_id = tunnel.id;
            
            // Unregister the tunnel
            state.registry.unregister(tunnel_id).await;
            
            info!("Tunnel {} disconnected via API", tunnel_id);

            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "message": format!("Tunnel '{}' disconnected", subdomain),
                    "tunnel_id": tunnel_id.to_string()
                })),
            )
                .into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(ApiError {
                error: format!("Tunnel '{}' not found", subdomain),
                code: 404,
            }),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_response_serialization() {
        let response = HealthResponse {
            status: "healthy".to_string(),
            version: "0.1.0".to_string(),
            active_tunnels: 5,
            uptime_seconds: 3600,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("healthy"));
        assert!(json.contains("0.1.0"));
    }
}

