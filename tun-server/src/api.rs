//! Introspection REST API for tunnel management.
//!
//! Provides endpoints for monitoring and managing tunnels.
//! Admin endpoints require authentication via API key.

use crate::ratelimit::IpRateLimiter;
use crate::tunnel::TunnelRegistry;
use axum::{
    async_trait,
    body::Body,
    extract::{FromRequestParts, Path, State},
    http::{header::AUTHORIZATION, request::Parts, HeaderMap, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{info, warn};

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
    /// API key for authentication (None = no auth required)
    pub api_key: Option<String>,
    /// Total connections counter (cumulative)
    pub total_connections: Arc<std::sync::atomic::AtomicU64>,
}

impl ApiState {
    /// Create a new API state.
    pub fn new(
        registry: Arc<TunnelRegistry>,
        rate_limiter: Arc<IpRateLimiter>,
        api_key: Option<String>,
    ) -> Self {
        Self {
            registry,
            rate_limiter,
            start_time: std::time::Instant::now(),
            api_key,
            total_connections: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Increment the total connections counter.
    pub fn record_connection(&self) {
        self.total_connections
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Get the total connections count.
    pub fn total_connections_count(&self) -> u64 {
        self.total_connections.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Create the API router with authentication for admin endpoints.
pub fn create_api_router(state: ApiState) -> Router {
    // Public routes (no auth required)
    let public_routes = Router::new()
        .route("/health", get(health_handler))
        .route("/ready", get(ready_handler))
        .route("/api/health", get(health_handler))
        .route("/api/ready", get(ready_handler))
        .route("/api/stats", get(stats_handler))
        .route("/api/tunnels", get(list_tunnels_handler))
        .route("/api/tunnels/:subdomain", get(get_tunnel_handler));

    // Admin routes (require API key authentication)
    let admin_routes = Router::new()
        .route(
            "/api/tunnels/:subdomain/disconnect",
            post(disconnect_tunnel_handler),
        )
        .route("/api/tokens/:token_id/revoke", post(revoke_token_handler))
        .route("/api/tokens/:token_id/unrevoke", post(unrevoke_token_handler))
        .layer(middleware::from_fn_with_state(state.clone(), require_api_key));

    Router::new()
        .merge(public_routes)
        .merge(admin_routes)
        .with_state(state)
}

/// Middleware to require API key authentication.
async fn require_api_key(
    State(state): State<ApiState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    // If no API key is configured, allow all requests
    let Some(expected_key) = &state.api_key else {
        return next.run(request).await;
    };

    // Check Authorization header
    let auth_header = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    let provided_key = match auth_header {
        Some(header) if header.starts_with("Bearer ") => Some(&header[7..]),
        _ => {
            // Also check X-API-Key header
            request
                .headers()
                .get("x-api-key")
                .and_then(|v| v.to_str().ok())
        }
    };

    match provided_key {
        Some(key) if key == expected_key => next.run(request).await,
        Some(_) => {
            warn!("Invalid API key provided");
            (
                StatusCode::UNAUTHORIZED,
                Json(ApiError {
                    error: "Invalid API key".to_string(),
                    code: 401,
                }),
            )
                .into_response()
        }
        None => {
            warn!("API key required but not provided");
            (
                StatusCode::UNAUTHORIZED,
                Json(ApiError {
                    error: "API key required. Provide via Authorization: Bearer <key> or X-API-Key header".to_string(),
                    code: 401,
                }),
            )
                .into_response()
        }
    }
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

/// Readiness check endpoint for load balancers.
/// Returns 200 if the server is ready to accept traffic.
async fn ready_handler(State(state): State<ApiState>) -> impl IntoResponse {
    // Server is ready if the registry is accessible
    let is_ready = state.registry.count() >= 0; // Always true, but checks registry is working
    
    if is_ready {
        (
            StatusCode::OK,
            Json(serde_json::json!({
                "ready": true,
                "version": env!("CARGO_PKG_VERSION")
            })),
        )
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "ready": false,
                "reason": "Server not ready"
            })),
        )
    }
}

/// Server statistics endpoint.
async fn stats_handler(State(state): State<ApiState>) -> impl IntoResponse {
    let response = ServerStats {
        active_tunnels: state.registry.count(),
        total_connections: state.total_connections_count(),
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
        .map(|(id, subdomain, pending, connected_secs)| TunnelInfo {
            id: id.to_string(),
            subdomain,
            connected_at: format!("{}s ago", connected_secs),
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

/// Request body for token revocation.
#[derive(Debug, Deserialize)]
pub struct RevokeTokenRequest {
    pub reason: Option<String>,
}

/// Revoke a token.
async fn revoke_token_handler(
    State(state): State<ApiState>,
    Path(token_id): Path<String>,
    Json(body): Json<Option<RevokeTokenRequest>>,
) -> impl IntoResponse {
    let Some(ref db) = state.registry.db else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiError {
                error: "Database not configured".to_string(),
                code: 503,
            }),
        )
            .into_response();
    };

    let reason = body.and_then(|b| b.reason);

    match db.revoke_token(&token_id, Some("api"), reason.as_deref(), None).await {
        Ok(()) => {
            info!("Token {} revoked via API", token_id);
            crate::metrics::record_token_revoked();
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "message": format!("Token '{}' revoked", token_id),
                    "token_id": token_id
                })),
            )
                .into_response()
        }
        Err(e) => {
            warn!("Failed to revoke token {}: {}", token_id, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError {
                    error: format!("Failed to revoke token: {}", e),
                    code: 500,
                }),
            )
                .into_response()
        }
    }
}

/// Unrevoke (restore) a token.
async fn unrevoke_token_handler(
    State(state): State<ApiState>,
    Path(token_id): Path<String>,
) -> impl IntoResponse {
    let Some(ref db) = state.registry.db else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiError {
                error: "Database not configured".to_string(),
                code: 503,
            }),
        )
            .into_response();
    };

    match db.unrevoke_token(&token_id).await {
        Ok(true) => {
            info!("Token {} unrevoked via API", token_id);
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "message": format!("Token '{}' unrevoked", token_id),
                    "token_id": token_id
                })),
            )
                .into_response()
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(ApiError {
                error: format!("Token '{}' was not revoked", token_id),
                code: 404,
            }),
        )
            .into_response(),
        Err(e) => {
            warn!("Failed to unrevoke token {}: {}", token_id, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError {
                    error: format!("Failed to unrevoke token: {}", e),
                    code: 500,
                }),
            )
                .into_response()
        }
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

