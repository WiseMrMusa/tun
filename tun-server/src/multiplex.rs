//! Single-port multiplexed server.
//!
//! Combines control plane (WebSocket) and proxy traffic on a single port.
//! Routes based on URL path: /ws goes to control plane, everything else to proxy.

use crate::ratelimit::{IpRateLimiter, RateLimitLayer};
use crate::tunnel::TunnelRegistry;
use anyhow::Result;
use axum::{
    body::Body,
    extract::{
        ws::WebSocketUpgrade,
        ConnectInfo, Host, State,
    },
    http::{Request, Response, StatusCode},
    response::IntoResponse,
    routing::{any, get},
    Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{debug, error, info};
use tun_core::protocol::{HttpMethod, HttpRequestData, HttpResponseData, Message, RequestId};

/// State for the multiplexed server
#[derive(Clone)]
pub struct MultiplexState {
    pub registry: Arc<TunnelRegistry>,
    pub rate_limiter: Arc<IpRateLimiter>,
}

/// Run the multiplexed server on a single port.
pub async fn run_multiplexed_server(
    addr: &str,
    registry: Arc<TunnelRegistry>,
    rate_limiter: Arc<IpRateLimiter>,
) -> Result<()> {
    let state = MultiplexState {
        registry,
        rate_limiter: rate_limiter.clone(),
    };

    let app = Router::new()
        // Control plane: WebSocket endpoint at /ws
        .route("/ws", get(websocket_handler))
        // Health check
        .route("/health", get(health_handler))
        // Everything else goes to proxy
        .route("/", any(proxy_handler))
        .route("/*path", any(proxy_handler))
        .layer(RateLimitLayer::from_limiter(rate_limiter))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("Multiplexed server listening on {} (single-port mode)", addr);

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

async fn health_handler() -> &'static str {
    "OK"
}

async fn websocket_handler(
    ws: WebSocketUpgrade,
    State(state): State<MultiplexState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    let client_ip = addr.ip().to_string();
    ws.on_upgrade(move |socket| {
        crate::tunnel::handle_tunnel_connection_internal(socket, state.registry, client_ip)
    })
}

async fn proxy_handler(
    State(state): State<MultiplexState>,
    Host(host): Host,
    request: Request<Body>,
) -> Response<Body> {
    let registry = &state.registry;
    
    // Extract subdomain from host
    let subdomain = extract_subdomain(&host, &registry.config.domain);

    let subdomain = match subdomain {
        Some(s) => s,
        None => {
            debug!("No subdomain found in host: {}", host);
            return error_response(
                StatusCode::NOT_FOUND,
                "Tunnel not found. Use a subdomain like: abc123.your-domain.com",
            );
        }
    };

    // Find the tunnel for this subdomain
    let tunnel = match registry.get_by_subdomain(&subdomain) {
        Some(t) => t,
        None => {
            debug!("No tunnel found for subdomain: {}", subdomain);
            return error_response(
                StatusCode::NOT_FOUND,
                &format!("Tunnel '{}' not found or not connected", subdomain),
            );
        }
    };

    debug!(
        "Proxying request to tunnel {} (subdomain: {})",
        tunnel.id, subdomain
    );

    // Convert the request to our protocol format
    let http_request = match convert_request(request, registry.config.body_size_limit).await {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to convert request: {}", e);
            return error_response(
                StatusCode::BAD_REQUEST,
                &format!("Failed to process request: {}", e),
            );
        }
    };

    // Send request through tunnel and wait for response
    let request_id = RequestId::new();
    let msg = Message::http_request(request_id, http_request);

    match tunnel.send_request(msg).await {
        Ok(response_msg) => convert_response(response_msg),
        Err(e) => {
            error!("Tunnel request failed: {}", e);
            error_response(StatusCode::BAD_GATEWAY, "Failed to reach upstream service")
        }
    }
}

fn extract_subdomain(host: &str, domain: &str) -> Option<String> {
    let host = host.split(':').next().unwrap_or(host);

    if host.ends_with(domain) && host.len() > domain.len() {
        let prefix = &host[..host.len() - domain.len()];
        let subdomain = prefix.trim_end_matches('.');
        if !subdomain.is_empty() && !subdomain.contains('.') {
            return Some(subdomain.to_string());
        }
    }

    if host.ends_with(".localhost") {
        let subdomain = host.trim_end_matches(".localhost");
        if !subdomain.is_empty() && !subdomain.contains('.') {
            return Some(subdomain.to_string());
        }
    }

    None
}

async fn convert_request(
    request: Request<Body>,
    body_size_limit: usize,
) -> Result<HttpRequestData> {
    let method = match request.method().as_str() {
        "GET" => HttpMethod::Get,
        "POST" => HttpMethod::Post,
        "PUT" => HttpMethod::Put,
        "DELETE" => HttpMethod::Delete,
        "PATCH" => HttpMethod::Patch,
        "HEAD" => HttpMethod::Head,
        "OPTIONS" => HttpMethod::Options,
        "CONNECT" => HttpMethod::Connect,
        "TRACE" => HttpMethod::Trace,
        _ => HttpMethod::Get,
    };

    let uri = request.uri().to_string();

    let headers: Vec<(String, String)> = request
        .headers()
        .iter()
        .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.to_string(), v.to_string())))
        .collect();

    let body = axum::body::to_bytes(request.into_body(), body_size_limit)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to read body: {}", e))?;

    Ok(HttpRequestData {
        method,
        uri,
        headers,
        body: body.to_vec(),
    })
}

fn convert_response(msg: Message) -> Response<Body> {
    use tun_core::protocol::Payload;

    match msg.payload {
        Payload::HttpResponse(response_data) => build_response(response_data),
        Payload::Error { code, message } => error_response(
            StatusCode::from_u16(code as u16).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            &message,
        ),
        _ => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Invalid response from tunnel",
        ),
    }
}

fn build_response(data: HttpResponseData) -> Response<Body> {
    let mut builder =
        Response::builder().status(StatusCode::from_u16(data.status).unwrap_or(StatusCode::OK));

    for (key, value) in data.headers {
        let key_lower = key.to_lowercase();
        if key_lower == "transfer-encoding" || key_lower == "connection" || key_lower == "keep-alive"
        {
            continue;
        }

        if let Ok(header_name) = axum::http::HeaderName::try_from(key.as_str()) {
            if let Ok(header_value) = axum::http::HeaderValue::try_from(value.as_str()) {
                builder = builder.header(header_name, header_value);
            }
        }
    }

    builder.body(Body::from(data.body)).unwrap_or_else(|_| {
        Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::from("Failed to build response"))
            .unwrap()
    })
}

fn error_response(status: StatusCode, message: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        .body(Body::from(message.to_string()))
        .unwrap_or_else(|_| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("Internal error"))
                .unwrap()
        })
}

