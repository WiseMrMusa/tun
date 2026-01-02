//! HTTP reverse proxy for tunneled traffic.
//!
//! Supports both HTTP/1.1 and HTTP/2 via ALPN negotiation when TLS is enabled.
//! Also supports WebSocket upgrade and frame forwarding.
//!
//! Integrates middleware for:
//! - Rate limiting (per-IP)
//! - Request validation (XSS, SQL injection detection)
//! - Request/response transformation (headers, paths)
//! - IP filtering (allow/block lists)
//! - Per-subdomain ACL (rate limits, max connections)
//! - Per-path body size limits

use crate::acl::{AclDenied, AclManager};
use crate::ipfilter::IpFilter;
use crate::limits::BodyLimiter;
use crate::metrics;
use crate::ratelimit::{IpRateLimiter, RateLimitLayer};
use crate::tls;
pub use crate::transform::TransformConfig;
use crate::transform::TransformLayer;
use crate::tunnel::TunnelRegistry;
pub use crate::validation::ValidationConfig;
use crate::validation::RequestValidator;
use crate::websocket::{frame_to_ws_message, ws_message_to_frame};
use anyhow::Result;
use axum::{
    body::Body,
    extract::{
        ws::{Message as WsMessage, WebSocket, WebSocketUpgrade},
        ConnectInfo, Host, State,
    },
    http::{Request, Response, StatusCode},
    response::IntoResponse,
    routing::any,
    Router,
};
use futures_util::{SinkExt, StreamExt};
use hyper::service::service_fn;
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;
use tracing::{debug, error, info, warn};
use tun_core::protocol::{
    HttpMethod, HttpRequestData, HttpResponseData, HttpVersion, Message, Payload, RequestId,
    StreamChunkData,
};

/// TLS configuration for the proxy server.
#[derive(Clone)]
pub struct ProxyTlsConfig {
    pub cert_path: String,
    pub key_path: String,
}

/// Application state shared across all handlers.
#[derive(Clone)]
pub struct AppState {
    /// Tunnel registry for routing requests
    pub registry: Arc<TunnelRegistry>,
    /// IP filter for allow/block lists
    pub ip_filter: Arc<IpFilter>,
    /// ACL manager for per-subdomain access control
    pub acl_manager: Arc<AclManager>,
    /// Body size limiter for per-path limits
    pub body_limiter: Arc<BodyLimiter>,
    /// Request validator for security checks
    pub validator: Arc<RequestValidator>,
}

impl AppState {
    /// Create new application state with all middleware components.
    pub fn new(
        registry: Arc<TunnelRegistry>,
        ip_filter: Arc<IpFilter>,
        acl_manager: Arc<AclManager>,
        body_limiter: Arc<BodyLimiter>,
        validator: Arc<RequestValidator>,
    ) -> Self {
        Self {
            registry,
            ip_filter,
            acl_manager,
            body_limiter,
            validator,
        }
    }
}

/// Run the HTTP proxy server for public traffic with full middleware stack.
pub async fn run_proxy_server(
    addr: &str,
    registry: Arc<TunnelRegistry>,
    rate_limiter: Arc<IpRateLimiter>,
) -> Result<()> {
    // Create default middleware components if not configured
    let ip_filter = Arc::new(IpFilter::allow_all());
    let acl_manager = Arc::new(AclManager::new());
    let body_limiter = Arc::new(BodyLimiter::new(
        crate::limits::BodyLimitConfig::new(registry.config.body_size_limit),
    ));
    let validator = Arc::new(RequestValidator::allow_all());

    run_proxy_server_with_middleware(
        addr,
        registry,
        rate_limiter,
        ip_filter,
        acl_manager,
        body_limiter,
        validator,
        TransformConfig::with_defaults(),
    )
    .await
}

/// Run the HTTP proxy server with explicit middleware configuration.
pub async fn run_proxy_server_with_middleware(
    addr: &str,
    registry: Arc<TunnelRegistry>,
    rate_limiter: Arc<IpRateLimiter>,
    ip_filter: Arc<IpFilter>,
    acl_manager: Arc<AclManager>,
    body_limiter: Arc<BodyLimiter>,
    validator: Arc<RequestValidator>,
    transform_config: TransformConfig,
) -> Result<()> {
    // Check if TLS is configured
    let tls_config = if registry.config.proxy_tls {
        match (&registry.config.cert_path, &registry.config.key_path) {
            (Some(cert), Some(key)) => Some(ProxyTlsConfig {
                cert_path: cert.clone(),
                key_path: key.clone(),
            }),
            _ => {
                warn!("proxy_tls enabled but cert_path or key_path not provided, falling back to plain HTTP");
                None
            }
        }
    } else {
        None
    };

    // Create shared application state
    let state = AppState::new(registry, ip_filter, acl_manager, body_limiter, validator);

    // Build the router with middleware stack
    // Order matters: outermost layer runs first
    // NOTE: The proxy_handler already detects and handles WebSocket upgrades
    // by passing them through the tunnel. The websocket_upgrade_handler is for
    // frame-level relay when we need finer control.
    let app = Router::new()
        .route("/", any(proxy_handler))
        .route("/*path", any(proxy_handler))
        // Apply transformation middleware (adds headers, rewrites paths)
        .layer(TransformLayer::new(transform_config))
        // Apply rate limiting (per-IP)
        .layer(RateLimitLayer::from_limiter(rate_limiter))
        .with_state(state);

    info!(
        "Proxy middleware stack: RateLimiting -> Transform -> IPFilter -> ACL -> BodyLimits -> Validation"
    );

    if let Some(tls_cfg) = tls_config {
        run_tls_server(addr, app, tls_cfg).await
    } else {
        run_plain_server(addr, app).await
    }
}

/// Run the proxy server with TLS (supports HTTP/1.1 and HTTP/2 via ALPN).
async fn run_tls_server(
    addr: &str,
    app: Router,
    tls_config: ProxyTlsConfig,
) -> Result<()> {
    // Load TLS config with ALPN for HTTP/2 + HTTP/1.1 support
    let rustls_config = tls::load_tls_config(&tls_config.cert_path, &tls_config.key_path)?;
    let tls_acceptor = TlsAcceptor::from(rustls_config);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("Proxy server listening on {} (TLS enabled, HTTP/2 + HTTP/1.1)", addr);

    loop {
        let (tcp_stream, remote_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                warn!("Failed to accept connection: {}", e);
                continue;
            }
        };

        let tls_acceptor = tls_acceptor.clone();
        let app = app.clone();

        tokio::spawn(async move {
            // Perform TLS handshake
            let tls_stream = match tls_acceptor.accept(tcp_stream).await {
                Ok(stream) => stream,
                Err(e) => {
                    debug!("TLS handshake failed from {}: {}", remote_addr, e);
                    return;
                }
            };

            // Check negotiated ALPN protocol for logging
            let alpn = tls_stream.get_ref().1.alpn_protocol();
            if let Some(proto) = alpn {
                debug!(
                    "Connection from {} using protocol: {}",
                    remote_addr,
                    String::from_utf8_lossy(proto)
                );
            }

            let io = TokioIo::new(tls_stream);

            let service = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                // Convert hyper::Request to http::Request
                let (parts, body) = req.into_parts();
                let body = Body::new(body);
                let req = Request::from_parts(parts, body);
                
                let app = app.clone();
                async move {
                    let resp = app.oneshot(req).await.map_err(|e| {
                        error!("Service error: {}", e);
                        e
                    })?;
                    
                    // Convert axum Response to hyper Response  
                    Ok::<_, Infallible>(resp)
                }
            });

            // Use auto builder to support both HTTP/1.1 and HTTP/2
            // The protocol is selected based on ALPN negotiation during TLS handshake
            let builder = AutoBuilder::new(TokioExecutor::new());
            
            if let Err(e) = builder.serve_connection(io, service).await {
                debug!("Connection error from {}: {}", remote_addr, e);
            }
        });
    }
}

/// Run the proxy server without TLS.
async fn run_plain_server(addr: &str, app: Router) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("Proxy server listening on {}", addr);

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

async fn proxy_handler(
    State(state): State<AppState>,
    Host(host): Host,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response<Body> {
    let start_time = Instant::now();
    let client_ip = extract_real_client_ip(&request, addr.ip());

    // === Phase 1.3: IP Filter Check ===
    if !state.ip_filter.is_allowed(client_ip) {
        debug!("IP {} blocked by filter", client_ip);
        metrics::record_ip_blocked(&client_ip.to_string(), "blocklist");
        return json_error_response(
            StatusCode::FORBIDDEN,
            "access_denied",
            "Access denied by IP filter",
            false,
        );
    }

    // Extract subdomain from host
    let subdomain = extract_subdomain(&host, &state.registry.config.domain);

    let subdomain = match subdomain {
        Some(s) => s,
        None => {
            debug!("No subdomain found in host: {}", host);
            return json_error_response(
                StatusCode::NOT_FOUND,
                "tunnel_not_found",
                "Tunnel not found. Use a subdomain like: abc123.your-domain.com",
                false,
            );
        }
    };

    // Find the tunnel for this subdomain
    let tunnel = match state.registry.get_by_subdomain(&subdomain) {
        Some(t) => t,
        None => {
            debug!("No tunnel found for subdomain: {}", subdomain);
            return json_error_response(
                StatusCode::NOT_FOUND,
                "tunnel_not_found",
                &format!("Tunnel '{}' not found or not connected", subdomain),
                false,
            );
        }
    };

    let tunnel_id_str = tunnel.id.to_string();

    // === Phase 1.4: ACL Check ===
    // Estimate body size from Content-Length header for ACL check
    let content_length = request
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0);

    if let Err(denied) = state.acl_manager.check_request(&subdomain, client_ip, content_length) {
        debug!(
            "ACL denied for subdomain '{}' from IP {}: {}",
            subdomain, client_ip, denied
        );
        let (status, code, retryable) = match denied {
            AclDenied::SubdomainDisabled => (StatusCode::SERVICE_UNAVAILABLE, "subdomain_disabled", false),
            AclDenied::IpNotAllowed => (StatusCode::FORBIDDEN, "ip_not_allowed", false),
            AclDenied::RateLimitExceeded => (StatusCode::TOO_MANY_REQUESTS, "rate_limit_exceeded", true),
            AclDenied::MaxConnectionsReached => (StatusCode::SERVICE_UNAVAILABLE, "max_connections", true),
            AclDenied::BodyTooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "body_too_large", false),
        };
        metrics::record_acl_denied(&subdomain, &denied.to_string());
        return json_error_response(status, code, &denied.to_string(), retryable);
    }

    debug!(
        "Proxying request to tunnel {} (subdomain: {})",
        tunnel.id, subdomain
    );

    // Check if this is a WebSocket upgrade request
    let is_websocket = is_websocket_upgrade(&request);

    // === Phase 1.5: Per-path body limit ===
    let path = request.uri().path().to_string();
    let body_limit = state.body_limiter.get_limit(&path);

    // Convert the request to our protocol format
    let http_request = match convert_request(request, body_limit).await {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to convert request: {}", e);
            return json_error_response(
                StatusCode::BAD_REQUEST,
                "request_error",
                &format!("Failed to process request: {}", e),
                false,
            );
        }
    };

    // === Request Validation ===
    let headers_vec: Vec<(String, String)> = http_request
        .headers
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let validation_result = state.validator.validate(
        &headers_vec,
        Some(&http_request.body),
        Some(http_request.body.len()),
    );
    if !validation_result.is_valid() {
        if let crate::validation::ValidationResult::Invalid(reason) = validation_result {
            warn!("Request validation failed: {}", reason);
            metrics::record_validation_failure(&subdomain, &reason);
            return json_error_response(
                StatusCode::BAD_REQUEST,
                "validation_failed",
                &reason,
                false,
            );
        }
    }

    // Record request body size
    let request_body_size = http_request.body.len();
    metrics::record_request_body_size(request_body_size);

    // Send request through tunnel and wait for response
    let request_id = RequestId::new();
    let msg = if is_websocket {
        debug!("WebSocket upgrade detected for tunnel {}", tunnel.id);
        Message::websocket_upgrade(request_id, http_request)
    } else {
        Message::http_request(request_id, http_request)
    };

    match tunnel.send_request(msg).await {
        Ok(response_msg) => {
            let response = convert_response(response_msg.clone());
            let duration_ms = start_time.elapsed().as_secs_f64() * 1000.0;

            // Extract response details for metrics
            let status = response.status().as_u16();
            let response_body_size = match &response_msg.payload {
                Payload::HttpResponse(r) => r.body.len(),
                _ => 0,
            };

            metrics::record_request(
                &tunnel_id_str,
                status,
                duration_ms,
                request_body_size as u64,
                response_body_size as u64,
            );
            metrics::record_response_body_size(response_body_size);

            response
        }
        Err(e) => {
            let duration_ms = start_time.elapsed().as_secs_f64() * 1000.0;
            error!("Tunnel request failed: {}", e);

            // Check if it's a timeout
            if e.to_string().contains("timeout") {
                metrics::record_request_timeout(&tunnel_id_str);
            } else {
                metrics::record_upstream_error(&tunnel_id_str, "tunnel_error");
            }
            metrics::record_request(
                &tunnel_id_str,
                502,
                duration_ms,
                request_body_size as u64,
                0,
            );

            json_error_response(
                StatusCode::BAD_GATEWAY,
                "upstream_error",
                "Failed to reach upstream service",
                true,
            )
        }
    }
}

/// Extract real client IP, considering X-Forwarded-For and X-Real-IP headers.
fn extract_real_client_ip(request: &Request<Body>, fallback: IpAddr) -> IpAddr {
    // Check X-Forwarded-For header first
    if let Some(forwarded_for) = request.headers().get("x-forwarded-for") {
        if let Ok(value) = forwarded_for.to_str() {
            if let Some(ip_str) = value.split(',').next() {
                if let Ok(ip) = ip_str.trim().parse::<IpAddr>() {
                    return ip;
                }
            }
        }
    }

    // Check X-Real-IP header
    if let Some(real_ip) = request.headers().get("x-real-ip") {
        if let Ok(value) = real_ip.to_str() {
            if let Ok(ip) = value.parse::<IpAddr>() {
                return ip;
            }
        }
    }

    fallback
}

/// WebSocket upgrade handler - this is called when we need to do frame-level relay
/// TODO(Phase 4): Wire this up for full WebSocket frame relay
#[allow(dead_code)]
async fn websocket_upgrade_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Host(host): Host,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    let client_ip = addr.ip();

    // IP filter check for WebSocket upgrades
    if !state.ip_filter.is_allowed(client_ip) {
        debug!("IP {} blocked by filter for WebSocket", client_ip);
        return json_error_response(StatusCode::FORBIDDEN, "access_denied", "Access denied", false)
            .into_response();
    }

    let subdomain = extract_subdomain(&host, &state.registry.config.domain);

    let subdomain = match subdomain {
        Some(s) => s,
        None => {
            return json_error_response(
                StatusCode::NOT_FOUND,
                "tunnel_not_found",
                "Tunnel not found",
                false,
            )
            .into_response();
        }
    };

    // ACL check for WebSocket connections
    if let Err(denied) = state.acl_manager.check_request(&subdomain, client_ip, 0) {
        return json_error_response(
            StatusCode::FORBIDDEN,
            "acl_denied",
            &denied.to_string(),
            false,
        )
        .into_response();
    }

    let tunnel = match state.registry.get_by_subdomain(&subdomain) {
        Some(t) => t,
        None => {
            return json_error_response(
                StatusCode::NOT_FOUND,
                "tunnel_not_found",
                &format!("Tunnel '{}' not found", subdomain),
                false,
            )
            .into_response();
        }
    };

    let request_id = RequestId::new();
    metrics::record_websocket_connected(&tunnel.id.to_string(), &subdomain);

    ws.on_upgrade(move |socket| handle_websocket_relay(socket, tunnel, request_id))
}

/// Handle bidirectional WebSocket frame relay.
/// TODO(Phase 4): This is used by websocket_upgrade_handler for frame-level relay
#[allow(dead_code)]
async fn handle_websocket_relay(
    socket: WebSocket,
    tunnel: Arc<crate::tunnel::TunnelConnection>,
    request_id: RequestId,
) {
    let (mut ws_tx, mut ws_rx) = socket.split();
    
    // Register this WebSocket session with the tunnel
    let mut from_tunnel_rx = tunnel.register_websocket_session(request_id);
    
    info!("WebSocket relay started for session {}", request_id);
    
    // Spawn task to forward frames from tunnel client to public client
    let tunnel_to_client = tokio::spawn(async move {
        while let Some(frame) = from_tunnel_rx.recv().await {
            let ws_msg = frame_to_ws_message(frame);
            if ws_tx.send(ws_msg).await.is_err() {
                break;
            }
        }
    });
    
    // Forward frames from public client to tunnel client
    let tunnel_clone = tunnel.clone();
    while let Some(result) = ws_rx.next().await {
        match result {
            Ok(msg) => {
                if let Some(frame) = ws_message_to_frame(&msg) {
                    let frame_msg = Message::websocket_frame(request_id, frame);
                    if tunnel_clone.send_message(frame_msg).await.is_err() {
                        break;
                    }
                    
                    // Check for close frame
                    if matches!(msg, WsMessage::Close(_)) {
                        break;
                    }
                }
            }
            Err(e) => {
                debug!("WebSocket receive error: {}", e);
                break;
            }
        }
    }
    
    // Clean up
    tunnel_to_client.abort();
    tunnel.unregister_websocket_session(request_id);
    
    // Notify tunnel client that WebSocket is closing
    let close_msg = Message::close(request_id);
    let _ = tunnel.send_message(close_msg).await;
    
    info!("WebSocket relay ended for session {}", request_id);
}

/// Check if a request is a WebSocket upgrade request.
fn is_websocket_upgrade<B>(request: &Request<B>) -> bool {
    // Check for Upgrade: websocket header
    let has_upgrade = request
        .headers()
        .get("upgrade")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);

    // Check for Connection: upgrade header
    let has_connection_upgrade = request
        .headers()
        .get("connection")
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("upgrade"))
        })
        .unwrap_or(false);

    has_upgrade && has_connection_upgrade
}

fn extract_subdomain(host: &str, domain: &str) -> Option<String> {
    // Remove port if present
    let host = host.split(':').next().unwrap_or(host);

    // Check if it's a subdomain of our domain
    if host.ends_with(domain) && host.len() > domain.len() {
        let prefix = &host[..host.len() - domain.len()];
        // Remove trailing dot
        let subdomain = prefix.trim_end_matches('.');
        if !subdomain.is_empty() && !subdomain.contains('.') {
            return Some(subdomain.to_string());
        }
    }

    // For localhost testing, check for subdomain.localhost pattern
    if host.ends_with(".localhost") {
        let subdomain = host.trim_end_matches(".localhost");
        if !subdomain.is_empty() && !subdomain.contains('.') {
            return Some(subdomain.to_string());
        }
    }

    None
}

async fn convert_request(request: Request<Body>, body_size_limit: usize) -> Result<HttpRequestData> {
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

    // Determine HTTP version
    let version = match request.version() {
        axum::http::Version::HTTP_10 => HttpVersion::Http10,
        axum::http::Version::HTTP_11 => HttpVersion::Http11,
        axum::http::Version::HTTP_2 => HttpVersion::H2,
        axum::http::Version::HTTP_3 => HttpVersion::H3,
        _ => HttpVersion::Http11,
    };

    let uri = request.uri().to_string();

    let headers: Vec<(String, String)> = request
        .headers()
        .iter()
        .filter_map(|(k, v)| {
            v.to_str().ok().map(|v| (k.to_string(), v.to_string()))
        })
        .collect();

    let body = axum::body::to_bytes(request.into_body(), body_size_limit)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to read body (limit: {} bytes): {}", body_size_limit, e))?;

    Ok(HttpRequestData {
        method,
        uri,
        headers,
        body: body.to_vec(),
        version,
    })
}

/// Streaming request handler for large bodies.
/// Sends the request headers first, then streams body chunks through the tunnel.
/// Returns the request ID for tracking the response.
#[allow(dead_code)]
async fn send_request_streaming(
    tunnel: &Arc<crate::tunnel::TunnelConnection>,
    request: Request<Body>,
    streaming_threshold: usize,
    chunk_size: usize,
) -> Result<(RequestId, usize)> {
    use futures_util::stream::StreamExt;

    let (parts, body) = request.into_parts();

    let method = match parts.method.as_str() {
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

    let version = match parts.version {
        axum::http::Version::HTTP_10 => HttpVersion::Http10,
        axum::http::Version::HTTP_11 => HttpVersion::Http11,
        axum::http::Version::HTTP_2 => HttpVersion::H2,
        axum::http::Version::HTTP_3 => HttpVersion::H3,
        _ => HttpVersion::Http11,
    };

    let headers: Vec<(String, String)> = parts
        .headers
        .iter()
        .filter_map(|(k, v)| {
            v.to_str().ok().map(|v| (k.to_string(), v.to_string()))
        })
        .collect();

    let uri = parts.uri.to_string();
    let request_id = RequestId::new();

    // Check Content-Length to decide whether to stream
    let content_length = parts
        .headers
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0);

    // If body is small enough, don't use streaming
    if content_length < streaming_threshold {
        let body_bytes = axum::body::to_bytes(body, streaming_threshold)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to read body: {}", e))?;

        let http_request = HttpRequestData {
            method,
            uri,
            headers,
            body: body_bytes.to_vec(),
            version,
        };

        let msg = Message::http_request(request_id, http_request);
        tunnel.send_message(msg).await?;

        return Ok((request_id, body_bytes.len()));
    }

    // For large bodies, send the request with empty body first
    let http_request = HttpRequestData {
        method,
        uri,
        headers,
        body: vec![], // Empty body - will be streamed
        version,
    };

    let msg = Message::http_request(request_id, http_request);
    tunnel.send_message(msg).await?;

    // Stream the body in chunks
    let mut body_stream = body.into_data_stream();
    let mut chunk_index = 0u32;
    let mut total_bytes = 0usize;
    let mut buffer = Vec::with_capacity(chunk_size);

    while let Some(chunk_result) = body_stream.next().await {
        let chunk = chunk_result.map_err(|e| anyhow::anyhow!("Error reading body chunk: {}", e))?;
        buffer.extend_from_slice(&chunk);
        total_bytes += chunk.len();

        // Send complete chunks
        while buffer.len() >= chunk_size {
            let to_send: Vec<u8> = buffer.drain(..chunk_size).collect();
            let stream_chunk = StreamChunkData {
                chunk_index,
                is_final: false,
                data: to_send,
            };
            let msg = Message::stream_chunk(request_id, stream_chunk);
            tunnel.send_message(msg).await?;
            
            metrics::record_stream_chunk(&tunnel.id.to_string(), chunk_size);
            chunk_index += 1;
        }
    }

    // Send any remaining data as the final chunk
    let stream_chunk = StreamChunkData {
        chunk_index,
        is_final: true,
        data: buffer,
    };
    let msg = Message::stream_chunk(request_id, stream_chunk);
    tunnel.send_message(msg).await?;

    // Send stream end marker
    let msg = Message::stream_end(request_id);
    tunnel.send_message(msg).await?;

    debug!(
        "Streamed {} bytes in {} chunks for request {}",
        total_bytes, chunk_index + 1, request_id
    );

    Ok((request_id, total_bytes))
}

fn convert_response(msg: Message) -> Response<Body> {
    use tun_core::protocol::Payload;

    match msg.payload {
        Payload::HttpResponse(response_data) => build_response(response_data),
        Payload::Error { code, message } => {
            error_response(
                StatusCode::from_u16(code as u16).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                &message,
            )
        }
        _ => error_response(StatusCode::INTERNAL_SERVER_ERROR, "Invalid response from tunnel"),
    }
}

fn build_response(data: HttpResponseData) -> Response<Body> {
    let mut builder = Response::builder()
        .status(StatusCode::from_u16(data.status).unwrap_or(StatusCode::OK));

    for (key, value) in data.headers {
        // Skip hop-by-hop headers
        let key_lower = key.to_lowercase();
        if key_lower == "transfer-encoding"
            || key_lower == "connection"
            || key_lower == "keep-alive"
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

/// Create a structured JSON error response (Phase 8: Structured Error Responses).
fn json_error_response(
    status: StatusCode,
    error_code: &str,
    message: &str,
    retryable: bool,
) -> Response<Body> {
    let body = serde_json::json!({
        "error": {
            "code": error_code,
            "message": message,
            "status": status.as_u16(),
            "retryable": retryable,
        }
    });

    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap_or_else(|_| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"error":{"code":"internal_error","message":"Internal server error"}}"#))
                .unwrap()
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_subdomain() {
        assert_eq!(
            extract_subdomain("abc123.tunnel.example.com", "tunnel.example.com"),
            Some("abc123".to_string())
        );

        assert_eq!(
            extract_subdomain("abc123.localhost", "localhost"),
            Some("abc123".to_string())
        );

        assert_eq!(
            extract_subdomain("abc123.localhost:8000", "localhost"),
            Some("abc123".to_string())
        );

        assert_eq!(
            extract_subdomain("tunnel.example.com", "tunnel.example.com"),
            None
        );

        assert_eq!(extract_subdomain("other.com", "tunnel.example.com"), None);
    }
}

