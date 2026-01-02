//! HTTP reverse proxy for tunneled traffic.
//!
//! Supports both HTTP/1.1 and HTTP/2 via ALPN negotiation when TLS is enabled.
//! Also supports WebSocket upgrade and frame forwarding.

use crate::metrics;
use crate::ratelimit::{IpRateLimiter, RateLimitLayer};
use crate::tls;
use crate::tunnel::TunnelRegistry;
use crate::websocket::{frame_to_ws_message, ws_message_to_frame};
use anyhow::Result;
use std::time::Instant;
use axum::{
    body::Body,
    extract::{
        ws::{Message as WsMessage, WebSocket, WebSocketUpgrade},
        Host, State,
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
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;
use tracing::{debug, error, info, warn};
use tun_core::protocol::{
    HttpMethod, HttpRequestData, HttpResponseData, HttpVersion, Message, Payload, RequestId,
};

/// TLS configuration for the proxy server.
#[derive(Clone)]
pub struct ProxyTlsConfig {
    pub cert_path: String,
    pub key_path: String,
}

/// Run the HTTP proxy server for public traffic.
pub async fn run_proxy_server(
    addr: &str,
    registry: Arc<TunnelRegistry>,
    rate_limiter: Arc<IpRateLimiter>,
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

    let app = Router::new()
        .route("/", any(proxy_handler))
        .route("/*path", any(proxy_handler))
        .layer(RateLimitLayer::from_limiter(rate_limiter))
        .with_state(registry);

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

    axum::serve(listener, app).await?;
    Ok(())
}

async fn proxy_handler(
    State(registry): State<Arc<TunnelRegistry>>,
    Host(host): Host,
    request: Request<Body>,
) -> Response<Body> {
    let start_time = Instant::now();
    
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

    let tunnel_id_str = tunnel.id.to_string();

    debug!(
        "Proxying request to tunnel {} (subdomain: {})",
        tunnel.id, subdomain
    );

    // Check if this is a WebSocket upgrade request
    let is_websocket = is_websocket_upgrade(&request);

    // Convert the request to our protocol format
    let http_request = match convert_request(request, registry.config.body_size_limit).await {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to convert request: {}", e);
            return error_response(StatusCode::BAD_REQUEST, &format!("Failed to process request: {}", e));
        }
    };

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
            
            metrics::record_request(&tunnel_id_str, status, duration_ms, request_body_size as u64, response_body_size as u64);
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
            metrics::record_request(&tunnel_id_str, 502, duration_ms, request_body_size as u64, 0);
            
            error_response(StatusCode::BAD_GATEWAY, "Failed to reach upstream service")
        }
    }
}

/// WebSocket upgrade handler - this is called when we need to do frame-level relay
async fn websocket_upgrade_handler(
    ws: WebSocketUpgrade,
    State(registry): State<Arc<TunnelRegistry>>,
    Host(host): Host,
) -> impl IntoResponse {
    let subdomain = extract_subdomain(&host, &registry.config.domain);
    
    let subdomain = match subdomain {
        Some(s) => s,
        None => {
            return error_response(StatusCode::NOT_FOUND, "Tunnel not found").into_response();
        }
    };

    let tunnel = match registry.get_by_subdomain(&subdomain) {
        Some(t) => t,
        None => {
            return error_response(StatusCode::NOT_FOUND, &format!("Tunnel '{}' not found", subdomain)).into_response();
        }
    };

    let request_id = RequestId::new();
    
    ws.on_upgrade(move |socket| handle_websocket_relay(socket, tunnel, request_id))
}

/// Handle bidirectional WebSocket frame relay.
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

