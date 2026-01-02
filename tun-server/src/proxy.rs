//! HTTP reverse proxy for tunneled traffic.

use crate::ratelimit::{IpRateLimiter, RateLimitLayer};
use crate::tls;
use crate::tunnel::TunnelRegistry;
use anyhow::Result;
use axum::{
    body::Body,
    extract::{Host, State},
    http::{Request, Response, StatusCode},
    routing::any,
    Router,
};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;
use tracing::{debug, error, info, warn};
use tun_core::protocol::{HttpMethod, HttpRequestData, HttpResponseData, Message, RequestId};

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

/// Run the proxy server with TLS.
async fn run_tls_server(
    addr: &str,
    app: Router,
    tls_config: ProxyTlsConfig,
) -> Result<()> {
    let rustls_config = tls::load_tls_config(&tls_config.cert_path, &tls_config.key_path)?;
    let tls_acceptor = TlsAcceptor::from(rustls_config);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("Proxy server listening on {} (TLS enabled)", addr);

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

            // Serve the connection
            if let Err(e) = http1::Builder::new()
                .serve_connection(io, service)
                .await
            {
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

    // Check if this is a WebSocket upgrade request
    let is_websocket = is_websocket_upgrade(&request);
    
    if is_websocket {
        debug!("WebSocket upgrade detected for tunnel {}", tunnel.id);
        // For WebSocket upgrades, we need special handling
        // The initial HTTP upgrade request is forwarded, then frames are passed through
    }

    // Convert the request to our protocol format
    let http_request = match convert_request(request, registry.config.body_size_limit).await {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to convert request: {}", e);
            return error_response(StatusCode::BAD_REQUEST, &format!("Failed to process request: {}", e));
        }
    };

    // Send request through tunnel and wait for response
    let request_id = RequestId::new();
    let msg = if is_websocket {
        Message::websocket_upgrade(request_id, http_request)
    } else {
        Message::http_request(request_id, http_request)
    };

    match tunnel.send_request(msg).await {
        Ok(response_msg) => convert_response(response_msg),
        Err(e) => {
            error!("Tunnel request failed: {}", e);
            error_response(StatusCode::BAD_GATEWAY, "Failed to reach upstream service")
        }
    }
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

