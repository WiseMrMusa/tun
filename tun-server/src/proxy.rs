//! HTTP reverse proxy for tunneled traffic.

use crate::tunnel::TunnelRegistry;
use anyhow::Result;
use axum::{
    body::Body,
    extract::{Host, State},
    http::{Request, Response, StatusCode},
    routing::any,
    Router,
};
use std::sync::Arc;
use tracing::{debug, error, info};
use tun_core::protocol::{HttpMethod, HttpRequestData, HttpResponseData, Message, RequestId};

/// Run the HTTP proxy server for public traffic.
pub async fn run_proxy_server(addr: &str, registry: Arc<TunnelRegistry>) -> Result<()> {
    let app = Router::new()
        .route("/", any(proxy_handler))
        .route("/*path", any(proxy_handler))
        .with_state(registry);

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

    // Convert the request to our protocol format
    let http_request = match convert_request(request).await {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to convert request: {}", e);
            return error_response(StatusCode::BAD_REQUEST, "Failed to process request");
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

async fn convert_request(request: Request<Body>) -> Result<HttpRequestData> {
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

    let body = axum::body::to_bytes(request.into_body(), 10 * 1024 * 1024)
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

