//! Request/response transformation middleware.
//!
//! This module provides configurable middleware for transforming HTTP
//! requests and responses as they pass through the tunnel.

use axum::{
    body::Body,
    http::{HeaderName, HeaderValue, Request, Response},
};
use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    str::FromStr,
    task::{Context, Poll},
};
use tower::{Layer, Service};
use tracing::{debug, trace};

/// Header transformation operation.
#[derive(Debug, Clone)]
pub enum HeaderOp {
    /// Set a header (overwrite if exists).
    Set(String),
    /// Add a header (append to existing).
    Add(String),
    /// Remove a header.
    Remove,
    /// Rename a header.
    Rename(String),
}

/// Path rewrite rule.
#[derive(Debug, Clone)]
pub struct PathRewrite {
    /// Pattern to match (supports simple prefix matching).
    pub pattern: String,
    /// Replacement string.
    pub replacement: String,
}

/// Configuration for request/response transformations.
#[derive(Debug, Clone, Default)]
pub struct TransformConfig {
    /// Request header transformations (header_name -> operation).
    pub request_headers: HashMap<String, HeaderOp>,
    /// Response header transformations (header_name -> operation).
    pub response_headers: HashMap<String, HeaderOp>,
    /// Path rewrite rules (applied in order).
    pub path_rewrites: Vec<PathRewrite>,
    /// Headers to add that indicate the tunnel server.
    pub add_tunnel_headers: bool,
    /// Strip hop-by-hop headers.
    pub strip_hop_by_hop: bool,
    /// Add X-Forwarded-* headers.
    pub add_forwarded_headers: bool,
}

impl TransformConfig {
    /// Create a new configuration with sensible defaults.
    pub fn with_defaults() -> Self {
        let mut config = Self::default();
        config.strip_hop_by_hop = true;
        config.add_forwarded_headers = true;
        config
    }
}

/// A Tower layer for request/response transformation.
#[derive(Clone)]
pub struct TransformLayer {
    config: TransformConfig,
}

impl TransformLayer {
    /// Create a new transform layer.
    pub fn new(config: TransformConfig) -> Self {
        Self { config }
    }
}

impl<S> Layer<S> for TransformLayer {
    type Service = TransformService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TransformService {
            inner,
            config: self.config.clone(),
        }
    }
}

/// A Tower service that performs transformations.
#[derive(Clone)]
pub struct TransformService<S> {
    inner: S,
    config: TransformConfig,
}

impl<S> Service<Request<Body>> for TransformService<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        let config = self.config.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            // Transform request
            transform_request(&mut req, &config);

            // Call inner service
            let mut response = inner.call(req).await?;

            // Transform response
            transform_response(&mut response, &config);

            Ok(response)
        })
    }
}

/// Hop-by-hop headers that should be stripped when proxying.
static HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
];

/// Transform an incoming request.
fn transform_request(req: &mut Request<Body>, config: &TransformConfig) {
    // Strip hop-by-hop headers
    if config.strip_hop_by_hop {
        for header_name in HOP_BY_HOP_HEADERS {
            if let Ok(name) = HeaderName::from_str(header_name) {
                req.headers_mut().remove(&name);
            }
        }
        trace!("Stripped hop-by-hop headers from request");
    }

    // Apply path rewrites
    for rewrite in &config.path_rewrites {
        let path = req.uri().path().to_string();
        if path.starts_with(&rewrite.pattern) {
            let new_path = path.replacen(&rewrite.pattern, &rewrite.replacement, 1);
            if let Ok(uri) = new_path.parse() {
                *req.uri_mut() = uri;
                debug!("Rewrote path from {} to {}", path, new_path);
            }
        }
    }

    // Apply header transformations
    apply_header_transforms(req.headers_mut(), &config.request_headers);

    // Add forwarded headers
    if config.add_forwarded_headers {
        // Note: In a real implementation, you'd get the actual client IP
        // from ConnectInfo or X-Forwarded-For chain
        if !req.headers().contains_key("x-forwarded-proto") {
            if let Ok(value) = HeaderValue::from_str("https") {
                req.headers_mut().insert("x-forwarded-proto", value);
            }
        }
    }

    // Add tunnel identification headers
    if config.add_tunnel_headers {
        let value = HeaderValue::from_static("tun-server");
        req.headers_mut().insert("x-tunnel-server", value);
    }
}

/// Transform an outgoing response.
fn transform_response(res: &mut Response<Body>, config: &TransformConfig) {
    // Strip hop-by-hop headers
    if config.strip_hop_by_hop {
        for header_name in HOP_BY_HOP_HEADERS {
            if let Ok(name) = HeaderName::from_str(header_name) {
                res.headers_mut().remove(&name);
            }
        }
        trace!("Stripped hop-by-hop headers from response");
    }

    // Apply header transformations
    apply_header_transforms(res.headers_mut(), &config.response_headers);

    // Add server identification header
    if config.add_tunnel_headers {
        let value = HeaderValue::from_static("tun-server");
        res.headers_mut()
            .entry("x-served-by")
            .or_insert(value);
    }
}

/// Apply header transformations to a header map.
fn apply_header_transforms(
    headers: &mut axum::http::HeaderMap,
    transforms: &HashMap<String, HeaderOp>,
) {
    for (name, op) in transforms {
        if let Ok(header_name) = HeaderName::from_str(name) {
            match op {
                HeaderOp::Set(value) => {
                    if let Ok(header_value) = HeaderValue::from_str(value) {
                        headers.insert(header_name, header_value);
                        trace!("Set header {}: {}", name, value);
                    }
                }
                HeaderOp::Add(value) => {
                    if let Ok(header_value) = HeaderValue::from_str(value) {
                        headers.append(header_name, header_value);
                        trace!("Added header {}: {}", name, value);
                    }
                }
                HeaderOp::Remove => {
                    headers.remove(&header_name);
                    trace!("Removed header {}", name);
                }
                HeaderOp::Rename(new_name) => {
                    if let Some(value) = headers.remove(&header_name) {
                        if let Ok(new_header_name) = HeaderName::from_str(new_name) {
                            headers.insert(new_header_name, value);
                            trace!("Renamed header {} to {}", name, new_name);
                        }
                    }
                }
            }
        }
    }
}

/// Builder for creating transform configurations.
#[derive(Default)]
pub struct TransformConfigBuilder {
    config: TransformConfig,
}

impl TransformConfigBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Start with sensible defaults.
    pub fn with_defaults(mut self) -> Self {
        self.config = TransformConfig::with_defaults();
        self
    }

    /// Add a request header transformation.
    pub fn request_header(mut self, name: &str, op: HeaderOp) -> Self {
        self.config.request_headers.insert(name.to_string(), op);
        self
    }

    /// Add a response header transformation.
    pub fn response_header(mut self, name: &str, op: HeaderOp) -> Self {
        self.config.response_headers.insert(name.to_string(), op);
        self
    }

    /// Add a path rewrite rule.
    pub fn path_rewrite(mut self, pattern: &str, replacement: &str) -> Self {
        self.config.path_rewrites.push(PathRewrite {
            pattern: pattern.to_string(),
            replacement: replacement.to_string(),
        });
        self
    }

    /// Enable tunnel identification headers.
    pub fn add_tunnel_headers(mut self, enable: bool) -> Self {
        self.config.add_tunnel_headers = enable;
        self
    }

    /// Enable stripping hop-by-hop headers.
    pub fn strip_hop_by_hop(mut self, enable: bool) -> Self {
        self.config.strip_hop_by_hop = enable;
        self
    }

    /// Enable adding X-Forwarded-* headers.
    pub fn add_forwarded_headers(mut self, enable: bool) -> Self {
        self.config.add_forwarded_headers = enable;
        self
    }

    /// Build the configuration.
    pub fn build(self) -> TransformConfig {
        self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transform_config_builder() {
        let config = TransformConfigBuilder::new()
            .with_defaults()
            .request_header("x-custom", HeaderOp::Set("value".to_string()))
            .response_header("server", HeaderOp::Remove)
            .path_rewrite("/api/v1", "/api/v2")
            .add_tunnel_headers(true)
            .build();

        assert!(config.strip_hop_by_hop);
        assert!(config.add_forwarded_headers);
        assert!(config.add_tunnel_headers);
        assert_eq!(config.path_rewrites.len(), 1);
        assert!(config.request_headers.contains_key("x-custom"));
        assert!(config.response_headers.contains_key("server"));
    }
}

