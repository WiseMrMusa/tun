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
use crate::circuit_breaker::{CircuitBreakerConfig, CircuitBreakerManager};
use crate::cluster::{route_to_peer_pooled, DbClusterCoordinator};
use crate::trace::{add_trace_headers, TraceContext};
use crate::ipfilter::IpFilter;
use crate::limits::BodyLimiter;
use crate::metrics;
use crate::ratelimit::{IpRateLimiter, RateLimitLayer};
use crate::shutdown::ShutdownSignal;
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
use std::time::{Duration, Instant};
use uuid::Uuid;
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

/// Configuration for retry behavior.
#[derive(Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    pub max_retries: u32,
    /// Base delay between retries
    pub retry_delay: Duration,
    /// HTTP status codes that are retryable
    pub retryable_status_codes: Vec<u16>,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 2,
            retry_delay: Duration::from_millis(100),
            retryable_status_codes: vec![502, 503, 504],
        }
    }
}

/// Configuration for streaming large request bodies.
#[derive(Clone)]
pub struct StreamingConfig {
    /// Threshold in bytes above which streaming is used
    pub threshold: usize,
    /// Size of each stream chunk in bytes
    pub chunk_size: usize,
}

impl Default for StreamingConfig {
    fn default() -> Self {
        Self {
            threshold: 1024 * 1024, // 1MB
            chunk_size: 64 * 1024,  // 64KB
        }
    }
}

/// Trusted proxy filter for secure X-Forwarded-For handling.
/// Only trusts forwarded headers when the direct connection is from a trusted proxy.
#[derive(Clone)]
pub struct TrustedProxyFilter {
    /// Trusted proxy IP networks
    networks: Vec<ipnet::IpNet>,
    /// If true, trust all proxies (insecure but backwards compatible)
    trust_all: bool,
}

impl TrustedProxyFilter {
    /// Create a new filter from a list of trusted proxy CIDR/IP strings.
    /// If the list is empty or None, trust all proxies (backwards compatible).
    pub fn new(proxies: Option<&[String]>) -> Self {
        match proxies {
            Some(proxies) if !proxies.is_empty() => {
                let networks: Vec<ipnet::IpNet> = proxies
                    .iter()
                    .filter_map(|s| {
                        // Try parsing as CIDR first
                        if let Ok(net) = s.parse::<ipnet::IpNet>() {
                            Some(net)
                        } else if let Ok(ip) = s.parse::<IpAddr>() {
                            // Convert single IP to /32 or /128
                            Some(ipnet::IpNet::from(ip))
                        } else {
                            warn!("Invalid trusted proxy: {}", s);
                            None
                        }
                    })
                    .collect();
                
                if networks.is_empty() {
                    warn!("No valid trusted proxies configured, trusting all");
                    Self { networks: Vec::new(), trust_all: true }
                } else {
                    info!("Configured {} trusted proxy networks", networks.len());
                    Self { networks, trust_all: false }
                }
            }
            _ => {
                debug!("No trusted proxies configured, trusting all (insecure)");
                Self { networks: Vec::new(), trust_all: true }
            }
        }
    }

    /// Check if a direct connection IP is a trusted proxy.
    pub fn is_trusted(&self, ip: IpAddr) -> bool {
        if self.trust_all {
            return true;
        }
        self.networks.iter().any(|net| net.contains(&ip))
    }
}

impl Default for TrustedProxyFilter {
    fn default() -> Self {
        Self::new(None)
    }
}

/// Application state shared across all handlers.
#[derive(Clone)]
pub struct AppState {
    /// Tunnel registry for routing requests
    pub registry: Arc<TunnelRegistry>,
    /// IP filter for allow/block lists (RwLock for hot reload support)
    pub ip_filter: Arc<tokio::sync::RwLock<IpFilter>>,
    /// ACL manager for per-subdomain access control (RwLock for hot reload support)
    pub acl_manager: Arc<tokio::sync::RwLock<AclManager>>,
    /// Body size limiter for per-path limits
    pub body_limiter: Arc<BodyLimiter>,
    /// Request validator for security checks
    pub validator: Arc<RequestValidator>,
    /// Optional cluster coordinator for cross-server routing
    pub cluster_coordinator: Option<Arc<DbClusterCoordinator>>,
    /// Circuit breaker manager for tunnel health
    pub circuit_breakers: Arc<CircuitBreakerManager>,
    /// Optional shutdown signal for graceful request draining
    pub shutdown_signal: Option<ShutdownSignal>,
    /// Retry configuration
    pub retry_config: RetryConfig,
    /// Streaming configuration for large request bodies
    pub streaming_config: StreamingConfig,
    /// Trusted proxy filter for X-Forwarded-For handling
    pub trusted_proxies: Arc<TrustedProxyFilter>,
}

impl AppState {
    /// Create new application state with all middleware components.
    pub fn new(
        registry: Arc<TunnelRegistry>,
        ip_filter: Arc<tokio::sync::RwLock<IpFilter>>,
        acl_manager: Arc<tokio::sync::RwLock<AclManager>>,
        body_limiter: Arc<BodyLimiter>,
        validator: Arc<RequestValidator>,
    ) -> Self {
        Self {
            registry,
            ip_filter,
            acl_manager,
            body_limiter,
            validator,
            cluster_coordinator: None,
            circuit_breakers: Arc::new(CircuitBreakerManager::new(CircuitBreakerConfig::default())),
            shutdown_signal: None,
            retry_config: RetryConfig::default(),
            streaming_config: StreamingConfig::default(),
            trusted_proxies: Arc::new(TrustedProxyFilter::default()),
        }
    }

    /// Set the streaming configuration.
    pub fn with_streaming_config(mut self, config: StreamingConfig) -> Self {
        self.streaming_config = config;
        self
    }

    /// Set the trusted proxy filter.
    pub fn with_trusted_proxies(mut self, filter: TrustedProxyFilter) -> Self {
        self.trusted_proxies = Arc::new(filter);
        self
    }

    /// Set the cluster coordinator for cross-server routing.
    pub fn with_cluster_coordinator(mut self, coordinator: Arc<DbClusterCoordinator>) -> Self {
        self.cluster_coordinator = Some(coordinator);
        self
    }

    /// Set the shutdown signal for graceful request draining.
    pub fn with_shutdown_signal(mut self, signal: ShutdownSignal) -> Self {
        self.shutdown_signal = Some(signal);
        self
    }

    /// Set the retry configuration.
    pub fn with_retry_config(mut self, config: RetryConfig) -> Self {
        self.retry_config = config;
        self
    }

    /// Set the circuit breaker manager.
    pub fn with_circuit_breakers(mut self, manager: Arc<CircuitBreakerManager>) -> Self {
        self.circuit_breakers = manager;
        self
    }
}

/// Run the HTTP proxy server for public traffic with full middleware stack.
pub async fn run_proxy_server(
    addr: &str,
    registry: Arc<TunnelRegistry>,
    rate_limiter: Arc<IpRateLimiter>,
) -> Result<()> {
    // Create default middleware components if not configured
    let ip_filter = Arc::new(tokio::sync::RwLock::new(IpFilter::allow_all()));
    let acl_manager = Arc::new(tokio::sync::RwLock::new(AclManager::new()));
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
    ip_filter: Arc<tokio::sync::RwLock<IpFilter>>,
    acl_manager: Arc<tokio::sync::RwLock<AclManager>>,
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
    // Extract or create trace context from incoming request
    let trace_ctx = TraceContext::from_headers(request.headers());
    let request_id = trace_ctx.request_id.clone();
    
    let response = proxy_handler_inner(state, host, addr, request, &request_id, &trace_ctx).await;
    add_trace_headers(response, &trace_ctx)
}

async fn proxy_handler_inner(
    state: AppState,
    host: String,
    addr: SocketAddr,
    request: Request<Body>,
    request_id: &str,
    trace_ctx: &TraceContext,
) -> Response<Body> {
    let start_time = Instant::now();
    let client_ip = extract_real_client_ip(&request, addr.ip(), &state.trusted_proxies);
    
    // Add request ID and trace context to tracing span
    let _span = tracing::info_span!("proxy_request", 
        request_id = %request_id,
        trace_id = %trace_ctx.trace_id,
        span_id = %trace_ctx.span_id,
        parent_span_id = %trace_ctx.parent_span_id,
        method = %request.method(),
        path = %request.uri().path()
    );

    // === Shutdown Check and Connection Registration ===
    let _connection_guard = if let Some(ref signal) = state.shutdown_signal {
        if signal.is_shutting_down() {
            return json_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "shutting_down",
                "Server is shutting down, please retry on another instance",
                true,
            );
        }
        // Register connection for draining
        Some(signal.register_connection())
    } else {
        None
    };

    // === Phase 1.3: IP Filter Check ===
    if !state.ip_filter.read().await.is_allowed(client_ip) {
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
            // Tunnel not found locally - check if it's on another server in the cluster
            if let Some(ref cluster_coord) = state.cluster_coordinator {
                if let Some(peer_addr) = cluster_coord.find_tunnel_server(&subdomain).await {
                    debug!(
                        "Tunnel '{}' found on peer server {}, forwarding request",
                        subdomain, peer_addr
                    );

                    // Extract request details for forwarding
                    let method = request.method().to_string();
                    let path = request.uri().path_and_query()
                        .map(|pq| pq.to_string())
                        .unwrap_or_else(|| "/".to_string());
                    let headers: Vec<(String, String)> = request
                        .headers()
                        .iter()
                        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                        .collect();

                    // Collect body (limited for cluster forwarding)
                    let body_bytes = match axum::body::to_bytes(request.into_body(), 10 * 1024 * 1024).await {
                        Ok(bytes) => bytes.to_vec(),
                        Err(e) => {
                            warn!("Failed to read request body for cluster forwarding: {}", e);
                            return json_error_response(
                                StatusCode::BAD_REQUEST,
                                "body_read_error",
                                "Failed to read request body",
                                false,
                            );
                        }
                    };

                    // Forward to peer using pooled connection
                    match route_to_peer_pooled(&peer_addr, &method, &path, &headers, &body_bytes).await {
                        Ok((status, resp_headers, resp_body)) => {
                            let elapsed = start_time.elapsed();
                            metrics::record_request(&subdomain, status, elapsed.as_millis() as f64, body_bytes.len() as u64, resp_body.len() as u64);
                            metrics::record_cluster_forward(&peer_addr, true);

                            let mut response = Response::builder()
                                .status(StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY));

                            for (name, value) in resp_headers {
                                if let Ok(header_value) = value.parse::<axum::http::HeaderValue>() {
                                    response = response.header(&name, header_value);
                                }
                            }

                            return response
                                .body(Body::from(resp_body))
                                .unwrap_or_else(|_| {
                                    Response::builder()
                                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                                        .body(Body::from("Internal error"))
                                        .unwrap()
                                });
                        }
                        Err(e) => {
                            warn!("Failed to forward request to peer {}: {}", peer_addr, e);
                            return json_error_response(
                                StatusCode::BAD_GATEWAY,
                                "cluster_forward_error",
                                &format!("Failed to forward request to cluster peer: {}", e),
                                true,
                            );
                        }
                    }
                }
            }

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

    // === Circuit Breaker Check ===
    if !state.circuit_breakers.can_execute(&tunnel_id_str) {
        debug!("Circuit breaker OPEN for tunnel {}", tunnel_id_str);
        metrics::record_circuit_breaker_trip(&tunnel_id_str);
        return json_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "circuit_open",
            "Tunnel circuit breaker is open, please retry later",
            true,
        );
    }

    // === Phase 1.4: ACL Check ===
    // Estimate body size from Content-Length header for ACL check
    let content_length = request
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0);

    if let Err(denied) = state.acl_manager.read().await.check_request(&subdomain, client_ip, content_length) {
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

    // Check content-length for streaming decision
    let content_length = request
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0);
    
    let should_stream = !is_websocket && content_length > state.streaming_config.threshold;

    // Use streaming for large request bodies
    if should_stream {
        debug!(
            "Using streaming for large request ({} bytes) to tunnel {}",
            content_length, tunnel.id
        );
        
        let streaming_result = send_request_streaming(
            &tunnel,
            request,
            state.streaming_config.threshold,
            state.streaming_config.chunk_size,
        ).await;
        
        match streaming_result {
            Ok((response_msg, total_bytes)) => {
                let duration_ms = start_time.elapsed().as_secs_f64() * 1000.0;
                metrics::record_request_body_size(total_bytes);
                
                let response = convert_response(response_msg.clone());
                let status = response.status().as_u16();
                let response_body_size = match &response_msg.payload {
                    Payload::HttpResponse(r) => r.body.len(),
                    _ => 0,
                };
                
                // Update circuit breaker
                if status < 500 {
                    state.circuit_breakers.record_success(&tunnel_id_str);
                } else {
                    state.circuit_breakers.record_failure(&tunnel_id_str);
                }
                
                metrics::record_request(
                    &tunnel_id_str,
                    status,
                    duration_ms,
                    total_bytes as u64,
                    response_body_size as u64,
                );
                metrics::record_response_body_size(response_body_size);
                
                response
            }
            Err(e) => {
                let duration_ms = start_time.elapsed().as_secs_f64() * 1000.0;
                error!("Streaming request failed: {}", e);
                
                state.circuit_breakers.record_failure(&tunnel_id_str);
                
                if e.to_string().contains("timeout") {
                    metrics::record_request_timeout(&tunnel_id_str);
                } else {
                    metrics::record_upstream_error(&tunnel_id_str, "streaming_error");
                }
                metrics::record_request(&tunnel_id_str, 502, duration_ms, content_length as u64, 0);
                
                json_error_response(
                    StatusCode::BAD_GATEWAY,
                    "streaming_error",
                    &format!("Failed to stream request: {}", e),
                    true,
                )
            }
        }
    } else {
        // Standard buffered request path
        // Convert the request to our protocol format and inject trace context
        let http_request = match convert_request(request, body_limit, Some(trace_ctx)).await {
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

        // Use retry logic for non-WebSocket requests
        let result = if is_websocket {
            // WebSocket upgrades should not be retried
            tunnel.send_request(msg).await
        } else {
            // Use retry logic with circuit breaker integration
            send_request_with_retry(
                &tunnel,
                msg,
                &state.retry_config,
                &state.circuit_breakers,
                &tunnel_id_str,
            )
            .await
        };

        match result {
            Ok(response_msg) => {
                let response = convert_response(response_msg.clone());
                let duration_ms = start_time.elapsed().as_secs_f64() * 1000.0;

                // Extract response details for metrics
                let status = response.status().as_u16();
                let response_body_size = match &response_msg.payload {
                    Payload::HttpResponse(r) => r.body.len(),
                    _ => 0,
                };

                // Circuit breaker updates are now handled in send_request_with_retry
                // Only update here for WebSocket upgrades
                if is_websocket {
                    if status < 500 {
                        state.circuit_breakers.record_success(&tunnel_id_str);
                    } else {
                        state.circuit_breakers.record_failure(&tunnel_id_str);
                    }
                }

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
}

/// Extract real client IP, considering X-Forwarded-For and X-Real-IP headers.
/// Only trusts these headers when the direct connection is from a trusted proxy.
fn extract_real_client_ip(
    request: &Request<Body>,
    direct_ip: IpAddr,
    trusted_proxies: &TrustedProxyFilter,
) -> IpAddr {
    // Only trust forwarded headers if connection is from a trusted proxy
    if !trusted_proxies.is_trusted(direct_ip) {
        debug!("Direct IP {} is not a trusted proxy, ignoring forwarded headers", direct_ip);
        return direct_ip;
    }

    // Check X-Forwarded-For header first
    if let Some(forwarded_for) = request.headers().get("x-forwarded-for") {
        if let Ok(value) = forwarded_for.to_str() {
            // X-Forwarded-For may contain multiple IPs: "client, proxy1, proxy2"
            // The first one is the original client
            if let Some(ip_str) = value.split(',').next() {
                if let Ok(ip) = ip_str.trim().parse::<IpAddr>() {
                    debug!("Using client IP {} from X-Forwarded-For", ip);
                    return ip;
                }
            }
        }
    }

    // Check X-Real-IP header
    if let Some(real_ip) = request.headers().get("x-real-ip") {
        if let Ok(value) = real_ip.to_str() {
            if let Ok(ip) = value.parse::<IpAddr>() {
                debug!("Using client IP {} from X-Real-IP", ip);
                return ip;
            }
        }
    }

    direct_ip
}

/// WebSocket upgrade handler for frame-level relay.
/// This provides more fine-grained control over WebSocket connections,
/// relaying individual frames through the tunnel rather than passing the entire connection.
/// Use this when you need to inspect or modify WebSocket frames.
pub async fn websocket_upgrade_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Host(host): Host,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    let client_ip = addr.ip();

    // IP filter check for WebSocket upgrades
    if !state.ip_filter.read().await.is_allowed(client_ip) {
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
    if let Err(denied) = state.acl_manager.read().await.check_request(&subdomain, client_ip, 0) {
        let denied_str = denied.to_string();
        return json_error_response(
            StatusCode::FORBIDDEN,
            "acl_denied",
            &denied_str,
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
/// Forwards WebSocket frames between the public client and the tunnel client.
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

async fn convert_request(
    request: Request<Body>,
    body_size_limit: usize,
    trace_ctx: Option<&TraceContext>,
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

    // Determine HTTP version
    let version = match request.version() {
        axum::http::Version::HTTP_10 => HttpVersion::Http10,
        axum::http::Version::HTTP_11 => HttpVersion::Http11,
        axum::http::Version::HTTP_2 => HttpVersion::H2,
        axum::http::Version::HTTP_3 => HttpVersion::H3,
        _ => HttpVersion::Http11,
    };

    let uri = request.uri().to_string();

    // Collect existing headers
    let mut headers: Vec<(String, String)> = request
        .headers()
        .iter()
        .filter_map(|(k, v)| {
            v.to_str().ok().map(|v| (k.to_string(), v.to_string()))
        })
        .collect();

    // Inject trace context headers for propagation
    if let Some(ctx) = trace_ctx {
        ctx.inject_headers(&mut headers);
    }

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
/// Waits for and returns the response message.
async fn send_request_streaming(
    tunnel: &Arc<crate::tunnel::TunnelConnection>,
    request: Request<Body>,
    streaming_threshold: usize,
    chunk_size: usize,
) -> Result<(Message, usize)> {
    use futures_util::stream::StreamExt;
    use tokio::sync::oneshot;

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

    // Register pending request for response handling
    let (response_tx, response_rx) = oneshot::channel();
    tunnel.pending_requests.insert(
        request_id,
        crate::tunnel::PendingRequest { response_tx },
    );

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
        tunnel.tx.send(msg).await?;

        // Wait for response with timeout
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(tunnel.request_timeout),
            response_rx,
        )
        .await
        .map_err(|_| anyhow::anyhow!("Request timeout ({}s)", tunnel.request_timeout))??;

        return Ok((response, body_bytes.len()));
    }

    // For large bodies, send the request with empty body first (indicating streaming)
    let http_request = HttpRequestData {
        method,
        uri,
        headers,
        body: vec![], // Empty body - will be streamed
        version,
    };

    let msg = Message::http_request(request_id, http_request);
    tunnel.tx.send(msg).await?;

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
            tunnel.tx.send(msg).await?;
            
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
    tunnel.tx.send(msg).await?;

    // Send stream end marker
    let msg = Message::stream_end(request_id);
    tunnel.tx.send(msg).await?;

    debug!(
        "Streamed {} bytes in {} chunks for request {}",
        total_bytes, chunk_index + 1, request_id
    );

    // Wait for response with timeout
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(tunnel.request_timeout),
        response_rx,
    )
    .await
    .map_err(|_| anyhow::anyhow!("Request timeout ({}s)", tunnel.request_timeout))??;

    Ok((response, total_bytes))
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

/// Send a request through the tunnel with retry logic.
/// Retries on connection failures and configured status codes.
async fn send_request_with_retry(
    tunnel: &Arc<crate::tunnel::TunnelConnection>,
    msg: Message,
    config: &RetryConfig,
    circuit_breakers: &CircuitBreakerManager,
    tunnel_id: &str,
) -> Result<Message, anyhow::Error> {
    let mut last_error = None;

    for attempt in 0..=config.max_retries {
        if attempt > 0 {
            debug!("Retrying request to tunnel {} (attempt {})", tunnel_id, attempt + 1);
            tokio::time::sleep(config.retry_delay).await;
        }

        match tunnel.send_request(msg.clone()).await {
            Ok(response_msg) => {
                // Check if response status is retryable
                let status = match &response_msg.payload {
                    Payload::HttpResponse(r) => r.status,
                    _ => 200,
                };

                if !config.retryable_status_codes.contains(&status) {
                    // Success - record and return
                    circuit_breakers.record_success(tunnel_id);
                    return Ok(response_msg);
                }

                // Status is retryable
                if attempt == config.max_retries {
                    // Last attempt - return whatever we got
                    circuit_breakers.record_failure(tunnel_id);
                    return Ok(response_msg);
                }

                last_error = Some(anyhow::anyhow!("Retryable status code: {}", status));
            }
            Err(e) => {
                circuit_breakers.record_failure(tunnel_id);
                last_error = Some(e);

                if attempt == config.max_retries {
                    break;
                }
            }
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("Retry exhausted")))
}

/// Add X-Request-Id header to a response.
fn add_request_id(mut response: Response<Body>, request_id: &str) -> Response<Body> {
    if let Ok(value) = request_id.parse() {
        response.headers_mut().insert("X-Request-Id", value);
    }
    response
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

/// Convert a TunnelError to an HTTP response.
/// Uses the structured error format from tun-core.
fn tunnel_error_response(err: tun_core::TunnelError) -> Response<Body> {
    let status = StatusCode::from_u16(err.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let body = err.to_json();

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

