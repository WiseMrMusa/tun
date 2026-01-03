//! Tunnel management and WebSocket control server.

use crate::config::ServerConfig;
use crate::db::TunnelDb;
use crate::metrics;
use crate::ratelimit::{IpRateLimiter, RateLimitLayer};
use crate::tls;
use crate::websocket::WebSocketManager;
use anyhow::Result;
use axum::{
    extract::{
        ws::{Message as WsMessage, WebSocket, WebSocketUpgrade},
        ConnectInfo, State,
    },
    response::IntoResponse,
    routing::get,
    Router,
};
use dashmap::DashMap;
use futures_util::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};
use tun_core::{
    auth::TokenValidator,
    protocol::{Message, MessageType, Payload, RequestId, TunnelId, WebSocketFrameData},
};

/// A pending HTTP request waiting for a response from the tunnel client.
pub struct PendingRequest {
    pub response_tx: oneshot::Sender<Message>,
}

/// Represents an active tunnel connection.
pub struct TunnelConnection {
    /// Unique tunnel identifier
    pub id: TunnelId,
    /// Subdomain for this tunnel
    pub subdomain: String,
    /// Channel to send messages to the tunnel client
    pub tx: mpsc::Sender<Message>,
    /// Pending HTTP requests waiting for responses
    pub pending_requests: DashMap<RequestId, PendingRequest>,
    /// Request timeout in seconds
    pub request_timeout: u64,
    /// WebSocket session manager for frame forwarding
    pub websocket_manager: WebSocketManager,
    /// When this tunnel was connected
    pub connected_at: std::time::Instant,
}

impl TunnelConnection {
    pub fn new(id: TunnelId, tx: mpsc::Sender<Message>, request_timeout: u64) -> Self {
        Self {
            subdomain: id.subdomain(),
            id,
            tx,
            pending_requests: DashMap::new(),
            request_timeout,
            websocket_manager: WebSocketManager::new(),
            connected_at: std::time::Instant::now(),
        }
    }

    pub fn new_with_subdomain(
        id: TunnelId,
        subdomain: String,
        tx: mpsc::Sender<Message>,
        request_timeout: u64,
    ) -> Self {
        Self {
            subdomain,
            id,
            tx,
            pending_requests: DashMap::new(),
            request_timeout,
            websocket_manager: WebSocketManager::new(),
            connected_at: std::time::Instant::now(),
        }
    }

    /// Get the duration since this tunnel was connected.
    pub fn connected_duration(&self) -> std::time::Duration {
        self.connected_at.elapsed()
    }

    /// Send an HTTP request and wait for a response.
    pub async fn send_request(&self, mut msg: Message) -> Result<Message, anyhow::Error> {
        let request_id = msg.request_id.unwrap_or_else(RequestId::new);
        msg.request_id = Some(request_id);

        let (response_tx, response_rx) = oneshot::channel();
        self.pending_requests
            .insert(request_id, PendingRequest { response_tx });

        self.tx.send(msg).await?;

        // Wait for response with configurable timeout
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(self.request_timeout),
            response_rx,
        )
        .await
        .map_err(|_| anyhow::anyhow!("Request timeout ({}s)", self.request_timeout))??;

        Ok(response)
    }

    /// Handle a response from the tunnel client.
    pub fn handle_response(&self, msg: Message) {
        if let Some(request_id) = msg.request_id {
            if let Some((_, pending)) = self.pending_requests.remove(&request_id) {
                let _ = pending.response_tx.send(msg);
            }
        }
    }

    /// Send a message to the tunnel client (for WebSocket frames).
    pub async fn send_message(&self, msg: Message) -> Result<(), anyhow::Error> {
        self.tx.send(msg).await?;
        Ok(())
    }

    /// Register a WebSocket session and return the frame receiver.
    pub fn register_websocket_session(
        &self,
        request_id: RequestId,
    ) -> mpsc::Receiver<WebSocketFrameData> {
        self.websocket_manager.register_session(request_id)
    }

    /// Unregister a WebSocket session.
    pub fn unregister_websocket_session(&self, request_id: RequestId) {
        self.websocket_manager.unregister_session(request_id);
    }

    /// Forward a WebSocket frame from the tunnel client to the public client.
    pub async fn forward_websocket_frame(&self, request_id: RequestId, frame: WebSocketFrameData) -> bool {
        self.websocket_manager.forward_to_client(request_id, frame).await
    }
}

/// Registry of all active tunnel connections.
pub struct TunnelRegistry {
    /// Map of subdomain -> tunnel connection
    tunnels_by_subdomain: DashMap<String, Arc<TunnelConnection>>,
    /// Map of tunnel ID -> tunnel connection
    tunnels_by_id: DashMap<TunnelId, Arc<TunnelConnection>>,
    /// Server configuration
    pub config: ServerConfig,
    /// Token validator
    pub token_validator: TokenValidator,
    /// Optional database for persistence
    pub db: Option<Arc<TunnelDb>>,
}

impl TunnelRegistry {
    pub fn new(config: ServerConfig, db: Option<Arc<TunnelDb>>) -> Self {
        let mut token_validator = if let Some(ref secret) = config.auth_secret {
            TokenValidator::from_hex(secret).unwrap_or_else(|_| {
                warn!("Invalid auth secret, generating new one");
                TokenValidator::default()
            })
        } else {
            let validator = TokenValidator::default();
            info!("Generated auth secret: {}", validator.secret_hex());
            info!("Use this secret to generate client tokens");
            validator
        };
        
        // Configure token TTL from config
        token_validator.set_ttl(config.token_ttl);
        info!("Token TTL: {} seconds ({} days)", config.token_ttl, config.token_ttl / 86400);

        Self {
            tunnels_by_subdomain: DashMap::new(),
            tunnels_by_id: DashMap::new(),
            config,
            token_validator,
            db,
        }
    }

    /// Register a new tunnel.
    pub async fn register(
        &self,
        tunnel: Arc<TunnelConnection>,
        token_id: &str,
        client_ip: Option<&str>,
    ) {
        info!(
            "Registering tunnel {} with subdomain {}",
            tunnel.id, tunnel.subdomain
        );
        
        // Persist to database if available
        if let Some(ref db) = self.db {
            if let Err(e) = db
                .register_tunnel(tunnel.id, &tunnel.subdomain, token_id, client_ip)
                .await
            {
                warn!("Failed to persist tunnel to database: {}", e);
            }
        }
        
        // Record metrics
        metrics::record_tunnel_connected(&tunnel.id.to_string(), &tunnel.subdomain);
        
        self.tunnels_by_subdomain
            .insert(tunnel.subdomain.clone(), tunnel.clone());
        self.tunnels_by_id.insert(tunnel.id, tunnel);
    }

    /// Unregister a tunnel.
    pub async fn unregister(&self, tunnel_id: TunnelId) {
        if let Some((_, tunnel)) = self.tunnels_by_id.remove(&tunnel_id) {
            info!("Unregistering tunnel {}", tunnel_id);
            self.tunnels_by_subdomain.remove(&tunnel.subdomain);
            
            // Record metrics
            metrics::record_tunnel_disconnected(&tunnel_id.to_string());
            
            // Update database if available
            if let Some(ref db) = self.db {
                if let Err(e) = db.unregister_tunnel(tunnel_id).await {
                    warn!("Failed to update tunnel in database: {}", e);
                }
            }
        }
    }

    /// Get a tunnel by subdomain.
    pub fn get_by_subdomain(&self, subdomain: &str) -> Option<Arc<TunnelConnection>> {
        self.tunnels_by_subdomain.get(subdomain).map(|r| r.clone())
    }

    /// Get the number of active tunnels.
    pub fn count(&self) -> usize {
        self.tunnels_by_id.len()
    }

    /// List all active tunnels.
    /// Returns tuples of (tunnel_id, subdomain, pending_request_count).
    /// List all active tunnels with their info.
    /// Returns: (tunnel_id, subdomain, pending_requests, connected_duration_secs)
    pub fn list_tunnels(&self) -> Vec<(TunnelId, String, usize, u64)> {
        self.tunnels_by_id
            .iter()
            .map(|entry| {
                let tunnel = entry.value();
                (
                    tunnel.id,
                    tunnel.subdomain.clone(),
                    tunnel.pending_requests.len(),
                    tunnel.connected_duration().as_secs(),
                )
            })
            .collect()
    }

    /// Check if we can accept more tunnels.
    pub fn can_accept(&self) -> bool {
        self.count() < self.config.max_tunnels
    }

    /// Check if a subdomain is available.
    pub async fn is_subdomain_available(&self, subdomain: &str) -> bool {
        // Check in-memory first
        if self.tunnels_by_subdomain.contains_key(subdomain) {
            return false;
        }
        
        // Check database if available
        if let Some(ref db) = self.db {
            match db.is_subdomain_available(subdomain).await {
                Ok(available) => return available,
                Err(e) => {
                    warn!("Failed to check subdomain availability in database: {}", e);
                }
            }
        }
        
        true
    }
}

/// TLS configuration for the control server.
#[derive(Clone)]
pub struct ControlTlsConfig {
    pub cert_path: String,
    pub key_path: String,
}

/// Run the control server for tunnel client connections.
pub async fn run_control_server(
    addr: &str,
    registry: Arc<TunnelRegistry>,
    rate_limiter: Arc<IpRateLimiter>,
) -> Result<()> {
    // Check if TLS is configured for the control plane
    let tls_config = if registry.config.control_tls {
        match (&registry.config.cert_path, &registry.config.key_path) {
            (Some(cert), Some(key)) => Some(ControlTlsConfig {
                cert_path: cert.clone(),
                key_path: key.clone(),
            }),
            _ => {
                warn!("control_tls enabled but cert_path or key_path not provided, falling back to plain WebSocket");
                None
            }
        }
    } else {
        None
    };

    let app = Router::new()
        .route("/ws", get(websocket_handler))
        .route("/health", get(health_handler))
        .layer(RateLimitLayer::from_limiter(rate_limiter))
        .with_state(registry);

    if let Some(tls_cfg) = tls_config {
        run_control_server_tls(addr, app, tls_cfg).await
    } else {
        run_control_server_plain(addr, app).await
    }
}

/// Run the control server without TLS.
async fn run_control_server_plain(addr: &str, app: Router) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("Control server listening on {} (plain WebSocket)", addr);

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

/// Run the control server with TLS.
async fn run_control_server_tls(
    addr: &str,
    app: Router,
    tls_config: ControlTlsConfig,
) -> Result<()> {
    use hyper::service::service_fn;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder as AutoBuilder;
    use std::convert::Infallible;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    // Load TLS configuration
    let rustls_config = tls::load_tls_config(&tls_config.cert_path, &tls_config.key_path)?;
    let tls_acceptor = TlsAcceptor::from(rustls_config);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("Control server listening on {} (TLS enabled)", addr);

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
                    Ok::<_, Infallible>(resp)
                }
            });

            let builder = AutoBuilder::new(TokioExecutor::new());

            if let Err(e) = builder.serve_connection(io, service).await {
                debug!("Connection error from {}: {}", remote_addr, e);
            }
        });
    }
}

async fn health_handler() -> &'static str {
    "OK"
}

/// Internal function for handling tunnel connections.
/// Exposed for use by the multiplex module.
pub async fn handle_tunnel_connection_internal(
    socket: WebSocket,
    registry: Arc<TunnelRegistry>,
    client_ip: String,
) {
    handle_tunnel_connection(socket, registry, client_ip).await
}

async fn websocket_handler(
    ws: WebSocketUpgrade,
    State(registry): State<Arc<TunnelRegistry>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    let client_ip = addr.ip().to_string();
    ws.on_upgrade(move |socket| handle_tunnel_connection(socket, registry, client_ip))
}

async fn handle_tunnel_connection(
    socket: WebSocket,
    registry: Arc<TunnelRegistry>,
    client_ip: String,
) {
    let (mut ws_tx, mut ws_rx) = socket.split();

    // Channel for sending messages to the WebSocket
    let (tx, mut rx) = mpsc::channel::<Message>(100);

    // Wait for authentication
    let auth_result = authenticate_client(&mut ws_rx, &registry).await;

    let (tunnel_id, token_id, subdomain) = match auth_result {
        Ok(result) => {
            metrics::record_auth_attempt(true);
            result
        }
        Err(e) => {
            metrics::record_auth_attempt(false);
            error!("Authentication failed: {}", e);
            let error_msg = Message::error(401, e.to_string());
            if let Ok(bytes) = error_msg.to_bytes() {
                let _ = ws_tx.send(WsMessage::Binary(bytes.to_vec())).await;
            }
            return;
        }
    };

    // Check if we can accept more tunnels
    if !registry.can_accept() {
        let error_msg = Message::error(503, "Server at capacity".to_string());
        if let Ok(bytes) = error_msg.to_bytes() {
            let _ = ws_tx.send(WsMessage::Binary(bytes.to_vec())).await;
        }
        return;
    }

    // Create and register the tunnel with custom subdomain
    let tunnel = Arc::new(TunnelConnection::new_with_subdomain(
        tunnel_id,
        subdomain.clone(),
        tx,
        registry.config.request_timeout,
    ));
    registry
        .register(tunnel.clone(), &token_id, Some(&client_ip))
        .await;

    // Send connected message with the actual subdomain
    let connected_msg = Message::new(
        MessageType::Connected,
        Payload::Connected {
            tunnel_id,
            subdomain: subdomain.clone(),
        },
    );
    if let Ok(bytes) = connected_msg.to_bytes() {
        if let Err(e) = ws_tx.send(WsMessage::Binary(bytes.to_vec())).await {
            error!("Failed to send connected message: {}", e);
            registry.unregister(tunnel_id).await;
            return;
        }
    }

    // subdomain is already extracted from auth result
    let url = registry.config.tunnel_base_url(&subdomain);
    info!("Tunnel {} connected: {}", tunnel_id, url);

    // Spawn task to forward messages from channel to WebSocket
    let tx_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if let Ok(bytes) = msg.to_bytes() {
                if ws_tx.send(WsMessage::Binary(bytes.to_vec())).await.is_err() {
                    break;
                }
            }
        }
    });

    // Handle incoming messages from tunnel client
    while let Some(result) = ws_rx.next().await {
        match result {
            Ok(WsMessage::Binary(data)) => {
                match Message::from_bytes(&data) {
                    Ok(msg) => {
                        handle_client_message(&tunnel, msg).await;
                    }
                    Err(e) => {
                        warn!("Invalid message from tunnel {}: {}", tunnel_id, e);
                    }
                }
            }
            Ok(WsMessage::Ping(_)) => {
                debug!("Ping from tunnel {}", tunnel_id);
                // Pong is handled automatically by axum
            }
            Ok(WsMessage::Close(_)) => {
                info!("Tunnel {} closed by client", tunnel_id);
                break;
            }
            Err(e) => {
                error!("WebSocket error for tunnel {}: {}", tunnel_id, e);
                break;
            }
            _ => {}
        }
    }

    // Cleanup
    tx_task.abort();
    registry.unregister(tunnel_id).await;
    info!("Tunnel {} disconnected", tunnel_id);
}

/// Result of successful authentication: (TunnelId, token_id, subdomain)
type AuthResult = (TunnelId, String, String);

async fn authenticate_client(
    ws_rx: &mut futures_util::stream::SplitStream<WebSocket>,
    registry: &TunnelRegistry,
) -> Result<AuthResult> {
    // Wait for auth message with configurable timeout
    let auth_timeout = std::time::Duration::from_secs(registry.config.auth_timeout);

    let msg = tokio::time::timeout(auth_timeout, ws_rx.next())
        .await
        .map_err(|_| anyhow::anyhow!("Authentication timeout"))?
        .ok_or_else(|| anyhow::anyhow!("Connection closed before auth"))?
        .map_err(|e| anyhow::anyhow!("WebSocket error: {}", e))?;

    let data = match msg {
        WsMessage::Binary(data) => data,
        _ => return Err(anyhow::anyhow!("Expected binary message")),
    };

    let message = Message::from_bytes(&data)?;

    match message.msg_type {
        MessageType::Auth => {
            if let Payload::Auth { token, requested_subdomain } = message.payload {
                let auth_token = registry
                    .token_validator
                    .validate_with_expiry(&token)
                    .map_err(|e| anyhow::anyhow!("Invalid token: {}", e))?;

                // === Phase 2.1: Check if token is revoked ===
                if let Some(ref db) = registry.db {
                    if db.is_token_revoked(&auth_token.id).await? {
                        warn!("Token {} has been revoked", auth_token.id);
                        return Err(anyhow::anyhow!("Token has been revoked"));
                    }
                }
                
                // Generate or use requested subdomain
                let tunnel_id = TunnelId::new();
                let subdomain = if let Some(requested) = requested_subdomain {
                    // Validate the requested subdomain
                    if !is_valid_subdomain(&requested) {
                        return Err(anyhow::anyhow!(
                            "Invalid subdomain '{}': must be alphanumeric with optional hyphens, 3-32 characters",
                            requested
                        ));
                    }
                    
                    // Check if subdomain is available
                    if !registry.is_subdomain_available(&requested).await {
                        return Err(anyhow::anyhow!(
                            "Subdomain '{}' is already in use or reserved",
                            requested
                        ));
                    }
                    
                    info!("Custom subdomain '{}' requested and approved", requested);
                    requested
                } else {
                    // Use auto-generated subdomain from tunnel ID
                    tunnel_id.subdomain()
                };
                
                Ok((tunnel_id, auth_token.id, subdomain))
            } else {
                Err(anyhow::anyhow!("Invalid auth payload"))
            }
        }
        _ => Err(anyhow::anyhow!("Expected auth message")),
    }
}

/// Validate a subdomain format.
fn is_valid_subdomain(subdomain: &str) -> bool {
    // Must be 3-32 characters, alphanumeric with optional hyphens
    // Cannot start or end with hyphen
    if subdomain.len() < 3 || subdomain.len() > 32 {
        return false;
    }
    
    if subdomain.starts_with('-') || subdomain.ends_with('-') {
        return false;
    }
    
    subdomain.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

async fn handle_client_message(tunnel: &TunnelConnection, msg: Message) {
    match msg.msg_type {
        MessageType::Pong => {
            debug!("Pong from tunnel {}", tunnel.id);
        }
        MessageType::WebSocketFrame => {
            // Forward WebSocket frames through the WebSocket manager
            if let Some(request_id) = msg.request_id {
                if let Payload::WebSocketFrame(frame) = msg.payload {
                    if !tunnel.forward_websocket_frame(request_id, frame).await {
                        debug!("Failed to forward WebSocket frame for session {}", request_id);
                    }
                }
            }
        }
        MessageType::HttpResponse
        | MessageType::WebSocketUpgradeResponse
        | MessageType::TcpData
        | MessageType::StreamChunk
        | MessageType::StreamEnd => {
            // Route to pending request
            tunnel.handle_response(msg);
        }
        MessageType::Close => {
            if let Some(request_id) = msg.request_id {
                tunnel.pending_requests.remove(&request_id);
                // Also clean up any WebSocket session
                tunnel.unregister_websocket_session(request_id);
            }
        }
        _ => {
            debug!("Unhandled message type {:?} from tunnel {}", msg.msg_type, tunnel.id);
        }
    }
}

