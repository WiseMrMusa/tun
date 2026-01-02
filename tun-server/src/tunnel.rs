//! Tunnel management and WebSocket control server.

use crate::config::ServerConfig;
use anyhow::Result;
use axum::{
    extract::{
        ws::{Message as WsMessage, WebSocket, WebSocketUpgrade},
        State,
    },
    response::IntoResponse,
    routing::get,
    Router,
};
use dashmap::DashMap;
use futures_util::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, warn};
use tun_core::{
    auth::TokenValidator,
    protocol::{Message, MessageType, Payload, RequestId, TunnelId},
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
}

impl TunnelConnection {
    pub fn new(id: TunnelId, tx: mpsc::Sender<Message>) -> Self {
        Self {
            subdomain: id.subdomain(),
            id,
            tx,
            pending_requests: DashMap::new(),
        }
    }

    /// Send an HTTP request and wait for a response.
    pub async fn send_request(&self, mut msg: Message) -> Result<Message, anyhow::Error> {
        let request_id = msg.request_id.unwrap_or_else(RequestId::new);
        msg.request_id = Some(request_id);

        let (response_tx, response_rx) = oneshot::channel();
        self.pending_requests
            .insert(request_id, PendingRequest { response_tx });

        self.tx.send(msg).await?;

        // Wait for response with timeout
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            response_rx,
        )
        .await
        .map_err(|_| anyhow::anyhow!("Request timeout"))??;

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
}

impl TunnelRegistry {
    pub fn new(config: ServerConfig) -> Self {
        let token_validator = if let Some(ref secret) = config.auth_secret {
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

        Self {
            tunnels_by_subdomain: DashMap::new(),
            tunnels_by_id: DashMap::new(),
            config,
            token_validator,
        }
    }

    /// Register a new tunnel.
    pub fn register(&self, tunnel: Arc<TunnelConnection>) {
        info!(
            "Registering tunnel {} with subdomain {}",
            tunnel.id, tunnel.subdomain
        );
        self.tunnels_by_subdomain
            .insert(tunnel.subdomain.clone(), tunnel.clone());
        self.tunnels_by_id.insert(tunnel.id, tunnel);
    }

    /// Unregister a tunnel.
    pub fn unregister(&self, tunnel_id: TunnelId) {
        if let Some((_, tunnel)) = self.tunnels_by_id.remove(&tunnel_id) {
            info!("Unregistering tunnel {}", tunnel_id);
            self.tunnels_by_subdomain.remove(&tunnel.subdomain);
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

    /// Check if we can accept more tunnels.
    pub fn can_accept(&self) -> bool {
        self.count() < self.config.max_tunnels
    }
}

/// Run the control server for tunnel client connections.
pub async fn run_control_server(addr: &str, registry: Arc<TunnelRegistry>) -> Result<()> {
    let app = Router::new()
        .route("/ws", get(websocket_handler))
        .route("/health", get(health_handler))
        .with_state(registry);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("Control server listening on {}", addr);

    axum::serve(listener, app).await?;
    Ok(())
}

async fn health_handler() -> &'static str {
    "OK"
}

async fn websocket_handler(
    ws: WebSocketUpgrade,
    State(registry): State<Arc<TunnelRegistry>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_tunnel_connection(socket, registry))
}

async fn handle_tunnel_connection(socket: WebSocket, registry: Arc<TunnelRegistry>) {
    let (mut ws_tx, mut ws_rx) = socket.split();

    // Channel for sending messages to the WebSocket
    let (tx, mut rx) = mpsc::channel::<Message>(100);

    // Wait for authentication
    let auth_result = authenticate_client(&mut ws_rx, &registry).await;

    let tunnel_id = match auth_result {
        Ok(tunnel_id) => tunnel_id,
        Err(e) => {
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

    // Create and register the tunnel
    let tunnel = Arc::new(TunnelConnection::new(tunnel_id, tx));
    registry.register(tunnel.clone());

    // Send connected message
    let connected_msg = Message::connected(tunnel_id);
    if let Ok(bytes) = connected_msg.to_bytes() {
        if let Err(e) = ws_tx.send(WsMessage::Binary(bytes.to_vec())).await {
            error!("Failed to send connected message: {}", e);
            registry.unregister(tunnel_id);
            return;
        }
    }

    let subdomain = tunnel.subdomain.clone();
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
    registry.unregister(tunnel_id);
    info!("Tunnel {} disconnected", tunnel_id);
}

async fn authenticate_client(
    ws_rx: &mut futures_util::stream::SplitStream<WebSocket>,
    registry: &TunnelRegistry,
) -> Result<TunnelId> {
    // Wait for auth message with timeout
    let auth_timeout = std::time::Duration::from_secs(10);

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
            if let Payload::Auth { token } = message.payload {
                registry
                    .token_validator
                    .validate(&token)
                    .map_err(|e| anyhow::anyhow!("Invalid token: {}", e))?;
                Ok(TunnelId::new())
            } else {
                Err(anyhow::anyhow!("Invalid auth payload"))
            }
        }
        _ => Err(anyhow::anyhow!("Expected auth message")),
    }
}

async fn handle_client_message(tunnel: &TunnelConnection, msg: Message) {
    match msg.msg_type {
        MessageType::Pong => {
            debug!("Pong from tunnel {}", tunnel.id);
        }
        MessageType::HttpResponse => {
            tunnel.handle_response(msg);
        }
        MessageType::Close => {
            if let Some(request_id) = msg.request_id {
                tunnel.pending_requests.remove(&request_id);
            }
        }
        _ => {
            debug!("Unhandled message type {:?} from tunnel {}", msg.msg_type, tunnel.id);
        }
    }
}

