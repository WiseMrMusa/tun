//! Tunnel connection and local port forwarding.
//!
//! Supports both HTTP/1.1 and HTTP/2 for forwarding requests to local services.
//! Also supports WebSocket frame forwarding.

use crate::config::ClientConfig;
use crate::pool::{ConnectionPool, PoolConfig};
use anyhow::Result;
use bytes::Bytes;
use dashmap::DashMap;
use futures_util::{SinkExt, StreamExt};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Method, Request};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_tungstenite::{
    connect_async as ws_connect_async,
    tungstenite::protocol::Message as TungsteniteMessage,
    MaybeTlsStream, WebSocketStream,
};
use tracing::{debug, error, info, warn};
use tun_core::protocol::{
    HttpMethod, HttpRequestData, HttpResponseData, HttpVersion, Message, MessageType, Payload,
    RequestId, WebSocketFrameData, WebSocketOpcode,
};

/// Active WebSocket sessions being relayed.
struct WebSocketSessions {
    /// Active sessions by request ID, with sender to forward frames to local WebSocket
    sessions: DashMap<RequestId, mpsc::Sender<WebSocketFrameData>>,
}

impl WebSocketSessions {
    fn new() -> Self {
        Self {
            sessions: DashMap::new(),
        }
    }

    fn register(&self, request_id: RequestId, tx: mpsc::Sender<WebSocketFrameData>) {
        self.sessions.insert(request_id, tx);
    }

    fn unregister(&self, request_id: RequestId) {
        self.sessions.remove(&request_id);
    }

    async fn forward_frame(&self, request_id: RequestId, frame: WebSocketFrameData) -> bool {
        if let Some(tx) = self.sessions.get(&request_id) {
            tx.send(frame).await.is_ok()
        } else {
            false
        }
    }
}

/// Run the tunnel with automatic reconnection.
pub async fn run_tunnel_loop(config: &ClientConfig) -> Result<()> {
    let mut attempts = 0u32;

    loop {
        attempts += 1;

        match run_tunnel(config).await {
            Ok(_) => {
                info!("Tunnel closed gracefully");
                break;
            }
            Err(e) => {
                error!("Tunnel error: {}", e);

                if config.max_reconnects > 0 && attempts >= config.max_reconnects {
                    error!("Max reconnect attempts ({}) reached", config.max_reconnects);
                    return Err(e);
                }

                info!(
                    "Reconnecting in {} seconds... (attempt {})",
                    config.reconnect_delay,
                    attempts + 1
                );
                tokio::time::sleep(std::time::Duration::from_secs(config.reconnect_delay)).await;
            }
        }
    }

    Ok(())
}

/// Run a single tunnel connection.
async fn run_tunnel(config: &ClientConfig) -> Result<()> {
    let url = config.ws_url();
    info!("Connecting to {}", url);

    // Connect to the tunnel server
    let (ws_stream, _) = ws_connect_async(&url).await?;
    let (mut ws_tx, mut ws_rx) = ws_stream.split();

    // WebSocket session manager for frame forwarding
    let ws_sessions = Arc::new(WebSocketSessions::new());
    
    // Initialize connection pool for local service connections
    let pool_config = PoolConfig {
        max_connections: 32,
        idle_timeout: Duration::from_secs(60),
        acquire_timeout: Duration::from_secs(30),
        max_lifetime: Duration::from_secs(300),
    };
    let connection_pool = ConnectionPool::new(pool_config);
    
    // Start background pool cleanup task
    let cleanup_handle = connection_pool.start_cleanup_task(Duration::from_secs(30));

    // Authenticate (with optional custom subdomain)
    let auth_msg = match &config.subdomain {
        Some(subdomain) => Message::auth_with_subdomain(config.token.clone(), subdomain.clone()),
        None => Message::auth(config.token.clone()),
    };
    let auth_bytes = auth_msg.to_bytes()?;
    ws_tx.send(TungsteniteMessage::Binary(auth_bytes.to_vec())).await?;

    // Wait for authentication response or connected message
    let response = ws_rx
        .next()
        .await
        .ok_or_else(|| anyhow::anyhow!("Connection closed"))??;

    let response_data = match response {
        TungsteniteMessage::Binary(data) => data,
        _ => return Err(anyhow::anyhow!("Unexpected message type")),
    };

    let response_msg = Message::from_bytes(&response_data)?;

    // Handle the response
    let (tunnel_id, subdomain) = match response_msg.msg_type {
        MessageType::Connected => {
            if let Payload::Connected {
                tunnel_id,
                subdomain,
            } = response_msg.payload
            {
                (tunnel_id, subdomain)
            } else {
                return Err(anyhow::anyhow!("Invalid connected payload"));
            }
        }
        MessageType::Error => {
            if let Payload::Error { code, message } = response_msg.payload {
                return Err(anyhow::anyhow!("Auth error ({}): {}", code, message));
            } else {
                return Err(anyhow::anyhow!("Unknown auth error"));
            }
        }
        _ => return Err(anyhow::anyhow!("Unexpected response type")),
    };

    info!("Connected! Tunnel ID: {}", tunnel_id);
    info!("Your tunnel is live at: https://{}.your-server-domain", subdomain);
    info!("Forwarding to {}", config.local_addr());

    // Start heartbeat task
    let (heartbeat_tx, mut heartbeat_rx) = tokio::sync::mpsc::channel::<()>(1);
    let heartbeat_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            if heartbeat_tx.send(()).await.is_err() {
                break;
            }
        }
    });

    // Channel for sending responses back through WebSocket
    let (response_tx, mut response_rx) = tokio::sync::mpsc::channel::<Message>(100);

    // Spawn task to send responses/pings
    let send_handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                Some(msg) = response_rx.recv() => {
                    if let Ok(bytes) = msg.to_bytes() {
                        if ws_tx.send(TungsteniteMessage::Binary(bytes.to_vec())).await.is_err() {
                            break;
                        }
                    }
                }
                Some(_) = heartbeat_rx.recv() => {
                    let ping = Message::ping();
                    if let Ok(bytes) = ping.to_bytes() {
                        if ws_tx.send(TungsteniteMessage::Binary(bytes.to_vec())).await.is_err() {
                            break;
                        }
                    }
                }
                else => break,
            }
        }
    });

    // Handle incoming messages
    while let Some(result) = ws_rx.next().await {
        match result {
            Ok(TungsteniteMessage::Binary(data)) => {
                match Message::from_bytes(&data) {
                    Ok(msg) => {
                        let response_tx = response_tx.clone();
                        let config = config.clone();
                        let ws_sessions = ws_sessions.clone();
                        let pool = connection_pool.clone();
                        tokio::spawn(async move {
                            handle_server_message(msg, &config, response_tx, ws_sessions, pool).await;
                        });
                    }
                    Err(e) => {
                        warn!("Invalid message from server: {}", e);
                    }
                }
            }
            Ok(TungsteniteMessage::Ping(_)) => {
                debug!("Received ping from server");
            }
            Ok(TungsteniteMessage::Close(_)) => {
                info!("Server closed connection");
                break;
            }
            Err(e) => {
                error!("WebSocket error: {}", e);
                break;
            }
            _ => {}
        }
    }

    // Cleanup
    heartbeat_handle.abort();
    send_handle.abort();
    cleanup_handle.abort();
    
    // Log pool stats at disconnect
    let stats = connection_pool.stats();
    info!(
        "Connection pool stats: total={}, reused={}, reuse_ratio={:.1}%",
        stats.total_connections,
        stats.reused_connections,
        stats.reuse_ratio() * 100.0
    );

    Ok(())
}

async fn handle_server_message(
    msg: Message,
    config: &crate::config::ClientConfig,
    response_tx: tokio::sync::mpsc::Sender<Message>,
    ws_sessions: Arc<WebSocketSessions>,
    pool: Arc<ConnectionPool>,
) {
    match msg.msg_type {
        MessageType::HttpRequest => {
            let request_id = msg.request_id.unwrap_or_else(RequestId::new);

            if let Payload::HttpRequest(request_data) = msg.payload {
                // Route to the appropriate local port based on path
                let local_addr = config.local_addr_for_path(&request_data.uri);
                let response = forward_http_request(&local_addr, request_data, &pool).await;
                let response_msg = Message::http_response(request_id, response);

                if response_tx.send(response_msg).await.is_err() {
                    error!("Failed to send response");
                }
            }
        }
        MessageType::WebSocketUpgrade => {
            let request_id = msg.request_id.unwrap_or_else(RequestId::new);

            if let Payload::HttpRequest(request_data) = msg.payload {
                let local_addr = config.local_addr_for_path(&request_data.uri);
                
                // Try to establish WebSocket connection to local service
                match establish_local_websocket(&local_addr, &request_data).await {
                    Ok((ws_stream, upgrade_response)) => {
                        info!("WebSocket connected to local service for session {}", request_id);
                        
                        // Send successful upgrade response
                        let response_msg = Message::websocket_upgrade_response(request_id, upgrade_response);
                        if response_tx.send(response_msg).await.is_err() {
                            error!("Failed to send WebSocket upgrade response");
                            return;
                        }
                        
                        // Start frame relay
                        tokio::spawn(handle_websocket_relay(
                            request_id,
                            ws_stream,
                            response_tx.clone(),
                            ws_sessions.clone(),
                        ));
                    }
                    Err(e) => {
                        error!("Failed to connect to local WebSocket: {}", e);
                        let response = HttpResponseData {
                            status: 502,
                            headers: vec![("Content-Type".to_string(), "text/plain".to_string())],
                            body: format!("Failed to connect to local WebSocket: {}", e).into_bytes(),
                            version: HttpVersion::Http11,
                        };
                        let response_msg = Message::websocket_upgrade_response(request_id, response);
                        let _ = response_tx.send(response_msg).await;
                    }
                }
            }
        }
        MessageType::WebSocketFrame => {
            // Forward frame to local WebSocket
            let request_id = msg.request_id.unwrap_or_else(RequestId::new);
            if let Payload::WebSocketFrame(frame) = msg.payload {
                if !ws_sessions.forward_frame(request_id, frame).await {
                    debug!("Failed to forward WebSocket frame to local service for session {}", request_id);
                }
            }
        }
        MessageType::Close => {
            // Close WebSocket session
            if let Some(request_id) = msg.request_id {
                ws_sessions.unregister(request_id);
                debug!("Closed WebSocket session {}", request_id);
            }
        }
        MessageType::TcpData => {
            // Handle raw TCP data forwarding (uses default port)
            let request_id = msg.request_id.unwrap_or_else(RequestId::new);
            if let Payload::TcpData { data } = msg.payload {
                let local_addr = config.local_addr();
                match forward_tcp_data(&local_addr, &data).await {
                    Ok(response_data) => {
                        let response_msg = Message::tcp_data(request_id, response_data);
                        if response_tx.send(response_msg).await.is_err() {
                            error!("Failed to send TCP response");
                        }
                    }
                    Err(e) => {
                        error!("Failed to forward TCP data: {}", e);
                        let error_msg = Message::error(502, format!("TCP forward failed: {}", e));
                        let _ = response_tx.send(error_msg).await;
                    }
                }
            }
        }
        MessageType::Ping => {
            let pong = Message::pong();
            let _ = response_tx.send(pong).await;
        }
        MessageType::Disconnect => {
            info!("Server requested disconnect");
        }
        _ => {
            debug!("Unhandled message type: {:?}", msg.msg_type);
        }
    }
}

/// Establish a WebSocket connection to the local service.
async fn establish_local_websocket(
    local_addr: &str,
    request_data: &HttpRequestData,
) -> Result<(WebSocketStream<MaybeTlsStream<TcpStream>>, HttpResponseData)> {
    // Build the WebSocket URL
    let ws_url = format!("ws://{}{}", local_addr, request_data.uri);
    
    debug!("Connecting to local WebSocket at {}", ws_url);
    
    // Connect to local WebSocket
    let (ws_stream, response) = ws_connect_async(&ws_url).await?;
    
    // Convert response to our format
    let upgrade_response = HttpResponseData {
        status: response.status().as_u16(),
        headers: response
            .headers()
            .iter()
            .filter_map(|(k, v)| {
                v.to_str().ok().map(|v| (k.to_string(), v.to_string()))
            })
            .collect(),
        body: vec![],
        version: HttpVersion::Http11,
    };
    
    Ok((ws_stream, upgrade_response))
}

/// Handle bidirectional WebSocket frame relay between server and local service.
async fn handle_websocket_relay(
    request_id: RequestId,
    ws_stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
    response_tx: mpsc::Sender<Message>,
    ws_sessions: Arc<WebSocketSessions>,
) {
    let (mut local_tx, mut local_rx) = ws_stream.split();
    
    // Create channel for forwarding frames to local WebSocket
    let (to_local_tx, mut to_local_rx) = mpsc::channel::<WebSocketFrameData>(100);
    ws_sessions.register(request_id, to_local_tx);
    
    info!("WebSocket relay started for session {}", request_id);
    
    // Task to forward frames from server to local
    let to_local_task = tokio::spawn(async move {
        while let Some(frame) = to_local_rx.recv().await {
            let msg = frame_to_tungstenite_message(frame);
            if local_tx.send(msg).await.is_err() {
                break;
            }
        }
    });
    
    // Forward frames from local to server
    while let Some(result) = local_rx.next().await {
        match result {
            Ok(msg) => {
                if let Some(frame) = tungstenite_message_to_frame(&msg) {
                    let frame_msg = Message::websocket_frame(request_id, frame);
                    if response_tx.send(frame_msg).await.is_err() {
                        break;
                    }
                }
                
                // Check for close frame
                if matches!(msg, TungsteniteMessage::Close(_)) {
                    break;
                }
            }
            Err(e) => {
                debug!("Local WebSocket error: {}", e);
                break;
            }
        }
    }
    
    // Clean up
    to_local_task.abort();
    ws_sessions.unregister(request_id);
    
    // Notify server that WebSocket is closing
    let close_msg = Message::close(request_id);
    let _ = response_tx.send(close_msg).await;
    
    info!("WebSocket relay ended for session {}", request_id);
}

/// Convert our WebSocketFrameData to a tungstenite Message.
fn frame_to_tungstenite_message(frame: WebSocketFrameData) -> TungsteniteMessage {
    match frame.opcode {
        WebSocketOpcode::Text => {
            let text = String::from_utf8_lossy(&frame.payload).to_string();
            TungsteniteMessage::Text(text)
        }
        WebSocketOpcode::Binary => TungsteniteMessage::Binary(frame.payload),
        WebSocketOpcode::Ping => TungsteniteMessage::Ping(frame.payload),
        WebSocketOpcode::Pong => TungsteniteMessage::Pong(frame.payload),
        WebSocketOpcode::Close => TungsteniteMessage::Close(None),
        WebSocketOpcode::Continuation => TungsteniteMessage::Binary(frame.payload),
    }
}

/// Convert a tungstenite Message to our WebSocketFrameData.
fn tungstenite_message_to_frame(msg: &TungsteniteMessage) -> Option<WebSocketFrameData> {
    match msg {
        TungsteniteMessage::Text(text) => Some(WebSocketFrameData {
            opcode: WebSocketOpcode::Text,
            payload: text.as_bytes().to_vec(),
            fin: true,
        }),
        TungsteniteMessage::Binary(data) => Some(WebSocketFrameData {
            opcode: WebSocketOpcode::Binary,
            payload: data.clone(),
            fin: true,
        }),
        TungsteniteMessage::Ping(data) => Some(WebSocketFrameData {
            opcode: WebSocketOpcode::Ping,
            payload: data.clone(),
            fin: true,
        }),
        TungsteniteMessage::Pong(data) => Some(WebSocketFrameData {
            opcode: WebSocketOpcode::Pong,
            payload: data.clone(),
            fin: true,
        }),
        TungsteniteMessage::Close(_) => Some(WebSocketFrameData {
            opcode: WebSocketOpcode::Close,
            payload: vec![],
            fin: true,
        }),
        TungsteniteMessage::Frame(_) => None, // Raw frames are not directly handled
    }
}

/// Forward raw TCP data to the local service.
async fn forward_tcp_data(local_addr: &str, data: &[u8]) -> Result<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    
    // Connect to local service
    let mut stream = TcpStream::connect(local_addr).await?;
    
    // Write data
    stream.write_all(data).await?;
    stream.flush().await?;
    
    // Read response (with timeout)
    let mut response = Vec::new();
    let mut buf = [0u8; 8192];
    
    // Use a short timeout for the initial response
    match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read(&mut buf)
    ).await {
        Ok(Ok(n)) if n > 0 => {
            response.extend_from_slice(&buf[..n]);
        }
        Ok(Ok(_)) => {
            // EOF - connection closed
        }
        Ok(Err(e)) => {
            return Err(anyhow::anyhow!("Read error: {}", e));
        }
        Err(_) => {
            // Timeout - return what we have (may be empty)
            debug!("TCP read timeout, returning partial response");
        }
    }
    
    Ok(response)
}

async fn forward_http_request(
    local_addr: &str,
    request: HttpRequestData,
    pool: &Arc<ConnectionPool>,
) -> HttpResponseData {
    debug!(
        "Forwarding {} {} {} to {}",
        request.version, request.method, request.uri, local_addr
    );

    // Choose HTTP version based on request
    let result = match request.version {
        HttpVersion::H2 => forward_with_http2(local_addr, &request).await,
        _ => forward_with_http1_pooled(local_addr, &request, pool).await,
    };

    match result {
        Ok(response) => response,
        Err(e) => {
            error!("Failed to forward request: {}", e);
            HttpResponseData {
                status: 502,
                headers: vec![("Content-Type".to_string(), "text/plain".to_string())],
                body: format!("Failed to connect to local service: {}", e).into_bytes(),
                version: HttpVersion::Http11,
            }
        }
    }
}

/// Forward an HTTP/1.1 request to the local service using hyper.
#[allow(dead_code)]
async fn forward_with_http1(
    local_addr: &str,
    request_data: &HttpRequestData,
) -> Result<HttpResponseData> {
    // Connect to local service
    let stream = TcpStream::connect(local_addr).await?;
    let io = TokioIo::new(stream);

    // Create HTTP/1 connection
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;

    // Spawn connection driver
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            debug!("HTTP/1.1 connection error: {}", e);
        }
    });

    // Build request
    let req = build_hyper_request(request_data, local_addr)?;

    // Send request
    let response = sender.send_request(req).await?;

    // Convert response
    convert_hyper_response(response, HttpVersion::Http11).await
}

/// Forward an HTTP/1.1 request to the local service using a pooled connection.
async fn forward_with_http1_pooled(
    local_addr: &str,
    request_data: &HttpRequestData,
    pool: &Arc<ConnectionPool>,
) -> Result<HttpResponseData> {
    // Get connection from pool (creates new if needed)
    let mut pooled_conn = pool.get(local_addr).await?;
    
    // Take the stream from the pooled connection
    // Note: We take ownership because hyper needs exclusive access
    let stream = pooled_conn
        .take()
        .ok_or_else(|| anyhow::anyhow!("Failed to get stream from pool"))?;
    
    let io = TokioIo::new(stream);

    // Create HTTP/1 connection
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;

    // Spawn connection driver
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            debug!("HTTP/1.1 pooled connection error: {}", e);
        }
    });

    // Build request
    let req = build_hyper_request(request_data, local_addr)?;

    // Send request
    let response = sender.send_request(req).await?;

    // Convert response
    convert_hyper_response(response, HttpVersion::Http11).await
}

/// Forward an HTTP/2 request to the local service using hyper.
async fn forward_with_http2(
    local_addr: &str,
    request_data: &HttpRequestData,
) -> Result<HttpResponseData> {
    // Connect to local service
    let stream = TcpStream::connect(local_addr).await?;
    let io = TokioIo::new(stream);

    // Create HTTP/2 connection (h2c - HTTP/2 over cleartext)
    let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io).await?;

    // Spawn connection driver
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            debug!("HTTP/2 connection error: {}", e);
        }
    });

    // Build request
    let req = build_hyper_request(request_data, local_addr)?;

    // Send request
    let response = sender.send_request(req).await?;

    // Convert response
    convert_hyper_response(response, HttpVersion::H2).await
}

/// Build a hyper request from our HttpRequestData.
fn build_hyper_request(
    request_data: &HttpRequestData,
    local_addr: &str,
) -> Result<Request<Full<Bytes>>> {
    // Convert method
    let method = match request_data.method {
        HttpMethod::Get => Method::GET,
        HttpMethod::Post => Method::POST,
        HttpMethod::Put => Method::PUT,
        HttpMethod::Delete => Method::DELETE,
        HttpMethod::Patch => Method::PATCH,
        HttpMethod::Head => Method::HEAD,
        HttpMethod::Options => Method::OPTIONS,
        HttpMethod::Connect => Method::CONNECT,
        HttpMethod::Trace => Method::TRACE,
    };

    // Build URI
    let uri = if request_data.uri.is_empty() {
        "/".to_string()
    } else {
        request_data.uri.clone()
    };

    // Build request
    let mut builder = Request::builder().method(method).uri(&uri);

    // Add headers
    let mut has_host = false;
    for (key, value) in &request_data.headers {
        if key.to_lowercase() == "host" {
            has_host = true;
        }
        builder = builder.header(key.as_str(), value.as_str());
    }

    // Add Host header if not present
    if !has_host {
        builder = builder.header("Host", local_addr);
    }

    // Build body
    let body = Full::new(Bytes::from(request_data.body.clone()));
    let req = builder.body(body)?;

    Ok(req)
}

/// Convert a hyper response to our HttpResponseData format.
async fn convert_hyper_response(
    response: hyper::Response<Incoming>,
    version: HttpVersion,
) -> Result<HttpResponseData> {
    let status = response.status().as_u16();

    // Determine actual HTTP version from response
    let actual_version = match response.version() {
        hyper::Version::HTTP_10 => HttpVersion::Http10,
        hyper::Version::HTTP_11 => HttpVersion::Http11,
        hyper::Version::HTTP_2 => HttpVersion::H2,
        hyper::Version::HTTP_3 => HttpVersion::H3,
        _ => version,
    };

    // Extract headers
    let headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .filter_map(|(k, v)| {
            v.to_str().ok().map(|v| (k.to_string(), v.to_string()))
        })
        .collect();

    // Read body - hyper handles chunked encoding automatically!
    let body = response.collect().await?.to_bytes().to_vec();

    Ok(HttpResponseData {
        status,
        headers,
        body,
        version: actual_version,
    })
}

