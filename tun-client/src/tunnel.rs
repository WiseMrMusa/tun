//! Tunnel connection and local port forwarding.

use crate::config::ClientConfig;
use anyhow::Result;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::client::conn::http1::SendRequest;
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message as WsMessage};
use tracing::{debug, error, info, warn};
use tun_core::protocol::{
    HttpMethod, HttpRequestData, HttpResponseData, Message, MessageType, Payload, RequestId,
};

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
    let (ws_stream, _) = connect_async(&url).await?;
    let (mut ws_tx, mut ws_rx) = ws_stream.split();

    // Authenticate (with optional custom subdomain)
    let auth_msg = match &config.subdomain {
        Some(subdomain) => Message::auth_with_subdomain(config.token.clone(), subdomain.clone()),
        None => Message::auth(config.token.clone()),
    };
    let auth_bytes = auth_msg.to_bytes()?;
    ws_tx.send(WsMessage::Binary(auth_bytes.to_vec())).await?;

    // Wait for authentication response or connected message
    let response = ws_rx
        .next()
        .await
        .ok_or_else(|| anyhow::anyhow!("Connection closed"))??;

    let response_data = match response {
        WsMessage::Binary(data) => data,
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
                        if ws_tx.send(WsMessage::Binary(bytes.to_vec())).await.is_err() {
                            break;
                        }
                    }
                }
                Some(_) = heartbeat_rx.recv() => {
                    let ping = Message::ping();
                    if let Ok(bytes) = ping.to_bytes() {
                        if ws_tx.send(WsMessage::Binary(bytes.to_vec())).await.is_err() {
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
            Ok(WsMessage::Binary(data)) => {
                match Message::from_bytes(&data) {
                    Ok(msg) => {
                        let response_tx = response_tx.clone();
                        let config = config.clone();
                        tokio::spawn(async move {
                            handle_server_message(msg, &config, response_tx).await;
                        });
                    }
                    Err(e) => {
                        warn!("Invalid message from server: {}", e);
                    }
                }
            }
            Ok(WsMessage::Ping(_)) => {
                debug!("Received ping from server");
            }
            Ok(WsMessage::Close(_)) => {
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

    Ok(())
}

async fn handle_server_message(
    msg: Message,
    config: &crate::config::ClientConfig,
    response_tx: tokio::sync::mpsc::Sender<Message>,
) {
    match msg.msg_type {
        MessageType::HttpRequest | MessageType::WebSocketUpgrade => {
            let request_id = msg.request_id.unwrap_or_else(RequestId::new);
            let is_ws_upgrade = msg.msg_type == MessageType::WebSocketUpgrade;

            if let Payload::HttpRequest(request_data) = msg.payload {
                // Route to the appropriate local port based on path
                let local_addr = config.local_addr_for_path(&request_data.uri);
                let response = forward_http_request(&local_addr, request_data).await;
                let response_msg = if is_ws_upgrade {
                    Message::websocket_upgrade_response(request_id, response)
                } else {
                    Message::http_response(request_id, response)
                };

                if response_tx.send(response_msg).await.is_err() {
                    error!("Failed to send response");
                }
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

async fn forward_http_request(local_addr: &str, request: HttpRequestData) -> HttpResponseData {
    debug!("Forwarding {} {} to {}", request.method, request.uri, local_addr);

    match forward_with_hyper(local_addr, &request).await {
        Ok(response) => response,
        Err(e) => {
            error!("Failed to forward request: {}", e);
            HttpResponseData {
                status: 502,
                headers: vec![("Content-Type".to_string(), "text/plain".to_string())],
                body: format!("Failed to connect to local service: {}", e).into_bytes(),
            }
        }
    }
}

/// Forward an HTTP request to the local service using hyper.
async fn forward_with_hyper(
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
            debug!("Connection error: {}", e);
        }
    });

    // Build the request
    let response = send_request(&mut sender, request_data, local_addr).await?;
    
    Ok(response)
}

/// Send an HTTP request using hyper and convert the response.
async fn send_request(
    sender: &mut SendRequest<Full<Bytes>>,
    request_data: &HttpRequestData,
    local_addr: &str,
) -> Result<HttpResponseData> {
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

    // Send request
    let response = sender.send_request(req).await?;

    // Convert response
    convert_hyper_response(response).await
}

/// Convert a hyper response to our HttpResponseData format.
async fn convert_hyper_response(response: hyper::Response<Incoming>) -> Result<HttpResponseData> {
    let status = response.status().as_u16();

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
    })
}

