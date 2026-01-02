//! Tunnel connection and local port forwarding.

use crate::config::ClientConfig;
use anyhow::Result;
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message as WsMessage};
use tracing::{debug, error, info, warn};
use tun_core::protocol::{
    HttpRequestData, HttpResponseData, Message, MessageType, Payload, RequestId,
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

    // Authenticate
    let auth_msg = Message::auth(config.token.clone());
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
    let local_addr = config.local_addr();
    while let Some(result) = ws_rx.next().await {
        match result {
            Ok(WsMessage::Binary(data)) => {
                match Message::from_bytes(&data) {
                    Ok(msg) => {
                        let response_tx = response_tx.clone();
                        let local_addr = local_addr.clone();
                        tokio::spawn(async move {
                            handle_server_message(msg, &local_addr, response_tx).await;
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
    local_addr: &str,
    response_tx: tokio::sync::mpsc::Sender<Message>,
) {
    match msg.msg_type {
        MessageType::HttpRequest => {
            let request_id = msg.request_id.unwrap_or_else(RequestId::new);

            if let Payload::HttpRequest(request_data) = msg.payload {
                let response = forward_http_request(local_addr, request_data).await;
                let response_msg = Message::http_response(request_id, response);

                if response_tx.send(response_msg).await.is_err() {
                    error!("Failed to send response");
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

async fn forward_http_request(local_addr: &str, request: HttpRequestData) -> HttpResponseData {
    debug!("Forwarding {} {} to {}", request.method, request.uri, local_addr);

    // Build the HTTP request
    let client = match reqwest_like_request(local_addr, &request).await {
        Ok(response) => response,
        Err(e) => {
            error!("Failed to forward request: {}", e);
            return HttpResponseData {
                status: 502,
                headers: vec![("Content-Type".to_string(), "text/plain".to_string())],
                body: format!("Failed to connect to local service: {}", e).into_bytes(),
            };
        }
    };

    client
}

/// Forward an HTTP request to the local service using raw TCP.
async fn reqwest_like_request(
    local_addr: &str,
    request: &HttpRequestData,
) -> Result<HttpResponseData> {
    // Connect to local service
    let mut stream = TcpStream::connect(local_addr).await?;

    // Build HTTP/1.1 request
    let mut http_request = format!(
        "{} {} HTTP/1.1\r\n",
        request.method,
        if request.uri.is_empty() { "/" } else { &request.uri }
    );

    // Add headers
    let mut has_host = false;
    let mut has_content_length = false;

    for (key, value) in &request.headers {
        let key_lower = key.to_lowercase();
        if key_lower == "host" {
            has_host = true;
        }
        if key_lower == "content-length" {
            has_content_length = true;
        }
        http_request.push_str(&format!("{}: {}\r\n", key, value));
    }

    // Add Host header if not present
    if !has_host {
        http_request.push_str(&format!("Host: {}\r\n", local_addr));
    }

    // Add Content-Length for body
    if !request.body.is_empty() && !has_content_length {
        http_request.push_str(&format!("Content-Length: {}\r\n", request.body.len()));
    }

    // End headers
    http_request.push_str("\r\n");

    // Send request
    stream.write_all(http_request.as_bytes()).await?;
    if !request.body.is_empty() {
        stream.write_all(&request.body).await?;
    }

    // Read response
    let mut response_buf = Vec::new();
    let mut buf = [0u8; 8192];

    // Read headers first
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        response_buf.extend_from_slice(&buf[..n]);

        // Check if we have complete headers
        if response_buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    // Parse response
    parse_http_response(&response_buf, &mut stream).await
}

async fn parse_http_response(
    initial_data: &[u8],
    stream: &mut TcpStream,
) -> Result<HttpResponseData> {
    // Find end of headers
    let header_end = initial_data
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("Invalid HTTP response"))?;

    let header_bytes = &initial_data[..header_end];
    let body_start = &initial_data[header_end + 4..];

    // Parse status line
    let header_str = String::from_utf8_lossy(header_bytes);
    let mut lines = header_str.lines();

    let status_line = lines.next().ok_or_else(|| anyhow::anyhow!("No status line"))?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(200);

    // Parse headers
    let mut headers = Vec::new();
    let mut content_length: Option<usize> = None;
    let mut chunked = false;

    for line in lines {
        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim().to_string();
            let value = value.trim().to_string();

            if key.to_lowercase() == "content-length" {
                content_length = value.parse().ok();
            }
            if key.to_lowercase() == "transfer-encoding" && value.to_lowercase().contains("chunked")
            {
                chunked = true;
            }

            headers.push((key, value));
        }
    }

    // Read body
    let mut body = body_start.to_vec();

    if let Some(len) = content_length {
        // Read remaining body based on content-length
        while body.len() < len {
            let mut buf = [0u8; 8192];
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&buf[..n]);
        }
        body.truncate(len);
    } else if chunked {
        // For chunked encoding, we'd need to decode chunks
        // For simplicity, we'll just read what we have
        // A production implementation would properly decode chunked transfer
    }
    // For responses without content-length or chunked, we just use what we have

    Ok(HttpResponseData {
        status,
        headers,
        body,
    })
}

