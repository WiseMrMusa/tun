//! WebSocket frame forwarding and session management.
//!
//! Handles bidirectional WebSocket frame relay between public clients and tunnel clients.
//! Supports compression, subprotocol pass-through, and continuation frame handling.

use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};
use tun_core::protocol::{Message, RequestId, WebSocketFrameData, WebSocketOpcode};

/// WebSocket compression configuration.
#[derive(Debug, Clone)]
pub struct WebSocketCompressionConfig {
    /// Enable permessage-deflate compression.
    pub permessage_deflate: bool,
    /// Compression level (1-9).
    pub compression_level: u8,
    /// Minimum message size to compress.
    pub min_compress_size: usize,
    /// Enable client context takeover.
    pub client_no_context_takeover: bool,
    /// Enable server context takeover.
    pub server_no_context_takeover: bool,
}

impl Default for WebSocketCompressionConfig {
    fn default() -> Self {
        Self {
            permessage_deflate: true,
            compression_level: 6,
            min_compress_size: 1024, // Only compress messages > 1KB
            client_no_context_takeover: false,
            server_no_context_takeover: false,
        }
    }
}

impl WebSocketCompressionConfig {
    /// Create a config that disables compression.
    pub fn none() -> Self {
        Self {
            permessage_deflate: false,
            ..Default::default()
        }
    }

    /// Build the Sec-WebSocket-Extensions header value.
    pub fn to_extension_header(&self) -> Option<String> {
        if !self.permessage_deflate {
            return None;
        }

        let mut parts = vec!["permessage-deflate".to_string()];
        
        if self.client_no_context_takeover {
            parts.push("client_no_context_takeover".to_string());
        }
        if self.server_no_context_takeover {
            parts.push("server_no_context_takeover".to_string());
        }

        Some(parts.join("; "))
    }

    /// Parse compression config from extension header.
    pub fn from_extension_header(header: &str) -> Self {
        let mut config = Self::default();
        
        if !header.contains("permessage-deflate") {
            config.permessage_deflate = false;
            return config;
        }

        config.permessage_deflate = true;
        config.client_no_context_takeover = header.contains("client_no_context_takeover");
        config.server_no_context_takeover = header.contains("server_no_context_takeover");

        config
    }
}

/// WebSocket subprotocol configuration.
#[derive(Debug, Clone)]
pub struct SubprotocolConfig {
    /// List of supported subprotocols.
    pub supported: Vec<String>,
    /// The negotiated subprotocol (if any).
    pub negotiated: Option<String>,
}

impl Default for SubprotocolConfig {
    fn default() -> Self {
        Self {
            supported: vec![
                "graphql-ws".to_string(),
                "graphql-transport-ws".to_string(),
                "json".to_string(),
            ],
            negotiated: None,
        }
    }
}

impl SubprotocolConfig {
    /// Create from a list of supported subprotocols.
    pub fn from_supported(protocols: Vec<String>) -> Self {
        Self {
            supported: protocols,
            negotiated: None,
        }
    }

    /// Negotiate a subprotocol from client's requested list.
    pub fn negotiate(&self, client_protocols: &[&str]) -> Option<String> {
        // Return the first matching protocol
        for client_proto in client_protocols {
            if self.supported.iter().any(|p| p.eq_ignore_ascii_case(client_proto)) {
                return Some(client_proto.to_string());
            }
        }
        None
    }

    /// Parse subprotocols from Sec-WebSocket-Protocol header.
    pub fn parse_header(header: &str) -> Vec<String> {
        header
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }
}

/// State for handling continuation frames.
#[derive(Debug, Default)]
struct ContinuationState {
    /// Accumulated payload for multi-frame messages.
    buffer: Vec<u8>,
    /// Original opcode of the fragmented message.
    original_opcode: Option<WebSocketOpcode>,
    /// Whether we're currently in a continuation sequence.
    in_continuation: bool,
}

impl ContinuationState {
    /// Start a new continuation sequence.
    fn start(&mut self, opcode: WebSocketOpcode, payload: Vec<u8>) {
        self.buffer = payload;
        self.original_opcode = Some(opcode);
        self.in_continuation = true;
        trace!("Started continuation for {:?}", opcode);
    }

    /// Continue an existing sequence.
    fn continue_frame(&mut self, payload: Vec<u8>) {
        self.buffer.extend(payload);
        trace!("Continuation buffer now {} bytes", self.buffer.len());
    }

    /// Finish the continuation sequence and return the complete frame.
    fn finish(&mut self) -> Option<WebSocketFrameData> {
        if !self.in_continuation {
            return None;
        }

        let opcode = self.original_opcode.take()?;
        let payload = std::mem::take(&mut self.buffer);
        self.in_continuation = false;

        debug!("Finished continuation: {:?}, {} bytes", opcode, payload.len());

        Some(WebSocketFrameData {
            opcode,
            payload,
            fin: true,
        })
    }

    /// Check if we're in a continuation.
    fn is_continuing(&self) -> bool {
        self.in_continuation
    }

    /// Reset state on error.
    fn reset(&mut self) {
        self.buffer.clear();
        self.original_opcode = None;
        self.in_continuation = false;
    }
}

/// An active WebSocket session being relayed through a tunnel.
pub struct WebSocketSession {
    /// Request ID for this WebSocket session
    pub request_id: RequestId,
    /// Channel to send frames to the public client
    pub to_client_tx: mpsc::Sender<WebSocketFrameData>,
    /// Whether the session is still active
    pub active: bool,
}

/// Manages active WebSocket sessions for a tunnel.
#[derive(Default)]
pub struct WebSocketManager {
    /// Active WebSocket sessions by request ID
    sessions: DashMap<RequestId, Arc<WebSocketSession>>,
}

impl WebSocketManager {
    /// Create a new WebSocket manager.
    pub fn new() -> Self {
        Self {
            sessions: DashMap::new(),
        }
    }

    /// Register a new WebSocket session.
    /// Returns a receiver for frames destined to the public client.
    pub fn register_session(
        &self,
        request_id: RequestId,
    ) -> mpsc::Receiver<WebSocketFrameData> {
        let (tx, rx) = mpsc::channel(100);
        
        let session = Arc::new(WebSocketSession {
            request_id,
            to_client_tx: tx,
            active: true,
        });
        
        self.sessions.insert(request_id, session);
        info!("WebSocket session {} registered", request_id);
        
        rx
    }

    /// Unregister a WebSocket session.
    pub fn unregister_session(&self, request_id: RequestId) {
        if self.sessions.remove(&request_id).is_some() {
            info!("WebSocket session {} unregistered", request_id);
        }
    }

    /// Get a session by request ID.
    pub fn get_session(&self, request_id: RequestId) -> Option<Arc<WebSocketSession>> {
        self.sessions.get(&request_id).map(|r| r.clone())
    }

    /// Forward a frame from the tunnel client to the public client.
    pub async fn forward_to_client(&self, request_id: RequestId, frame: WebSocketFrameData) -> bool {
        if let Some(session) = self.sessions.get(&request_id) {
            match session.to_client_tx.send(frame).await {
                Ok(_) => {
                    debug!("Forwarded frame to client for session {}", request_id);
                    true
                }
                Err(e) => {
                    warn!("Failed to forward frame to client for session {}: {}", request_id, e);
                    false
                }
            }
        } else {
            warn!("No session found for request ID {}", request_id);
            false
        }
    }

    /// Get the number of active sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Check if a session exists.
    pub fn has_session(&self, request_id: RequestId) -> bool {
        self.sessions.contains_key(&request_id)
    }
}

/// Convert a tungstenite Message to our WebSocketFrameData format.
pub fn ws_message_to_frame(msg: &axum::extract::ws::Message) -> Option<WebSocketFrameData> {
    match msg {
        axum::extract::ws::Message::Text(text) => Some(WebSocketFrameData {
            opcode: WebSocketOpcode::Text,
            payload: text.as_bytes().to_vec(),
            fin: true,
        }),
        axum::extract::ws::Message::Binary(data) => Some(WebSocketFrameData {
            opcode: WebSocketOpcode::Binary,
            payload: data.clone(),
            fin: true,
        }),
        axum::extract::ws::Message::Ping(data) => Some(WebSocketFrameData {
            opcode: WebSocketOpcode::Ping,
            payload: data.clone(),
            fin: true,
        }),
        axum::extract::ws::Message::Pong(data) => Some(WebSocketFrameData {
            opcode: WebSocketOpcode::Pong,
            payload: data.clone(),
            fin: true,
        }),
        axum::extract::ws::Message::Close(_) => Some(WebSocketFrameData {
            opcode: WebSocketOpcode::Close,
            payload: vec![],
            fin: true,
        }),
    }
}

/// Convert our WebSocketFrameData to a tungstenite Message.
pub fn frame_to_ws_message(frame: WebSocketFrameData) -> axum::extract::ws::Message {
    match frame.opcode {
        WebSocketOpcode::Text => {
            let text = String::from_utf8_lossy(&frame.payload).to_string();
            axum::extract::ws::Message::Text(text)
        }
        WebSocketOpcode::Binary => {
            axum::extract::ws::Message::Binary(frame.payload)
        }
        WebSocketOpcode::Ping => {
            axum::extract::ws::Message::Ping(frame.payload)
        }
        WebSocketOpcode::Pong => {
            axum::extract::ws::Message::Pong(frame.payload)
        }
        WebSocketOpcode::Close => {
            axum::extract::ws::Message::Close(None)
        }
        WebSocketOpcode::Continuation => {
            // Continuation frames should be assembled before this point.
            // If we receive one here, treat as binary for compatibility.
            debug!("Received continuation frame without assembly");
            axum::extract::ws::Message::Binary(frame.payload)
        }
    }
}

/// Handle incoming WebSocket frame with continuation support.
/// Returns the complete frame when assembly is finished, or None if still accumulating.
pub fn handle_frame_with_continuation(
    frame: WebSocketFrameData,
    state: &mut ContinuationState,
) -> Option<WebSocketFrameData> {
    match frame.opcode {
        WebSocketOpcode::Continuation => {
            if !state.is_continuing() {
                warn!("Received continuation frame without initial frame");
                state.reset();
                return None;
            }

            state.continue_frame(frame.payload);

            if frame.fin {
                state.finish()
            } else {
                None
            }
        }
        WebSocketOpcode::Text | WebSocketOpcode::Binary => {
            if !frame.fin {
                // Start of fragmented message
                state.start(frame.opcode, frame.payload);
                None
            } else {
                // Complete message in single frame
                Some(frame)
            }
        }
        // Control frames are never fragmented
        WebSocketOpcode::Ping | WebSocketOpcode::Pong | WebSocketOpcode::Close => {
            Some(frame)
        }
    }
}

/// Create a WebSocketFrameData for continuation frames.
pub fn create_continuation_frame(payload: Vec<u8>, is_final: bool) -> WebSocketFrameData {
    WebSocketFrameData {
        opcode: WebSocketOpcode::Continuation,
        payload,
        fin: is_final,
    }
}

/// Fragment a large frame into multiple frames for streaming.
pub fn fragment_frame(
    frame: WebSocketFrameData,
    max_fragment_size: usize,
) -> Vec<WebSocketFrameData> {
    if frame.payload.len() <= max_fragment_size {
        return vec![frame];
    }

    let mut fragments = Vec::new();
    let chunks: Vec<&[u8]> = frame.payload.chunks(max_fragment_size).collect();
    let num_chunks = chunks.len();

    for (i, chunk) in chunks.into_iter().enumerate() {
        let is_first = i == 0;
        let is_last = i == num_chunks - 1;

        let fragment = WebSocketFrameData {
            opcode: if is_first {
                frame.opcode.clone()
            } else {
                WebSocketOpcode::Continuation
            },
            payload: chunk.to_vec(),
            fin: is_last,
        };

        fragments.push(fragment);
    }

    debug!(
        "Fragmented {:?} frame ({} bytes) into {} fragments",
        frame.opcode,
        frame.payload.len(),
        fragments.len()
    );

    fragments
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_session_lifecycle() {
        let manager = WebSocketManager::new();
        let request_id = RequestId::new();
        
        // Register session
        let _rx = manager.register_session(request_id);
        assert!(manager.has_session(request_id));
        assert_eq!(manager.session_count(), 1);
        
        // Unregister session
        manager.unregister_session(request_id);
        assert!(!manager.has_session(request_id));
        assert_eq!(manager.session_count(), 0);
    }
}

