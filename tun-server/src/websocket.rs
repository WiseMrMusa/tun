//! WebSocket frame forwarding and session management.
//!
//! Handles bidirectional WebSocket frame relay between public clients and tunnel clients.

use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use tun_core::protocol::{Message, RequestId, WebSocketFrameData, WebSocketOpcode};

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
            // Continuation frames are handled as binary
            axum::extract::ws::Message::Binary(frame.payload)
        }
    }
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

