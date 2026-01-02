//! Wire protocol for tunnel communication.
//!
//! Defines message types exchanged between tunnel client and server over WebSocket.

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique identifier for a tunnel connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TunnelId(pub Uuid);

impl TunnelId {
    /// Generate a new random tunnel ID.
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Get the subdomain for this tunnel.
    pub fn subdomain(&self) -> String {
        // Use first 8 characters of UUID for subdomain
        self.0.to_string()[..8].to_string()
    }
}

impl Default for TunnelId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for TunnelId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unique identifier for a request/connection within a tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RequestId(pub Uuid);

impl RequestId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for RequestId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Type of message being sent over the tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageType {
    /// Client requesting to establish a tunnel
    Connect,
    /// Server acknowledging tunnel connection
    Connected,
    /// Authentication request from client
    Auth,
    /// Authentication response from server
    AuthResponse,
    /// HTTP request data from server to client
    HttpRequest,
    /// HTTP response data from client to server
    HttpResponse,
    /// WebSocket upgrade request (HTTP request with upgrade headers)
    WebSocketUpgrade,
    /// WebSocket upgrade response (101 Switching Protocols)
    WebSocketUpgradeResponse,
    /// WebSocket frame data (bidirectional)
    WebSocketFrame,
    /// Raw TCP data
    TcpData,
    /// HTTP request/response stream chunk (for large bodies)
    StreamChunk,
    /// End of stream marker
    StreamEnd,
    /// Heartbeat/ping message
    Ping,
    /// Heartbeat/pong response
    Pong,
    /// Request to close a specific connection
    Close,
    /// Error message
    Error,
    /// Tunnel disconnected
    Disconnect,
}

/// HTTP method for requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Options,
    Connect,
    Trace,
}

impl std::fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpMethod::Get => write!(f, "GET"),
            HttpMethod::Post => write!(f, "POST"),
            HttpMethod::Put => write!(f, "PUT"),
            HttpMethod::Delete => write!(f, "DELETE"),
            HttpMethod::Patch => write!(f, "PATCH"),
            HttpMethod::Head => write!(f, "HEAD"),
            HttpMethod::Options => write!(f, "OPTIONS"),
            HttpMethod::Connect => write!(f, "CONNECT"),
            HttpMethod::Trace => write!(f, "TRACE"),
        }
    }
}

/// HTTP version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum HttpVersion {
    /// HTTP/1.0
    Http10,
    /// HTTP/1.1 (default)
    #[default]
    Http11,
    /// HTTP/2
    H2,
    /// HTTP/3
    H3,
}

impl std::fmt::Display for HttpVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpVersion::Http10 => write!(f, "HTTP/1.0"),
            HttpVersion::Http11 => write!(f, "HTTP/1.1"),
            HttpVersion::H2 => write!(f, "HTTP/2"),
            HttpVersion::H3 => write!(f, "HTTP/3"),
        }
    }
}

/// HTTP request sent through the tunnel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequestData {
    pub method: HttpMethod,
    pub uri: String,
    pub headers: Vec<(String, String)>,
    #[serde(with = "base64_bytes")]
    pub body: Vec<u8>,
    /// HTTP version (defaults to HTTP/1.1 for backwards compatibility)
    #[serde(default)]
    pub version: HttpVersion,
}

/// HTTP response sent through the tunnel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponseData {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    #[serde(with = "base64_bytes")]
    pub body: Vec<u8>,
    /// HTTP version (defaults to HTTP/1.1 for backwards compatibility)
    #[serde(default)]
    pub version: HttpVersion,
}

/// WebSocket frame opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebSocketOpcode {
    /// Continuation frame
    Continuation,
    /// Text frame
    Text,
    /// Binary frame
    Binary,
    /// Close frame
    Close,
    /// Ping frame
    Ping,
    /// Pong frame
    Pong,
}

impl From<u8> for WebSocketOpcode {
    fn from(opcode: u8) -> Self {
        match opcode {
            0 => WebSocketOpcode::Continuation,
            1 => WebSocketOpcode::Text,
            2 => WebSocketOpcode::Binary,
            8 => WebSocketOpcode::Close,
            9 => WebSocketOpcode::Ping,
            10 => WebSocketOpcode::Pong,
            _ => WebSocketOpcode::Binary, // Default to binary for unknown
        }
    }
}

impl From<WebSocketOpcode> for u8 {
    fn from(opcode: WebSocketOpcode) -> Self {
        match opcode {
            WebSocketOpcode::Continuation => 0,
            WebSocketOpcode::Text => 1,
            WebSocketOpcode::Binary => 2,
            WebSocketOpcode::Close => 8,
            WebSocketOpcode::Ping => 9,
            WebSocketOpcode::Pong => 10,
        }
    }
}

/// WebSocket frame data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSocketFrameData {
    /// Frame opcode
    pub opcode: WebSocketOpcode,
    /// Frame payload
    #[serde(with = "base64_bytes")]
    pub payload: Vec<u8>,
    /// Whether this is the final frame in a message
    pub fin: bool,
}

/// Stream chunk data for large request/response bodies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamChunkData {
    /// Chunk sequence number
    pub chunk_index: u32,
    /// Whether this is the final chunk
    pub is_final: bool,
    /// Chunk data
    #[serde(with = "base64_bytes")]
    pub data: Vec<u8>,
}

/// Message payload variants.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Payload {
    /// Empty payload
    Empty,
    /// Authentication token with optional custom subdomain
    Auth {
        token: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        requested_subdomain: Option<String>,
    },
    /// Authentication result
    AuthResult { success: bool, message: String },
    /// Connection established
    Connected {
        tunnel_id: TunnelId,
        subdomain: String,
    },
    /// HTTP request
    HttpRequest(HttpRequestData),
    /// HTTP response
    HttpResponse(HttpResponseData),
    /// WebSocket frame
    WebSocketFrame(WebSocketFrameData),
    /// Stream chunk for large bodies
    StreamChunk(StreamChunkData),
    /// Raw TCP data
    TcpData {
        #[serde(with = "base64_bytes")]
        data: Vec<u8>,
    },
    /// Error information
    Error { code: u32, message: String },
}

/// Main message type for tunnel communication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// Type of message
    pub msg_type: MessageType,
    /// Tunnel identifier (set after connection established)
    pub tunnel_id: Option<TunnelId>,
    /// Request identifier (for multiplexing requests)
    pub request_id: Option<RequestId>,
    /// Message payload
    pub payload: Payload,
    /// Timestamp (milliseconds since epoch)
    pub timestamp: u64,
}

impl Message {
    /// Create a new message with the current timestamp.
    pub fn new(msg_type: MessageType, payload: Payload) -> Self {
        Self {
            msg_type,
            tunnel_id: None,
            request_id: None,
            payload,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        }
    }

    /// Set the tunnel ID.
    pub fn with_tunnel_id(mut self, tunnel_id: TunnelId) -> Self {
        self.tunnel_id = Some(tunnel_id);
        self
    }

    /// Set the request ID.
    pub fn with_request_id(mut self, request_id: RequestId) -> Self {
        self.request_id = Some(request_id);
        self
    }

    /// Create an auth message.
    pub fn auth(token: String) -> Self {
        Self::new(MessageType::Auth, Payload::Auth {
            token,
            requested_subdomain: None,
        })
    }

    /// Create an auth message with a custom subdomain request.
    pub fn auth_with_subdomain(token: String, subdomain: String) -> Self {
        Self::new(MessageType::Auth, Payload::Auth {
            token,
            requested_subdomain: Some(subdomain),
        })
    }

    /// Create an auth response message.
    pub fn auth_response(success: bool, message: String) -> Self {
        Self::new(
            MessageType::AuthResponse,
            Payload::AuthResult { success, message },
        )
    }

    /// Create a connect message.
    pub fn connect() -> Self {
        Self::new(MessageType::Connect, Payload::Empty)
    }

    /// Create a connected message.
    pub fn connected(tunnel_id: TunnelId) -> Self {
        Self::new(
            MessageType::Connected,
            Payload::Connected {
                subdomain: tunnel_id.subdomain(),
                tunnel_id,
            },
        )
    }

    /// Create a ping message.
    pub fn ping() -> Self {
        Self::new(MessageType::Ping, Payload::Empty)
    }

    /// Create a pong message.
    pub fn pong() -> Self {
        Self::new(MessageType::Pong, Payload::Empty)
    }

    /// Create an error message.
    pub fn error(code: u32, message: String) -> Self {
        Self::new(MessageType::Error, Payload::Error { code, message })
    }

    /// Create an HTTP request message.
    pub fn http_request(request_id: RequestId, data: HttpRequestData) -> Self {
        Self::new(MessageType::HttpRequest, Payload::HttpRequest(data))
            .with_request_id(request_id)
    }

    /// Create an HTTP response message.
    pub fn http_response(request_id: RequestId, data: HttpResponseData) -> Self {
        Self::new(MessageType::HttpResponse, Payload::HttpResponse(data))
            .with_request_id(request_id)
    }

    /// Create a close message for a specific request.
    pub fn close(request_id: RequestId) -> Self {
        Self::new(MessageType::Close, Payload::Empty)
            .with_request_id(request_id)
    }

    /// Create a disconnect message.
    pub fn disconnect() -> Self {
        Self::new(MessageType::Disconnect, Payload::Empty)
    }

    /// Create a WebSocket frame message.
    pub fn websocket_frame(request_id: RequestId, frame: WebSocketFrameData) -> Self {
        Self::new(MessageType::WebSocketFrame, Payload::WebSocketFrame(frame))
            .with_request_id(request_id)
    }

    /// Create a WebSocket upgrade request (uses HttpRequest payload with upgrade headers).
    pub fn websocket_upgrade(request_id: RequestId, data: HttpRequestData) -> Self {
        Self::new(MessageType::WebSocketUpgrade, Payload::HttpRequest(data))
            .with_request_id(request_id)
    }

    /// Create a WebSocket upgrade response.
    pub fn websocket_upgrade_response(request_id: RequestId, data: HttpResponseData) -> Self {
        Self::new(MessageType::WebSocketUpgradeResponse, Payload::HttpResponse(data))
            .with_request_id(request_id)
    }

    /// Create a stream chunk message.
    pub fn stream_chunk(request_id: RequestId, chunk: StreamChunkData) -> Self {
        Self::new(MessageType::StreamChunk, Payload::StreamChunk(chunk))
            .with_request_id(request_id)
    }

    /// Create a stream end message.
    pub fn stream_end(request_id: RequestId) -> Self {
        Self::new(MessageType::StreamEnd, Payload::Empty)
            .with_request_id(request_id)
    }

    /// Create a TCP data message.
    pub fn tcp_data(request_id: RequestId, data: Vec<u8>) -> Self {
        Self::new(MessageType::TcpData, Payload::TcpData { data })
            .with_request_id(request_id)
    }

    /// Serialize to JSON bytes.
    pub fn to_bytes(&self) -> Result<Bytes, serde_json::Error> {
        serde_json::to_vec(self).map(Bytes::from)
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

/// Module for base64 encoding/decoding of byte vectors in serde.
mod base64_bytes {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        STANDARD.decode(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tunnel_id_subdomain() {
        let id = TunnelId::new();
        let subdomain = id.subdomain();
        assert_eq!(subdomain.len(), 8);
    }

    #[test]
    fn test_message_serialization() {
        let msg = Message::ping();
        let bytes = msg.to_bytes().unwrap();
        let decoded = Message::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.msg_type, MessageType::Ping);
    }

    #[test]
    fn test_http_request_message() {
        let request = HttpRequestData {
            method: HttpMethod::Get,
            uri: "/api/test".to_string(),
            headers: vec![("Host".to_string(), "example.com".to_string())],
            body: vec![],
        };
        let msg = Message::http_request(RequestId::new(), request);
        let bytes = msg.to_bytes().unwrap();
        let decoded = Message::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.msg_type, MessageType::HttpRequest);
    }
}

