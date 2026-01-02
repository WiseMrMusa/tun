//! WebSocket multiplexing protocol for high throughput.
//!
//! Allows multiple logical channels to share a single WebSocket connection,
//! with flow control and prioritization.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, trace, warn};

/// Stream identifier for multiplexed channels.
pub type StreamId = u32;

/// Maximum number of concurrent streams.
pub const MAX_STREAMS: u32 = 10000;

/// Default flow control window size.
pub const DEFAULT_WINDOW_SIZE: u32 = 65536;

/// Frame type for multiplexed communication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrameType {
    /// Data frame.
    Data,
    /// Stream creation.
    Open,
    /// Stream close.
    Close,
    /// Window update (flow control).
    WindowUpdate,
    /// Ping for keepalive.
    Ping,
    /// Pong response.
    Pong,
    /// Go away (graceful shutdown).
    GoAway,
}

/// A multiplexed frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiplexFrame {
    /// Stream ID (0 for control frames).
    pub stream_id: StreamId,
    /// Frame type.
    pub frame_type: FrameType,
    /// Frame flags (stream-specific).
    pub flags: u8,
    /// Frame payload.
    #[serde(with = "base64_bytes")]
    pub payload: Vec<u8>,
}

impl MultiplexFrame {
    /// Create a new data frame.
    pub fn data(stream_id: StreamId, data: Vec<u8>) -> Self {
        Self {
            stream_id,
            frame_type: FrameType::Data,
            flags: 0,
            payload: data,
        }
    }

    /// Create a stream open frame.
    pub fn open(stream_id: StreamId) -> Self {
        Self {
            stream_id,
            frame_type: FrameType::Open,
            flags: 0,
            payload: Vec::new(),
        }
    }

    /// Create a stream close frame.
    pub fn close(stream_id: StreamId) -> Self {
        Self {
            stream_id,
            frame_type: FrameType::Close,
            flags: 0,
            payload: Vec::new(),
        }
    }

    /// Create a window update frame.
    pub fn window_update(stream_id: StreamId, increment: u32) -> Self {
        Self {
            stream_id,
            frame_type: FrameType::WindowUpdate,
            flags: 0,
            payload: increment.to_be_bytes().to_vec(),
        }
    }

    /// Create a ping frame.
    pub fn ping(data: Vec<u8>) -> Self {
        Self {
            stream_id: 0,
            frame_type: FrameType::Ping,
            flags: 0,
            payload: data,
        }
    }

    /// Create a pong frame.
    pub fn pong(data: Vec<u8>) -> Self {
        Self {
            stream_id: 0,
            frame_type: FrameType::Pong,
            flags: 0,
            payload: data,
        }
    }

    /// Create a go away frame.
    pub fn go_away(last_stream_id: StreamId, reason: &str) -> Self {
        let mut payload = last_stream_id.to_be_bytes().to_vec();
        payload.extend_from_slice(reason.as_bytes());
        Self {
            stream_id: 0,
            frame_type: FrameType::GoAway,
            flags: 0,
            payload,
        }
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    /// Deserialize from bytes.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        bincode::deserialize(data).ok()
    }

    /// Check if this is a control frame (stream_id == 0).
    pub fn is_control(&self) -> bool {
        self.stream_id == 0
    }

    /// Get the end stream flag.
    pub fn is_end_stream(&self) -> bool {
        self.flags & 0x01 != 0
    }

    /// Set the end stream flag.
    pub fn with_end_stream(mut self) -> Self {
        self.flags |= 0x01;
        self
    }
}

/// State of a multiplexed stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    /// Stream is open and can send/receive.
    Open,
    /// Local side has sent close.
    HalfClosedLocal,
    /// Remote side has sent close.
    HalfClosedRemote,
    /// Stream is fully closed.
    Closed,
}

/// A single multiplexed stream.
pub struct MultiplexStream {
    /// Stream ID.
    pub id: StreamId,
    /// Current state.
    pub state: StreamState,
    /// Send window size (flow control).
    pub send_window: u32,
    /// Receive window size (flow control).
    pub recv_window: u32,
    /// Channel for incoming data.
    pub incoming: mpsc::Receiver<Vec<u8>>,
    /// Sender for the incoming channel.
    incoming_tx: mpsc::Sender<Vec<u8>>,
}

impl MultiplexStream {
    /// Create a new stream.
    pub fn new(id: StreamId) -> Self {
        let (incoming_tx, incoming) = mpsc::channel(64);
        Self {
            id,
            state: StreamState::Open,
            send_window: DEFAULT_WINDOW_SIZE,
            recv_window: DEFAULT_WINDOW_SIZE,
            incoming,
            incoming_tx,
        }
    }

    /// Get a sender for this stream.
    pub fn sender(&self) -> mpsc::Sender<Vec<u8>> {
        self.incoming_tx.clone()
    }

    /// Check if the stream is open for sending.
    pub fn can_send(&self) -> bool {
        matches!(self.state, StreamState::Open | StreamState::HalfClosedRemote)
    }

    /// Check if the stream is open for receiving.
    pub fn can_receive(&self) -> bool {
        matches!(self.state, StreamState::Open | StreamState::HalfClosedLocal)
    }

    /// Update send window.
    pub fn update_send_window(&mut self, increment: u32) {
        self.send_window = self.send_window.saturating_add(increment);
        trace!("Stream {} send window updated to {}", self.id, self.send_window);
    }

    /// Consume send window.
    pub fn consume_send_window(&mut self, size: u32) -> bool {
        if self.send_window >= size {
            self.send_window -= size;
            true
        } else {
            false
        }
    }
}

/// Multiplexer for managing multiple streams over a single connection.
pub struct Multiplexer {
    /// Next stream ID to assign.
    next_stream_id: AtomicU32,
    /// Active streams.
    streams: tokio::sync::RwLock<HashMap<StreamId, Arc<tokio::sync::Mutex<MultiplexStream>>>>,
    /// Maximum concurrent streams.
    max_streams: u32,
    /// Is this the client side (odd stream IDs) or server side (even stream IDs)?
    is_client: bool,
}

impl Multiplexer {
    /// Create a new multiplexer.
    pub fn new(is_client: bool) -> Self {
        // Clients use odd stream IDs, servers use even
        let initial_id = if is_client { 1 } else { 2 };
        Self {
            next_stream_id: AtomicU32::new(initial_id),
            streams: tokio::sync::RwLock::new(HashMap::new()),
            max_streams: MAX_STREAMS,
            is_client,
        }
    }

    /// Create a new stream.
    pub async fn create_stream(&self) -> Option<StreamId> {
        let streams = self.streams.read().await;
        if streams.len() >= self.max_streams as usize {
            warn!("Maximum streams reached ({})", self.max_streams);
            return None;
        }
        drop(streams);

        let stream_id = self.next_stream_id.fetch_add(2, Ordering::SeqCst);
        let stream = MultiplexStream::new(stream_id);

        let mut streams = self.streams.write().await;
        streams.insert(stream_id, Arc::new(tokio::sync::Mutex::new(stream)));

        debug!("Created stream {}", stream_id);
        Some(stream_id)
    }

    /// Get a stream by ID.
    pub async fn get_stream(
        &self,
        stream_id: StreamId,
    ) -> Option<Arc<tokio::sync::Mutex<MultiplexStream>>> {
        let streams = self.streams.read().await;
        streams.get(&stream_id).cloned()
    }

    /// Accept a stream from the remote side.
    pub async fn accept_stream(&self, stream_id: StreamId) -> bool {
        // Check if this is a valid stream ID from the remote
        let is_valid = if self.is_client {
            stream_id % 2 == 0 // Server-initiated streams are even
        } else {
            stream_id % 2 == 1 // Client-initiated streams are odd
        };

        if !is_valid {
            warn!("Invalid stream ID {} for this side", stream_id);
            return false;
        }

        let mut streams = self.streams.write().await;
        if streams.len() >= self.max_streams as usize {
            warn!("Maximum streams reached ({})", self.max_streams);
            return false;
        }

        let stream = MultiplexStream::new(stream_id);
        streams.insert(stream_id, Arc::new(tokio::sync::Mutex::new(stream)));

        debug!("Accepted stream {}", stream_id);
        true
    }

    /// Close a stream.
    pub async fn close_stream(&self, stream_id: StreamId) {
        let mut streams = self.streams.write().await;
        if let Some(stream) = streams.remove(&stream_id) {
            let mut stream = stream.lock().await;
            stream.state = StreamState::Closed;
            debug!("Closed stream {}", stream_id);
        }
    }

    /// Get the number of active streams.
    pub async fn stream_count(&self) -> usize {
        self.streams.read().await.len()
    }

    /// Process an incoming frame.
    pub async fn process_frame(&self, frame: MultiplexFrame) -> Option<MultiplexFrame> {
        match frame.frame_type {
            FrameType::Open => {
                if self.accept_stream(frame.stream_id).await {
                    None
                } else {
                    // Send close if we can't accept
                    Some(MultiplexFrame::close(frame.stream_id))
                }
            }
            FrameType::Close => {
                self.close_stream(frame.stream_id).await;
                None
            }
            FrameType::Data => {
                if let Some(stream) = self.get_stream(frame.stream_id).await {
                    let stream = stream.lock().await;
                    if stream.can_receive() {
                        let _ = stream.incoming_tx.send(frame.payload).await;
                    }
                }
                None
            }
            FrameType::WindowUpdate => {
                if let Some(stream) = self.get_stream(frame.stream_id).await {
                    let mut stream = stream.lock().await;
                    if frame.payload.len() >= 4 {
                        let increment = u32::from_be_bytes([
                            frame.payload[0],
                            frame.payload[1],
                            frame.payload[2],
                            frame.payload[3],
                        ]);
                        stream.update_send_window(increment);
                    }
                }
                None
            }
            FrameType::Ping => Some(MultiplexFrame::pong(frame.payload)),
            FrameType::Pong => None,
            FrameType::GoAway => {
                // Handle graceful shutdown
                warn!("Received GoAway frame");
                None
            }
        }
    }
}

// Base64 serialization helper
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
        STANDARD
            .decode(&s)
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_serialization() {
        let frame = MultiplexFrame::data(1, vec![1, 2, 3, 4]);
        let bytes = frame.to_bytes();
        let restored = MultiplexFrame::from_bytes(&bytes).unwrap();

        assert_eq!(restored.stream_id, 1);
        assert_eq!(restored.frame_type, FrameType::Data);
        assert_eq!(restored.payload, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_stream_state() {
        let mut stream = MultiplexStream::new(1);
        assert!(stream.can_send());
        assert!(stream.can_receive());

        stream.state = StreamState::HalfClosedLocal;
        assert!(stream.can_send()); // Can still send
        assert!(!stream.can_receive()); // Can't receive
    }

    #[tokio::test]
    async fn test_multiplexer() {
        let mux = Multiplexer::new(true); // Client side

        // Create a stream
        let stream_id = mux.create_stream().await.unwrap();
        assert_eq!(stream_id, 1); // First client stream is 1
        assert_eq!(mux.stream_count().await, 1);

        // Create another stream
        let stream_id2 = mux.create_stream().await.unwrap();
        assert_eq!(stream_id2, 3); // Second client stream is 3
        assert_eq!(mux.stream_count().await, 2);

        // Close first stream
        mux.close_stream(stream_id).await;
        assert_eq!(mux.stream_count().await, 1);
    }
}

