//! Server-Sent Events (SSE) pass-through support.
//!
//! Provides detection and handling of SSE streams, ensuring proper
//! headers are set and the connection stays open for streaming events.

use axum::http::{header, HeaderMap, HeaderValue, Request, Response, StatusCode};
use tracing::{debug, trace};

/// Content-Type for SSE streams.
pub const SSE_CONTENT_TYPE: &str = "text/event-stream";

/// Check if a request is asking for SSE.
pub fn is_sse_request<B>(req: &Request<B>) -> bool {
    // Check Accept header for text/event-stream
    if let Some(accept) = req.headers().get(header::ACCEPT) {
        if let Ok(accept_str) = accept.to_str() {
            if accept_str.contains(SSE_CONTENT_TYPE) {
                trace!("Request Accept header indicates SSE: {}", accept_str);
                return true;
            }
        }
    }

    false
}

/// Check if a response is an SSE stream.
pub fn is_sse_response<B>(res: &Response<B>) -> bool {
    if let Some(content_type) = res.headers().get(header::CONTENT_TYPE) {
        if let Ok(ct_str) = content_type.to_str() {
            if ct_str.contains(SSE_CONTENT_TYPE) {
                trace!("Response Content-Type indicates SSE: {}", ct_str);
                return true;
            }
        }
    }

    false
}

/// Prepare request headers for SSE.
/// Ensures the Accept header includes text/event-stream.
pub fn prepare_sse_request_headers(headers: &mut HeaderMap) {
    // Ensure Accept header includes SSE
    if !headers.contains_key(header::ACCEPT) {
        headers.insert(
            header::ACCEPT,
            HeaderValue::from_static(SSE_CONTENT_TYPE),
        );
    }

    // Disable caching
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-cache"),
    );
}

/// Prepare response headers for SSE pass-through.
/// Ensures proper headers for streaming.
pub fn prepare_sse_response_headers(headers: &mut HeaderMap) {
    // Ensure Content-Type is set correctly
    if !headers.contains_key(header::CONTENT_TYPE) {
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(SSE_CONTENT_TYPE),
        );
    }

    // Disable caching
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-cache, no-transform"),
    );

    // Prevent connection from being closed
    headers.insert(
        header::CONNECTION,
        HeaderValue::from_static("keep-alive"),
    );

    // Disable buffering (X-Accel-Buffering for nginx proxies)
    headers.insert(
        "x-accel-buffering",
        HeaderValue::from_static("no"),
    );
}

/// SSE event structure for parsing/creating events.
#[derive(Debug, Clone, Default)]
pub struct SseEvent {
    /// Event ID (optional).
    pub id: Option<String>,
    /// Event type (optional, defaults to "message").
    pub event: Option<String>,
    /// Event data (required).
    pub data: String,
    /// Retry interval in milliseconds (optional).
    pub retry: Option<u32>,
}

impl SseEvent {
    /// Create a new SSE event with data.
    pub fn new(data: impl Into<String>) -> Self {
        Self {
            data: data.into(),
            ..Default::default()
        }
    }

    /// Set the event ID.
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Set the event type.
    pub fn with_event(mut self, event: impl Into<String>) -> Self {
        self.event = Some(event.into());
        self
    }

    /// Set the retry interval.
    pub fn with_retry(mut self, retry: u32) -> Self {
        self.retry = Some(retry);
        self
    }

    /// Serialize the event to SSE format.
    pub fn to_string(&self) -> String {
        let mut output = String::new();

        if let Some(ref id) = self.id {
            output.push_str(&format!("id: {}\n", id));
        }

        if let Some(ref event) = self.event {
            output.push_str(&format!("event: {}\n", event));
        }

        // Data can be multiline
        for line in self.data.lines() {
            output.push_str(&format!("data: {}\n", line));
        }

        if let Some(retry) = self.retry {
            output.push_str(&format!("retry: {}\n", retry));
        }

        // Empty line to end the event
        output.push('\n');

        output
    }

    /// Parse an SSE event from raw text.
    pub fn parse(text: &str) -> Option<Self> {
        if text.is_empty() {
            return None;
        }

        let mut event = SseEvent::default();
        let mut data_lines = Vec::new();

        for line in text.lines() {
            if let Some(value) = line.strip_prefix("id: ") {
                event.id = Some(value.to_string());
            } else if let Some(value) = line.strip_prefix("event: ") {
                event.event = Some(value.to_string());
            } else if let Some(value) = line.strip_prefix("data: ") {
                data_lines.push(value.to_string());
            } else if let Some(value) = line.strip_prefix("retry: ") {
                if let Ok(retry) = value.parse() {
                    event.retry = Some(retry);
                }
            }
        }

        if data_lines.is_empty() {
            return None;
        }

        event.data = data_lines.join("\n");
        Some(event)
    }
}

/// Parse SSE events from a byte stream.
/// Returns parsed events and any remaining partial data.
pub fn parse_sse_events(data: &[u8]) -> (Vec<SseEvent>, Vec<u8>) {
    let text = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return (Vec::new(), data.to_vec()),
    };

    let mut events = Vec::new();
    let mut current_event = String::new();
    let mut last_complete_idx = 0;

    for (idx, chunk) in text.split("\n\n").enumerate() {
        if idx < text.matches("\n\n").count() {
            // Complete event
            if let Some(event) = SseEvent::parse(chunk) {
                events.push(event);
            }
            last_complete_idx = text.find(&format!("{}\n\n", chunk))
                .map(|i| i + chunk.len() + 2)
                .unwrap_or(0);
        } else {
            // Partial event at the end
            current_event = chunk.to_string();
        }
    }

    let remaining = if current_event.is_empty() {
        Vec::new()
    } else {
        current_event.into_bytes()
    };

    (events, remaining)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sse_event_to_string() {
        let event = SseEvent::new("Hello, world!")
            .with_id("1")
            .with_event("message");

        let output = event.to_string();
        assert!(output.contains("id: 1\n"));
        assert!(output.contains("event: message\n"));
        assert!(output.contains("data: Hello, world!\n"));
        assert!(output.ends_with("\n\n"));
    }

    #[test]
    fn test_sse_event_parse() {
        let text = "id: 1\nevent: message\ndata: Hello\ndata: World\n";
        let event = SseEvent::parse(text).unwrap();

        assert_eq!(event.id, Some("1".to_string()));
        assert_eq!(event.event, Some("message".to_string()));
        assert_eq!(event.data, "Hello\nWorld");
    }

    #[test]
    fn test_sse_event_multiline_data() {
        let event = SseEvent::new("Line 1\nLine 2\nLine 3");
        let output = event.to_string();

        assert!(output.contains("data: Line 1\n"));
        assert!(output.contains("data: Line 2\n"));
        assert!(output.contains("data: Line 3\n"));
    }
}

