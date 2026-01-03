//! Distributed tracing support for tunnel server.
//!
//! Implements W3C Trace Context propagation for end-to-end request correlation.
//! https://www.w3.org/TR/trace-context/

use axum::http::{HeaderMap, HeaderValue};
use uuid::Uuid;

/// W3C Trace Context version.
const TRACEPARENT_VERSION: &str = "00";

/// Trace context extracted from incoming requests.
#[derive(Debug, Clone)]
pub struct TraceContext {
    /// Unique trace ID (16 bytes, hex encoded = 32 chars)
    pub trace_id: String,
    /// Parent span ID (8 bytes, hex encoded = 16 chars)
    pub parent_span_id: String,
    /// Current span ID (8 bytes, hex encoded = 16 chars)
    pub span_id: String,
    /// Trace flags (1 byte)
    pub trace_flags: u8,
    /// Optional tracestate header value
    pub trace_state: Option<String>,
    /// Our request ID (UUID format)
    pub request_id: String,
}

impl TraceContext {
    /// Create a new root trace context (no parent).
    pub fn new() -> Self {
        let trace_id = generate_trace_id();
        let span_id = generate_span_id();
        let request_id = Uuid::new_v4().to_string();

        Self {
            trace_id,
            parent_span_id: "0000000000000000".to_string(),
            span_id,
            trace_flags: 0x01, // sampled by default
            trace_state: None,
            request_id,
        }
    }

    /// Extract trace context from incoming request headers.
    /// Falls back to creating a new root trace if no valid trace context found.
    pub fn from_headers(headers: &HeaderMap) -> Self {
        // Try to extract W3C traceparent header
        if let Some(traceparent) = headers.get("traceparent") {
            if let Ok(value) = traceparent.to_str() {
                if let Some(ctx) = parse_traceparent(value) {
                    // Extract tracestate if present
                    let trace_state = headers
                        .get("tracestate")
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_string());

                    return Self {
                        trace_id: ctx.0,
                        parent_span_id: ctx.1,
                        span_id: generate_span_id(),
                        trace_flags: ctx.2,
                        trace_state,
                        request_id: Uuid::new_v4().to_string(),
                    };
                }
            }
        }

        // Check for existing X-Request-Id header
        let request_id = headers
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        // Check for X-Trace-Id header (alternative format)
        let trace_id = headers
            .get("x-trace-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(generate_trace_id);

        Self {
            trace_id,
            parent_span_id: "0000000000000000".to_string(),
            span_id: generate_span_id(),
            trace_flags: 0x01,
            trace_state: None,
            request_id,
        }
    }

    /// Generate the traceparent header value.
    pub fn traceparent(&self) -> String {
        format!(
            "{}-{}-{}-{:02x}",
            TRACEPARENT_VERSION, self.trace_id, self.span_id, self.trace_flags
        )
    }

    /// Create a child span from this context.
    pub fn child(&self) -> Self {
        Self {
            trace_id: self.trace_id.clone(),
            parent_span_id: self.span_id.clone(),
            span_id: generate_span_id(),
            trace_flags: self.trace_flags,
            trace_state: self.trace_state.clone(),
            request_id: self.request_id.clone(),
        }
    }

    /// Add trace context headers to an outgoing request.
    pub fn inject_headers(&self, headers: &mut Vec<(String, String)>) {
        // Add W3C traceparent
        headers.push(("traceparent".to_string(), self.traceparent()));

        // Add tracestate if present
        if let Some(ref state) = self.trace_state {
            headers.push(("tracestate".to_string(), state.clone()));
        }

        // Add our request ID
        headers.push(("X-Request-Id".to_string(), self.request_id.clone()));

        // Add trace ID for systems that use X-Trace-Id
        headers.push(("X-Trace-Id".to_string(), self.trace_id.clone()));

        // Add span ID
        headers.push(("X-Span-Id".to_string(), self.span_id.clone()));
    }

    /// Get headers as HeaderValue pairs for axum responses.
    pub fn response_headers(&self) -> Vec<(&'static str, String)> {
        let mut headers = vec![
            ("X-Request-Id", self.request_id.clone()),
            ("X-Trace-Id", self.trace_id.clone()),
            ("X-Span-Id", self.span_id.clone()),
        ];

        if self.parent_span_id != "0000000000000000" {
            headers.push(("X-Parent-Span-Id", self.parent_span_id.clone()));
        }

        headers
    }
}

impl Default for TraceContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse a W3C traceparent header value.
/// Format: VERSION-TRACE_ID-PARENT_ID-FLAGS
fn parse_traceparent(value: &str) -> Option<(String, String, u8)> {
    let parts: Vec<&str> = value.split('-').collect();
    if parts.len() != 4 {
        return None;
    }

    // Validate version (must be "00" for current spec)
    if parts[0] != "00" {
        return None;
    }

    // Validate trace ID (32 hex chars)
    let trace_id = parts[1];
    if trace_id.len() != 32 || !trace_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }

    // Validate parent ID (16 hex chars)
    let parent_id = parts[2];
    if parent_id.len() != 16 || !parent_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }

    // Parse flags
    let flags = u8::from_str_radix(parts[3], 16).ok()?;

    Some((trace_id.to_string(), parent_id.to_string(), flags))
}

/// Generate a random 16-byte trace ID (32 hex chars).
fn generate_trace_id() -> String {
    format!("{:032x}", rand::random::<u128>())
}

/// Generate a random 8-byte span ID (16 hex chars).
fn generate_span_id() -> String {
    format!("{:016x}", rand::random::<u64>())
}

/// Add trace context headers to an axum response.
pub fn add_trace_headers(
    mut response: axum::response::Response<axum::body::Body>,
    ctx: &TraceContext,
) -> axum::response::Response<axum::body::Body> {
    for (name, value) in ctx.response_headers() {
        if let Ok(header_value) = HeaderValue::from_str(&value) {
            response.headers_mut().insert(name, header_value);
        }
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_traceparent() {
        let valid = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
        let result = parse_traceparent(valid);
        assert!(result.is_some());

        let (trace_id, parent_id, flags) = result.unwrap();
        assert_eq!(trace_id, "0af7651916cd43dd8448eb211c80319c");
        assert_eq!(parent_id, "b7ad6b7169203331");
        assert_eq!(flags, 0x01);
    }

    #[test]
    fn test_invalid_traceparent() {
        assert!(parse_traceparent("invalid").is_none());
        assert!(parse_traceparent("00-short-id-01").is_none());
        assert!(parse_traceparent("01-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01").is_none());
    }

    #[test]
    fn test_trace_context_new() {
        let ctx = TraceContext::new();
        assert_eq!(ctx.trace_id.len(), 32);
        assert_eq!(ctx.span_id.len(), 16);
        assert_eq!(ctx.parent_span_id, "0000000000000000");
    }

    #[test]
    fn test_trace_context_child() {
        let parent = TraceContext::new();
        let child = parent.child();

        assert_eq!(child.trace_id, parent.trace_id);
        assert_eq!(child.parent_span_id, parent.span_id);
        assert_ne!(child.span_id, parent.span_id);
    }
}

