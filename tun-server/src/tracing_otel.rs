//! OpenTelemetry distributed tracing support.
//!
//! Provides request tracing across the tunnel system using OpenTelemetry.

use std::collections::HashMap;
use tracing::{info, span, Level, Span};
use uuid::Uuid;

/// Trace context for distributed tracing.
#[derive(Debug, Clone)]
pub struct TraceContext {
    /// Trace ID (128-bit UUID).
    pub trace_id: String,
    /// Span ID (64-bit).
    pub span_id: String,
    /// Parent span ID (if any).
    pub parent_span_id: Option<String>,
    /// Trace flags.
    pub flags: u8,
    /// Baggage items (key-value pairs that propagate).
    pub baggage: HashMap<String, String>,
}

impl TraceContext {
    /// Create a new trace context.
    pub fn new() -> Self {
        Self {
            trace_id: Uuid::new_v4().to_string().replace("-", ""),
            span_id: generate_span_id(),
            parent_span_id: None,
            flags: 1, // Sampled
            baggage: HashMap::new(),
        }
    }

    /// Create a child context.
    pub fn child(&self) -> Self {
        Self {
            trace_id: self.trace_id.clone(),
            span_id: generate_span_id(),
            parent_span_id: Some(self.span_id.clone()),
            flags: self.flags,
            baggage: self.baggage.clone(),
        }
    }

    /// Parse from W3C traceparent header.
    pub fn from_traceparent(header: &str) -> Option<Self> {
        // Format: version-traceid-spanid-flags
        // Example: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01
        let parts: Vec<&str> = header.split('-').collect();
        if parts.len() != 4 {
            return None;
        }

        let version = parts[0];
        if version != "00" {
            return None; // Unsupported version
        }

        let trace_id = parts[1].to_string();
        let span_id = parts[2].to_string();
        let flags = u8::from_str_radix(parts[3], 16).ok()?;

        Some(Self {
            trace_id,
            span_id,
            parent_span_id: None,
            flags,
            baggage: HashMap::new(),
        })
    }

    /// Convert to W3C traceparent header.
    pub fn to_traceparent(&self) -> String {
        format!("00-{}-{}-{:02x}", self.trace_id, self.span_id, self.flags)
    }

    /// Parse baggage from tracestate header.
    pub fn add_baggage_from_header(&mut self, header: &str) {
        for item in header.split(',') {
            if let Some((key, value)) = item.trim().split_once('=') {
                self.baggage.insert(key.to_string(), value.to_string());
            }
        }
    }

    /// Convert baggage to tracestate header.
    pub fn baggage_to_header(&self) -> String {
        self.baggage
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Check if this trace is sampled.
    pub fn is_sampled(&self) -> bool {
        self.flags & 0x01 != 0
    }

    /// Add a baggage item.
    pub fn with_baggage(mut self, key: &str, value: &str) -> Self {
        self.baggage.insert(key.to_string(), value.to_string());
        self
    }
}

impl Default for TraceContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate a random span ID (16 hex characters).
fn generate_span_id() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 8] = rng.gen();
    hex::encode(bytes)
}

/// Request span builder for creating traced operations.
pub struct RequestSpan {
    span: Span,
    context: TraceContext,
}

impl RequestSpan {
    /// Create a new request span.
    pub fn new(operation: &str, context: Option<TraceContext>) -> Self {
        let context = context.unwrap_or_else(TraceContext::new);
        let span = span!(
            Level::INFO,
            "request",
            trace_id = %context.trace_id,
            span_id = %context.span_id,
            parent_span_id = ?context.parent_span_id,
            operation = %operation,
        );

        Self { span, context }
    }

    /// Get the span.
    pub fn span(&self) -> &Span {
        &self.span
    }

    /// Get the trace context.
    pub fn context(&self) -> &TraceContext {
        &self.context
    }

    /// Create a child span.
    pub fn child(&self, operation: &str) -> Self {
        let child_context = self.context.child();
        let span = span!(
            parent: &self.span,
            Level::INFO,
            "span",
            trace_id = %child_context.trace_id,
            span_id = %child_context.span_id,
            parent_span_id = ?child_context.parent_span_id,
            operation = %operation,
        );

        Self {
            span,
            context: child_context,
        }
    }

    /// Record an event in this span.
    pub fn event(&self, message: &str) {
        let _guard = self.span.enter();
        info!(message = %message, "span_event");
    }

    /// Set an attribute on this span.
    pub fn set_attribute(&self, key: &str, value: &str) {
        let _guard = self.span.enter();
        info!(key = %key, value = %value, "span_attribute");
    }

    /// Mark the span as having an error.
    pub fn set_error(&self, error: &str) {
        let _guard = self.span.enter();
        info!(error = %error, status = "error", "span_status");
    }

    /// Mark the span as successful.
    pub fn set_ok(&self) {
        let _guard = self.span.enter();
        info!(status = "ok", "span_status");
    }
}

/// Extract trace context from HTTP headers.
pub fn extract_context(headers: &[(String, String)]) -> Option<TraceContext> {
    let mut context: Option<TraceContext> = None;

    for (name, value) in headers {
        let name_lower = name.to_lowercase();
        if name_lower == "traceparent" {
            context = TraceContext::from_traceparent(value);
        } else if name_lower == "tracestate" {
            if let Some(ref mut ctx) = context {
                ctx.add_baggage_from_header(value);
            }
        }
    }

    context
}

/// Inject trace context into HTTP headers.
pub fn inject_context(context: &TraceContext, headers: &mut Vec<(String, String)>) {
    headers.push(("traceparent".to_string(), context.to_traceparent()));

    let baggage = context.baggage_to_header();
    if !baggage.is_empty() {
        headers.push(("tracestate".to_string(), baggage));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_context() {
        let ctx = TraceContext::new();
        assert_eq!(ctx.trace_id.len(), 32);
        assert_eq!(ctx.span_id.len(), 16);
        assert!(ctx.is_sampled());
    }

    #[test]
    fn test_traceparent_roundtrip() {
        let ctx = TraceContext::new();
        let header = ctx.to_traceparent();
        let parsed = TraceContext::from_traceparent(&header).unwrap();

        assert_eq!(ctx.trace_id, parsed.trace_id);
        assert_eq!(ctx.span_id, parsed.span_id);
        assert_eq!(ctx.flags, parsed.flags);
    }

    #[test]
    fn test_child_context() {
        let parent = TraceContext::new();
        let child = parent.child();

        assert_eq!(parent.trace_id, child.trace_id);
        assert_ne!(parent.span_id, child.span_id);
        assert_eq!(Some(parent.span_id), child.parent_span_id);
    }

    #[test]
    fn test_baggage() {
        let ctx = TraceContext::new()
            .with_baggage("user_id", "123")
            .with_baggage("tenant", "acme");

        let header = ctx.baggage_to_header();
        assert!(header.contains("user_id=123"));
        assert!(header.contains("tenant=acme"));
    }
}

