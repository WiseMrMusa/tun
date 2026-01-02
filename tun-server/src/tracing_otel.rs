//! OpenTelemetry distributed tracing support.
//!
//! Provides request tracing across the tunnel system using OpenTelemetry.
//! Supports OTLP export for integration with observability backends like Jaeger,
//! Zipkin, Honeycomb, Datadog, etc.

use opentelemetry::trace::TracerProvider as _;
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::runtime::Tokio;
use opentelemetry_sdk::trace::Sampler;
use opentelemetry_sdk::Resource;
use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime};
use tracing::{info, span, warn, Level, Span};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Layer;
use uuid::Uuid;

/// Global tracer provider for shutdown handling.
static TRACER_PROVIDER: OnceLock<opentelemetry_sdk::trace::TracerProvider> = OnceLock::new();

/// Configuration for OTLP exporter.
#[derive(Debug, Clone)]
pub struct OtlpConfig {
    /// OTLP endpoint URL (e.g., "http://localhost:4317" for gRPC or "http://localhost:4318/v1/traces" for HTTP)
    pub endpoint: String,
    /// Service name to report.
    pub service_name: String,
    /// Optional API key for authenticated endpoints.
    pub api_key: Option<String>,
    /// Export timeout.
    pub timeout: Duration,
    /// Batch size for exporting spans.
    pub batch_size: usize,
    /// Sample rate (0.0 - 1.0). Default is 1.0 (sample everything).
    pub sample_rate: f64,
    /// Whether to use gRPC (true) or HTTP (false) protocol.
    pub use_grpc: bool,
}

impl Default for OtlpConfig {
    fn default() -> Self {
        Self {
            endpoint: "http://localhost:4317".to_string(),
            service_name: "tun-server".to_string(),
            api_key: None,
            timeout: Duration::from_secs(10),
            batch_size: 512,
            sample_rate: 1.0,
            use_grpc: true,
        }
    }
}

impl OtlpConfig {
    /// Create a new OTLP config with the specified endpoint.
    pub fn new(endpoint: &str, service_name: &str) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            service_name: service_name.to_string(),
            ..Default::default()
        }
    }

    /// Set the API key for authentication.
    pub fn with_api_key(mut self, api_key: &str) -> Self {
        self.api_key = Some(api_key.to_string());
        self
    }

    /// Set the sample rate.
    pub fn with_sample_rate(mut self, rate: f64) -> Self {
        self.sample_rate = rate.clamp(0.0, 1.0);
        self
    }

    /// Use HTTP protocol instead of gRPC.
    pub fn with_http(mut self) -> Self {
        self.use_grpc = false;
        self
    }
}

/// Initialize OpenTelemetry tracing with OTLP export.
///
/// This function sets up:
/// - A tracer provider with batch span processing
/// - OTLP exporter (gRPC or HTTP based on config)
/// - tracing-subscriber integration via tracing-opentelemetry
///
/// Returns an error if initialization fails.
pub fn init_otel_tracing(config: &OtlpConfig) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Build resource with service information
    let resource = Resource::new(vec![
        KeyValue::new("service.name", config.service_name.clone()),
        KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
    ]);

    // Configure sampler
    let sampler = if config.sample_rate >= 1.0 {
        Sampler::AlwaysOn
    } else if config.sample_rate <= 0.0 {
        Sampler::AlwaysOff
    } else {
        Sampler::TraceIdRatioBased(config.sample_rate)
    };

    // Build the tracer provider with OTLP exporter
    let tracer_provider = if config.use_grpc {
        // gRPC exporter
        let mut exporter = opentelemetry_otlp::new_exporter()
            .tonic()
            .with_endpoint(&config.endpoint)
            .with_timeout(config.timeout);

        // Add authorization header if API key provided
        if let Some(ref api_key) = config.api_key {
            let mut metadata = tonic::metadata::MetadataMap::new();
            metadata.insert(
                "authorization",
                format!("Bearer {}", api_key).parse().unwrap(),
            );
            exporter = exporter.with_metadata(metadata);
        }

        opentelemetry_sdk::trace::TracerProvider::builder()
            .with_config(
                opentelemetry_sdk::trace::config()
                    .with_sampler(sampler)
                    .with_resource(resource),
            )
            .with_batch_exporter(exporter.build_span_exporter()?, Tokio)
            .build()
    } else {
        // HTTP exporter
        let mut exporter = opentelemetry_otlp::new_exporter()
            .http()
            .with_endpoint(&config.endpoint)
            .with_timeout(config.timeout);

        // Add authorization header if API key provided
        if let Some(ref api_key) = config.api_key {
            let mut headers = HashMap::new();
            headers.insert("Authorization".to_string(), format!("Bearer {}", api_key));
            exporter = exporter.with_headers(headers);
        }

        opentelemetry_sdk::trace::TracerProvider::builder()
            .with_config(
                opentelemetry_sdk::trace::config()
                    .with_sampler(sampler)
                    .with_resource(resource),
            )
            .with_batch_exporter(exporter.build_span_exporter()?, Tokio)
            .build()
    };

    // Store for shutdown
    let _ = TRACER_PROVIDER.set(tracer_provider.clone());

    // Get tracer
    let tracer = tracer_provider.tracer("tun-server");

    // Create OpenTelemetry tracing layer
    let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

    // Install subscriber with both fmt (console) and OpenTelemetry layers
    tracing_subscriber::registry()
        .with(otel_layer)
        .with(
            tracing_subscriber::fmt::layer().with_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive(tracing::Level::INFO.into()),
            ),
        )
        .init();

    info!(
        endpoint = %config.endpoint,
        service = %config.service_name,
        sample_rate = %config.sample_rate,
        protocol = if config.use_grpc { "gRPC" } else { "HTTP" },
        "OpenTelemetry OTLP tracing initialized"
    );

    Ok(())
}

/// Initialize basic logging without OTLP (fallback).
pub fn init_basic_logging(debug: bool) {
    let level = if debug { Level::DEBUG } else { Level::INFO };

    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_target(true)
        .with_thread_ids(true)
        .init();
}

/// Shutdown OpenTelemetry and flush pending spans.
pub fn shutdown_otel() {
    if let Some(provider) = TRACER_PROVIDER.get() {
        info!("Shutting down OpenTelemetry tracer, flushing pending spans...");
        // force_flush returns Vec<Result<(), TraceError>> - check if any failed
        let results = provider.force_flush();
        for result in results {
            if let Err(e) = result {
                warn!("Error flushing OpenTelemetry span: {:?}", e);
            }
        }
        info!("OpenTelemetry shutdown complete");
    }
}

// ============================================================================
// Manual Span Collector (for custom span management)
// ============================================================================

/// A span ready for export to OTLP.
#[derive(Debug, Clone)]
pub struct ExportableSpan {
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub operation_name: String,
    pub start_time: SystemTime,
    pub end_time: Option<SystemTime>,
    pub status: SpanStatus,
    pub attributes: HashMap<String, SpanValue>,
    pub events: Vec<SpanEvent>,
}

/// Span status for OTLP export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpanStatus {
    Unset,
    Ok,
    Error,
}

/// Attribute value types.
#[derive(Debug, Clone)]
pub enum SpanValue {
    String(String),
    Int(i64),
    Float(f64),
    Bool(bool),
}

/// A span event.
#[derive(Debug, Clone)]
pub struct SpanEvent {
    pub name: String,
    pub timestamp: SystemTime,
    pub attributes: HashMap<String, SpanValue>,
}

impl ExportableSpan {
    /// Create a new exportable span.
    pub fn new(trace_id: &str, span_id: &str, operation_name: &str) -> Self {
        Self {
            trace_id: trace_id.to_string(),
            span_id: span_id.to_string(),
            parent_span_id: None,
            operation_name: operation_name.to_string(),
            start_time: SystemTime::now(),
            end_time: None,
            status: SpanStatus::Unset,
            attributes: HashMap::new(),
            events: Vec::new(),
        }
    }

    /// Set the parent span ID.
    pub fn with_parent(mut self, parent_span_id: &str) -> Self {
        self.parent_span_id = Some(parent_span_id.to_string());
        self
    }

    /// Add an attribute.
    pub fn set_attribute(&mut self, key: &str, value: SpanValue) {
        self.attributes.insert(key.to_string(), value);
    }

    /// Add an event.
    pub fn add_event(&mut self, name: &str) {
        self.events.push(SpanEvent {
            name: name.to_string(),
            timestamp: SystemTime::now(),
            attributes: HashMap::new(),
        });
    }

    /// Add an event with attributes.
    pub fn add_event_with_attributes(&mut self, name: &str, attributes: HashMap<String, SpanValue>) {
        self.events.push(SpanEvent {
            name: name.to_string(),
            timestamp: SystemTime::now(),
            attributes,
        });
    }

    /// Mark the span as finished.
    pub fn finish(&mut self) {
        self.end_time = Some(SystemTime::now());
    }

    /// Mark the span as OK.
    pub fn set_ok(&mut self) {
        self.status = SpanStatus::Ok;
    }

    /// Mark the span as Error.
    pub fn set_error(&mut self, message: &str) {
        self.status = SpanStatus::Error;
        self.set_attribute("error.message", SpanValue::String(message.to_string()));
    }

    /// Get the duration in milliseconds.
    pub fn duration_ms(&self) -> Option<f64> {
        self.end_time.map(|end| {
            end.duration_since(self.start_time)
                .unwrap_or_default()
                .as_secs_f64()
                * 1000.0
        })
    }
}

// ============================================================================
// Trace Context (W3C Trace Context propagation)
// ============================================================================

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

    #[test]
    fn test_otlp_config() {
        let config = OtlpConfig::new("http://localhost:4317", "test-service")
            .with_api_key("secret")
            .with_sample_rate(0.5)
            .with_http();

        assert_eq!(config.endpoint, "http://localhost:4317");
        assert_eq!(config.service_name, "test-service");
        assert_eq!(config.api_key, Some("secret".to_string()));
        assert_eq!(config.sample_rate, 0.5);
        assert!(!config.use_grpc);
    }
}
