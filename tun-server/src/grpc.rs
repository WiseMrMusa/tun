//! gRPC and HTTP/2 streaming support.
//!
//! Provides detection and handling of gRPC traffic over HTTP/2,
//! including proper header propagation and stream handling.

use axum::http::{header, HeaderMap, HeaderValue, Request, Response, StatusCode};
use tracing::{debug, trace};

/// gRPC content type.
pub const GRPC_CONTENT_TYPE: &str = "application/grpc";

/// gRPC-Web content type.
pub const GRPC_WEB_CONTENT_TYPE: &str = "application/grpc-web";

/// gRPC-Web text content type.
pub const GRPC_WEB_TEXT_CONTENT_TYPE: &str = "application/grpc-web-text";

/// Check if a request is a gRPC request.
pub fn is_grpc_request<B>(req: &Request<B>) -> bool {
    if let Some(content_type) = req.headers().get(header::CONTENT_TYPE) {
        if let Ok(ct_str) = content_type.to_str() {
            if ct_str.starts_with(GRPC_CONTENT_TYPE)
                || ct_str.starts_with(GRPC_WEB_CONTENT_TYPE)
                || ct_str.starts_with(GRPC_WEB_TEXT_CONTENT_TYPE)
            {
                trace!("Request Content-Type indicates gRPC: {}", ct_str);
                return true;
            }
        }
    }

    false
}

/// Check if a response is a gRPC response.
pub fn is_grpc_response<B>(res: &Response<B>) -> bool {
    if let Some(content_type) = res.headers().get(header::CONTENT_TYPE) {
        if let Ok(ct_str) = content_type.to_str() {
            return ct_str.starts_with(GRPC_CONTENT_TYPE)
                || ct_str.starts_with(GRPC_WEB_CONTENT_TYPE)
                || ct_str.starts_with(GRPC_WEB_TEXT_CONTENT_TYPE);
        }
    }

    false
}

/// gRPC status codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GrpcStatus {
    Ok = 0,
    Cancelled = 1,
    Unknown = 2,
    InvalidArgument = 3,
    DeadlineExceeded = 4,
    NotFound = 5,
    AlreadyExists = 6,
    PermissionDenied = 7,
    ResourceExhausted = 8,
    FailedPrecondition = 9,
    Aborted = 10,
    OutOfRange = 11,
    Unimplemented = 12,
    Internal = 13,
    Unavailable = 14,
    DataLoss = 15,
    Unauthenticated = 16,
}

impl GrpcStatus {
    /// Convert from HTTP status code.
    pub fn from_http_status(status: u16) -> Self {
        match status {
            200 => GrpcStatus::Ok,
            400 => GrpcStatus::InvalidArgument,
            401 => GrpcStatus::Unauthenticated,
            403 => GrpcStatus::PermissionDenied,
            404 => GrpcStatus::NotFound,
            408 => GrpcStatus::DeadlineExceeded,
            409 => GrpcStatus::AlreadyExists,
            429 => GrpcStatus::ResourceExhausted,
            499 => GrpcStatus::Cancelled,
            500 => GrpcStatus::Internal,
            501 => GrpcStatus::Unimplemented,
            503 => GrpcStatus::Unavailable,
            504 => GrpcStatus::DeadlineExceeded,
            _ => GrpcStatus::Unknown,
        }
    }

    /// Convert to HTTP status code.
    pub fn to_http_status(self) -> u16 {
        match self {
            GrpcStatus::Ok => 200,
            GrpcStatus::InvalidArgument => 400,
            GrpcStatus::Unauthenticated => 401,
            GrpcStatus::PermissionDenied => 403,
            GrpcStatus::NotFound => 404,
            GrpcStatus::AlreadyExists => 409,
            GrpcStatus::ResourceExhausted => 429,
            GrpcStatus::Cancelled => 499,
            GrpcStatus::DeadlineExceeded => 504,
            GrpcStatus::Unavailable => 503,
            GrpcStatus::Unimplemented => 501,
            _ => 500,
        }
    }

    /// Get the status code as a number.
    pub fn code(self) -> u8 {
        self as u8
    }
}

impl std::fmt::Display for GrpcStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            GrpcStatus::Ok => "OK",
            GrpcStatus::Cancelled => "CANCELLED",
            GrpcStatus::Unknown => "UNKNOWN",
            GrpcStatus::InvalidArgument => "INVALID_ARGUMENT",
            GrpcStatus::DeadlineExceeded => "DEADLINE_EXCEEDED",
            GrpcStatus::NotFound => "NOT_FOUND",
            GrpcStatus::AlreadyExists => "ALREADY_EXISTS",
            GrpcStatus::PermissionDenied => "PERMISSION_DENIED",
            GrpcStatus::ResourceExhausted => "RESOURCE_EXHAUSTED",
            GrpcStatus::FailedPrecondition => "FAILED_PRECONDITION",
            GrpcStatus::Aborted => "ABORTED",
            GrpcStatus::OutOfRange => "OUT_OF_RANGE",
            GrpcStatus::Unimplemented => "UNIMPLEMENTED",
            GrpcStatus::Internal => "INTERNAL",
            GrpcStatus::Unavailable => "UNAVAILABLE",
            GrpcStatus::DataLoss => "DATA_LOSS",
            GrpcStatus::Unauthenticated => "UNAUTHENTICATED",
        };
        write!(f, "{}", name)
    }
}

/// gRPC metadata (headers/trailers).
#[derive(Debug, Clone, Default)]
pub struct GrpcMetadata {
    entries: Vec<(String, Vec<u8>)>,
}

impl GrpcMetadata {
    /// Create empty metadata.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a text entry.
    pub fn insert(&mut self, key: &str, value: &str) {
        self.entries.push((key.to_string(), value.as_bytes().to_vec()));
    }

    /// Add a binary entry.
    pub fn insert_bin(&mut self, key: &str, value: &[u8]) {
        // Binary keys must end with -bin
        let key = if key.ends_with("-bin") {
            key.to_string()
        } else {
            format!("{}-bin", key)
        };
        self.entries.push((key, value.to_vec()));
    }

    /// Get a text entry.
    pub fn get(&self, key: &str) -> Option<&str> {
        for (k, v) in &self.entries {
            if k.eq_ignore_ascii_case(key) {
                return std::str::from_utf8(v).ok();
            }
        }
        None
    }

    /// Get a binary entry.
    pub fn get_bin(&self, key: &str) -> Option<&[u8]> {
        let key = if key.ends_with("-bin") {
            key.to_string()
        } else {
            format!("{}-bin", key)
        };
        for (k, v) in &self.entries {
            if k.eq_ignore_ascii_case(&key) {
                return Some(v);
            }
        }
        None
    }

    /// Convert to HTTP headers.
    pub fn to_headers(&self) -> HeaderMap {
        use base64::Engine;
        let mut headers = HeaderMap::new();
        for (k, v) in &self.entries {
            if k.ends_with("-bin") {
                // Binary values are base64 encoded
                if let Ok(name) = k.parse::<header::HeaderName>() {
                    let encoded = base64::engine::general_purpose::STANDARD.encode(v);
                    if let Ok(value) = HeaderValue::from_str(&encoded) {
                        headers.insert(name, value);
                    }
                }
            } else {
                // Text values
                if let Ok(name) = k.parse::<header::HeaderName>() {
                    if let Ok(value) = HeaderValue::from_bytes(v) {
                        headers.insert(name, value);
                    }
                }
            }
        }
        headers
    }
}

/// Prepare request headers for gRPC proxying.
pub fn prepare_grpc_request_headers(headers: &mut HeaderMap) {
    // Ensure TE header is set for trailers
    headers.insert("te", HeaderValue::from_static("trailers"));
}

/// Prepare response headers for gRPC proxying.
pub fn prepare_grpc_response_headers(headers: &mut HeaderMap, status: GrpcStatus) {
    // Add grpc-status header if not present
    if !headers.contains_key("grpc-status") {
        if let Ok(value) = HeaderValue::from_str(&status.code().to_string()) {
            headers.insert("grpc-status", value);
        }
    }
}

/// Extract gRPC status from response headers/trailers.
pub fn extract_grpc_status(headers: &HeaderMap) -> Option<GrpcStatus> {
    headers
        .get("grpc-status")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u8>().ok())
        .map(|code| match code {
            0 => GrpcStatus::Ok,
            1 => GrpcStatus::Cancelled,
            2 => GrpcStatus::Unknown,
            3 => GrpcStatus::InvalidArgument,
            4 => GrpcStatus::DeadlineExceeded,
            5 => GrpcStatus::NotFound,
            6 => GrpcStatus::AlreadyExists,
            7 => GrpcStatus::PermissionDenied,
            8 => GrpcStatus::ResourceExhausted,
            9 => GrpcStatus::FailedPrecondition,
            10 => GrpcStatus::Aborted,
            11 => GrpcStatus::OutOfRange,
            12 => GrpcStatus::Unimplemented,
            13 => GrpcStatus::Internal,
            14 => GrpcStatus::Unavailable,
            15 => GrpcStatus::DataLoss,
            16 => GrpcStatus::Unauthenticated,
            _ => GrpcStatus::Unknown,
        })
}

/// Extract gRPC message from response headers/trailers.
pub fn extract_grpc_message(headers: &HeaderMap) -> Option<String> {
    headers
        .get("grpc-message")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grpc_status() {
        assert_eq!(GrpcStatus::Ok.code(), 0);
        assert_eq!(GrpcStatus::Internal.code(), 13);
        assert_eq!(GrpcStatus::from_http_status(200), GrpcStatus::Ok);
        assert_eq!(GrpcStatus::from_http_status(500), GrpcStatus::Internal);
    }

    #[test]
    fn test_grpc_metadata() {
        let mut metadata = GrpcMetadata::new();
        metadata.insert("key", "value");
        metadata.insert_bin("binary", &[1, 2, 3]);

        assert_eq!(metadata.get("key"), Some("value"));
        assert_eq!(metadata.get_bin("binary"), Some(&[1, 2, 3][..]));
    }
}

