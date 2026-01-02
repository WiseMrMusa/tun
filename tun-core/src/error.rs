//! Structured error types for the tunnel system.
//!
//! Replaces anyhow with strongly-typed errors for better error handling.

use std::fmt;

/// Main error type for tunnel operations.
#[derive(Debug)]
pub enum TunnelError {
    // === Connection Errors ===
    /// Failed to establish connection.
    ConnectionFailed(String),
    /// Connection was closed unexpectedly.
    ConnectionClosed,
    /// Connection timeout.
    ConnectionTimeout,
    
    // === Authentication Errors ===
    /// Invalid authentication token.
    InvalidToken(String),
    /// Token has expired.
    TokenExpired,
    /// Token has been revoked.
    TokenRevoked,
    /// Authentication timeout.
    AuthTimeout,
    
    // === Protocol Errors ===
    /// Failed to parse message.
    ProtocolError(String),
    /// Invalid message type.
    InvalidMessageType(String),
    /// Message too large.
    MessageTooLarge { size: usize, max: usize },
    /// Invalid payload.
    InvalidPayload(String),
    
    // === Request Errors ===
    /// Request timeout.
    RequestTimeout { timeout_secs: u64 },
    /// Request body too large.
    BodyTooLarge { size: usize, max: usize },
    /// Invalid request.
    InvalidRequest(String),
    /// Request validation failed.
    ValidationFailed(String),
    
    // === Tunnel Errors ===
    /// Tunnel not found.
    TunnelNotFound(String),
    /// Subdomain not available.
    SubdomainUnavailable(String),
    /// Maximum tunnels reached.
    MaxTunnelsReached { max: usize },
    /// Tunnel already exists.
    TunnelAlreadyExists(String),
    
    // === Rate Limiting ===
    /// Rate limit exceeded.
    RateLimitExceeded,
    /// IP blocked.
    IpBlocked(String),
    
    // === Access Control ===
    /// Access denied.
    AccessDenied(String),
    /// Subdomain disabled.
    SubdomainDisabled,
    /// IP not allowed.
    IpNotAllowed,
    /// Max connections reached.
    MaxConnectionsReached,
    
    // === Database Errors ===
    /// Database operation failed.
    DatabaseError(String),
    /// Record not found.
    NotFound(String),
    
    // === I/O Errors ===
    /// I/O error.
    IoError(std::io::Error),
    /// TLS error.
    TlsError(String),
    
    // === Cluster Errors ===
    /// Peer server unavailable.
    PeerUnavailable(String),
    /// Request forwarding failed.
    ForwardingFailed(String),
    
    // === Configuration Errors ===
    /// Invalid configuration.
    ConfigError(String),
    /// Missing required configuration.
    MissingConfig(String),
    
    // === Internal Errors ===
    /// Internal error (shouldn't happen).
    Internal(String),
}

impl fmt::Display for TunnelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // Connection Errors
            TunnelError::ConnectionFailed(msg) => write!(f, "connection failed: {}", msg),
            TunnelError::ConnectionClosed => write!(f, "connection closed unexpectedly"),
            TunnelError::ConnectionTimeout => write!(f, "connection timed out"),
            
            // Authentication Errors
            TunnelError::InvalidToken(msg) => write!(f, "invalid token: {}", msg),
            TunnelError::TokenExpired => write!(f, "token has expired"),
            TunnelError::TokenRevoked => write!(f, "token has been revoked"),
            TunnelError::AuthTimeout => write!(f, "authentication timed out"),
            
            // Protocol Errors
            TunnelError::ProtocolError(msg) => write!(f, "protocol error: {}", msg),
            TunnelError::InvalidMessageType(msg) => write!(f, "invalid message type: {}", msg),
            TunnelError::MessageTooLarge { size, max } => {
                write!(f, "message too large: {} bytes (max {})", size, max)
            }
            TunnelError::InvalidPayload(msg) => write!(f, "invalid payload: {}", msg),
            
            // Request Errors
            TunnelError::RequestTimeout { timeout_secs } => {
                write!(f, "request timed out after {} seconds", timeout_secs)
            }
            TunnelError::BodyTooLarge { size, max } => {
                write!(f, "request body too large: {} bytes (max {})", size, max)
            }
            TunnelError::InvalidRequest(msg) => write!(f, "invalid request: {}", msg),
            TunnelError::ValidationFailed(msg) => write!(f, "validation failed: {}", msg),
            
            // Tunnel Errors
            TunnelError::TunnelNotFound(subdomain) => {
                write!(f, "tunnel not found: {}", subdomain)
            }
            TunnelError::SubdomainUnavailable(subdomain) => {
                write!(f, "subdomain unavailable: {}", subdomain)
            }
            TunnelError::MaxTunnelsReached { max } => {
                write!(f, "maximum tunnels reached: {}", max)
            }
            TunnelError::TunnelAlreadyExists(subdomain) => {
                write!(f, "tunnel already exists: {}", subdomain)
            }
            
            // Rate Limiting
            TunnelError::RateLimitExceeded => write!(f, "rate limit exceeded"),
            TunnelError::IpBlocked(ip) => write!(f, "IP blocked: {}", ip),
            
            // Access Control
            TunnelError::AccessDenied(reason) => write!(f, "access denied: {}", reason),
            TunnelError::SubdomainDisabled => write!(f, "subdomain is disabled"),
            TunnelError::IpNotAllowed => write!(f, "IP address not allowed"),
            TunnelError::MaxConnectionsReached => write!(f, "maximum connections reached"),
            
            // Database Errors
            TunnelError::DatabaseError(msg) => write!(f, "database error: {}", msg),
            TunnelError::NotFound(what) => write!(f, "not found: {}", what),
            
            // I/O Errors
            TunnelError::IoError(e) => write!(f, "I/O error: {}", e),
            TunnelError::TlsError(msg) => write!(f, "TLS error: {}", msg),
            
            // Cluster Errors
            TunnelError::PeerUnavailable(peer) => write!(f, "peer unavailable: {}", peer),
            TunnelError::ForwardingFailed(msg) => write!(f, "request forwarding failed: {}", msg),
            
            // Configuration Errors
            TunnelError::ConfigError(msg) => write!(f, "configuration error: {}", msg),
            TunnelError::MissingConfig(what) => write!(f, "missing configuration: {}", what),
            
            // Internal Errors
            TunnelError::Internal(msg) => write!(f, "internal error: {}", msg),
        }
    }
}

impl std::error::Error for TunnelError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TunnelError::IoError(e) => Some(e),
            _ => None,
        }
    }
}

impl TunnelError {
    /// Get the HTTP status code for this error.
    pub fn status_code(&self) -> u16 {
        match self {
            // 400 Bad Request
            TunnelError::InvalidRequest(_)
            | TunnelError::InvalidPayload(_)
            | TunnelError::ProtocolError(_)
            | TunnelError::InvalidMessageType(_)
            | TunnelError::ValidationFailed(_) => 400,
            
            // 401 Unauthorized
            TunnelError::InvalidToken(_)
            | TunnelError::TokenExpired
            | TunnelError::AuthTimeout => 401,
            
            // 403 Forbidden
            TunnelError::TokenRevoked
            | TunnelError::AccessDenied(_)
            | TunnelError::SubdomainDisabled
            | TunnelError::IpNotAllowed
            | TunnelError::IpBlocked(_) => 403,
            
            // 404 Not Found
            TunnelError::TunnelNotFound(_)
            | TunnelError::NotFound(_) => 404,
            
            // 408 Request Timeout
            TunnelError::RequestTimeout { .. }
            | TunnelError::ConnectionTimeout => 408,
            
            // 409 Conflict
            TunnelError::SubdomainUnavailable(_)
            | TunnelError::TunnelAlreadyExists(_) => 409,
            
            // 413 Payload Too Large
            TunnelError::BodyTooLarge { .. }
            | TunnelError::MessageTooLarge { .. } => 413,
            
            // 429 Too Many Requests
            TunnelError::RateLimitExceeded => 429,
            
            // 502 Bad Gateway
            TunnelError::ConnectionFailed(_)
            | TunnelError::ForwardingFailed(_)
            | TunnelError::PeerUnavailable(_) => 502,
            
            // 503 Service Unavailable
            TunnelError::MaxTunnelsReached { .. }
            | TunnelError::MaxConnectionsReached
            | TunnelError::ConnectionClosed => 503,
            
            // 500 Internal Server Error (default)
            TunnelError::DatabaseError(_)
            | TunnelError::IoError(_)
            | TunnelError::TlsError(_)
            | TunnelError::ConfigError(_)
            | TunnelError::MissingConfig(_)
            | TunnelError::Internal(_) => 500,
        }
    }
    
    /// Get an error code string for JSON responses.
    pub fn error_code(&self) -> &'static str {
        match self {
            TunnelError::ConnectionFailed(_) => "connection_failed",
            TunnelError::ConnectionClosed => "connection_closed",
            TunnelError::ConnectionTimeout => "connection_timeout",
            TunnelError::InvalidToken(_) => "invalid_token",
            TunnelError::TokenExpired => "token_expired",
            TunnelError::TokenRevoked => "token_revoked",
            TunnelError::AuthTimeout => "auth_timeout",
            TunnelError::ProtocolError(_) => "protocol_error",
            TunnelError::InvalidMessageType(_) => "invalid_message_type",
            TunnelError::MessageTooLarge { .. } => "message_too_large",
            TunnelError::InvalidPayload(_) => "invalid_payload",
            TunnelError::RequestTimeout { .. } => "request_timeout",
            TunnelError::BodyTooLarge { .. } => "body_too_large",
            TunnelError::InvalidRequest(_) => "invalid_request",
            TunnelError::ValidationFailed(_) => "validation_failed",
            TunnelError::TunnelNotFound(_) => "tunnel_not_found",
            TunnelError::SubdomainUnavailable(_) => "subdomain_unavailable",
            TunnelError::MaxTunnelsReached { .. } => "max_tunnels_reached",
            TunnelError::TunnelAlreadyExists(_) => "tunnel_exists",
            TunnelError::RateLimitExceeded => "rate_limit_exceeded",
            TunnelError::IpBlocked(_) => "ip_blocked",
            TunnelError::AccessDenied(_) => "access_denied",
            TunnelError::SubdomainDisabled => "subdomain_disabled",
            TunnelError::IpNotAllowed => "ip_not_allowed",
            TunnelError::MaxConnectionsReached => "max_connections_reached",
            TunnelError::DatabaseError(_) => "database_error",
            TunnelError::NotFound(_) => "not_found",
            TunnelError::IoError(_) => "io_error",
            TunnelError::TlsError(_) => "tls_error",
            TunnelError::PeerUnavailable(_) => "peer_unavailable",
            TunnelError::ForwardingFailed(_) => "forwarding_failed",
            TunnelError::ConfigError(_) => "config_error",
            TunnelError::MissingConfig(_) => "missing_config",
            TunnelError::Internal(_) => "internal_error",
        }
    }
    
    /// Check if this error is retryable.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            TunnelError::ConnectionTimeout
                | TunnelError::RequestTimeout { .. }
                | TunnelError::RateLimitExceeded
                | TunnelError::PeerUnavailable(_)
                | TunnelError::MaxTunnelsReached { .. }
                | TunnelError::MaxConnectionsReached
                | TunnelError::ConnectionClosed
        )
    }
    
    /// Convert to a JSON-serializable error response.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "error": {
                "code": self.error_code(),
                "message": self.to_string(),
                "status": self.status_code(),
                "retryable": self.is_retryable(),
            }
        })
    }
}

// Conversions from common error types
impl From<std::io::Error> for TunnelError {
    fn from(e: std::io::Error) -> Self {
        TunnelError::IoError(e)
    }
}

impl From<serde_json::Error> for TunnelError {
    fn from(e: serde_json::Error) -> Self {
        TunnelError::ProtocolError(e.to_string())
    }
}

impl From<bincode::Error> for TunnelError {
    fn from(e: bincode::Error) -> Self {
        TunnelError::ProtocolError(e.to_string())
    }
}

/// Result type alias using TunnelError.
pub type TunnelResult<T> = Result<T, TunnelError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_status_codes() {
        assert_eq!(TunnelError::InvalidToken("bad".into()).status_code(), 401);
        assert_eq!(TunnelError::TunnelNotFound("test".into()).status_code(), 404);
        assert_eq!(TunnelError::RateLimitExceeded.status_code(), 429);
        assert_eq!(TunnelError::BodyTooLarge { size: 1000, max: 100 }.status_code(), 413);
    }

    #[test]
    fn test_error_codes() {
        assert_eq!(TunnelError::TokenExpired.error_code(), "token_expired");
        assert_eq!(TunnelError::RateLimitExceeded.error_code(), "rate_limit_exceeded");
    }

    #[test]
    fn test_retryable() {
        assert!(TunnelError::RateLimitExceeded.is_retryable());
        assert!(TunnelError::ConnectionTimeout.is_retryable());
        assert!(!TunnelError::InvalidToken("bad".into()).is_retryable());
    }

    #[test]
    fn test_to_json() {
        let err = TunnelError::RateLimitExceeded;
        let json = err.to_json();
        
        assert_eq!(json["error"]["code"], "rate_limit_exceeded");
        assert_eq!(json["error"]["status"], 429);
        assert_eq!(json["error"]["retryable"], true);
    }
}
