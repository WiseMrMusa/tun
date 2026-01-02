//! Custom error types with rich context for the tunnel system.
//!
//! Provides structured errors with context that can be logged and displayed
//! in a user-friendly manner.

use std::fmt;

/// Error categories for the tunnel system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCategory {
    /// Authentication-related errors.
    Authentication,
    /// Connection and network errors.
    Connection,
    /// Protocol parsing/validation errors.
    Protocol,
    /// Configuration errors.
    Configuration,
    /// Upstream service errors.
    Upstream,
    /// Rate limiting errors.
    RateLimit,
    /// Internal server errors.
    Internal,
    /// Timeout errors.
    Timeout,
}

impl fmt::Display for ErrorCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorCategory::Authentication => write!(f, "authentication"),
            ErrorCategory::Connection => write!(f, "connection"),
            ErrorCategory::Protocol => write!(f, "protocol"),
            ErrorCategory::Configuration => write!(f, "configuration"),
            ErrorCategory::Upstream => write!(f, "upstream"),
            ErrorCategory::RateLimit => write!(f, "rate_limit"),
            ErrorCategory::Internal => write!(f, "internal"),
            ErrorCategory::Timeout => write!(f, "timeout"),
        }
    }
}

/// A tunnel error with category and context.
#[derive(Debug)]
pub struct TunnelError {
    /// The error category.
    pub category: ErrorCategory,
    /// A human-readable message.
    pub message: String,
    /// The underlying cause, if any.
    pub cause: Option<Box<dyn std::error::Error + Send + Sync>>,
    /// Additional context as key-value pairs.
    pub context: Vec<(String, String)>,
}

impl TunnelError {
    /// Create a new tunnel error.
    pub fn new(category: ErrorCategory, message: impl Into<String>) -> Self {
        Self {
            category,
            message: message.into(),
            cause: None,
            context: Vec::new(),
        }
    }

    /// Add an underlying cause.
    pub fn with_cause<E: std::error::Error + Send + Sync + 'static>(mut self, cause: E) -> Self {
        self.cause = Some(Box::new(cause));
        self
    }

    /// Add context to the error.
    pub fn with_context(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.context.push((key.into(), value.into()));
        self
    }

    /// Check if this is a retryable error.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self.category,
            ErrorCategory::Connection | ErrorCategory::Timeout | ErrorCategory::RateLimit
        )
    }

    /// Get the HTTP status code for this error type.
    pub fn http_status(&self) -> u16 {
        match self.category {
            ErrorCategory::Authentication => 401,
            ErrorCategory::Connection => 502,
            ErrorCategory::Protocol => 400,
            ErrorCategory::Configuration => 500,
            ErrorCategory::Upstream => 502,
            ErrorCategory::RateLimit => 429,
            ErrorCategory::Internal => 500,
            ErrorCategory::Timeout => 504,
        }
    }
}

impl fmt::Display for TunnelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.category, self.message)?;

        if !self.context.is_empty() {
            write!(f, " (")?;
            for (i, (k, v)) in self.context.iter().enumerate() {
                if i > 0 {
                    write!(f, ", ")?;
                }
                write!(f, "{}={}", k, v)?;
            }
            write!(f, ")")?;
        }

        if let Some(ref cause) = self.cause {
            write!(f, ": {}", cause)?;
        }

        Ok(())
    }
}

impl std::error::Error for TunnelError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cause
            .as_ref()
            .map(|e| e.as_ref() as &(dyn std::error::Error + 'static))
    }
}

// Convenience constructors
impl TunnelError {
    /// Create an authentication error.
    pub fn auth(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::Authentication, message)
    }

    /// Create a connection error.
    pub fn connection(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::Connection, message)
    }

    /// Create a protocol error.
    pub fn protocol(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::Protocol, message)
    }

    /// Create a configuration error.
    pub fn config(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::Configuration, message)
    }

    /// Create an upstream error.
    pub fn upstream(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::Upstream, message)
    }

    /// Create a rate limit error.
    pub fn rate_limit(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::RateLimit, message)
    }

    /// Create an internal error.
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::Internal, message)
    }

    /// Create a timeout error.
    pub fn timeout(message: impl Into<String>) -> Self {
        Self::new(ErrorCategory::Timeout, message)
    }
}

/// Result type using TunnelError.
pub type TunnelResult<T> = Result<T, TunnelError>;

/// Helper trait for adding context to errors.
pub trait ResultExt<T> {
    /// Add context to an error.
    fn with_context(
        self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<T, TunnelError>;

    /// Convert error category.
    fn with_category(self, category: ErrorCategory) -> Result<T, TunnelError>;
}

impl<T, E: std::error::Error + Send + Sync + 'static> ResultExt<T> for Result<T, E> {
    fn with_context(
        self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<T, TunnelError> {
        self.map_err(|e| {
            TunnelError::internal(e.to_string())
                .with_cause(e)
                .with_context(key, value)
        })
    }

    fn with_category(self, category: ErrorCategory) -> Result<T, TunnelError> {
        self.map_err(|e| TunnelError::new(category, e.to_string()).with_cause(e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = TunnelError::auth("Invalid token")
            .with_context("token_id", "abc123")
            .with_context("ip", "1.2.3.4");

        let display = err.to_string();
        assert!(display.contains("[authentication]"));
        assert!(display.contains("Invalid token"));
        assert!(display.contains("token_id=abc123"));
        assert!(display.contains("ip=1.2.3.4"));
    }

    #[test]
    fn test_error_retryable() {
        assert!(TunnelError::connection("test").is_retryable());
        assert!(TunnelError::timeout("test").is_retryable());
        assert!(TunnelError::rate_limit("test").is_retryable());
        assert!(!TunnelError::auth("test").is_retryable());
    }

    #[test]
    fn test_http_status() {
        assert_eq!(TunnelError::auth("test").http_status(), 401);
        assert_eq!(TunnelError::rate_limit("test").http_status(), 429);
        assert_eq!(TunnelError::timeout("test").http_status(), 504);
    }
}

