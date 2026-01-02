//! Per-path body size limits.
//!
//! Allows configuring different maximum body sizes for different paths,
//! useful for APIs that handle file uploads on specific endpoints.

use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, trace};

/// Configuration for per-path body size limits.
#[derive(Debug, Clone)]
pub struct BodyLimitConfig {
    /// Default body size limit in bytes.
    pub default_limit: usize,
    /// Per-path limits (path prefix -> limit in bytes).
    pub path_limits: HashMap<String, usize>,
}

impl Default for BodyLimitConfig {
    fn default() -> Self {
        Self {
            default_limit: 10 * 1024 * 1024, // 10 MB default
            path_limits: HashMap::new(),
        }
    }
}

impl BodyLimitConfig {
    /// Create a new config with a default limit.
    pub fn new(default_limit: usize) -> Self {
        Self {
            default_limit,
            path_limits: HashMap::new(),
        }
    }

    /// Add a path-specific limit.
    pub fn with_path_limit(mut self, path_prefix: &str, limit: usize) -> Self {
        self.path_limits.insert(path_prefix.to_string(), limit);
        self
    }

    /// Get the limit for a specific path.
    pub fn get_limit(&self, path: &str) -> usize {
        // Find the most specific matching path prefix
        let mut best_match: Option<(&String, &usize)> = None;

        for (prefix, limit) in &self.path_limits {
            if path.starts_with(prefix) {
                match &best_match {
                    Some((best_prefix, _)) if prefix.len() > best_prefix.len() => {
                        best_match = Some((prefix, limit));
                    }
                    None => {
                        best_match = Some((prefix, limit));
                    }
                    _ => {}
                }
            }
        }

        match best_match {
            Some((prefix, limit)) => {
                trace!(
                    "Using path-specific limit {} for path {} (prefix: {})",
                    limit,
                    path,
                    prefix
                );
                *limit
            }
            None => {
                trace!(
                    "Using default limit {} for path {}",
                    self.default_limit,
                    path
                );
                self.default_limit
            }
        }
    }

    /// Check if a body size is within the limit for a path.
    pub fn check(&self, path: &str, body_size: usize) -> Result<(), BodyLimitError> {
        let limit = self.get_limit(path);
        if body_size > limit {
            debug!(
                "Body size {} exceeds limit {} for path {}",
                body_size, limit, path
            );
            Err(BodyLimitError {
                path: path.to_string(),
                size: body_size,
                limit,
            })
        } else {
            Ok(())
        }
    }
}

/// Error when body size exceeds limit.
#[derive(Debug, Clone)]
pub struct BodyLimitError {
    /// The path that was checked.
    pub path: String,
    /// The actual body size.
    pub size: usize,
    /// The limit that was exceeded.
    pub limit: usize,
}

impl std::fmt::Display for BodyLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Body size {} exceeds limit {} for path {}",
            self.size, self.limit, self.path
        )
    }
}

impl std::error::Error for BodyLimitError {}

/// Body limit checker that can be shared across requests.
#[derive(Clone)]
pub struct BodyLimiter {
    config: Arc<BodyLimitConfig>,
}

impl BodyLimiter {
    /// Create a new body limiter.
    pub fn new(config: BodyLimitConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }

    /// Get the limit for a path.
    pub fn get_limit(&self, path: &str) -> usize {
        self.config.get_limit(path)
    }

    /// Check if a body size is within limits.
    pub fn check(&self, path: &str, body_size: usize) -> Result<(), BodyLimitError> {
        self.config.check(path, body_size)
    }

    /// Get the underlying config.
    pub fn config(&self) -> &BodyLimitConfig {
        &self.config
    }
}

/// Parse a size string like "10MB" or "1024" into bytes.
pub fn parse_size(s: &str) -> Result<usize, String> {
    let s = s.trim().to_uppercase();

    if s.is_empty() {
        return Err("Empty size string".to_string());
    }

    // Check for unit suffix
    let (num_str, multiplier): (&str, usize) = if s.ends_with("TB") {
        (&s[..s.len() - 2], 1024_usize * 1024 * 1024 * 1024)
    } else if s.ends_with("GB") {
        (&s[..s.len() - 2], 1024_usize * 1024 * 1024)
    } else if s.ends_with("MB") {
        (&s[..s.len() - 2], 1024_usize * 1024)
    } else if s.ends_with("KB") {
        (&s[..s.len() - 2], 1024)
    } else if s.ends_with("B") {
        (&s[..s.len() - 1], 1)
    } else if s.ends_with('T') {
        (&s[..s.len() - 1], 1024_usize * 1024 * 1024 * 1024)
    } else if s.ends_with('G') {
        (&s[..s.len() - 1], 1024_usize * 1024 * 1024)
    } else if s.ends_with('M') {
        (&s[..s.len() - 1], 1024_usize * 1024)
    } else if s.ends_with('K') {
        (&s[..s.len() - 1], 1024)
    } else {
        (s.as_str(), 1)
    };

    let num: f64 = num_str
        .trim()
        .parse()
        .map_err(|_| format!("Invalid number: {}", num_str))?;

    Ok((num * multiplier as f64) as usize)
}

/// Parse a path limit configuration string.
/// Format: "path:size,path:size,..." (e.g., "/upload:100MB,/api:1MB")
pub fn parse_path_limits(s: &str) -> Result<Vec<(String, usize)>, String> {
    if s.is_empty() {
        return Ok(Vec::new());
    }

    let mut limits = Vec::new();

    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        let (path, size_str) = part
            .split_once(':')
            .ok_or_else(|| format!("Invalid format '{}': expected 'path:size'", part))?;

        let size = parse_size(size_str)?;
        limits.push((path.to_string(), size));
    }

    Ok(limits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_size() {
        assert_eq!(parse_size("1024").unwrap(), 1024);
        assert_eq!(parse_size("1KB").unwrap(), 1024);
        assert_eq!(parse_size("1MB").unwrap(), 1024 * 1024);
        assert_eq!(parse_size("1GB").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_size("10M").unwrap(), 10 * 1024 * 1024);
        assert_eq!(parse_size("1.5MB").unwrap(), (1.5 * 1024.0 * 1024.0) as usize);
    }

    #[test]
    fn test_body_limit_config() {
        let config = BodyLimitConfig::new(1024 * 1024) // 1MB default
            .with_path_limit("/upload", 100 * 1024 * 1024) // 100MB for uploads
            .with_path_limit("/api", 64 * 1024); // 64KB for API

        assert_eq!(config.get_limit("/"), 1024 * 1024);
        assert_eq!(config.get_limit("/upload"), 100 * 1024 * 1024);
        assert_eq!(config.get_limit("/upload/file.jpg"), 100 * 1024 * 1024);
        assert_eq!(config.get_limit("/api"), 64 * 1024);
        assert_eq!(config.get_limit("/api/users"), 64 * 1024);
    }

    #[test]
    fn test_parse_path_limits() {
        let limits = parse_path_limits("/upload:100MB,/api:1MB").unwrap();
        assert_eq!(limits.len(), 2);
        assert_eq!(limits[0], ("/upload".to_string(), 100 * 1024 * 1024));
        assert_eq!(limits[1], ("/api".to_string(), 1 * 1024 * 1024));
    }

    #[test]
    fn test_body_limit_check() {
        let config = BodyLimitConfig::new(1024);

        assert!(config.check("/", 500).is_ok());
        assert!(config.check("/", 1024).is_ok());
        assert!(config.check("/", 1025).is_err());
    }
}

