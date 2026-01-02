//! Request validation middleware.
//!
//! Provides configurable validation for incoming HTTP requests including:
//! - Header validation (required headers, forbidden headers)
//! - Content-Type validation
//! - Content-Length limits
//! - Basic pattern detection for security

use regex::Regex;
use std::collections::HashSet;
use tracing::{debug, warn};

/// Validation result.
#[derive(Debug)]
pub enum ValidationResult {
    /// Request is valid
    Valid,
    /// Request is invalid with reason
    Invalid(String),
}

impl ValidationResult {
    pub fn is_valid(&self) -> bool {
        matches!(self, ValidationResult::Valid)
    }
}

/// Configuration for request validation.
#[derive(Debug, Clone)]
pub struct ValidationConfig {
    /// Maximum Content-Length (0 = unlimited)
    pub max_content_length: usize,
    /// Required headers (must be present)
    pub required_headers: HashSet<String>,
    /// Forbidden headers (must not be present)
    pub forbidden_headers: HashSet<String>,
    /// Allowed Content-Types (empty = all allowed)
    pub allowed_content_types: HashSet<String>,
    /// Enable basic XSS pattern detection
    pub detect_xss_patterns: bool,
    /// Enable basic SQL injection pattern detection
    pub detect_sql_injection: bool,
    /// Custom validation patterns (request body must not match these)
    pub forbidden_patterns: Vec<String>,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            max_content_length: 0, // No limit by default
            required_headers: HashSet::new(),
            forbidden_headers: HashSet::new(),
            allowed_content_types: HashSet::new(),
            detect_xss_patterns: false,
            detect_sql_injection: false,
            forbidden_patterns: Vec::new(),
        }
    }
}

impl ValidationConfig {
    /// Create a strict validation config with common security checks.
    pub fn strict() -> Self {
        let mut config = Self::default();
        config.detect_xss_patterns = true;
        config.detect_sql_injection = true;
        config.max_content_length = 10 * 1024 * 1024; // 10MB
        config
    }
}

/// Request validator.
pub struct RequestValidator {
    config: ValidationConfig,
    /// Compiled XSS patterns
    xss_patterns: Vec<Regex>,
    /// Compiled SQL injection patterns
    sql_patterns: Vec<Regex>,
    /// Custom forbidden patterns
    forbidden_patterns: Vec<Regex>,
}

impl RequestValidator {
    /// Create a new validator with the given configuration.
    pub fn new(config: ValidationConfig) -> Self {
        let xss_patterns = if config.detect_xss_patterns {
            compile_xss_patterns()
        } else {
            Vec::new()
        };

        let sql_patterns = if config.detect_sql_injection {
            compile_sql_patterns()
        } else {
            Vec::new()
        };

        let forbidden_patterns = config
            .forbidden_patterns
            .iter()
            .filter_map(|p| Regex::new(p).ok())
            .collect();

        Self {
            config,
            xss_patterns,
            sql_patterns,
            forbidden_patterns,
        }
    }

    /// Create a validator that allows all requests.
    pub fn allow_all() -> Self {
        Self::new(ValidationConfig::default())
    }

    /// Validate a request.
    pub fn validate(
        &self,
        headers: &[(String, String)],
        body: Option<&[u8]>,
        content_length: Option<usize>,
    ) -> ValidationResult {
        // Check Content-Length limit
        if self.config.max_content_length > 0 {
            if let Some(len) = content_length {
                if len > self.config.max_content_length {
                    return ValidationResult::Invalid(format!(
                        "Content-Length {} exceeds limit {}",
                        len, self.config.max_content_length
                    ));
                }
            }
        }

        // Check required headers
        for required in &self.config.required_headers {
            let found = headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(required));
            if !found {
                return ValidationResult::Invalid(format!(
                    "Missing required header: {}",
                    required
                ));
            }
        }

        // Check forbidden headers
        for forbidden in &self.config.forbidden_headers {
            let found = headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(forbidden));
            if found {
                return ValidationResult::Invalid(format!(
                    "Forbidden header present: {}",
                    forbidden
                ));
            }
        }

        // Check Content-Type if restrictions are configured
        if !self.config.allowed_content_types.is_empty() {
            let content_type = headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                .map(|(_, v)| v.as_str());

            if let Some(ct) = content_type {
                // Extract the main content type (before any parameters like charset)
                let main_type = ct.split(';').next().unwrap_or(ct).trim();
                if !self.config.allowed_content_types.contains(main_type) {
                    return ValidationResult::Invalid(format!(
                        "Content-Type '{}' not allowed",
                        main_type
                    ));
                }
            }
        }

        // Check body patterns
        if let Some(body_bytes) = body {
            // Convert body to string for pattern matching (lossy)
            let body_str = String::from_utf8_lossy(body_bytes);

            // Check XSS patterns
            for pattern in &self.xss_patterns {
                if pattern.is_match(&body_str) {
                    warn!("Potential XSS detected in request body");
                    return ValidationResult::Invalid("Potential XSS detected".to_string());
                }
            }

            // Check SQL injection patterns
            for pattern in &self.sql_patterns {
                if pattern.is_match(&body_str) {
                    warn!("Potential SQL injection detected in request body");
                    return ValidationResult::Invalid(
                        "Potential SQL injection detected".to_string(),
                    );
                }
            }

            // Check custom forbidden patterns
            for pattern in &self.forbidden_patterns {
                if pattern.is_match(&body_str) {
                    return ValidationResult::Invalid(
                        "Request matches forbidden pattern".to_string(),
                    );
                }
            }
        }

        debug!("Request validation passed");
        ValidationResult::Valid
    }

    /// Get the configuration.
    pub fn config(&self) -> &ValidationConfig {
        &self.config
    }
}

/// Compile common XSS detection patterns.
fn compile_xss_patterns() -> Vec<Regex> {
    let patterns = [
        r#"<script[^>]*>.*?</script>"#,
        r#"javascript:"#,
        r#"on\w+\s*="#,
        r#"<iframe[^>]*>"#,
        r#"<object[^>]*>"#,
        r#"<embed[^>]*>"#,
    ];

    patterns
        .iter()
        .filter_map(|p| Regex::new(&format!("(?i){}", p)).ok())
        .collect()
}

/// Compile common SQL injection detection patterns.
fn compile_sql_patterns() -> Vec<Regex> {
    let patterns = [
        r#"'\s*(or|and)\s*'?1'?\s*=\s*'?1"#,
        r#";\s*(drop|delete|truncate|update|insert)\s+"#,
        r#"union\s+(all\s+)?select"#,
        r#"--\s*$"#,
        r#"/\*.*?\*/"#,
    ];

    patterns
        .iter()
        .filter_map(|p| Regex::new(&format!("(?i){}", p)).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allow_all() {
        let validator = RequestValidator::allow_all();
        let result = validator.validate(&[], None, None);
        assert!(result.is_valid());
    }

    #[test]
    fn test_content_length_limit() {
        let mut config = ValidationConfig::default();
        config.max_content_length = 100;
        let validator = RequestValidator::new(config);

        // Under limit
        let result = validator.validate(&[], None, Some(50));
        assert!(result.is_valid());

        // Over limit
        let result = validator.validate(&[], None, Some(200));
        assert!(!result.is_valid());
    }

    #[test]
    fn test_required_headers() {
        let mut config = ValidationConfig::default();
        config.required_headers.insert("Authorization".to_string());
        let validator = RequestValidator::new(config);

        // Missing header
        let result = validator.validate(&[], None, None);
        assert!(!result.is_valid());

        // With header
        let headers = vec![("Authorization".to_string(), "Bearer token".to_string())];
        let result = validator.validate(&headers, None, None);
        assert!(result.is_valid());
    }

    #[test]
    fn test_xss_detection() {
        let config = ValidationConfig::strict();
        let validator = RequestValidator::new(config);

        // Clean body
        let clean = b"Hello, world!";
        let result = validator.validate(&[], Some(clean), None);
        assert!(result.is_valid());

        // XSS in body
        let xss = b"<script>alert('xss')</script>";
        let result = validator.validate(&[], Some(xss), None);
        assert!(!result.is_valid());
    }

    #[test]
    fn test_sql_injection_detection() {
        let config = ValidationConfig::strict();
        let validator = RequestValidator::new(config);

        // Clean body
        let clean = b"name=john";
        let result = validator.validate(&[], Some(clean), None);
        assert!(result.is_valid());

        // SQL injection
        let sqli = b"name=' OR '1'='1";
        let result = validator.validate(&[], Some(sqli), None);
        assert!(!result.is_valid());
    }
}

