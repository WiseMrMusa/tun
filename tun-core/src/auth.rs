//! Authentication for tunnel connections.
//!
//! Provides token-based authentication using HMAC-SHA256.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

/// Default token time-to-live: 7 days in seconds.
pub const DEFAULT_TOKEN_TTL_SECONDS: u64 = 86400 * 7;

/// Authentication errors.
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Invalid token format")]
    InvalidFormat,
    #[error("Token signature mismatch")]
    SignatureMismatch,
    #[error("Token expired (age: {age_secs}s, max: {max_age_secs}s)")]
    Expired { age_secs: u64, max_age_secs: u64 },
    #[error("Invalid secret key")]
    InvalidKey,
    #[error("Invalid timestamp in token")]
    InvalidTimestamp,
}

/// An authentication token for tunnel access.
#[derive(Debug, Clone)]
pub struct AuthToken {
    /// The raw token string
    pub token: String,
    /// Token ID (first part before the signature)
    pub id: String,
    /// Timestamp when the token was created (Unix epoch seconds)
    pub timestamp: u64,
    /// Signature (second part after the dot)
    signature: String,
}

impl AuthToken {
    /// Generate a new token with the given secret key.
    pub fn generate(secret: &[u8]) -> Result<Self, AuthError> {
        let id = generate_random_id();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let data = format!("{}:{}", id, timestamp);
        let signature = sign_data(&data, secret)?;

        let token = format!("{}.{}", data, signature);

        Ok(Self {
            token: token.clone(),
            id,
            timestamp,
            signature,
        })
    }

    /// Parse a token string.
    pub fn parse(token: &str) -> Result<Self, AuthError> {
        let parts: Vec<&str> = token.rsplitn(2, '.').collect();
        if parts.len() != 2 {
            return Err(AuthError::InvalidFormat);
        }

        let signature = parts[0].to_string();
        let data = parts[1].to_string();
        
        let mut data_parts = data.split(':');
        let id = data_parts.next().unwrap_or("").to_string();
        let timestamp: u64 = data_parts
            .next()
            .and_then(|s| s.parse().ok())
            .ok_or(AuthError::InvalidTimestamp)?;

        Ok(Self {
            token: token.to_string(),
            id,
            timestamp,
            signature,
        })
    }

    /// Get the age of this token in seconds.
    pub fn age_seconds(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now.saturating_sub(self.timestamp)
    }

    /// Verify this token against a secret (signature only, no expiration check).
    pub fn verify(&self, secret: &[u8]) -> Result<(), AuthError> {
        let parts: Vec<&str> = self.token.rsplitn(2, '.').collect();
        if parts.len() != 2 {
            return Err(AuthError::InvalidFormat);
        }

        let data = parts[1];
        let expected_signature = sign_data(data, secret)?;

        if self.signature != expected_signature {
            return Err(AuthError::SignatureMismatch);
        }

        Ok(())
    }

    /// Verify this token against a secret with expiration check.
    /// 
    /// # Arguments
    /// * `secret` - The secret key to verify the signature against
    /// * `max_age_secs` - Maximum allowed age of the token in seconds. 
    ///                    If `None`, uses `DEFAULT_TOKEN_TTL_SECONDS`.
    pub fn verify_with_expiry(&self, secret: &[u8], max_age_secs: Option<u64>) -> Result<(), AuthError> {
        // First verify the signature
        self.verify(secret)?;

        // Then check expiration
        let max_age = max_age_secs.unwrap_or(DEFAULT_TOKEN_TTL_SECONDS);
        let age = self.age_seconds();

        if age > max_age {
            return Err(AuthError::Expired {
                age_secs: age,
                max_age_secs: max_age,
            });
        }

        Ok(())
    }
}

/// Token validator for the server.
#[derive(Clone)]
pub struct TokenValidator {
    secret: Vec<u8>,
    /// Token TTL in seconds. If None, uses DEFAULT_TOKEN_TTL_SECONDS.
    token_ttl: Option<u64>,
}

impl TokenValidator {
    /// Create a new validator with the given secret.
    pub fn new(secret: impl AsRef<[u8]>) -> Self {
        Self {
            secret: secret.as_ref().to_vec(),
            token_ttl: None,
        }
    }

    /// Create a new validator with a custom TTL.
    pub fn with_ttl(secret: impl AsRef<[u8]>, ttl_seconds: u64) -> Self {
        Self {
            secret: secret.as_ref().to_vec(),
            token_ttl: Some(ttl_seconds),
        }
    }

    /// Set the token TTL.
    pub fn set_ttl(&mut self, ttl_seconds: u64) {
        self.token_ttl = Some(ttl_seconds);
    }

    /// Get the configured TTL or the default.
    pub fn ttl(&self) -> u64 {
        self.token_ttl.unwrap_or(DEFAULT_TOKEN_TTL_SECONDS)
    }

    /// Create a validator from a hex-encoded secret.
    pub fn from_hex(hex_secret: &str) -> Result<Self, AuthError> {
        let secret = hex::decode(hex_secret).map_err(|_| AuthError::InvalidKey)?;
        Ok(Self::new(secret))
    }

    /// Create a validator from a hex-encoded secret with custom TTL.
    pub fn from_hex_with_ttl(hex_secret: &str, ttl_seconds: u64) -> Result<Self, AuthError> {
        let secret = hex::decode(hex_secret).map_err(|_| AuthError::InvalidKey)?;
        Ok(Self::with_ttl(secret, ttl_seconds))
    }

    /// Generate a new authentication token.
    pub fn generate_token(&self) -> Result<AuthToken, AuthError> {
        AuthToken::generate(&self.secret)
    }

    /// Validate a token string (signature only, no expiration check).
    pub fn validate(&self, token: &str) -> Result<AuthToken, AuthError> {
        let auth_token = AuthToken::parse(token)?;
        auth_token.verify(&self.secret)?;
        Ok(auth_token)
    }

    /// Validate a token string with expiration check.
    /// Uses the configured TTL or DEFAULT_TOKEN_TTL_SECONDS if not set.
    pub fn validate_with_expiry(&self, token: &str) -> Result<AuthToken, AuthError> {
        let auth_token = AuthToken::parse(token)?;
        auth_token.verify_with_expiry(&self.secret, self.token_ttl)?;
        Ok(auth_token)
    }

    /// Validate a token string with a custom expiration time.
    pub fn validate_with_custom_expiry(&self, token: &str, max_age_secs: u64) -> Result<AuthToken, AuthError> {
        let auth_token = AuthToken::parse(token)?;
        auth_token.verify_with_expiry(&self.secret, Some(max_age_secs))?;
        Ok(auth_token)
    }

    /// Get the secret as a hex string (for display/storage).
    pub fn secret_hex(&self) -> String {
        hex::encode(&self.secret)
    }
}

impl Default for TokenValidator {
    fn default() -> Self {
        // Generate a random secret for new instances
        Self::new(generate_random_secret())
    }
}

/// Sign data using HMAC-SHA256.
fn sign_data(data: &str, secret: &[u8]) -> Result<String, AuthError> {
    let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| AuthError::InvalidKey)?;
    mac.update(data.as_bytes());
    let result = mac.finalize();
    Ok(hex::encode(result.into_bytes()))
}

/// Generate a random 16-character ID.
fn generate_random_id() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 8] = rng.gen();
    hex::encode(bytes)
}

/// Generate a random 32-byte secret.
fn generate_random_secret() -> Vec<u8> {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let mut bytes = vec![0u8; 32];
    rng.fill(&mut bytes[..]);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_generation_and_validation() {
        let validator = TokenValidator::default();
        let token = validator.generate_token().unwrap();

        // Should validate successfully
        assert!(validator.validate(&token.token).is_ok());
        
        // Should also validate with expiry (fresh token)
        assert!(validator.validate_with_expiry(&token.token).is_ok());
    }

    #[test]
    fn test_invalid_token() {
        let validator = TokenValidator::default();
        let result = validator.validate("invalid.token");
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_secret() {
        let validator1 = TokenValidator::default();
        let validator2 = TokenValidator::default();

        let token = validator1.generate_token().unwrap();

        // Should fail with different secret
        assert!(validator2.validate(&token.token).is_err());
    }

    #[test]
    fn test_token_parse() {
        let token_str = "abc123:1234567890.signature";
        let token = AuthToken::parse(token_str).unwrap();
        assert_eq!(token.id, "abc123");
        assert_eq!(token.timestamp, 1234567890);
    }

    #[test]
    fn test_token_expiration() {
        let validator = TokenValidator::default();
        let token = validator.generate_token().unwrap();

        // Fresh token should not be expired with default TTL
        assert!(validator.validate_with_expiry(&token.token).is_ok());

        // Fresh token should not be expired with a reasonable TTL
        assert!(validator.validate_with_custom_expiry(&token.token, 3600).is_ok());

        // Token should be expired if max age is 0
        let result = validator.validate_with_custom_expiry(&token.token, 0);
        assert!(matches!(result, Err(AuthError::Expired { .. })));
    }

    #[test]
    fn test_token_age() {
        let validator = TokenValidator::default();
        let token = validator.generate_token().unwrap();

        // Fresh token should have age close to 0
        assert!(token.age_seconds() < 2);
    }

    #[test]
    fn test_expired_token_error_message() {
        let validator = TokenValidator::default();
        let token = validator.generate_token().unwrap();

        // Artificially "expire" by using max_age of 0
        let result = validator.validate_with_custom_expiry(&token.token, 0);
        
        match result {
            Err(AuthError::Expired { age_secs, max_age_secs }) => {
                // age_secs is u64, so it's always >= 0, just verify it's a small value
                assert!(age_secs < 10, "Token age should be small for fresh token");
                assert_eq!(max_age_secs, 0);
            }
            _ => panic!("Expected Expired error"),
        }
    }

    #[test]
    fn test_validator_with_ttl() {
        let secret = generate_random_secret();
        let validator = TokenValidator::with_ttl(&secret, 3600);
        assert_eq!(validator.ttl(), 3600);
        
        let token = validator.generate_token().unwrap();
        assert!(validator.validate_with_expiry(&token.token).is_ok());
    }

    #[test]
    fn test_invalid_timestamp() {
        // Token without proper timestamp format
        let result = AuthToken::parse("abc123.signature");
        assert!(matches!(result, Err(AuthError::InvalidTimestamp)));
    }
}

