//! Authentication for tunnel connections.
//!
//! Provides token-based authentication using HMAC-SHA256.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

/// Authentication errors.
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Invalid token format")]
    InvalidFormat,
    #[error("Token signature mismatch")]
    SignatureMismatch,
    #[error("Token expired")]
    Expired,
    #[error("Invalid secret key")]
    InvalidKey,
}

/// An authentication token for tunnel access.
#[derive(Debug, Clone)]
pub struct AuthToken {
    /// The raw token string
    pub token: String,
    /// Token ID (first part before the signature)
    pub id: String,
    /// Signature (second part after the dot)
    signature: String,
}

impl AuthToken {
    /// Generate a new token with the given secret key.
    pub fn generate(secret: &[u8]) -> Result<Self, AuthError> {
        let id = generate_random_id();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let data = format!("{}:{}", id, timestamp);
        let signature = sign_data(&data, secret)?;

        let token = format!("{}.{}", data, signature);

        Ok(Self {
            token: token.clone(),
            id,
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
        let id = data.split(':').next().unwrap_or("").to_string();

        Ok(Self {
            token: token.to_string(),
            id,
            signature,
        })
    }

    /// Verify this token against a secret.
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
}

/// Token validator for the server.
#[derive(Clone)]
pub struct TokenValidator {
    secret: Vec<u8>,
}

impl TokenValidator {
    /// Create a new validator with the given secret.
    pub fn new(secret: impl AsRef<[u8]>) -> Self {
        Self {
            secret: secret.as_ref().to_vec(),
        }
    }

    /// Create a validator from a hex-encoded secret.
    pub fn from_hex(hex_secret: &str) -> Result<Self, AuthError> {
        let secret = hex::decode(hex_secret).map_err(|_| AuthError::InvalidKey)?;
        Ok(Self::new(secret))
    }

    /// Generate a new authentication token.
    pub fn generate_token(&self) -> Result<AuthToken, AuthError> {
        AuthToken::generate(&self.secret)
    }

    /// Validate a token string.
    pub fn validate(&self, token: &str) -> Result<AuthToken, AuthError> {
        let auth_token = AuthToken::parse(token)?;
        auth_token.verify(&self.secret)?;
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
    }
}

