use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::EngineError;

type HmacSha256 = Hmac<Sha256>;

// base64url({"alg":"HS256","typ":"JWT"}) — constant, computed once
const HEADER_B64: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";

#[derive(Clone)]
pub struct JwtSecret {
    secret: [u8; 32],
    cached_iat: u64,
    cached_token: String,
}

impl JwtSecret {
    pub fn from_hex(s: &str) -> Result<Self, EngineError> {
        let s = s.trim().strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s).map_err(|e| EngineError::Jwt(e.to_string()))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| EngineError::Jwt("secret must be 32 bytes (64 hex chars)".into()))?;
        Ok(Self { secret: arr, cached_iat: 0, cached_token: String::new() })
    }

    pub fn from_file(path: &std::path::Path) -> Result<Self, EngineError> {
        let s = std::fs::read_to_string(path).map_err(|e| EngineError::Jwt(e.to_string()))?;
        Self::from_hex(s.trim())
    }

    /// Returns a cached `Bearer <token>` valid for the current second.
    /// Recomputes (one HMAC-SHA256) only when the Unix timestamp advances.
    pub fn bearer_token(&mut self) -> &str {
        let iat =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();

        if iat == self.cached_iat && !self.cached_token.is_empty() {
            return &self.cached_token;
        }

        let payload_b64 = URL_SAFE_NO_PAD.encode(format!(r#"{{"iat":{iat}}}"#));
        let signing_input = format!("{HEADER_B64}.{payload_b64}");

        let mut mac = HmacSha256::new_from_slice(&self.secret).unwrap();
        mac.update(signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());

        self.cached_iat = iat;
        self.cached_token = format!("Bearer {signing_input}.{sig_b64}");
        &self.cached_token
    }
}

#[cfg(test)]
mod tests {
    use simd_json::prelude::ValueObjectAccess;

    use super::*;

    const ZERO_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn from_hex_accepts_zero_key() {
        assert!(JwtSecret::from_hex(ZERO_KEY).is_ok());
    }

    #[test]
    fn from_hex_strips_0x_prefix() {
        let with_prefix = JwtSecret::from_hex(&format!("0x{ZERO_KEY}"));
        let without_prefix = JwtSecret::from_hex(ZERO_KEY);
        assert!(with_prefix.is_ok());
        assert!(without_prefix.is_ok());
    }

    #[test]
    fn from_hex_rejects_wrong_length() {
        assert!(JwtSecret::from_hex("deadbeef").is_err());
        assert!(JwtSecret::from_hex("").is_err());
    }

    #[test]
    fn bearer_token_is_three_part_jwt() {
        let mut jwt = JwtSecret::from_hex(ZERO_KEY).unwrap();
        let token = jwt.bearer_token();

        assert!(token.starts_with("Bearer "), "should start with 'Bearer '");
        let jwt_str = token.strip_prefix("Bearer ").unwrap();
        let parts: Vec<&str> = jwt_str.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT must have header.payload.signature");

        // Header is always the same constant
        assert_eq!(parts[0], HEADER_B64);

        // Payload must base64-decode to JSON containing "iat"
        let mut payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .expect("payload must be valid base64url");
        let payload: simd_json::OwnedValue =
            simd_json::from_slice(&mut payload_bytes).expect("payload must be valid JSON");
        assert!(payload.get("iat").is_some(), "JWT payload must contain 'iat'");
    }

    #[test]
    fn bearer_token_cached_within_same_second() {
        let mut jwt = JwtSecret::from_hex(ZERO_KEY).unwrap();
        let t1 = jwt.bearer_token().to_owned();
        let t2 = jwt.bearer_token().to_owned();
        assert_eq!(t1, t2, "consecutive calls in the same second must return the same token");
    }
}
