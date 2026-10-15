//! JWT encoding/decoding on top of `jsonwebtoken`.

use jsonwebtoken::{Algorithm, Header, Validation};
use serde::Serialize;
use serde_json::Value;
use thiserror::Error;

use super::keys::KeySet;

#[derive(Debug, Error)]
pub enum JwtError {
    #[error("JWT error: {0}")]
    Inner(#[from] jsonwebtoken::errors::Error),
}

/// Options controlling token verification.
#[derive(Debug, Clone)]
pub struct TokenValidation {
    pub issuer: String,
    /// When false (introspection of expired tokens) `exp` is not enforced.
    pub validate_exp: bool,
}

impl TokenValidation {
    pub fn new(issuer: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            validate_exp: true,
        }
    }

    pub fn allow_expired(mut self) -> Self {
        self.validate_exp = false;
        self
    }

    fn build(&self, algorithm: Algorithm) -> Validation {
        let mut validation = Validation::new(algorithm);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.validate_exp = self.validate_exp;
        // Access tokens may carry several audiences and none is required to
        // consume our own endpoints; audience checks are up to resource servers.
        validation.validate_aud = false;
        // No leeway: this is a single process, and short TTLs (5s) are a
        // first-class development feature.
        validation.leeway = 0;
        validation
    }
}

/// Signs `claims` with the active key.
pub fn encode_jwt(keys: &KeySet, claims: &impl Serialize) -> Result<String, JwtError> {
    Ok(jsonwebtoken::encode(
        &keys.header(),
        claims,
        keys.encoding_key(),
    )?)
}

/// Verifies the signature and standard claims of `token` and returns its payload.
pub fn decode_jwt(
    keys: &KeySet,
    token: &str,
    validation: &TokenValidation,
) -> Result<Value, JwtError> {
    let validation = validation.build(keys.algorithm());
    let data = jsonwebtoken::decode::<Value>(token, keys.decoding_key(), &validation)?;
    Ok(data.claims)
}

/// Reads the header without verifying the signature (used for diagnostics).
pub fn decode_jwt_header(token: &str) -> Result<Header, JwtError> {
    Ok(jsonwebtoken::decode_header(token)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::{DEFAULT_KEY_BITS, KeySet};
    use serde_json::json;

    fn keys() -> KeySet {
        KeySet::generate("RS256", DEFAULT_KEY_BITS).unwrap()
    }

    #[test]
    fn roundtrip_with_issuer_check() {
        let keys = keys();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let token = encode_jwt(
            &keys,
            &json!({ "iss": "http://localhost:9000", "sub": "alice", "exp": now + 60 }),
        )
        .unwrap();

        let claims = decode_jwt(
            &keys,
            &token,
            &TokenValidation::new("http://localhost:9000"),
        )
        .unwrap();
        assert_eq!(claims["sub"], "alice");

        let err = decode_jwt(&keys, &token, &TokenValidation::new("http://other")).unwrap_err();
        assert!(err.to_string().contains("InvalidIssuer"), "{err}");
    }

    #[test]
    fn expired_tokens_are_rejected_unless_explicitly_allowed() {
        let keys = keys();
        let token = encode_jwt(
            &keys,
            &json!({ "iss": "iss", "exp": 1_000_000, "sub": "alice" }),
        )
        .unwrap();

        let err = decode_jwt(&keys, &token, &TokenValidation::new("iss")).unwrap_err();
        assert!(err.to_string().contains("ExpiredSignature"), "{err}");

        let claims =
            decode_jwt(&keys, &token, &TokenValidation::new("iss").allow_expired()).unwrap();
        assert_eq!(claims["sub"], "alice");
    }

    #[test]
    fn signature_from_another_key_is_rejected() {
        let other = keys();
        let token = encode_jwt(
            &other,
            &json!({ "iss": "iss", "exp": 4_000_000_000_u64, "sub": "alice" }),
        )
        .unwrap();
        let err = decode_jwt(&keys(), &token, &TokenValidation::new("iss")).unwrap_err();
        assert!(err.to_string().contains("InvalidSignature"), "{err}");
    }

    #[test]
    fn header_exposes_kid_and_alg() {
        let keys = keys();
        let token = encode_jwt(&keys, &json!({ "iss": "iss", "exp": 4_000_000_000_u64 })).unwrap();
        let header = decode_jwt_header(&token).unwrap();
        assert_eq!(header.alg, Algorithm::RS256);
        assert_eq!(header.kid.as_deref(), Some(keys.kid()));
    }

    #[test]
    fn garbage_is_not_a_token() {
        assert!(decode_jwt(&keys(), "not-a-jwt", &TokenValidation::new("iss")).is_err());
    }
}
