//! Password hashing (argon2) and constant-time comparisons.

use argon2::{Argon2, PasswordHasher as _, PasswordVerifier as _};
use thiserror::Error;

/// Marker prefix of an argon2 PHC hash string.
pub const ARGON2_PREFIX: &str = "$argon2";

#[derive(Debug, Error)]
pub enum PasswordError {
    #[error("failed to hash password: {0}")]
    Hash(String),
    #[error("stored password hash is not a valid argon2 PHC string: {0}")]
    InvalidHash(String),
}

/// Hashes a plaintext password with argon2id (random salt, PHC string output).
pub fn hash_password(plain: &str) -> Result<String, PasswordError> {
    let salt = argon2::password_hash::generate_salt();
    let hash = Argon2::default()
        .hash_password_with_salt(plain.as_bytes(), &salt)
        .map_err(|err| PasswordError::Hash(err.to_string()))?;
    Ok(hash.to_string())
}

/// Verifies `plain` against `stored`, which may be an argon2 PHC hash or a
/// plaintext password (development convenience).
pub fn verify_password(plain: &str, stored: &str) -> bool {
    if stored.starts_with(ARGON2_PREFIX) {
        let Ok(parsed) = argon2::PasswordHash::new(stored) else {
            return false;
        };
        Argon2::default()
            .verify_password(plain.as_bytes(), &parsed)
            .is_ok()
    } else {
        constant_time_eq(plain, stored)
    }
}

/// Length-aware constant-time string comparison.
pub fn constant_time_eq(left: &str, right: &str) -> bool {
    use subtle::ConstantTimeEq;
    left.as_bytes().ct_eq(right.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2_roundtrip() {
        let hash = hash_password("s3cret").unwrap();
        assert!(hash.starts_with("$argon2"), "{hash}");
        assert!(verify_password("s3cret", &hash));
        assert!(!verify_password("wrong", &hash));
    }

    #[test]
    fn hashes_are_salted() {
        let a = hash_password("same").unwrap();
        let b = hash_password("same").unwrap();
        assert_ne!(a, b);
        assert!(verify_password("same", &a) && verify_password("same", &b));
    }

    #[test]
    fn plaintext_passwords_are_supported() {
        assert!(verify_password("dev", "dev"));
        assert!(!verify_password("dev", "prod"));
        assert!(!verify_password("dev", "d"));
    }

    #[test]
    fn malformed_hash_never_matches() {
        assert!(!verify_password("x", "$argon2id$not-a-hash"));
    }

    #[test]
    fn constant_time_comparison() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
    }
}
