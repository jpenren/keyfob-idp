//! Cryptography helpers: signing keys, JWT encoding/decoding, password hashing,
//! PKCE and random token generation. Everything is pure Rust (`ring` is used by
//! the TLS stack, `openssl` is not used anywhere).

pub mod jwt;
pub mod keys;
pub mod password;
pub mod pkce;
pub mod random;

pub use jwt::{TokenValidation, decode_jwt, encode_jwt};
pub use keys::{DEFAULT_KEY_BITS, KeyOrigin, KeySet};
pub use password::{constant_time_eq, hash_password, verify_password};
pub use pkce::{pkce_verify, s256_challenge};
pub use random::{random_string, random_token};

/// Installs the `ring` crypto provider as the process-wide rustls default.
///
/// `rustls` is built without a compiled-in default provider (to avoid the
/// `aws-lc-rs` C toolchain requirement), so this must run once before any TLS
/// server or client is created. Calling it more than once is harmless.
pub fn install_crypto_provider() {
    // Ignore the error: it only means another provider was installed first.
    let _ = rustls::crypto::ring::default_provider().install_default();
}
