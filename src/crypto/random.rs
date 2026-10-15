//! Random identifiers: opaque tokens (refresh tokens, session ids) and codes.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngExt as _;
use rand::distr::Alphanumeric;

/// Random base64url string with `bytes` bytes of entropy (no padding).
pub fn random_token_bytes(bytes: usize) -> String {
    let mut buffer = vec![0_u8; bytes];
    rand::fill(&mut buffer[..]);
    URL_SAFE_NO_PAD.encode(buffer)
}

/// 256-bit opaque token; 43 base64url characters.
pub fn random_token() -> String {
    random_token_bytes(32)
}

/// Alphanumeric string of `len` characters (authorization codes, session ids).
pub fn random_string(len: usize) -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_unpredictable_and_url_safe() {
        let a = random_token();
        let b = random_token();
        assert_ne!(a, b);
        assert_eq!(a.len(), 43);
        assert!(
            a.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
    }

    #[test]
    fn strings_have_requested_length() {
        assert_eq!(random_string(43).len(), 43);
        assert_eq!(random_string(8).len(), 8);
        assert_ne!(random_string(32), random_string(32));
    }
}
