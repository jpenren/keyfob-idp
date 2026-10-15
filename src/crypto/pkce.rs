//! PKCE (RFC 7636) helpers. Only `S256` is supported; `plain` is rejected.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Minimum length of a `code_verifier` (RFC 7636 section 4.1).
pub const MIN_VERIFIER_LEN: usize = 43;
/// Maximum length of a `code_verifier`.
pub const MAX_VERIFIER_LEN: usize = 128;

#[derive(Debug, Error)]
pub enum PkceError {
    #[error(
        "code_challenge_method '{0}' is not supported; use S256 (S256 is required for public clients)"
    )]
    UnsupportedMethod(String),
    #[error(
        "code_verifier must be between {MIN_VERIFIER_LEN} and {MAX_VERIFIER_LEN} characters of \
         [A-Za-z0-9-._~]"
    )]
    InvalidVerifier,
    #[error("code_verifier does not match the code_challenge sent to /authorize")]
    Mismatch,
}

/// `BASE64URL(SHA256(ASCII(code_verifier)))` without padding.
pub fn s256_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// Validates the `code_verifier` against the `code_challenge` (S256 only).
pub fn pkce_verify(verifier: &str, challenge: &str, method: &str) -> Result<(), PkceError> {
    if !method.eq_ignore_ascii_case("S256") {
        return Err(PkceError::UnsupportedMethod(method.to_string()));
    }
    if !is_valid_verifier(verifier) {
        return Err(PkceError::InvalidVerifier);
    }
    let computed = s256_challenge(verifier);
    if subtle::ConstantTimeEq::ct_eq(computed.as_bytes(), challenge.as_bytes()).into() {
        Ok(())
    } else {
        Err(PkceError::Mismatch)
    }
}

/// True when `verifier` uses only the RFC 7636 unreserved character set and has
/// an acceptable length.
pub fn is_valid_verifier(verifier: &str) -> bool {
    let len = verifier.len();
    (MIN_VERIFIER_LEN..=MAX_VERIFIER_LEN).contains(&len)
        && verifier
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~'))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known-answer test from RFC 7636 appendix B.
    #[test]
    fn rfc7636_appendix_b() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert_eq!(s256_challenge(verifier), challenge);
        assert!(pkce_verify(verifier, challenge, "S256").is_ok());
        assert!(pkce_verify(verifier, challenge, "s256").is_ok());
    }

    #[test]
    fn plain_is_rejected() {
        let err = pkce_verify("a".repeat(43).as_str(), "whatever", "plain").unwrap_err();
        assert!(err.to_string().contains("not supported"), "{err}");
    }

    #[test]
    fn wrong_verifier_does_not_match() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = s256_challenge("another-verifier-that-is-long-enough-ok");
        let err = pkce_verify(verifier, &challenge, "S256").unwrap_err();
        assert!(matches!(err, PkceError::Mismatch));
    }

    #[test]
    fn verifier_length_is_enforced() {
        assert!(!is_valid_verifier("too-short"));
        assert!(is_valid_verifier(&"a".repeat(43)));
        assert!(is_valid_verifier(&"a".repeat(128)));
        assert!(!is_valid_verifier(&"a".repeat(129)));
        assert!(!is_valid_verifier(&"ä".repeat(43)));
    }
}
