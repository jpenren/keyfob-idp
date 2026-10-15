//! RSA signing keys, persistence and JWKS generation.

use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header};
use rsa::RsaPrivateKey;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::traits::PublicKeyParts;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Default RSA key size. 2048 bits keeps key generation fast (a few tens of
/// milliseconds) which matters for a development tool that starts on demand.
pub const DEFAULT_KEY_BITS: usize = 2048;

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("failed to generate the RSA key: {0}")]
    Generate(String),

    #[error("failed to encode the RSA key as PEM: {0}")]
    Encode(String),

    #[error("failed to parse the RSA key: {0}")]
    Parse(String),

    #[error("unsupported signing algorithm '{0}': use RS256")]
    UnsupportedAlgorithm(String),

    #[error(
        "signing key file {path} uses algorithm '{found}' but the configuration asks for '{expected}'\n\
         Delete {path} (tokens signed with the old key stop being valid) or set keys.algorithm accordingly"
    )]
    AlgorithmMismatch {
        path: String,
        found: String,
        expected: String,
    },

    #[error(
        "signing key file {path} is invalid: {message}\n\
         Delete it to let keyfob generate a fresh key, or fix the file"
    )]
    CorruptKey { path: String, message: String },

    #[error("cannot read signing key file {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("cannot write signing key file {path}: {source}")]
    Write {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

/// How the current key was obtained; surfaced in logs and `/ui/info`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyOrigin {
    Generated,
    Loaded,
    Ephemeral,
}

impl KeyOrigin {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Generated => "generated",
            Self::Loaded => "loaded",
            Self::Ephemeral => "ephemeral (not persisted)",
        }
    }
}

/// On-disk representation of the signing key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedKey {
    pub kid: String,
    pub algorithm: String,
    pub private_pem: String,
    pub public_pem: String,
    pub created_at: i64,
}

/// The active signing key plus the derived material used across the server.
pub struct KeySet {
    kid: String,
    algorithm: Algorithm,
    persisted: PersistedKey,
    encoding: EncodingKey,
    decoding: DecodingKey,
    modulus: String,
    exponent: String,
}

impl std::fmt::Debug for KeySet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeySet")
            .field("kid", &self.kid)
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

impl KeySet {
    /// Generates a fresh in-memory RSA key pair.
    pub fn generate(algorithm: &str, bits: usize) -> Result<Self, KeyError> {
        let algorithm = parse_algorithm(algorithm)?;
        if algorithm != Algorithm::RS256 {
            return Err(KeyError::UnsupportedAlgorithm(format!("{algorithm:?}")));
        }

        let private = RsaPrivateKey::new(&mut rand::rngs::OsRng, bits)
            .map_err(|err| KeyError::Generate(err.to_string()))?;
        Self::from_private_key(private, algorithm)
    }

    /// Loads the key from `path`, generating and persisting it on first run.
    pub fn load_or_generate(
        path: &Path,
        persist: bool,
        algorithm: &str,
    ) -> Result<(Self, KeyOrigin), KeyError> {
        let _ = parse_algorithm(algorithm)?;

        if path.is_file() {
            let raw = std::fs::read_to_string(path).map_err(|source| KeyError::Read {
                path: path.display().to_string(),
                source,
            })?;
            let stored: PersistedKey =
                serde_json::from_str(&raw).map_err(|err| KeyError::CorruptKey {
                    path: path.display().to_string(),
                    message: err.to_string(),
                })?;
            if !stored.algorithm.eq_ignore_ascii_case(algorithm) {
                return Err(KeyError::AlgorithmMismatch {
                    path: path.display().to_string(),
                    found: stored.algorithm.clone(),
                    expected: algorithm.to_string(),
                });
            }
            let keys = Self::from_persisted(stored)?;
            return Ok((keys, KeyOrigin::Loaded));
        }

        let keys = Self::generate(algorithm, DEFAULT_KEY_BITS)?;
        if persist {
            keys.save(path)?;
            Ok((keys, KeyOrigin::Generated))
        } else {
            Ok((keys, KeyOrigin::Ephemeral))
        }
    }

    /// Rebuilds a key set from its on-disk representation.
    pub fn from_persisted(stored: PersistedKey) -> Result<Self, KeyError> {
        let algorithm = parse_algorithm(&stored.algorithm)?;
        let encoding = EncodingKey::from_rsa_pem(stored.private_pem.as_bytes())
            .map_err(|err| KeyError::Parse(err.to_string()))?;
        let decoding = DecodingKey::from_rsa_pem(stored.public_pem.as_bytes())
            .map_err(|err| KeyError::Parse(err.to_string()))?;

        let private = RsaPrivateKey::from_pkcs8_pem(&stored.private_pem)
            .map_err(|err| KeyError::Parse(err.to_string()))?;
        let modulus = URL_SAFE_NO_PAD.encode(private.n().to_bytes_be());
        let exponent = URL_SAFE_NO_PAD.encode(private.e().to_bytes_be());

        Ok(Self {
            kid: stored.kid.clone(),
            algorithm,
            persisted: stored,
            encoding,
            decoding,
            modulus,
            exponent,
        })
    }

    fn from_private_key(private: RsaPrivateKey, algorithm: Algorithm) -> Result<Self, KeyError> {
        let private_pem = private
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|err| KeyError::Encode(err.to_string()))?
            .to_string();
        let public_pem = private
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .map_err(|err| KeyError::Encode(err.to_string()))?;

        let modulus = URL_SAFE_NO_PAD.encode(private.n().to_bytes_be());
        let exponent = URL_SAFE_NO_PAD.encode(private.e().to_bytes_be());
        let kid = thumbprint(&modulus, &exponent);

        let stored = PersistedKey {
            kid: kid.clone(),
            algorithm: algorithm_name(algorithm).to_string(),
            private_pem: private_pem.clone(),
            public_pem: public_pem.clone(),
            created_at: time::OffsetDateTime::now_utc().unix_timestamp(),
        };

        let encoding = EncodingKey::from_rsa_pem(private_pem.as_bytes())
            .map_err(|err| KeyError::Parse(err.to_string()))?;
        let decoding = DecodingKey::from_rsa_pem(public_pem.as_bytes())
            .map_err(|err| KeyError::Parse(err.to_string()))?;

        Ok(Self {
            kid,
            algorithm,
            persisted: stored,
            encoding,
            decoding,
            modulus,
            exponent,
        })
    }

    /// Writes the key to disk (creating parent directories), mode 0600 on Unix.
    pub fn save(&self, path: &Path) -> Result<(), KeyError> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|source| KeyError::Write {
                path: parent.display().to_string(),
                source,
            })?;
        }
        let json = serde_json::to_string_pretty(&self.persisted)
            .map_err(|err| KeyError::Encode(err.to_string()))?;
        std::fs::write(path, json).map_err(|source| KeyError::Write {
            path: path.display().to_string(),
            source,
        })?;
        restrict_permissions(path)?;
        Ok(())
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    pub fn algorithm_name(&self) -> &'static str {
        algorithm_name(self.algorithm)
    }

    pub fn encoding_key(&self) -> &EncodingKey {
        &self.encoding
    }

    pub fn decoding_key(&self) -> &DecodingKey {
        &self.decoding
    }

    /// JWT header pointing at this key.
    pub fn header(&self) -> Header {
        let mut header = Header::new(self.algorithm);
        header.kid = Some(self.kid.clone());
        header
    }

    /// RFC 7517 JWK Set document served at `/jwks`.
    pub fn jwks(&self) -> serde_json::Value {
        serde_json::json!({
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": self.algorithm_name(),
                    "kid": self.kid,
                    "n": self.modulus,
                    "e": self.exponent,
                }
            ]
        })
    }

    pub fn persisted(&self) -> &PersistedKey {
        &self.persisted
    }

    pub fn modulus(&self) -> &str {
        &self.modulus
    }

    pub fn exponent(&self) -> &str {
        &self.exponent
    }
}

fn parse_algorithm(name: &str) -> Result<Algorithm, KeyError> {
    match name.to_ascii_uppercase().as_str() {
        "RS256" => Ok(Algorithm::RS256),
        other => Err(KeyError::UnsupportedAlgorithm(other.to_string())),
    }
}

fn algorithm_name(algorithm: Algorithm) -> &'static str {
    match algorithm {
        Algorithm::RS256 => "RS256",
        // Unreachable today: parse_algorithm only yields RS256.
        _ => "RS256",
    }
}

/// RFC 7638 JWK thumbprint: SHA-256 over the required members in lexical order.
fn thumbprint(modulus: &str, exponent: &str) -> String {
    let canonical = format!("{{\"e\":\"{exponent}\",\"kty\":\"RSA\",\"n\":\"{modulus}\"}}");
    let digest = Sha256::digest(canonical.as_bytes());
    URL_SAFE_NO_PAD.encode(&digest[..])
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) -> Result<(), KeyError> {
    use std::os::unix::fs::PermissionsExt;

    let permissions = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, permissions).map_err(|source| KeyError::Write {
        path: path.display().to_string(),
        source,
    })
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> Result<(), KeyError> {
    // Windows ACLs are inherited from the parent directory; nothing to do.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn generates_and_persists_a_key() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keys.json");

        let (generated, origin) = KeySet::load_or_generate(&path, true, "RS256").unwrap();
        assert_eq!(origin, KeyOrigin::Generated);
        assert!(path.is_file());
        assert!(generated.persisted().created_at > 0);

        let (loaded, origin) = KeySet::load_or_generate(&path, true, "RS256").unwrap();
        assert_eq!(origin, KeyOrigin::Loaded);
        assert_eq!(loaded.kid(), generated.kid(), "kid must be stable");
    }

    #[test]
    fn non_persisted_keys_are_ephemeral() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keys.json");
        let (_, origin) = KeySet::load_or_generate(&path, false, "RS256").unwrap();
        assert_eq!(origin, KeyOrigin::Ephemeral);
        assert!(!path.exists());
    }

    #[test]
    fn jwks_matches_the_thumbprint_derivation() {
        let keys = KeySet::generate("RS256", DEFAULT_KEY_BITS).unwrap();
        let jwks = keys.jwks();
        let jwk = &jwks["keys"][0];
        assert_eq!(jwk["kty"], "RSA");
        assert_eq!(jwk["alg"], "RS256");
        assert_eq!(jwk["use"], "sig");
        assert_eq!(jwk["kid"], keys.kid());
        assert_eq!(jwk["n"], keys.modulus());
        assert_eq!(jwk["e"], "AQAB");

        // The thumbprint is reproducible.
        assert_eq!(thumbprint(keys.modulus(), keys.exponent()), keys.kid());
    }

    #[test]
    fn algorithm_mismatch_is_explained() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keys.json");
        KeySet::load_or_generate(&path, true, "RS256").unwrap();

        // Force a different algorithm into the file.
        let raw = std::fs::read_to_string(&path).unwrap();
        let updated = raw.replace("\"RS256\"", "\"RS512\"");
        std::fs::write(&path, updated).unwrap();

        let err = KeySet::load_or_generate(&path, true, "RS256").unwrap_err();
        let text = err.to_string();
        assert!(text.contains("algorithm"), "{text}");
        assert!(text.contains("Delete"), "{text}");
    }

    #[test]
    fn corrupt_key_file_is_reported() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keys.json");
        std::fs::write(&path, "{ not json").unwrap();
        let err = KeySet::load_or_generate(&path, true, "RS256").unwrap_err();
        assert!(err.to_string().contains("is invalid"), "{err}");
    }

    #[test]
    fn unsupported_algorithms_are_rejected() {
        let err = KeySet::generate("ES256", DEFAULT_KEY_BITS).unwrap_err();
        assert!(err.to_string().contains("use RS256"), "{err}");
        let err = KeySet::generate("HS256", DEFAULT_KEY_BITS).unwrap_err();
        assert!(err.to_string().contains("use RS256"), "{err}");
    }
}
