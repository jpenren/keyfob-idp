//! Client authentication at the token, introspection and revocation endpoints.
//!
//! Two methods are supported (RFC 6749 section 2.3): HTTP Basic
//! (`client_secret_basic`) and form parameters (`client_secret_post`). Secret
//! comparison is constant-time. Public clients authenticate with `client_id`
//! alone.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use crate::config::ClientCfg;
use crate::crypto::constant_time_eq;
use crate::state::Runtime;

use super::encoding::percent_decode;
use super::error::OAuthError;

/// Credentials extracted from the request.
#[derive(Debug, Clone, Default)]
pub struct Credentials {
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

impl Credentials {
    /// Parses an `Authorization: Basic ...` header value.
    ///
    /// Returns `None` when the header is not a well-formed Basic credential so
    /// the caller can fall back to form parameters.
    pub fn from_basic_header(header: &str) -> Option<Self> {
        let encoded = header
            .strip_prefix("Basic ")
            .or_else(|| header.strip_prefix("basic "))?;
        let decoded = STANDARD.decode(encoded.trim()).ok()?;
        let decoded = String::from_utf8(decoded).ok()?;
        let (id, secret) = decoded.split_once(':')?;
        Some(Self {
            client_id: Some(percent_decode(id)),
            client_secret: Some(percent_decode(secret)),
        })
    }
}

/// Resolves and authenticates the calling client.
///
/// `client_id` and `client_secret` are merged from Basic and form parameters,
/// with Basic taking precedence (a request must not mix both).
pub fn authenticate<'a>(
    runtime: &'a Runtime,
    credentials: &Credentials,
) -> Result<&'a ClientCfg, OAuthError> {
    let Some(client_id) = credentials.client_id.as_deref().filter(|id| !id.is_empty()) else {
        return Err(OAuthError::invalid_client(
            "client authentication failed: no client_id provided",
        )
        .with_hint("Send client_id as a form parameter or use HTTP Basic authentication"));
    };

    let Some(client) = runtime.client(client_id) else {
        return Err(
            OAuthError::invalid_client(format!("unknown client_id '{client_id}'"))
                .with_hint("Check the client_id against the `clients` list in keyfob.yaml"),
        );
    };

    match credentials.client_secret.as_deref() {
        None => {
            if client.is_confidential() {
                return Err(OAuthError::invalid_client(format!(
                    "client '{client_id}' is confidential and requires a client_secret"
                ))
                .with_hint("Send the secret with HTTP Basic authentication or as client_secret"));
            }
            Ok(client)
        }
        Some(secret) => {
            if client.public {
                return Err(OAuthError::invalid_client(format!(
                    "client '{client_id}' is public and must not send a client_secret"
                )));
            }
            let expected = client.client_secret.as_deref().unwrap_or_default();
            if constant_time_eq(secret, expected) {
                Ok(client)
            } else {
                Err(OAuthError::invalid_client(format!(
                    "invalid client_secret for client '{client_id}'"
                )))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use crate::state::Runtime;

    fn runtime() -> Runtime {
        let config = config::parse_str(
            r#"
clients:
  - client_id: spa
    public: true
    redirect_uris: [http://localhost/cb]
  - client_id: backend
    client_secret: dev-secret
    grant_types: [client_credentials]
users:
  - username: alice
    password: alice123
"#,
            "test.yaml",
        )
        .unwrap();
        Runtime::build(config)
    }

    #[test]
    fn decodes_basic_credentials() {
        // "backend:dev-secret" base64.
        let header = format!("Basic {}", STANDARD.encode("backend:dev-secret"));
        let credentials = Credentials::from_basic_header(&header).unwrap();
        assert_eq!(credentials.client_id.as_deref(), Some("backend"));
        assert_eq!(credentials.client_secret.as_deref(), Some("dev-secret"));
        assert!(Credentials::from_basic_header("Bearer x").is_none());
        assert!(Credentials::from_basic_header("Basic not-base64!!").is_none());
    }

    #[test]
    fn decodes_form_encoded_basic_credentials() {
        let header = format!("Basic {}", STANDARD.encode("back%20end:dev+secret"));
        let credentials = Credentials::from_basic_header(&header).unwrap();
        assert_eq!(credentials.client_id.as_deref(), Some("back end"));
        assert_eq!(credentials.client_secret.as_deref(), Some("dev secret"));
    }

    #[test]
    fn public_client_authenticates_without_secret() {
        let runtime = runtime();
        let client = authenticate(
            &runtime,
            &Credentials {
                client_id: Some("spa".into()),
                client_secret: None,
            },
        )
        .unwrap();
        assert_eq!(client.client_id, "spa");
    }

    #[test]
    fn confidential_client_requires_the_right_secret() {
        let runtime = runtime();
        let ok = authenticate(
            &runtime,
            &Credentials {
                client_id: Some("backend".into()),
                client_secret: Some("dev-secret".into()),
            },
        );
        assert!(ok.is_ok());

        let wrong = authenticate(
            &runtime,
            &Credentials {
                client_id: Some("backend".into()),
                client_secret: Some("nope".into()),
            },
        )
        .unwrap_err();
        assert_eq!(wrong.code, super::super::error::ErrorCode::InvalidClient);

        let missing = authenticate(
            &runtime,
            &Credentials {
                client_id: Some("backend".into()),
                client_secret: None,
            },
        );
        assert!(missing.is_err());
    }

    #[test]
    fn public_client_rejecting_a_secret_and_unknown_client() {
        let runtime = runtime();
        let with_secret = authenticate(
            &runtime,
            &Credentials {
                client_id: Some("spa".into()),
                client_secret: Some("anything".into()),
            },
        );
        assert!(with_secret.is_err());

        let unknown = authenticate(
            &runtime,
            &Credentials {
                client_id: Some("ghost".into()),
                client_secret: None,
            },
        );
        assert!(
            unknown
                .unwrap_err()
                .description
                .contains("unknown client_id")
        );
    }
}
