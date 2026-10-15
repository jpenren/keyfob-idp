//! Authorization endpoint (`/authorize`) domain logic: request validation and
//! authorization code creation.
//!
//! Validation distinguishes two failure modes: errors detected *before* the
//! client and redirect URI are trusted cannot be redirected and become an HTML
//! error page ([`AuthorizeFailure::Fatal`]); everything after that is returned
//! to the client as a redirect carrying `error` and `state`
//! ([`AuthorizeFailure::Redirect`]).

use crate::config::ClientCfg;
use crate::crypto::{random_string, s256_challenge};
use crate::state::Runtime;
use crate::store::{AuthCode, Store};

use super::error::OAuthError;
use super::scope::resolve_scopes;

/// Authorization code lifetime (RFC 6749 recommends a maximum of 10 minutes).
pub const CODE_TTL_SECONDS: i64 = 60;

/// Words accepted by the `response_type` parameter.
pub const RESPONSE_TYPE_CODE: &str = "code";

/// Length of the generated authorization code.
const CODE_LENGTH: usize = 43;

/// Value of the `prompt` parameter, when present.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Prompt {
    None,
    Login,
    Consent,
    SelectAccount,
}

impl Prompt {
    fn parse(value: Option<&str>) -> Option<Self> {
        match value?.trim().to_ascii_lowercase().as_str() {
            "none" => Some(Self::None),
            "login" => Some(Self::Login),
            "consent" => Some(Self::Consent),
            "select_account" => Some(Self::SelectAccount),
            _ => None,
        }
    }
}

/// Raw authorize query parameters.
#[derive(Debug, Clone, Default)]
pub struct AuthorizeRequest {
    pub response_type: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub prompt: Option<String>,
    pub login_hint: Option<String>,
    pub max_age: Option<String>,
}

/// A validated authorize request, ready to authenticate the user and issue a code.
#[derive(Debug, Clone)]
pub struct AuthorizePlan {
    pub client_id: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub prompt: Option<Prompt>,
    pub login_hint: Option<String>,
    pub max_age: Option<i64>,
}

/// Why an authorize request could not be turned into a plan.
#[derive(Debug)]
pub enum AuthorizeFailure {
    /// The client or redirect URI is not trustworthy: show an HTML error page.
    Fatal(OAuthError),
    /// Return `error` (and `state`) to the client's redirect URI.
    Redirect {
        redirect_uri: String,
        state: Option<String>,
        error: OAuthError,
    },
}

impl AuthorizeFailure {
    /// The error in either mode.
    pub fn error(&self) -> &OAuthError {
        match self {
            Self::Fatal(error) => error,
            Self::Redirect { error, .. } => error,
        }
    }
}

/// Validates the authorize request against the runtime configuration.
pub fn validate(
    runtime: &Runtime,
    request: &AuthorizeRequest,
) -> Result<AuthorizePlan, AuthorizeFailure> {
    let Some(client_id) = request.client_id.as_deref().filter(|id| !id.is_empty()) else {
        return Err(AuthorizeFailure::Fatal(
            OAuthError::invalid_request("missing required parameter: client_id")
                .with_hint("Add ?client_id=<id> to the authorization request"),
        ));
    };

    let Some(client) = runtime.client(client_id) else {
        return Err(AuthorizeFailure::Fatal(
            OAuthError::invalid_request(format!("unknown client_id '{client_id}'"))
                .with_hint("Check the client_id against the `clients` list in keyfob.yaml"),
        ));
    };

    // From here on the client is known; a redirect URI may be resolvable.
    let redirect_uri = match resolve_redirect_uri(client, request.redirect_uri.as_deref()) {
        Ok(uri) => uri,
        Err(error) => {
            // Only redirect when the provided URI is exactly registered;
            // otherwise an open redirect would be possible.
            let requested = request.redirect_uri.clone().unwrap_or_default();
            if !requested.is_empty() && client.redirect_uris.iter().any(|uri| uri == &requested) {
                return Err(AuthorizeFailure::Redirect {
                    redirect_uri: requested,
                    state: request.state.clone(),
                    error,
                });
            }
            return Err(AuthorizeFailure::Fatal(error));
        }
    };

    let redirect = |error: OAuthError| AuthorizeFailure::Redirect {
        redirect_uri: redirect_uri.clone(),
        state: request.state.clone(),
        error,
    };

    if request.response_type.as_deref() != Some(RESPONSE_TYPE_CODE) {
        let got = request.response_type.as_deref().unwrap_or("(missing)");
        return Err(redirect(
            OAuthError::new(
                super::error::ErrorCode::UnsupportedResponseType,
                format!("response_type '{got}' is not supported"),
            )
            .with_hint(
                "Only response_type=code is supported (the implicit flow is not implemented)",
            ),
        ));
    }

    let scopes = match resolve_scopes(client, request.scope.as_deref()) {
        Ok(scopes) => scopes,
        Err(error) => return Err(redirect(error)),
    };

    // PKCE: mandatory for public clients, optional (but validated) otherwise.
    let (code_challenge, code_challenge_method) = match validate_pkce(
        client,
        request.code_challenge.as_deref(),
        request.code_challenge_method.as_deref(),
    ) {
        Ok(pkce) => pkce,
        Err(error) => return Err(redirect(error)),
    };

    let prompt = Prompt::parse(request.prompt.as_deref());
    let max_age = request
        .max_age
        .as_deref()
        .filter(|value| !value.is_empty())
        .map(|value| {
            value
                .parse::<i64>()
                .map_err(|_| redirect(OAuthError::invalid_request("max_age must be an integer")))
        })
        .transpose()?;

    Ok(AuthorizePlan {
        client_id: client.client_id.clone(),
        redirect_uri,
        scopes,
        state: request.state.clone(),
        nonce: request.nonce.clone(),
        code_challenge,
        code_challenge_method,
        prompt,
        login_hint: request.login_hint.clone(),
        max_age,
    })
}

fn resolve_redirect_uri(client: &ClientCfg, requested: Option<&str>) -> Result<String, OAuthError> {
    match requested {
        Some(uri) if !uri.is_empty() => {
            if client
                .redirect_uris
                .iter()
                .any(|registered| registered == uri)
            {
                Ok(uri.to_string())
            } else {
                Err(
                    OAuthError::invalid_request(format!("redirect_uri '{uri}' is not registered"))
                        .with_hint(format!(
                            "Register it under clients[].redirect_uris or send one of: {}",
                            client.redirect_uris.join(", ")
                        )),
                )
            }
        }
        _ => match client.redirect_uris.as_slice() {
            [only] => Ok(only.clone()),
            [] => Err(OAuthError::invalid_request(format!(
                "client '{}' has no registered redirect_uri",
                client.client_id
            ))),
            _ => Err(OAuthError::invalid_request(
                "redirect_uri is required when the client registers more than one",
            )
            .with_hint(format!(
                "Registered redirect URIs: {}",
                client.redirect_uris.join(", ")
            ))),
        },
    }
}

fn validate_pkce(
    client: &ClientCfg,
    challenge: Option<&str>,
    method: Option<&str>,
) -> Result<(Option<String>, Option<String>), OAuthError> {
    let challenge = challenge.filter(|value| !value.is_empty());
    match challenge {
        None => {
            if client.public {
                return Err(
                    OAuthError::invalid_request("PKCE is required for public clients")
                        .with_hint("Send code_challenge and code_challenge_method=S256 (RFC 7636)"),
                );
            }
            Ok((None, None))
        }
        Some(challenge) => {
            let method = method.filter(|value| !value.is_empty()).unwrap_or("S256");
            if !method.eq_ignore_ascii_case("S256") {
                return Err(OAuthError::invalid_request(format!(
                    "code_challenge_method '{method}' is not supported"
                ))
                .with_hint("Only S256 is supported; 'plain' is disabled"));
            }
            // A SHA-256 challenge is 32 bytes -> 43 base64url characters.
            if challenge.len() != 43 || !challenge.bytes().all(is_base64url) {
                return Err(OAuthError::invalid_request(
                    "code_challenge is not a valid S256 challenge",
                )
                .with_hint("S256 challenges are 43 base64url characters"));
            }
            Ok((Some(challenge.to_string()), Some("S256".to_string())))
        }
    }
}

fn is_base64url(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
}

/// Stores a single-use authorization code bound to the client and redirect URI.
#[allow(clippy::too_many_arguments)]
pub async fn create_code(
    store: &Store,
    plan: &AuthorizePlan,
    username: &str,
    session_id: Option<String>,
    auth_time: i64,
    now: i64,
) -> AuthCode {
    let code = AuthCode {
        code: random_string(CODE_LENGTH),
        client_id: plan.client_id.clone(),
        redirect_uri: plan.redirect_uri.clone(),
        username: username.to_string(),
        scopes: plan.scopes.clone(),
        nonce: plan.nonce.clone(),
        code_challenge: plan.code_challenge.clone(),
        code_challenge_method: plan.code_challenge_method.clone(),
        session_id,
        auth_time,
        expires_at: now + CODE_TTL_SECONDS,
    };
    store.insert_code(code.clone()).await;
    code
}

/// Computes the S256 challenge for a verifier (exposed for tests and the UI).
pub fn derive_challenge(verifier: &str) -> String {
    s256_challenge(verifier)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use crate::store::Store;

    fn runtime() -> Runtime {
        let config = config::parse_str(
            r#"
clients:
  - client_id: spa
    public: true
    redirect_uris: [http://localhost:3000/cb]
  - client_id: web
    client_secret: s
    redirect_uris: [http://localhost:8080/cb, http://localhost:8081/cb]
users:
  - username: alice
    password: alice123
"#,
            "test.yaml",
        )
        .unwrap();
        Runtime::build(config)
    }

    fn request(client_id: &str, redirect_uri: Option<&str>) -> AuthorizeRequest {
        AuthorizeRequest {
            response_type: Some("code".into()),
            client_id: Some(client_id.into()),
            redirect_uri: redirect_uri.map(str::to_string),
            scope: Some("openid profile".into()),
            state: Some("xyz".into()),
            code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".into()),
            code_challenge_method: Some("S256".into()),
            ..AuthorizeRequest::default()
        }
    }

    #[test]
    fn happy_path_resolves_scopes_and_state() {
        let plan = validate(
            &runtime(),
            &request("spa", Some("http://localhost:3000/cb")),
        )
        .unwrap();
        assert_eq!(plan.client_id, "spa");
        assert_eq!(plan.scopes, vec!["openid", "profile"]);
        assert_eq!(plan.state.as_deref(), Some("xyz"));
    }

    #[test]
    fn unknown_client_is_fatal() {
        let failure = validate(&runtime(), &request("ghost", None)).unwrap_err();
        assert!(matches!(failure, AuthorizeFailure::Fatal(_)));
    }

    #[test]
    fn mismatched_redirect_uri_is_fatal() {
        let failure =
            validate(&runtime(), &request("spa", Some("http://evil.test/cb"))).unwrap_err();
        assert!(matches!(failure, AuthorizeFailure::Fatal(_)));
        assert!(failure.error().description.contains("not registered"));
    }

    #[test]
    fn supported_errors_are_redirected() {
        let mut req = request("spa", Some("http://localhost:3000/cb"));
        req.response_type = Some("token".into());
        let failure = validate(&runtime(), &req).unwrap_err();
        match failure {
            AuthorizeFailure::Redirect {
                redirect_uri,
                state,
                error,
            } => {
                assert_eq!(redirect_uri, "http://localhost:3000/cb");
                assert_eq!(state.as_deref(), Some("xyz"));
                assert_eq!(
                    error.code,
                    super::super::error::ErrorCode::UnsupportedResponseType
                );
            }
            AuthorizeFailure::Fatal(_) => panic!("should have been redirected"),
        }
    }

    #[test]
    fn public_client_requires_s256() {
        let runtime = runtime();
        let mut req = request("spa", Some("http://localhost:3000/cb"));
        req.code_challenge = None;
        let failure = validate(&runtime, &req).unwrap_err();
        assert!(failure.error().description.contains("PKCE is required"));

        let mut req = request("spa", Some("http://localhost:3000/cb"));
        req.code_challenge_method = Some("plain".into());
        let failure = validate(&runtime, &req).unwrap_err();
        assert!(failure.error().description.contains("not supported"));
    }

    #[test]
    fn confidential_client_may_omit_pkce() {
        let mut req = request("web", Some("http://localhost:8080/cb"));
        req.code_challenge = None;
        req.code_challenge_method = None;
        let plan = validate(&runtime(), &req).unwrap();
        assert!(plan.code_challenge.is_none());
    }

    #[test]
    fn redirect_uri_required_when_several_registered() {
        let runtime = runtime();
        let mut req = request("web", None);
        req.code_challenge = None;
        req.code_challenge_method = None;
        let failure = validate(&runtime, &req).unwrap_err();
        // No redirect_uri was provided, so even the fatal path cannot redirect.
        assert!(matches!(failure, AuthorizeFailure::Fatal(_)));
    }

    #[tokio::test]
    async fn codes_are_single_use_and_bound() {
        let store = Store::new();
        let plan = validate(
            &runtime(),
            &request("spa", Some("http://localhost:3000/cb")),
        )
        .unwrap();
        let code = create_code(&store, &plan, "alice", Some("sess".into()), 100, 100).await;
        assert_eq!(code.expires_at, 100 + CODE_TTL_SECONDS);
        assert_eq!(code.code_challenge_method.as_deref(), Some("S256"));
        assert!(store.take_code(&code.code).await.is_some());
        assert!(store.take_code(&code.code).await.is_none());
    }

    #[test]
    fn max_age_must_be_numeric() {
        let mut req = request("spa", Some("http://localhost:3000/cb"));
        req.max_age = Some("soon".into());
        let failure = validate(&runtime(), &req).unwrap_err();
        assert!(failure.error().description.contains("max_age"));
    }
}
