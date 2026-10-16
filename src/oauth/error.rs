//! OAuth 2.0 / OIDC error codes and the error type shared by the domain layer.
//!
//! Codes follow RFC 6749 section 5.2 (token endpoint), RFC 7009 (revocation),
//! RFC 7662 (introspection) and OpenID Connect Core. The HTTP layer translates
//! [`OAuthError`] into either a JSON body (RFC 6749) or a redirect back to the
//! client, depending on the endpoint.

use std::fmt;

use thiserror::Error;

/// Every `error` value this server can return.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    UnauthorizedClient,
    UnsupportedGrantType,
    UnsupportedResponseType,
    InvalidScope,
    /// RFC 8693 / RFC 8707: the requested `resource` / `audience` is not allowed.
    InvalidTarget,
    AccessDenied,
    ServerError,
    /// OIDC userinfo / bearer token errors.
    InvalidToken,
    InsufficientScope,
    /// OIDC authorization endpoint.
    LoginRequired,
    InteractionRequired,
    ConsentRequired,
    TemporarilyUnavailable,
}

impl ErrorCode {
    /// Wire representation (`error` member of the RFC 6749 error response).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::InvalidScope => "invalid_scope",
            Self::InvalidTarget => "invalid_target",
            Self::AccessDenied => "access_denied",
            Self::ServerError => "server_error",
            Self::InvalidToken => "invalid_token",
            Self::InsufficientScope => "insufficient_scope",
            Self::LoginRequired => "login_required",
            Self::InteractionRequired => "interaction_required",
            Self::ConsentRequired => "consent_required",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
        }
    }

    /// HTTP status recommended for the code.
    ///
    /// RFC 6749 says `invalid_client` is 401, everything else 400; userinfo
    /// errors use 401/403 and `server_error` uses 500.
    pub fn status(self) -> u16 {
        match self {
            Self::InvalidClient | Self::InvalidToken => 401,
            Self::InsufficientScope => 403,
            Self::ServerError => 500,
            Self::TemporarilyUnavailable => 503,
            _ => 400,
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A rejected OAuth request.
///
/// `description` is the human-readable `error_description`; `hint` is shown by
/// the HTML error page (and the UI) to explain how to fix the request, but it
/// is never sent in JSON responses.
#[derive(Debug, Error)]
#[error("{code}: {description}")]
pub struct OAuthError {
    pub code: ErrorCode,
    pub description: String,
    pub hint: Option<String>,
}

impl OAuthError {
    pub fn new(code: ErrorCode, description: impl Into<String>) -> Self {
        Self {
            code,
            description: description.into(),
            hint: None,
        }
    }

    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    pub fn invalid_request(description: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidRequest, description)
    }

    pub fn invalid_client(description: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidClient, description)
    }

    pub fn invalid_grant(description: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidGrant, description)
    }

    pub fn unauthorized_client(description: impl Into<String>) -> Self {
        Self::new(ErrorCode::UnauthorizedClient, description)
    }

    pub fn unsupported_grant_type(description: impl Into<String>) -> Self {
        Self::new(ErrorCode::UnsupportedGrantType, description)
    }

    pub fn invalid_scope(description: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidScope, description)
    }

    pub fn invalid_target(description: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidTarget, description)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_map_to_the_spec_wire_values() {
        assert_eq!(ErrorCode::InvalidGrant.as_str(), "invalid_grant");
        assert_eq!(ErrorCode::InvalidClient.as_str(), "invalid_client");
        assert_eq!(ErrorCode::LoginRequired.as_str(), "login_required");
        assert_eq!(ErrorCode::InvalidTarget.as_str(), "invalid_target");
    }

    #[test]
    fn invalid_client_is_unauthorized() {
        assert_eq!(ErrorCode::InvalidClient.status(), 401);
        assert_eq!(ErrorCode::InvalidGrant.status(), 400);
        assert_eq!(ErrorCode::InvalidTarget.status(), 400);
        assert_eq!(ErrorCode::ServerError.status(), 500);
    }

    #[test]
    fn description_is_part_of_the_message() {
        let error = OAuthError::invalid_grant("authorization code expired")
            .with_hint("codes live for 60 seconds");
        assert_eq!(
            error.to_string(),
            "invalid_grant: authorization code expired"
        );
        assert_eq!(error.hint.as_deref(), Some("codes live for 60 seconds"));
    }
}
