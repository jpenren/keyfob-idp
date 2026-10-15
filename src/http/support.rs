//! Shared helpers for the HTTP layer: form/query parsing, cookies, bearer
//! tokens and response construction.

use axum::Json;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

use crate::oauth::OAuthError;
use crate::oauth::encoding::percent_decode;
use crate::state::AppState;

/// Session cookie name.
pub const SESSION_COOKIE: &str = "keyfob_session";

// --------------------------------------------------------------- parameters

/// Ordered `application/x-www-form-urlencoded` parameters.
///
/// Parsing is done by hand so that repeated keys, missing values and odd
/// encodings never cause an error, and to avoid a dependency.
#[derive(Debug, Clone, Default)]
pub struct Params(Vec<(String, String)>);

impl Params {
    /// Parses a query string or form body (both use the same encoding).
    pub fn parse(input: &str) -> Self {
        let pairs = input
            .split('&')
            .filter(|pair| !pair.is_empty())
            .map(|pair| match pair.split_once('=') {
                Some((key, value)) => (percent_decode(key), percent_decode(value)),
                None => (percent_decode(pair), String::new()),
            })
            .collect();
        Self(pairs)
    }

    /// First value for `key`.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(candidate, _)| candidate == key)
            .map(|(_, value)| value.as_str())
    }

    /// All parameters in order, for rebuilding a URL.
    pub fn as_pairs(&self) -> &[(String, String)] {
        &self.0
    }
}

// ------------------------------------------------------------------ cookies

/// Reads the session id from the `Cookie` header.
pub fn session_id(headers: &HeaderMap) -> Option<String> {
    for value in headers.get_all(header::COOKIE) {
        let Ok(value) = value.to_str() else {
            continue;
        };
        for pair in value.split(';') {
            if let Some((name, value)) = pair.trim().split_once('=')
                && name == SESSION_COOKIE
                && !value.is_empty()
            {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// `Set-Cookie` value that starts a session.
pub fn session_set_cookie(session_id: &str, max_age: i64, secure: bool) -> String {
    let mut cookie =
        format!("{SESSION_COOKIE}={session_id}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}");
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

/// `Set-Cookie` value that deletes the session cookie.
pub fn session_clear_cookie(secure: bool) -> String {
    let mut cookie = format!("{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

/// Extracts the token from an `Authorization: Bearer ...` header.
pub fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let token = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))?;
    let token = token.trim();
    (!token.is_empty()).then(|| token.to_string())
}

// ---------------------------------------------------------------- responses

/// Adds the `no-store` caching headers required by RFC 6749 section 5.1.
pub fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

/// JSON response with `Content-Type: application/json` and `no-store`.
pub fn json_response(status: StatusCode, value: Value) -> Response {
    no_store((status, Json(value)).into_response())
}

/// RFC 6749 error body: `{ "error": ..., "error_description": ... }`.
pub fn oauth_error_response(error: &OAuthError) -> Response {
    let status = StatusCode::from_u16(error.code.status()).unwrap_or(StatusCode::BAD_REQUEST);
    tracing::debug!(error = %error, "rejecting request");
    json_response(
        status,
        json!({
            "error": error.code.as_str(),
            "error_description": error.description,
        }),
    )
}

/// RFC 6750 bearer error, with the `WWW-Authenticate` challenge header.
pub fn bearer_error_response(error: &OAuthError) -> Response {
    let status = StatusCode::from_u16(error.code.status()).unwrap_or(StatusCode::UNAUTHORIZED);
    let challenge = format!(
        "Bearer error=\"{}\", error_description=\"{}\"",
        error.code.as_str(),
        error.description.replace('"', "'")
    );
    let mut response = json_response(
        status,
        json!({
            "error": error.code.as_str(),
            "error_description": error.description,
        }),
    );
    if let Ok(value) = HeaderValue::from_str(&challenge) {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, value);
    }
    response
}

/// `302 Found` redirect to `location`.
pub fn redirect(location: &str) -> Response {
    match HeaderValue::from_str(location) {
        Ok(value) => {
            let mut response = StatusCode::FOUND.into_response();
            response.headers_mut().insert(header::LOCATION, value);
            response
        }
        Err(_) => {
            // A location that cannot be represented as a header value is a bug
            // in the caller, never user data; fail safely.
            tracing::error!(location, "refusing to redirect to an invalid location");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Renders one of the embedded HTML templates.
pub async fn render_template(
    state: &AppState,
    name: &str,
    context: &impl serde::Serialize,
) -> Response {
    let templates = state.templates().await;
    match templates.render(name, context) {
        Ok(html) => {
            let mut response = html.into_response();
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            );
            response
        }
        Err(error) => {
            tracing::error!(template = name, error = %error, "failed to render template");
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
        }
    }
}

/// HTML page shown when a request cannot be redirected back to the client.
pub async fn error_page(state: &AppState, error: &OAuthError) -> Response {
    tracing::debug!(error = %error, "showing error page");
    let context = json!({
        "error": error.code.as_str(),
        "description": error.description,
        "hint": error.hint,
    });
    let mut response = render_template(state, "error.html", &context).await;
    if response.status() == StatusCode::OK {
        *response.status_mut() =
            StatusCode::from_u16(error.code.status()).unwrap_or(StatusCode::BAD_REQUEST);
    }
    response
}

/// Current Unix timestamp.
pub fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}
