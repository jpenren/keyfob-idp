//! Token endpoint and the resource-server helpers (userinfo, introspection,
//! revocation).

use axum::extract::{RawQuery, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

use crate::crypto::{TokenValidation, decode_jwt};
use crate::oauth::{
    Credentials, ErrorCode, OAuthError, TokenExchange, authenticate, exchange, introspect, revoke,
};
use crate::state::AppState;

use super::support::{
    Params, bearer_error_response, bearer_token, json_response, no_store, oauth_error_response,
};

/// Extracts client credentials from the `Authorization` header and the form.
fn credentials(headers: &HeaderMap, params: &Params) -> Credentials {
    let mut credentials = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(Credentials::from_basic_header)
        .unwrap_or_default();
    if credentials.client_id.is_none() {
        credentials.client_id = params.get("client_id").map(str::to_string);
    }
    if credentials.client_secret.is_none() {
        credentials.client_secret = params.get("client_secret").map(str::to_string);
    }
    credentials
}

/// `POST /token`
pub async fn token(State(state): State<AppState>, headers: HeaderMap, body: String) -> Response {
    let params = Params::parse(&body);
    let runtime = state.runtime().await;

    let client = match authenticate(&runtime, &credentials(&headers, &params)) {
        Ok(client) => client,
        Err(error) => return oauth_error_response(&error),
    };

    let Some(grant_type) = params.get("grant_type").filter(|value| !value.is_empty()) else {
        return oauth_error_response(&OAuthError::invalid_request(
            "missing required parameter: grant_type",
        ));
    };

    let now = super::support::now();
    let result = exchange(TokenExchange {
        runtime: &runtime,
        keys: &state.keys,
        client,
        store: &state.store,
        grant_type,
        code: params.get("code"),
        redirect_uri: params.get("redirect_uri"),
        code_verifier: params.get("code_verifier"),
        refresh_token: params.get("refresh_token"),
        scope: params.get("scope"),
        username: params.get("username"),
        password: params.get("password"),
        now,
    })
    .await;

    match result {
        Ok(issued) => {
            let mut body = json!({
                "access_token": issued.access_token,
                "token_type": "Bearer",
                "expires_in": issued.access_expires_in,
                "scope": issued.scopes.join(" "),
            });
            if let Some(id_token) = issued.id_token {
                body["id_token"] = json!(id_token);
            }
            if let Some(refresh_token) = issued.refresh_token {
                body["refresh_token"] = json!(refresh_token);
            }
            json_response(StatusCode::OK, body)
        }
        Err(error) => oauth_error_response(&error),
    }
}

/// `GET|POST /userinfo`
pub async fn userinfo(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let params = Params::parse(query.as_deref().unwrap_or_default());
    let token = match bearer_token(&headers) {
        Some(token) => token,
        None => match params.get("access_token") {
            Some(token) if !token.is_empty() => token.to_string(),
            _ => {
                return bearer_error_response(&OAuthError::new(
                    ErrorCode::InvalidToken,
                    "no bearer token was provided",
                ));
            }
        },
    };

    let runtime = state.runtime().await;
    let claims = match decode_jwt(&state.keys, &token, &TokenValidation::new(&runtime.issuer)) {
        Ok(claims) => claims,
        Err(error) => {
            return bearer_error_response(&OAuthError::new(
                ErrorCode::InvalidToken,
                format!("invalid access token: {error}"),
            ));
        }
    };

    // Only access tokens carry `client_id`; an ID token must not be accepted.
    if claims.get("client_id").and_then(Value::as_str).is_none() {
        return bearer_error_response(&OAuthError::new(
            ErrorCode::InvalidToken,
            "the token is not an access token",
        ));
    }
    if let Some(jti) = claims.get("jti").and_then(Value::as_str)
        && state.store.is_access_token_revoked(jti).await
    {
        return bearer_error_response(&OAuthError::new(
            ErrorCode::InvalidToken,
            "the access token was revoked",
        ));
    }

    let Some(subject) = claims.get("sub").and_then(Value::as_str) else {
        return bearer_error_response(&OAuthError::new(
            ErrorCode::InvalidToken,
            "the access token has no subject",
        ));
    };
    let Some(user) = runtime.user(subject) else {
        return bearer_error_response(&OAuthError::new(
            ErrorCode::InvalidToken,
            "the token does not represent a user (client_credentials tokens have no userinfo)",
        ));
    };

    let scopes: Vec<String> = claims
        .get("scope")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_string)
        .collect();
    let payload = crate::oidc::userinfo_claims(user, &scopes, subject);
    json_response(StatusCode::OK, payload)
}

/// `POST /introspect`
pub async fn introspect_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let params = Params::parse(&body);
    let runtime = state.runtime().await;

    if let Err(error) = authenticate(&runtime, &credentials(&headers, &params)) {
        return oauth_error_response(&error);
    }

    let Some(token) = params.get("token").filter(|value| !value.is_empty()) else {
        return oauth_error_response(&OAuthError::invalid_request(
            "missing required parameter: token",
        ));
    };

    let now = super::support::now();
    let response = introspect(&runtime, &state.keys, &state.store, token, now).await;
    json_response(StatusCode::OK, response)
}

/// `POST /revoke`
pub async fn revoke_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let params = Params::parse(&body);
    let runtime = state.runtime().await;

    if let Err(error) = authenticate(&runtime, &credentials(&headers, &params)) {
        return oauth_error_response(&error);
    }

    let Some(token) = params.get("token").filter(|value| !value.is_empty()) else {
        return oauth_error_response(&OAuthError::invalid_request(
            "missing required parameter: token",
        ));
    };

    revoke(&runtime, &state.keys, &state.store, token).await;
    // RFC 7009: the response is empty and successful even for unknown tokens.
    no_store(StatusCode::OK.into_response())
}
