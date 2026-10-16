//! Handlers that serve metadata, the health probe, the home page, the UI
//! support endpoints and logout.

use axum::extract::{RawQuery, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

use crate::oauth::encoding::encode_query;
use crate::oidc::{oauth_authorization_server, openid_configuration};
use crate::state::AppState;
use crate::store::RecentToken;

use super::support::{
    Params, json_response, redirect, render_template, session_clear_cookie, session_id,
};

/// `GET /healthz`
pub async fn healthz(State(state): State<AppState>) -> Response {
    let started = state.started_at.elapsed().as_secs();
    let mut response = json_response(
        StatusCode::OK,
        json!({
            "status": "ok",
            "version": env!("CARGO_PKG_VERSION"),
            "uptime_seconds": started,
        }),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}

/// `GET /.well-known/openid-configuration`
pub async fn discovery(state: State<AppState>) -> Response {
    let runtime = state.runtime().await;
    json_response(StatusCode::OK, openid_configuration(&runtime, &state.keys))
}

/// `GET /.well-known/oauth-authorization-server` (RFC 8414)
pub async fn authorization_server_metadata(state: State<AppState>) -> Response {
    let runtime = state.runtime().await;
    json_response(
        StatusCode::OK,
        oauth_authorization_server(&runtime, &state.keys),
    )
}

/// `GET /jwks` (and the Keycloak-style alias)
pub async fn jwks(state: State<AppState>) -> Response {
    json_response(StatusCode::OK, state.keys.jwks())
}

/// `GET /` — server information and token generator.
pub async fn home(State(state): State<AppState>) -> Response {
    let runtime = state.runtime().await;
    if !runtime.config.ui.enabled {
        return not_found("The home page is disabled (ui.enabled: false)");
    }
    render_template(
        &state,
        "home.html",
        &json!({ "version": env!("CARGO_PKG_VERSION") }),
    )
    .await
}

/// `GET /ui/info` — the JSON document powering the home page.
pub async fn ui_info(State(state): State<AppState>) -> Response {
    let runtime = state.runtime().await;
    if !runtime.config.ui.enabled {
        return not_found("The UI is disabled (ui.enabled: false)");
    }

    let status = state.reload_status().await;
    let warnings = crate::state::current_warnings(&state).await;
    let loopback = runtime.config.server.is_loopback();
    let prefill = runtime.config.ui.prefill_secrets && loopback;
    let issuer = runtime.issuer.clone();

    let clients: Vec<Value> = runtime
        .clients
        .iter()
        .map(|client| {
            let kind = if runtime.is_internal_client(&client.client_id) {
                "internal"
            } else if client.public {
                "public"
            } else {
                "confidential"
            };
            json!({
                "client_id": client.client_id,
                "type": kind,
                "public": client.public,
                "redirect_uris": client.redirect_uris,
                "post_logout_redirect_uris": client.post_logout_redirect_uris,
                "audience": client.audience,
                "scopes": client.scopes(),
                "grants": client.grants().iter().map(|g| g.config_name()).collect::<Vec<_>>(),
                "auto_approve": client.auto_approve,
                // Only ever exposed for a loopback development server.
                "client_secret": if prefill { client.client_secret.clone() } else { None },
            })
        })
        .collect();

    let users: Vec<Value> = runtime
        .users()
        .iter()
        .map(|user| {
            json!({
                "username": user.username,
                "email": crate::oidc::resolved_email(user),
                "name": crate::oidc::resolved_name(user),
                "roles": user.roles,
                "groups": user.groups,
            })
        })
        .collect();

    json_response(
        StatusCode::OK,
        json!({
            "version": env!("CARGO_PKG_VERSION"),
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "uptime_seconds": state.started_at.elapsed().as_secs(),
            "started_at": state.started_wall,
            "config_path": state.config_path.display().to_string(),
            "config_loaded_at": status.loaded_at,
            "config_last_attempt_at": status.last_attempt_at,
            "config_error": status.last_error,
            "warnings": warnings,
            "issuer": issuer,
            "tls": runtime.config.server.tls,
            "loopback": loopback,
            "debug": runtime.config.debug,
            "allow_password_grant": runtime.config.allow_password_grant,
            "allow_token_exchange": runtime.config.allow_token_exchange,
            "login_mode": match runtime.config.login.mode {
                crate::config::LoginMode::Form => "form",
                crate::config::LoginMode::Picker => "picker",
                crate::config::LoginMode::Auto => "auto",
            },
            "prefill_secrets": prefill,
            "algorithm": state.keys.algorithm_name(),
            "kid": state.keys.kid(),
            "key_origin": state.key_origin.as_str(),
            "grants": runtime.grant_types_supported,
            "scopes": runtime.scopes_supported,
            "clients": clients,
            "users": users,
            "endpoints": endpoints(&issuer),
        }),
    )
}

/// `GET /ui/callback` — authorization code redirect target of the token generator.
pub async fn ui_callback(State(state): State<AppState>) -> Response {
    let runtime = state.runtime().await;
    if !runtime.config.ui.enabled {
        return not_found("The UI is disabled (ui.enabled: false)");
    }
    render_template(
        &state,
        "callback.html",
        &json!({
            "issuer": runtime.issuer,
            "issuer_js": runtime.issuer,
        }),
    )
    .await
}

/// `GET /debug/tokens` — recently issued tokens (only with `debug: true`).
pub async fn debug_tokens(State(state): State<AppState>) -> Response {
    let runtime = state.runtime().await;
    if !runtime.config.debug {
        return not_found("Token debugging is disabled (set `debug: true` to enable it)");
    }
    let tokens: Vec<RecentToken> = state.store.recent_tokens().await;
    json_response(
        StatusCode::OK,
        json!({
            "count": tokens.len(),
            "tokens": tokens,
        }),
    )
}

/// `GET|POST /logout` — OIDC RP-initiated logout.
pub async fn logout_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let params = Params::parse(query.as_deref().unwrap_or_default());
    logout(state, headers, params).await
}

/// `POST /logout`
pub async fn logout_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> Response {
    logout(state, headers, Params::parse(&body)).await
}

async fn logout(state: AppState, headers: HeaderMap, params: Params) -> Response {
    let runtime = state.runtime().await;
    let secure = runtime.config.server.tls;

    // End the browser session.
    if let Some(session_id) = session_id(&headers) {
        state.store.remove_session(&session_id).await;
    }

    // Resolve a safe post-logout redirect.
    let state_param = params.get("state");
    let destination = logout_destination(&runtime, &state, &params);

    match destination {
        Some(uri) => {
            let location = match state_param {
                Some(value) => format!(
                    "{uri}{}{}",
                    separator(&uri),
                    encode_query([("state", value)])
                ),
                None => uri,
            };
            let mut response = redirect(&location);
            response.headers_mut().append(
                header::SET_COOKIE,
                header::HeaderValue::from_str(&session_clear_cookie(secure)).unwrap_or_else(|_| {
                    header::HeaderValue::from_static("keyfob_session=; Max-Age=0")
                }),
            );
            response
        }
        None => {
            let mut response = render_template(
                &state,
                "logout.html",
                &json!({ "issuer": runtime.issuer, "ui_enabled": runtime.config.ui.enabled }),
            )
            .await;
            response.headers_mut().append(
                header::SET_COOKIE,
                header::HeaderValue::from_str(&session_clear_cookie(secure)).unwrap_or_else(|_| {
                    header::HeaderValue::from_static("keyfob_session=; Max-Age=0")
                }),
            );
            *response.status_mut() = StatusCode::OK;
            response
        }
    }
}

/// A post-logout redirect is only honoured when its URI is registered for the
/// client referenced by `client_id` or by the `id_token_hint` audience.
fn logout_destination(
    runtime: &crate::state::Runtime,
    state: &AppState,
    params: &Params,
) -> Option<String> {
    let requested = params.get("post_logout_redirect_uri")?;

    let from_param = params.get("client_id").filter(|id| !id.is_empty());
    let from_hint = params
        .get("id_token_hint")
        .and_then(|token| {
            crate::crypto::decode_jwt(
                &state.keys,
                token,
                &crate::crypto::TokenValidation::new(&runtime.issuer).allow_expired(),
            )
            .ok()
        })
        .and_then(|claims| {
            claims
                .get("aud")
                .and_then(|aud| aud.as_str().map(str::to_string))
        });

    let client_id = from_param.map(str::to_string).or(from_hint)?;
    let client = runtime.client(&client_id)?;
    if client
        .post_logout_redirect_uris
        .iter()
        .any(|uri| uri == requested)
    {
        Some(requested.to_string())
    } else {
        tracing::warn!(
            client_id = %client_id,
            requested,
            "refusing post_logout_redirect_uri that is not registered"
        );
        None
    }
}

fn separator(uri: &str) -> &'static str {
    if uri.contains('?') { "&" } else { "?" }
}

/// Endpoint URLs advertised in the home page and discovery document.
pub fn endpoints(issuer: &str) -> Value {
    json!({
        "discovery": format!("{issuer}/.well-known/openid-configuration"),
        "oauth_metadata": format!("{issuer}/.well-known/oauth-authorization-server"),
        "jwks": format!("{issuer}/jwks"),
        "authorization": format!("{issuer}/authorize"),
        "token": format!("{issuer}/token"),
        "userinfo": format!("{issuer}/userinfo"),
        "introspection": format!("{issuer}/introspect"),
        "revocation": format!("{issuer}/revoke"),
        "end_session": format!("{issuer}/logout"),
        "health": format!("{issuer}/healthz"),
    })
}

/// 404 helper shared by the UI handlers.
pub fn not_found(message: &str) -> Response {
    (StatusCode::NOT_FOUND, message.to_string()).into_response()
}
