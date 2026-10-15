//! Authorization endpoint and interactive login.

use axum::extract::{RawQuery, State};
use axum::http::{HeaderMap, header};
use axum::response::Response;
use serde_json::{Value, json};

use crate::config::LoginMode;
use crate::crypto::{random_token, verify_password};
use crate::oauth::authorize::{AuthorizeFailure, AuthorizePlan, AuthorizeRequest, Prompt};
use crate::oauth::encoding::encode_query;
use crate::oauth::{ErrorCode, OAuthError, authorize};
use crate::state::{AppState, Runtime};
use crate::store::Session;

use super::support::{
    Params, error_page, no_store, redirect, render_template, session_id, session_set_cookie,
};

/// `GET /authorize`
pub async fn authorize_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let params = Params::parse(query.as_deref().unwrap_or_default());
    handle_authorize(state, headers, params).await
}

/// `POST /authorize` (allowed by RFC 6749; most clients use GET)
pub async fn authorize_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> Response {
    handle_authorize(state, headers, Params::parse(&body)).await
}

async fn handle_authorize(state: AppState, headers: HeaderMap, params: Params) -> Response {
    let runtime = state.runtime().await;
    let request = request_from_params(&params);

    let plan = match authorize::validate(&runtime, &request) {
        Ok(plan) => plan,
        Err(AuthorizeFailure::Fatal(error)) => return error_page(&state, &error).await,
        Err(AuthorizeFailure::Redirect {
            redirect_uri,
            state: request_state,
            error,
        }) => return redirect_error(&redirect_uri, request_state.as_deref(), &error),
    };

    let now = super::support::now();
    match resolve_login(&runtime, &state, &headers, &plan, now).await {
        LoginOutcome::LoggedIn {
            username,
            auth_time,
            session_id,
        } => {
            let code = authorize::create_code(
                &state.store,
                &plan,
                &username,
                session_id.clone(),
                auth_time,
                now,
            )
            .await;
            let location = redirect_success(&plan, &code.code);
            let mut response = redirect(&location);
            if let Some(session_id) = session_id {
                attach_session_cookie(
                    &mut response,
                    &session_id,
                    runtime.config.server.tls,
                    session_ttl(&runtime),
                );
            }
            tracing::debug!(client_id = %plan.client_id, user = %username, "issued authorization code");
            response
        }
        LoginOutcome::ShowForm => {
            render_login(&state, &runtime, &plan, None, return_to(&params)).await
        }
        LoginOutcome::AutoUser(username) => {
            let session = create_session(&state, &username, now).await;
            let code = authorize::create_code(
                &state.store,
                &plan,
                &username,
                Some(session.id.clone()),
                session.auth_time,
                now,
            )
            .await;
            let mut response = redirect(&redirect_success(&plan, &code.code));
            attach_session_cookie(
                &mut response,
                &session.id,
                runtime.config.server.tls,
                session_ttl(&runtime),
            );
            response
        }
        LoginOutcome::Error(error) => {
            redirect_error(&plan.redirect_uri, plan.state.as_deref(), &error)
        }
    }
}

/// `GET /login`
pub async fn login_page(State(state): State<AppState>, RawQuery(query): RawQuery) -> Response {
    let params = Params::parse(query.as_deref().unwrap_or_default());
    let runtime = state.runtime().await;
    let return_to = return_to(&params);
    let client_id = params.get("client_id").unwrap_or_default();
    let scopes = params.get("scope").unwrap_or_default();
    render_raw_login(&state, &runtime, client_id, scopes, None, &return_to).await
}

/// `POST /login`
pub async fn login_submit(
    State(state): State<AppState>,
    _headers: HeaderMap,
    body: String,
) -> Response {
    let params = Params::parse(&body);
    let runtime = state.runtime().await;

    let raw_return_to = params.get("return_to").unwrap_or("/");
    if !is_local_path(raw_return_to) {
        return error_page(
            &state,
            &OAuthError::invalid_request("return_to must be a local path")
                .with_hint("The login form was tampered with; open the authorization URL again"),
        )
        .await;
    }
    let return_to = raw_return_to.to_string();
    let client_id = params.get("client_id").unwrap_or_default().to_string();
    let scopes = params.get("scopes").unwrap_or_default().to_string();

    let username = params.get("username").unwrap_or("").trim().to_string();
    if username.is_empty() {
        return render_raw_login(
            &state,
            &runtime,
            &client_id,
            &scopes,
            Some("Enter a username"),
            &return_to,
        )
        .await;
    }

    let authenticated = if runtime.config.login.mode == LoginMode::Picker {
        runtime.user(&username).is_some()
    } else {
        let password = params.get("password").unwrap_or("");
        match runtime.user(&username) {
            Some(user) => verify_password(password, &user.password),
            None => false,
        }
    };

    if !authenticated {
        tracing::info!(user = %username, "failed login attempt");
        return render_raw_login(
            &state,
            &runtime,
            &client_id,
            &scopes,
            Some("Invalid username or password"),
            &return_to,
        )
        .await;
    }

    let now = super::support::now();
    let session = create_session(&state, &username, now).await;
    let mut response = redirect(&return_to);
    attach_session_cookie(
        &mut response,
        &session.id,
        runtime.config.server.tls,
        session_ttl(&runtime),
    );
    tracing::info!(user = %username, "login succeeded");
    response
}

// ------------------------------------------------------------------ helpers

enum LoginOutcome {
    LoggedIn {
        username: String,
        auth_time: i64,
        session_id: Option<String>,
    },
    ShowForm,
    AutoUser(String),
    Error(OAuthError),
}

async fn resolve_login(
    runtime: &Runtime,
    state: &AppState,
    headers: &HeaderMap,
    plan: &AuthorizePlan,
    now: i64,
) -> LoginOutcome {
    let forced = matches!(
        plan.prompt,
        Some(Prompt::Login) | Some(Prompt::SelectAccount)
    );

    if !forced
        && let Some(session_id) = session_id(headers)
        && let Some(session) = state.store.get_session(&session_id).await
        && session.expires_at > now
        && !max_age_exceeded(plan, &session, now)
    {
        return LoginOutcome::LoggedIn {
            username: session.username,
            auth_time: session.auth_time,
            session_id: Some(session.id),
        };
    }

    // Without an interactive prompt we cannot show a login page.
    if plan.prompt == Some(Prompt::None) {
        return LoginOutcome::Error(
            OAuthError::new(ErrorCode::LoginRequired, "login is required")
                .with_hint("prompt=none was requested but there is no active session"),
        );
    }

    let client_auto = runtime
        .client(&plan.client_id)
        .map(|client| client.auto_approve)
        .unwrap_or(false);
    if runtime.config.login.mode == LoginMode::Auto || client_auto {
        return match runtime.default_login_user() {
            Some(user) => LoginOutcome::AutoUser(user.username.clone()),
            None => LoginOutcome::Error(OAuthError::new(
                ErrorCode::ServerError,
                "no default user is configured for automatic login",
            )),
        };
    }

    LoginOutcome::ShowForm
}

fn max_age_exceeded(plan: &AuthorizePlan, session: &Session, now: i64) -> bool {
    match plan.max_age {
        Some(max_age) => now - session.auth_time > max_age,
        None => false,
    }
}

async fn create_session(state: &AppState, username: &str, now: i64) -> Session {
    let runtime = state.runtime().await;
    let session = Session {
        id: random_token(),
        username: username.to_string(),
        auth_time: now,
        expires_at: now + session_ttl(&runtime),
    };
    state.store.insert_session(session.clone()).await;
    session
}

fn session_ttl(runtime: &Runtime) -> i64 {
    runtime.config.tokens.refresh_ttl.as_secs() as i64
}

fn attach_session_cookie(response: &mut Response, session_id: &str, secure: bool, max_age: i64) {
    if let Ok(value) =
        header::HeaderValue::from_str(&session_set_cookie(session_id, max_age, secure))
    {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

fn redirect_success(plan: &AuthorizePlan, code: &str) -> String {
    let mut pairs = vec![("code", code)];
    if let Some(state) = plan.state.as_deref() {
        pairs.push(("state", state));
    }
    let query = encode_query(pairs);
    join_query(&plan.redirect_uri, &query)
}

fn redirect_error(redirect_uri: &str, state: Option<&str>, error: &OAuthError) -> Response {
    let mut pairs = vec![
        ("error", error.code.as_str()),
        ("error_description", error.description.as_str()),
    ];
    if let Some(state) = state {
        pairs.push(("state", state));
    }
    no_store(redirect(&join_query(redirect_uri, &encode_query(pairs))))
}

fn join_query(uri: &str, query: &str) -> String {
    if query.is_empty() {
        return uri.to_string();
    }
    let separator = if uri.contains('?') { '&' } else { '?' };
    format!("{uri}{separator}{query}")
}

async fn render_login(
    state: &AppState,
    runtime: &Runtime,
    plan: &AuthorizePlan,
    error: Option<&str>,
    return_to: String,
) -> Response {
    render_raw_login(
        state,
        runtime,
        &plan.client_id,
        &plan.scopes.join(" "),
        error,
        &return_to,
    )
    .await
}

async fn render_raw_login(
    state: &AppState,
    runtime: &Runtime,
    client_id: &str,
    scopes: &str,
    error: Option<&str>,
    return_to: &str,
) -> Response {
    let users: Vec<Value> = runtime
        .users()
        .iter()
        .map(|user| {
            json!({
                "username": user.username,
                "name": crate::oidc::resolved_name(user),
            })
        })
        .collect();
    let mode = match runtime.config.login.mode {
        LoginMode::Picker => "picker",
        // `auto` never reaches the form, but fall back to the form for a
        // direct visit to /login.
        LoginMode::Form | LoginMode::Auto => "form",
    };
    render_template(
        state,
        "login.html",
        &json!({
            "mode": mode,
            "client_id": client_id,
            "scopes": scopes,
            "users": users,
            "error": error,
            "return_to": return_to,
        }),
    )
    .await
}

fn request_from_params(params: &Params) -> AuthorizeRequest {
    AuthorizeRequest {
        response_type: params.get("response_type").map(str::to_string),
        client_id: params.get("client_id").map(str::to_string),
        redirect_uri: params.get("redirect_uri").map(str::to_string),
        scope: params.get("scope").map(str::to_string),
        state: params.get("state").map(str::to_string),
        nonce: params.get("nonce").map(str::to_string),
        code_challenge: params.get("code_challenge").map(str::to_string),
        code_challenge_method: params.get("code_challenge_method").map(str::to_string),
        prompt: params.get("prompt").map(str::to_string),
        login_hint: params.get("login_hint").map(str::to_string),
        max_age: params.get("max_age").map(str::to_string),
    }
}

/// `return_to` for the login form: the full original authorize request.
fn return_to(params: &Params) -> String {
    let pairs: Vec<(&str, &str)> = params
        .as_pairs()
        .iter()
        .filter(|(key, _)| !matches!(key.as_str(), "error" | "error_description"))
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();
    if pairs.is_empty() {
        return "/".to_string();
    }
    format!("/authorize?{}", encode_query(pairs))
}

/// True for a same-site absolute path (defends against open redirects).
pub fn is_local_path(value: &str) -> bool {
    value.starts_with('/') && !value.starts_with("//") && !value.contains("://")
}
