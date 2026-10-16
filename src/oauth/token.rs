//! Token endpoint (`/token`) domain logic: the four supported grant types and
//! token issuance.
//!
//! Everything here is independent from axum: the HTTP layer only parses the
//! request, authenticates the client and serialises the result.

use serde_json::{Value, json};

use crate::config::{ClientCfg, GrantType, UserCfg};
use crate::crypto::{
    KeySet, TokenValidation, decode_jwt, encode_jwt, pkce_verify, random_token, verify_password,
};
use crate::oidc::{ClaimsInput, access_token_claims, has_scope, id_token_claims};
use crate::state::Runtime;
use crate::store::{RecentToken, RefreshToken, Store};

use super::error::OAuthError;
use super::scope::{OFFLINE_ACCESS, narrow_scopes, resolve_scopes};

/// `grant_type` value mandated by RFC 8693.
pub const TOKEN_EXCHANGE_GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

/// RFC 8693 token type identifiers this server understands.
const TOKEN_TYPE_ACCESS: &str = "urn:ietf:params:oauth:token-type:access_token";
const TOKEN_TYPE_JWT: &str = "urn:ietf:params:oauth:token-type:jwt";
const TOKEN_TYPE_ID: &str = "urn:ietf:params:oauth:token-type:id_token";
const TOKEN_TYPE_REFRESH: &str = "urn:ietf:params:oauth:token-type:refresh_token";

/// Token set produced by a successful exchange.
#[derive(Debug, Clone)]
pub struct IssuedTokens {
    pub access_token: String,
    pub id_token: Option<String>,
    pub refresh_token: Option<String>,
    pub scopes: Vec<String>,
    pub access_expires_in: i64,
    /// RFC 8693 `issued_token_type`; only set by the token exchange grant.
    pub issued_token_type: Option<String>,
}

/// A parsed token request plus the authenticated client.
pub struct TokenExchange<'a> {
    pub runtime: &'a Runtime,
    pub keys: &'a KeySet,
    pub store: &'a Store,
    pub client: &'a ClientCfg,
    pub grant_type: &'a str,
    pub code: Option<&'a str>,
    pub redirect_uri: Option<&'a str>,
    pub code_verifier: Option<&'a str>,
    pub refresh_token: Option<&'a str>,
    pub scope: Option<&'a str>,
    pub username: Option<&'a str>,
    pub password: Option<&'a str>,
    /// RFC 8693 `subject_token`.
    pub subject_token: Option<&'a str>,
    /// RFC 8693 `subject_token_type`.
    pub subject_token_type: Option<&'a str>,
    /// RFC 8693 `actor_token` (delegation).
    pub actor_token: Option<&'a str>,
    /// RFC 8693 `actor_token_type`.
    pub actor_token_type: Option<&'a str>,
    /// RFC 8693 `requested_token_type`.
    pub requested_token_type: Option<&'a str>,
    /// RFC 8693 `audience` values (may be repeated).
    pub audiences: &'a [String],
    /// RFC 8707 `resource` values (may be repeated).
    pub resources: &'a [String],
    pub now: i64,
}

/// Dispatches a token request to the grant implementation for `grant_type`.
pub async fn exchange(request: TokenExchange<'_>) -> Result<IssuedTokens, OAuthError> {
    match request.grant_type {
        "authorization_code" => authorization_code(request).await,
        "client_credentials" => client_credentials(request).await,
        "refresh_token" => refresh_token(request).await,
        "password" => password(request).await,
        TOKEN_EXCHANGE_GRANT => token_exchange(request).await,
        other => Err(OAuthError::unsupported_grant_type(format!(
            "grant_type '{other}' is not supported"
        ))
        .with_hint(format!(
            "Supported grant types: authorization_code, client_credentials, refresh_token, \
             password, {TOKEN_EXCHANGE_GRANT}"
        ))),
    }
}

// ---------------------------------------------------------------- grants

async fn authorization_code(request: TokenExchange<'_>) -> Result<IssuedTokens, OAuthError> {
    require_grant(request.client, GrantType::AuthorizationCode)?;

    let Some(code) = request.code.filter(|value| !value.is_empty()) else {
        return Err(OAuthError::invalid_request(
            "missing required parameter: code",
        ));
    };
    // Single use: the code is removed even if the rest of the exchange fails.
    let Some(stored) = request.store.take_code(code).await else {
        return Err(
            OAuthError::invalid_grant("authorization code is invalid or was already used")
                .with_hint("Authorization codes are single use; start the login again"),
        );
    };

    if stored.client_id != request.client.client_id {
        return Err(OAuthError::invalid_grant(
            "authorization code was issued to a different client",
        ));
    }
    if stored.expires_at <= request.now {
        return Err(OAuthError::invalid_grant("authorization code has expired"));
    }

    match request.redirect_uri {
        Some(uri) if uri == stored.redirect_uri => {}
        Some(_) => {
            return Err(OAuthError::invalid_grant(
                "redirect_uri does not match the authorization request",
            ));
        }
        None => {
            return Err(
                OAuthError::invalid_request("missing required parameter: redirect_uri")
                    .with_hint("Resend the redirect_uri used at /authorize"),
            );
        }
    }

    if let Some(challenge) = &stored.code_challenge {
        let method = stored.code_challenge_method.as_deref().unwrap_or("S256");
        let Some(verifier) = request.code_verifier.filter(|value| !value.is_empty()) else {
            return Err(
                OAuthError::invalid_request("missing required parameter: code_verifier")
                    .with_hint("The PKCE verifier generated before /authorize is required"),
            );
        };
        pkce_verify(verifier, challenge, method).map_err(|error| {
            OAuthError::invalid_grant(format!("PKCE verification failed: {error}"))
                .with_hint("Send the code_verifier that matches the code_challenge")
        })?;
    } else if request.code_verifier.is_some() {
        return Err(OAuthError::invalid_grant(
            "code_verifier was sent but no code_challenge was provided",
        ));
    }

    let Some(user) = request.runtime.user(&stored.username) else {
        return Err(OAuthError::invalid_grant(
            "the user of this authorization code no longer exists",
        ));
    };

    let issue = IssueInput {
        runtime: request.runtime,
        keys: request.keys,
        store: request.store,
        client: request.client,
        user: Some(user),
        scopes: stored.scopes,
        nonce: stored.nonce,
        session_id: stored.session_id,
        auth_time: stored.auth_time,
        now: request.now,
        grant_type: "authorization_code",
        act: None,
        audience: None,
        subject: None,
        mint_refresh: true,
    };
    issue.issue().await
}

async fn client_credentials(request: TokenExchange<'_>) -> Result<IssuedTokens, OAuthError> {
    require_grant(request.client, GrantType::ClientCredentials)?;
    if request.client.public {
        return Err(OAuthError::unauthorized_client(
            "the client_credentials grant requires a confidential client",
        ));
    }

    let scopes = resolve_scopes(request.client, request.scope)?;
    if has_scope(&scopes, OFFLINE_ACCESS) {
        return Err(OAuthError::invalid_scope(
            "offline_access is not available without a user",
        ));
    }

    let issue = IssueInput {
        runtime: request.runtime,
        keys: request.keys,
        store: request.store,
        client: request.client,
        user: None,
        scopes,
        nonce: None,
        session_id: None,
        auth_time: request.now,
        now: request.now,
        grant_type: "client_credentials",
        act: None,
        audience: None,
        subject: None,
        mint_refresh: true,
    };
    issue.issue().await
}

async fn refresh_token(request: TokenExchange<'_>) -> Result<IssuedTokens, OAuthError> {
    require_grant(request.client, GrantType::RefreshToken)?;

    let Some(token) = request.refresh_token.filter(|value| !value.is_empty()) else {
        return Err(OAuthError::invalid_request(
            "missing required parameter: refresh_token",
        ));
    };

    let Some(stored) = request.store.get_refresh_token(token).await else {
        return Err(OAuthError::invalid_grant(
            "refresh token is unknown or has expired",
        ));
    };

    if stored.revoked {
        // A rotated token is being replayed: revoke the whole family.
        let revoked = request.store.revoke_refresh_family(&stored.family).await;
        tracing::warn!(
            client_id = %stored.client_id,
            family = %stored.family,
            revoked,
            "refresh token replay detected; token family revoked"
        );
        return Err(
            OAuthError::invalid_grant("refresh token has already been used")
                .with_hint("Refresh tokens rotate on every use; the whole session was revoked"),
        );
    }
    if stored.expires_at <= request.now {
        return Err(OAuthError::invalid_grant("refresh token has expired"));
    }
    if stored.client_id != request.client.client_id {
        return Err(OAuthError::invalid_grant(
            "refresh token was issued to a different client",
        ));
    }

    let scopes = narrow_scopes(request.client, &stored.scopes, request.scope)?;
    let user = request.runtime.user(&stored.username);

    let old_token = stored.token.clone();
    let rotate = request.runtime.config.tokens.rotate_refresh;
    let issue = IssueInput {
        runtime: request.runtime,
        keys: request.keys,
        store: request.store,
        client: request.client,
        user,
        scopes: scopes.clone(),
        nonce: None,
        session_id: stored.session_id.clone(),
        auth_time: stored.auth_time,
        now: request.now,
        grant_type: "refresh_token",
        act: None,
        audience: None,
        subject: None,
        mint_refresh: true,
    };

    let family = stored.family.clone();
    let issued = issue.issue().await?;

    // Rotation: atomically revoke the presented token and store the new one.
    match issued.refresh_token.clone() {
        Some(new_token) if rotate => {
            let replacement = RefreshToken {
                token: new_token,
                client_id: request.client.client_id.clone(),
                username: stored.username.clone(),
                scopes: scopes.clone(),
                family,
                auth_time: stored.auth_time,
                session_id: stored.session_id.clone(),
                issued_at: request.now,
                expires_at: request.now + refresh_ttl(request.runtime),
                revoked: false,
            };
            request
                .store
                .rotate_refresh_token(&old_token, replacement)
                .await;
        }
        _ => {}
    }

    Ok(issued)
}

async fn password(request: TokenExchange<'_>) -> Result<IssuedTokens, OAuthError> {
    if !request.runtime.config.allow_password_grant {
        return Err(
            OAuthError::unsupported_grant_type("the password grant is disabled")
                .with_hint("Set `allow_password_grant: true` in keyfob.yaml to enable it"),
        );
    }
    require_grant(request.client, GrantType::Password)?;

    let Some(username) = request.username.filter(|value| !value.is_empty()) else {
        return Err(OAuthError::invalid_request(
            "missing required parameter: username",
        ));
    };
    let Some(password) = request.password else {
        return Err(OAuthError::invalid_request(
            "missing required parameter: password",
        ));
    };

    let Some(user) = request.runtime.user(username) else {
        return Err(OAuthError::invalid_grant("invalid username or password"));
    };
    if !verify_password(password, &user.password) {
        return Err(OAuthError::invalid_grant("invalid username or password"));
    }

    let scopes = resolve_scopes(request.client, request.scope)?;
    let issue = IssueInput {
        runtime: request.runtime,
        keys: request.keys,
        store: request.store,
        client: request.client,
        user: Some(user),
        scopes,
        nonce: None,
        session_id: None,
        auth_time: request.now,
        now: request.now,
        grant_type: "password",
        act: None,
        audience: None,
        subject: None,
        mint_refresh: true,
    };
    issue.issue().await
}

// -------------------------------------------------------- token exchange

/// RFC 8693 Token Exchange.
///
/// The authenticated client presents a `subject_token` (and optionally an
/// `actor_token`) and receives a fresh access token. Impersonation issues a
/// token for the subject; delegation adds an `act` claim naming the actor.
/// Scopes are never widened and no refresh token is issued.
async fn token_exchange(request: TokenExchange<'_>) -> Result<IssuedTokens, OAuthError> {
    if !request.runtime.config.allow_token_exchange {
        return Err(
            OAuthError::unsupported_grant_type("the token exchange grant is disabled")
                .with_hint("Set `allow_token_exchange: true` in keyfob.yaml to enable it"),
        );
    }
    require_grant(request.client, GrantType::TokenExchange)?;

    let Some(subject_token) = request.subject_token.filter(|value| !value.is_empty()) else {
        return Err(OAuthError::invalid_request(
            "missing required parameter: subject_token",
        ));
    };
    let Some(subject_token_type) = request.subject_token_type.filter(|value| !value.is_empty())
    else {
        return Err(OAuthError::invalid_request(
            "missing required parameter: subject_token_type",
        ));
    };
    let subject = resolve_token(
        &request,
        subject_token,
        parse_token_type(subject_token_type)?,
        true,
    )
    .await?;

    let actor = match request.actor_token.filter(|value| !value.is_empty()) {
        Some(actor_token) => {
            let Some(actor_token_type) = request.actor_token_type.filter(|value| !value.is_empty())
            else {
                return Err(OAuthError::invalid_request(
                    "missing required parameter: actor_token_type",
                ));
            };
            Some(
                resolve_token(
                    &request,
                    actor_token,
                    parse_token_type(actor_token_type)?,
                    false,
                )
                .await?,
            )
        }
        None => {
            if request
                .actor_token_type
                .is_some_and(|value| !value.is_empty())
            {
                return Err(OAuthError::invalid_request(
                    "actor_token_type was provided without actor_token",
                ));
            }
            None
        }
    };

    // Only access tokens can be requested (RFC 8693 `requested_token_type`).
    let issued_token_type = match request
        .requested_token_type
        .filter(|value| !value.is_empty())
    {
        None => TOKEN_TYPE_ACCESS,
        Some(value) if value == TOKEN_TYPE_ACCESS || value == TOKEN_TYPE_JWT => TOKEN_TYPE_ACCESS,
        Some(other) => {
            return Err(OAuthError::invalid_request(format!(
                "requested_token_type '{other}' is not supported"
            ))
            .with_hint("The token exchange grant only issues access tokens"));
        }
    };

    let audience = resolve_audience(request.client, request.audiences, request.resources)?;
    let scopes = exchange_scopes(&request, &subject)?;

    let user = match subject.username.as_deref() {
        Some(username) => Some(request.runtime.user(username).ok_or_else(|| {
            OAuthError::invalid_grant("the subject of the token no longer exists")
        })?),
        None => None,
    };
    let act = actor.map(|actor| build_act(&actor, &request.runtime.issuer));

    let issue = IssueInput {
        runtime: request.runtime,
        keys: request.keys,
        store: request.store,
        client: request.client,
        user,
        scopes,
        nonce: None,
        session_id: subject.session_id.clone(),
        auth_time: subject.auth_time,
        now: request.now,
        grant_type: GrantType::TokenExchange.config_name(),
        act,
        audience,
        subject: Some(subject.sub.clone()),
        mint_refresh: false,
    };
    let mut issued = issue.issue().await?;
    issued.issued_token_type = Some(issued_token_type.to_string());
    Ok(issued)
}

/// Effective scopes for an exchange: the subject token is the ceiling and the
/// requesting client must be allowed every resulting scope.
fn exchange_scopes(
    request: &TokenExchange<'_>,
    subject: &ResolvedToken,
) -> Result<Vec<String>, OAuthError> {
    let mut scopes = if subject.id_token {
        // An ID token carries no scope: fall back to the client's own scopes.
        resolve_scopes(request.client, request.scope)?
    } else {
        narrow_scopes(request.client, &subject.scopes, request.scope)?
    };
    scopes.retain(|scope| scope != OFFLINE_ACCESS);
    for scope in &scopes {
        if !request.client.allows_scope(scope) {
            return Err(OAuthError::invalid_scope(format!(
                "scope '{scope}' is not allowed through token exchange for client '{}'",
                request.client.client_id
            )));
        }
    }
    Ok(scopes)
}

/// Validates RFC 8693 `audience` / RFC 8707 `resource` against the client.
fn resolve_audience(
    client: &ClientCfg,
    audiences: &[String],
    resources: &[String],
) -> Result<Option<Vec<String>>, OAuthError> {
    let mut requested: Vec<String> = Vec::new();
    for value in audiences.iter().chain(resources.iter()) {
        let value = value.trim();
        if value.is_empty() || requested.iter().any(|existing| existing == value) {
            continue;
        }
        requested.push(value.to_string());
    }
    if requested.is_empty() {
        return Ok(None);
    }
    let allowed: Vec<&String> = if client.audience.is_empty() {
        vec![&client.client_id]
    } else {
        client.audience.iter().collect()
    };
    for value in &requested {
        if !allowed.contains(&value) {
            return Err(OAuthError::invalid_target(format!(
                "audience '{value}' is not allowed for client '{}'",
                client.client_id
            ))
            .with_hint(
                "List it under the client's `audience` in keyfob.yaml, or omit \
                 `audience` / `resource`",
            ));
        }
    }
    Ok(Some(requested))
}

/// Token types this server accepts in `subject_token_type` / `actor_token_type`.
#[derive(Debug, Clone, Copy)]
enum TokenKind {
    Access,
    Id,
    Refresh,
}

fn parse_token_type(value: &str) -> Result<TokenKind, OAuthError> {
    match value {
        TOKEN_TYPE_ACCESS | TOKEN_TYPE_JWT => Ok(TokenKind::Access),
        TOKEN_TYPE_ID => Ok(TokenKind::Id),
        TOKEN_TYPE_REFRESH => Ok(TokenKind::Refresh),
        other => Err(
            OAuthError::invalid_request(format!("unsupported token type '{other}'")).with_hint(
                "Supported types: urn:ietf:params:oauth:token-type:access_token, \
             ...:jwt, ...:id_token and ...:refresh_token",
            ),
        ),
    }
}

/// The validated identity carried by a subject or actor token.
struct ResolvedToken {
    sub: String,
    username: Option<String>,
    scopes: Vec<String>,
    /// Whether the token carries no scope concept at all (an ID token), in
    /// which case the client's own scopes are the ceiling.
    id_token: bool,
    session_id: Option<String>,
    auth_time: i64,
    /// The token's own `act`, preserved when the token becomes an actor.
    act: Option<Value>,
}

async fn resolve_token(
    request: &TokenExchange<'_>,
    token: &str,
    kind: TokenKind,
    allow_refresh: bool,
) -> Result<ResolvedToken, OAuthError> {
    match kind {
        TokenKind::Refresh => {
            if !allow_refresh {
                return Err(OAuthError::invalid_request(
                    "a refresh token cannot be used as an actor token",
                ));
            }
            let Some(entry) = request.store.get_refresh_token(token).await else {
                return Err(OAuthError::invalid_grant(
                    "refresh token is unknown or has expired",
                ));
            };
            if entry.revoked {
                return Err(
                    OAuthError::invalid_grant("refresh token has already been used").with_hint(
                        "Refresh tokens rotate on every use; the whole session was revoked",
                    ),
                );
            }
            if entry.expires_at <= request.now {
                return Err(OAuthError::invalid_grant("refresh token has expired"));
            }
            if entry.client_id != request.client.client_id {
                return Err(OAuthError::invalid_grant(
                    "refresh token was issued to a different client",
                ));
            }
            Ok(ResolvedToken {
                sub: entry.username.clone(),
                username: Some(entry.username),
                scopes: entry.scopes,
                id_token: false,
                session_id: entry.session_id,
                auth_time: entry.auth_time,
                act: None,
            })
        }
        TokenKind::Access | TokenKind::Id => {
            // Decode without enforcing `exp` so the check uses the request's
            // clock (consistent with introspection) instead of the system clock.
            let claims = decode_jwt(
                request.keys,
                token,
                &TokenValidation::new(&request.runtime.issuer).allow_expired(),
            )
            .map_err(|error| {
                OAuthError::invalid_grant(format!("token could not be validated: {error}"))
                    .with_hint("The token must be an unexpired token issued by this server")
            })?;

            if claims
                .get("exp")
                .and_then(Value::as_i64)
                .is_none_or(|exp| exp <= request.now)
            {
                return Err(OAuthError::invalid_grant("the token has expired"));
            }

            // Only access tokens carry `client_id`; ID tokens do not.
            let is_access_token = claims.get("client_id").and_then(Value::as_str).is_some();
            match kind {
                TokenKind::Access if !is_access_token => {
                    return Err(OAuthError::invalid_grant(
                        "subject_token_type is an access token but the token is not one",
                    ));
                }
                TokenKind::Id if is_access_token => {
                    return Err(OAuthError::invalid_grant(
                        "subject_token_type is an ID token but the token is an access token",
                    ));
                }
                _ => {}
            }

            if let Some(jti) = claims.get("jti").and_then(Value::as_str)
                && request.store.is_access_token_revoked(jti).await
            {
                return Err(OAuthError::invalid_grant("the token was revoked"));
            }

            let Some(sub) = claims.get("sub").and_then(Value::as_str) else {
                return Err(OAuthError::invalid_grant("the token has no subject"));
            };
            Ok(ResolvedToken {
                sub: sub.to_string(),
                username: request.runtime.user(sub).map(|user| user.username.clone()),
                scopes: claims
                    .get("scope")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .split_whitespace()
                    .map(str::to_string)
                    .collect(),
                id_token: matches!(kind, TokenKind::Id),
                session_id: claims
                    .get("sid")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                auth_time: claims
                    .get("auth_time")
                    .and_then(Value::as_i64)
                    .unwrap_or(request.now),
                act: claims.get("act").cloned(),
            })
        }
    }
}

/// Builds the `act` claim for delegation (RFC 8693 section 4.1), nesting the
/// actor's own `act` chain so a chain of delegations is preserved.
fn build_act(actor: &ResolvedToken, issuer: &str) -> Value {
    let mut act = json!({ "sub": actor.sub, "iss": issuer });
    if let Some(nested) = &actor.act {
        act["act"] = nested.clone();
    }
    act
}

// ------------------------------------------------------------- issuance

struct IssueInput<'a> {
    runtime: &'a Runtime,
    keys: &'a KeySet,
    store: &'a Store,
    client: &'a ClientCfg,
    user: Option<&'a UserCfg>,
    scopes: Vec<String>,
    nonce: Option<String>,
    session_id: Option<String>,
    auth_time: i64,
    now: i64,
    grant_type: &'a str,
    /// Delegation chain (`act`) attached to the access token (RFC 8693).
    act: Option<Value>,
    /// Overrides the access token audience (RFC 8693 `audience` / `resource`).
    audience: Option<Vec<String>>,
    /// Overrides the token subject (RFC 8693: the subject token's `sub`).
    subject: Option<String>,
    /// Whether this grant may mint a refresh token at all.
    mint_refresh: bool,
}

impl IssueInput<'_> {
    async fn issue(self) -> Result<IssuedTokens, OAuthError> {
        let issuer = &self.runtime.issuer;
        let access_ttl = self.runtime.config.tokens.access_ttl.as_secs() as i64;
        let id_ttl = self.runtime.config.tokens.id_ttl.as_secs() as i64;

        let access_claims = access_token_claims(&ClaimsInput {
            issuer,
            client: self.client,
            user: self.user,
            scopes: &self.scopes,
            nonce: self.nonce.as_deref(),
            auth_time: self.auth_time,
            session_id: self.session_id.as_deref(),
            now: self.now,
            ttl_seconds: access_ttl,
            access_token: None,
            act: self.act.as_ref(),
            audience: self.audience.as_deref(),
            subject: self.subject.as_deref(),
        });
        let access_token = encode_jwt(self.keys, &access_claims).map_err(|error| {
            OAuthError::new(super::error::ErrorCode::ServerError, error.to_string())
        })?;

        let id_token = match self.user {
            Some(user) if has_scope(&self.scopes, "openid") => {
                let claims = id_token_claims(&ClaimsInput {
                    issuer,
                    client: self.client,
                    user: Some(user),
                    scopes: &self.scopes,
                    nonce: self.nonce.as_deref(),
                    auth_time: self.auth_time,
                    session_id: self.session_id.as_deref(),
                    now: self.now,
                    ttl_seconds: id_ttl,
                    access_token: Some(&access_token),
                    act: None,
                    audience: None,
                    subject: None,
                });
                Some(encode_jwt(self.keys, &claims).map_err(|error| {
                    OAuthError::new(super::error::ErrorCode::ServerError, error.to_string())
                })?)
            }
            _ => None,
        };

        let refresh_token = if self.mint_refresh && refresh_allowed(self.client, &self.scopes) {
            let token = random_token();
            let entry = RefreshToken {
                token: token.clone(),
                client_id: self.client.client_id.clone(),
                username: self
                    .user
                    .map(|user| user.username.clone())
                    .unwrap_or_else(|| self.client.client_id.clone()),
                scopes: self.scopes.clone(),
                family: random_token(),
                auth_time: self.auth_time,
                session_id: self.session_id.clone(),
                issued_at: self.now,
                expires_at: self.now + refresh_ttl(self.runtime),
                revoked: false,
            };
            self.store.insert_refresh_token(entry).await;
            Some(token)
        } else {
            None
        };

        self.store
            .record_recent_token(RecentToken {
                issued_at: self.now,
                grant_type: self.grant_type.to_string(),
                client_id: self.client.client_id.clone(),
                username: self.user.map(|user| user.username.clone()),
                scopes: self.scopes.clone(),
                access_token: Some(access_token.clone()),
                id_token: id_token.clone(),
                refresh_token: refresh_token.clone(),
            })
            .await;

        tracing::info!(
            grant_type = self.grant_type,
            client_id = %self.client.client_id,
            user = self.user.map(|user| user.username.as_str()).unwrap_or("-"),
            scopes = %self.scopes.join(" "),
            "issued tokens"
        );

        Ok(IssuedTokens {
            access_token,
            id_token,
            refresh_token,
            scopes: self.scopes,
            access_expires_in: access_ttl,
            issued_token_type: None,
        })
    }
}

/// Whether this grant should also mint a refresh token.
///
/// Public clients must additionally request `offline_access`.
fn refresh_allowed(client: &ClientCfg, scopes: &[String]) -> bool {
    if !client.allows_grant(GrantType::RefreshToken) {
        return false;
    }
    !client.public || has_scope(scopes, OFFLINE_ACCESS)
}

fn refresh_ttl(runtime: &Runtime) -> i64 {
    runtime.config.tokens.refresh_ttl.as_secs() as i64
}

/// Issues a token set directly, without going through HTTP.
///
/// Used by `keyfob token` to mint a token from the command line. The caller is
/// responsible for having authenticated the client.
// Mirrors the fields of `IssueInput`; a single convenience entry point is
// clearer than an intermediate builder at this stage.
#[allow(clippy::too_many_arguments)]
pub async fn issue_direct(
    runtime: &Runtime,
    keys: &KeySet,
    store: &Store,
    client: &ClientCfg,
    user: Option<&UserCfg>,
    scopes: Vec<String>,
    grant_type: &str,
    now: i64,
) -> Result<IssuedTokens, OAuthError> {
    let input = IssueInput {
        runtime,
        keys,
        store,
        client,
        user,
        scopes,
        nonce: None,
        session_id: None,
        auth_time: now,
        now,
        grant_type,
        act: None,
        audience: None,
        subject: None,
        mint_refresh: true,
    };
    input.issue().await
}

fn require_grant(client: &ClientCfg, grant: GrantType) -> Result<(), OAuthError> {
    if client.allows_grant(grant) {
        Ok(())
    } else {
        Err(OAuthError::unauthorized_client(format!(
            "client '{}' is not allowed to use the {} grant",
            client.client_id,
            grant.config_name()
        ))
        .with_hint(format!(
            "Add '{}' to this client's grant_types in keyfob.yaml",
            grant.config_name()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use crate::crypto::{DEFAULT_KEY_BITS, KeySet};
    use crate::oauth::authorize::{self, AuthorizeRequest};
    use crate::store::Store;
    use serde_json::Value;

    struct Fixture {
        runtime: Runtime,
        store: Store,
    }

    /// A single key pair shared by every test: RSA generation is the slow part.
    fn keys() -> &'static KeySet {
        static KEYS: std::sync::OnceLock<KeySet> = std::sync::OnceLock::new();
        KEYS.get_or_init(|| KeySet::generate("RS256", DEFAULT_KEY_BITS).unwrap())
    }

    fn fixture() -> Fixture {
        let config = config::parse_str(
            r#"
allow_password_grant: true
allow_token_exchange: true
clients:
  - client_id: spa
    public: true
    redirect_uris: [http://localhost:3000/cb]
  - client_id: backend
    client_secret: dev-secret
    grant_types: [client_credentials, refresh_token]
  - client_id: cli
    client_secret: cli-secret
    grant_types: [password]
  - client_id: exchanger
    client_secret: exch-secret
    grant_types: [token_exchange]
users:
  - username: alice
    password: alice123
    roles: [admin]
"#,
            "test.yaml",
        )
        .unwrap();
        Fixture {
            runtime: Runtime::build(config),
            store: Store::new(),
        }
    }

    /// A token-exchange request with every optional field cleared; tests set
    /// only what they exercise.
    fn token_request<'a>(
        fixture: &'a Fixture,
        client_id: &str,
        grant_type: &'a str,
    ) -> TokenExchange<'a> {
        TokenExchange {
            runtime: &fixture.runtime,
            keys: keys(),
            store: &fixture.store,
            client: client(fixture, client_id),
            grant_type,
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
            scope: None,
            username: None,
            password: None,
            subject_token: None,
            subject_token_type: None,
            actor_token: None,
            actor_token_type: None,
            requested_token_type: None,
            audiences: &[],
            resources: &[],
            now: 20,
        }
    }

    /// Issues a user access token for `alice` through the authorization code
    /// grant, to use as a token exchange subject.
    async fn user_access_token(fixture: &Fixture, scopes: &str) -> String {
        let code = authorize_code(fixture, scopes, VERIFIER).await;
        let mut request = token_request(fixture, "spa", "authorization_code");
        request.code = Some(&code);
        request.redirect_uri = Some("http://localhost:3000/cb");
        request.code_verifier = Some(VERIFIER);
        exchange(request).await.unwrap().access_token
    }

    fn claims(fixture: &Fixture, token: &str) -> Value {
        crate::crypto::decode_jwt(
            keys(),
            token,
            &crate::crypto::TokenValidation::new(&fixture.runtime.issuer).allow_expired(),
        )
        .unwrap()
    }

    fn client<'a>(fixture: &'a Fixture, id: &str) -> &'a ClientCfg {
        fixture.runtime.client(id).unwrap()
    }

    async fn authorize_code(fixture: &Fixture, scopes: &str, verifier: &str) -> String {
        let plan = authorize::validate(
            &fixture.runtime,
            &AuthorizeRequest {
                response_type: Some("code".into()),
                client_id: Some("spa".into()),
                redirect_uri: Some("http://localhost:3000/cb".into()),
                scope: Some(scopes.into()),
                nonce: Some("n-1".into()),
                code_challenge: Some(authorize::derive_challenge(verifier)),
                code_challenge_method: Some("S256".into()),
                ..AuthorizeRequest::default()
            },
        )
        .unwrap();
        let code =
            authorize::create_code(&fixture.store, &plan, "alice", Some("sess".into()), 10, 10)
                .await;
        code.code
    }

    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    #[tokio::test]
    async fn authorization_code_exchange_issues_all_tokens() {
        let fixture = fixture();
        let code = authorize_code(&fixture, "openid profile offline_access", VERIFIER).await;
        let issued = exchange(TokenExchange {
            runtime: &fixture.runtime,
            keys: keys(),
            store: &fixture.store,
            client: client(&fixture, "spa"),
            grant_type: "authorization_code",
            code: Some(&code),
            redirect_uri: Some("http://localhost:3000/cb"),
            code_verifier: Some(VERIFIER),
            refresh_token: None,
            scope: None,
            username: None,
            password: None,
            subject_token: None,
            subject_token_type: None,
            actor_token: None,
            actor_token_type: None,
            requested_token_type: None,
            audiences: &[],
            resources: &[],
            now: 20,
        })
        .await
        .unwrap();

        assert!(issued.id_token.is_some());
        assert!(issued.refresh_token.is_some());
        // The ID token carries the nonce from the authorization request.
        let claims = crate::crypto::decode_jwt(
            keys(),
            issued.id_token.as_deref().unwrap(),
            &crate::crypto::TokenValidation::new(&fixture.runtime.issuer).allow_expired(),
        )
        .unwrap();
        assert_eq!(claims["nonce"], "n-1");
        assert_eq!(claims["aud"], "spa");
        assert!(claims["at_hash"].is_string());
    }

    #[tokio::test]
    async fn code_is_single_use_and_pkce_is_checked() {
        let fixture = fixture();
        let code = authorize_code(&fixture, "openid", VERIFIER).await;

        // Wrong verifier: invalid_grant, and the code is consumed.
        let error = exchange(TokenExchange {
            runtime: &fixture.runtime,
            keys: keys(),
            store: &fixture.store,
            client: client(&fixture, "spa"),
            grant_type: "authorization_code",
            code: Some(&code),
            redirect_uri: Some("http://localhost:3000/cb"),
            code_verifier: Some("wrong-verifier-that-is-long-enough-000000000000"),
            refresh_token: None,
            scope: None,
            username: None,
            password: None,
            subject_token: None,
            subject_token_type: None,
            actor_token: None,
            actor_token_type: None,
            requested_token_type: None,
            audiences: &[],
            resources: &[],
            now: 20,
        })
        .await
        .unwrap_err();
        assert_eq!(error.code, super::super::error::ErrorCode::InvalidGrant);

        // Reuse: the code is gone.
        let reuse = exchange(TokenExchange {
            runtime: &fixture.runtime,
            keys: keys(),
            store: &fixture.store,
            client: client(&fixture, "spa"),
            grant_type: "authorization_code",
            code: Some(&code),
            redirect_uri: Some("http://localhost:3000/cb"),
            code_verifier: Some(VERIFIER),
            refresh_token: None,
            scope: None,
            username: None,
            password: None,
            subject_token: None,
            subject_token_type: None,
            actor_token: None,
            actor_token_type: None,
            requested_token_type: None,
            audiences: &[],
            resources: &[],
            now: 21,
        })
        .await
        .unwrap_err();
        assert!(reuse.description.contains("already used"));
    }

    #[tokio::test]
    async fn redirect_uri_must_match() {
        let fixture = fixture();
        let code = authorize_code(&fixture, "openid", VERIFIER).await;
        let error = exchange(TokenExchange {
            runtime: &fixture.runtime,
            keys: keys(),
            store: &fixture.store,
            client: client(&fixture, "spa"),
            grant_type: "authorization_code",
            code: Some(&code),
            redirect_uri: Some("http://localhost:3000/other"),
            code_verifier: Some(VERIFIER),
            refresh_token: None,
            scope: None,
            username: None,
            password: None,
            subject_token: None,
            subject_token_type: None,
            actor_token: None,
            actor_token_type: None,
            requested_token_type: None,
            audiences: &[],
            resources: &[],
            now: 20,
        })
        .await
        .unwrap_err();
        assert!(error.description.contains("redirect_uri"));
    }

    #[tokio::test]
    async fn client_credentials_has_no_id_token() {
        let fixture = fixture();
        let issued = exchange(TokenExchange {
            runtime: &fixture.runtime,
            keys: keys(),
            store: &fixture.store,
            client: client(&fixture, "backend"),
            grant_type: "client_credentials",
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
            scope: None,
            username: None,
            password: None,
            subject_token: None,
            subject_token_type: None,
            actor_token: None,
            actor_token_type: None,
            requested_token_type: None,
            audiences: &[],
            resources: &[],
            now: 20,
        })
        .await
        .unwrap();
        assert!(issued.id_token.is_none());
        assert!(issued.refresh_token.is_some());
    }

    #[tokio::test]
    async fn refresh_rotates_and_detects_replay() {
        let fixture = fixture();
        let code = authorize_code(&fixture, "openid offline_access", VERIFIER).await;
        let first = exchange(TokenExchange {
            runtime: &fixture.runtime,
            keys: keys(),
            store: &fixture.store,
            client: client(&fixture, "spa"),
            grant_type: "authorization_code",
            code: Some(&code),
            redirect_uri: Some("http://localhost:3000/cb"),
            code_verifier: Some(VERIFIER),
            refresh_token: None,
            scope: None,
            username: None,
            password: None,
            subject_token: None,
            subject_token_type: None,
            actor_token: None,
            actor_token_type: None,
            requested_token_type: None,
            audiences: &[],
            resources: &[],
            now: 20,
        })
        .await
        .unwrap();
        let refresh = first.refresh_token.clone().unwrap();

        let refreshed = exchange(TokenExchange {
            runtime: &fixture.runtime,
            keys: keys(),
            store: &fixture.store,
            client: client(&fixture, "spa"),
            grant_type: "refresh_token",
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: Some(&refresh),
            scope: None,
            username: None,
            password: None,
            subject_token: None,
            subject_token_type: None,
            actor_token: None,
            actor_token_type: None,
            requested_token_type: None,
            audiences: &[],
            resources: &[],
            now: 30,
        })
        .await
        .unwrap();
        assert_ne!(refreshed.refresh_token.as_deref(), Some(refresh.as_str()));
        // Refresh does not carry the nonce.
        let claims = crate::crypto::decode_jwt(
            keys(),
            refreshed.id_token.as_deref().unwrap(),
            &crate::crypto::TokenValidation::new(&fixture.runtime.issuer).allow_expired(),
        )
        .unwrap();
        assert!(claims.get("nonce").is_none());

        // Replaying the old token revokes the family.
        exchange(TokenExchange {
            runtime: &fixture.runtime,
            keys: keys(),
            store: &fixture.store,
            client: client(&fixture, "spa"),
            grant_type: "refresh_token",
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: Some(&refresh),
            scope: None,
            username: None,
            password: None,
            subject_token: None,
            subject_token_type: None,
            actor_token: None,
            actor_token_type: None,
            requested_token_type: None,
            audiences: &[],
            resources: &[],
            now: 40,
        })
        .await
        .unwrap_err();
        let replacement = refreshed.refresh_token.unwrap();
        assert!(
            fixture
                .store
                .get_refresh_token(&replacement)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn password_grant_checks_credentials() {
        let first = fixture();
        let ok = exchange(TokenExchange {
            runtime: &first.runtime,
            keys: keys(),
            store: &first.store,
            client: client(&first, "backend"),
            grant_type: "password",
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
            scope: Some("openid"),
            username: Some("alice"),
            password: Some("alice123"),
            subject_token: None,
            subject_token_type: None,
            actor_token: None,
            actor_token_type: None,
            requested_token_type: None,
            audiences: &[],
            resources: &[],
            now: 20,
        })
        .await;
        // backend does not allow the password grant.
        assert_eq!(
            ok.unwrap_err().code,
            super::super::error::ErrorCode::UnauthorizedClient
        );

        let second = fixture();
        let error = exchange(TokenExchange {
            runtime: &second.runtime,
            keys: keys(),
            store: &second.store,
            client: client(&second, "cli"),
            grant_type: "password",
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
            scope: None,
            username: Some("alice"),
            password: Some("wrong"),
            subject_token: None,
            subject_token_type: None,
            actor_token: None,
            actor_token_type: None,
            requested_token_type: None,
            audiences: &[],
            resources: &[],
            now: 20,
        })
        .await
        .unwrap_err();
        assert_eq!(error.code, super::super::error::ErrorCode::InvalidGrant);
    }

    #[tokio::test]
    async fn unknown_grant_is_rejected() {
        let fixture = fixture();
        let error = exchange(TokenExchange {
            runtime: &fixture.runtime,
            keys: keys(),
            store: &fixture.store,
            client: client(&fixture, "backend"),
            grant_type: "device_code",
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
            scope: None,
            username: None,
            password: None,
            subject_token: None,
            subject_token_type: None,
            actor_token: None,
            actor_token_type: None,
            requested_token_type: None,
            audiences: &[],
            resources: &[],
            now: 20,
        })
        .await
        .unwrap_err();
        assert_eq!(
            error.code,
            super::super::error::ErrorCode::UnsupportedGrantType
        );
    }

    #[test]
    fn refresh_is_gated_by_offline_access_for_public_clients() {
        let config = config::parse_str(
            r#"
clients:
  - client_id: spa
    public: true
    redirect_uris: [http://localhost/cb]
users:
  - username: alice
    password: alice123
"#,
            "test.yaml",
        )
        .unwrap();
        let client = &config.clients[0];
        assert!(!refresh_allowed(client, &["openid".to_string()]));
        assert!(refresh_allowed(client, &["offline_access".to_string()]));
    }

    #[tokio::test]
    async fn token_exchange_impersonates_a_user() {
        let fixture = fixture();
        let subject = user_access_token(&fixture, "openid profile").await;

        let mut request = token_request(&fixture, "exchanger", TOKEN_EXCHANGE_GRANT);
        request.subject_token = Some(&subject);
        request.subject_token_type = Some(TOKEN_TYPE_ACCESS);
        let issued = exchange(request).await.unwrap();

        assert_eq!(issued.issued_token_type.as_deref(), Some(TOKEN_TYPE_ACCESS));
        assert!(
            issued.refresh_token.is_none(),
            "token exchange never mints a refresh token"
        );
        let claims = claims(&fixture, &issued.access_token);
        assert_eq!(claims["sub"], "alice");
        assert_eq!(claims["client_id"], "exchanger");
        assert_eq!(claims["scope"], "openid profile");
        assert!(claims.get("act").is_none(), "impersonation has no act");
    }

    #[tokio::test]
    async fn token_exchange_accepts_an_id_token_subject() {
        let fixture = fixture();
        let code = authorize_code(&fixture, "openid profile", VERIFIER).await;
        let mut request = token_request(&fixture, "spa", "authorization_code");
        request.code = Some(&code);
        request.redirect_uri = Some("http://localhost:3000/cb");
        request.code_verifier = Some(VERIFIER);
        let id_token = exchange(request).await.unwrap().id_token.unwrap();

        let mut request = token_request(&fixture, "exchanger", TOKEN_EXCHANGE_GRANT);
        request.subject_token = Some(&id_token);
        request.subject_token_type = Some(TOKEN_TYPE_ID);
        request.scope = Some("openid");
        let issued = exchange(request).await.unwrap();

        let claims = claims(&fixture, &issued.access_token);
        assert_eq!(claims["sub"], "alice");
        assert_eq!(claims["scope"], "openid");
    }

    #[tokio::test]
    async fn token_exchange_delegates_with_an_act_claim() {
        let fixture = fixture();
        let subject = user_access_token(&fixture, "openid").await;
        let actor = {
            let mut request = token_request(&fixture, "backend", "client_credentials");
            request.scope = Some("openid");
            exchange(request).await.unwrap().access_token
        };

        let mut request = token_request(&fixture, "exchanger", TOKEN_EXCHANGE_GRANT);
        request.subject_token = Some(&subject);
        request.subject_token_type = Some(TOKEN_TYPE_ACCESS);
        request.actor_token = Some(&actor);
        request.actor_token_type = Some(TOKEN_TYPE_ACCESS);
        let issued = exchange(request).await.unwrap();

        let claims = claims(&fixture, &issued.access_token);
        assert_eq!(claims["sub"], "alice");
        assert_eq!(claims["act"]["sub"], "backend");
        assert_eq!(claims["act"]["iss"], fixture.runtime.issuer);
    }

    #[tokio::test]
    async fn token_exchange_cannot_widen_scopes() {
        let fixture = fixture();
        let subject = user_access_token(&fixture, "openid").await;

        let mut request = token_request(&fixture, "exchanger", TOKEN_EXCHANGE_GRANT);
        request.subject_token = Some(&subject);
        request.subject_token_type = Some(TOKEN_TYPE_ACCESS);
        request.scope = Some("openid profile");
        let error = exchange(request).await.unwrap_err();
        assert_eq!(error.code, super::super::error::ErrorCode::InvalidScope);

        let mut request = token_request(&fixture, "exchanger", TOKEN_EXCHANGE_GRANT);
        request.subject_token = Some(&subject);
        request.subject_token_type = Some(TOKEN_TYPE_ACCESS);
        request.scope = Some("openid");
        let issued = exchange(request).await.unwrap();
        assert_eq!(issued.scopes, vec!["openid".to_string()]);
    }

    #[tokio::test]
    async fn token_exchange_validates_the_subject_token() {
        let fixture = fixture();

        let mut request = token_request(&fixture, "exchanger", TOKEN_EXCHANGE_GRANT);
        request.subject_token = Some("not-a-jwt");
        request.subject_token_type = Some(TOKEN_TYPE_ACCESS);
        let error = exchange(request).await.unwrap_err();
        assert_eq!(error.code, super::super::error::ErrorCode::InvalidGrant);

        let mut request = token_request(&fixture, "exchanger", TOKEN_EXCHANGE_GRANT);
        request.subject_token = Some("not-a-jwt");
        let error = exchange(request).await.unwrap_err();
        assert_eq!(error.code, super::super::error::ErrorCode::InvalidRequest);
    }

    #[tokio::test]
    async fn token_exchange_restricts_the_audience() {
        let fixture = fixture();
        let subject = user_access_token(&fixture, "openid").await;

        let other = vec!["other-api".to_string()];
        let mut request = token_request(&fixture, "exchanger", TOKEN_EXCHANGE_GRANT);
        request.subject_token = Some(&subject);
        request.subject_token_type = Some(TOKEN_TYPE_ACCESS);
        request.audiences = &other;
        let error = exchange(request).await.unwrap_err();
        assert_eq!(error.code, super::super::error::ErrorCode::InvalidTarget);

        // The client's own id is always an allowed audience.
        let allowed = vec!["exchanger".to_string()];
        let mut request = token_request(&fixture, "exchanger", TOKEN_EXCHANGE_GRANT);
        request.subject_token = Some(&subject);
        request.subject_token_type = Some(TOKEN_TYPE_ACCESS);
        request.audiences = &allowed;
        let issued = exchange(request).await.unwrap();
        let claims = claims(&fixture, &issued.access_token);
        assert_eq!(claims["aud"][0], "exchanger");
    }

    #[tokio::test]
    async fn token_exchange_refresh_subject_is_bound_to_its_client() {
        let fixture = fixture();
        let code = authorize_code(&fixture, "openid offline_access", VERIFIER).await;
        let mut request = token_request(&fixture, "spa", "authorization_code");
        request.code = Some(&code);
        request.redirect_uri = Some("http://localhost:3000/cb");
        request.code_verifier = Some(VERIFIER);
        let refresh = exchange(request).await.unwrap().refresh_token.unwrap();

        let mut request = token_request(&fixture, "exchanger", TOKEN_EXCHANGE_GRANT);
        request.subject_token = Some(&refresh);
        request.subject_token_type = Some(TOKEN_TYPE_REFRESH);
        let error = exchange(request).await.unwrap_err();
        assert_eq!(error.code, super::super::error::ErrorCode::InvalidGrant);
    }

    #[tokio::test]
    async fn token_exchange_rejects_a_refresh_token_as_actor() {
        let fixture = fixture();
        let subject = user_access_token(&fixture, "openid").await;

        let mut request = token_request(&fixture, "exchanger", TOKEN_EXCHANGE_GRANT);
        request.subject_token = Some(&subject);
        request.subject_token_type = Some(TOKEN_TYPE_ACCESS);
        request.actor_token = Some("some-refresh-token");
        request.actor_token_type = Some(TOKEN_TYPE_REFRESH);
        let error = exchange(request).await.unwrap_err();
        assert_eq!(error.code, super::super::error::ErrorCode::InvalidRequest);
    }

    #[tokio::test]
    async fn token_exchange_is_disabled_by_default() {
        let config = config::parse_str(
            r#"
clients:
  - client_id: backend
    client_secret: s
    grant_types: [client_credentials]
"#,
            "test.yaml",
        )
        .unwrap();
        let runtime = Runtime::build(config);
        let store = Store::new();
        let error = exchange(TokenExchange {
            runtime: &runtime,
            keys: keys(),
            store: &store,
            client: runtime.client("backend").unwrap(),
            grant_type: TOKEN_EXCHANGE_GRANT,
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
            scope: None,
            username: None,
            password: None,
            subject_token: None,
            subject_token_type: None,
            actor_token: None,
            actor_token_type: None,
            requested_token_type: None,
            audiences: &[],
            resources: &[],
            now: 20,
        })
        .await
        .unwrap_err();
        assert_eq!(
            error.code,
            super::super::error::ErrorCode::UnsupportedGrantType
        );
    }
}
