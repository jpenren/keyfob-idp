//! Token endpoint (`/token`) domain logic: the four supported grant types and
//! token issuance.
//!
//! Everything here is independent from axum: the HTTP layer only parses the
//! request, authenticates the client and serialises the result.

use crate::config::{ClientCfg, GrantType, UserCfg};
use crate::crypto::{KeySet, encode_jwt, pkce_verify, random_token, verify_password};
use crate::oidc::{ClaimsInput, access_token_claims, has_scope, id_token_claims};
use crate::state::Runtime;
use crate::store::{RecentToken, RefreshToken, Store};

use super::error::OAuthError;
use super::scope::{OFFLINE_ACCESS, narrow_scopes, resolve_scopes};

/// Token set produced by a successful exchange.
#[derive(Debug, Clone)]
pub struct IssuedTokens {
    pub access_token: String,
    pub id_token: Option<String>,
    pub refresh_token: Option<String>,
    pub scopes: Vec<String>,
    pub access_expires_in: i64,
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
    pub now: i64,
}

/// Dispatches a token request to the grant implementation for `grant_type`.
pub async fn exchange(request: TokenExchange<'_>) -> Result<IssuedTokens, OAuthError> {
    match request.grant_type {
        "authorization_code" => authorization_code(request).await,
        "client_credentials" => client_credentials(request).await,
        "refresh_token" => refresh_token(request).await,
        "password" => password(request).await,
        other => Err(OAuthError::unsupported_grant_type(format!(
            "grant_type '{other}' is not supported"
        ))
        .with_hint(
            "Supported grant types: authorization_code, client_credentials, refresh_token, password",
        )),
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
    };
    issue.issue().await
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
                });
                Some(encode_jwt(self.keys, &claims).map_err(|error| {
                    OAuthError::new(super::error::ErrorCode::ServerError, error.to_string())
                })?)
            }
            _ => None,
        };

        let refresh_token = if refresh_allowed(self.client, &self.scopes) {
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
            grant.as_str()
        ))
        .with_hint(format!(
            "Add '{}' to this client's grant_types in keyfob.yaml",
            grant.as_str()
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
}
