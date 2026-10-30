//! End-to-end HTTP tests.
//!
//! Each test starts a real server on an ephemeral loopback port, drives it with
//! `reqwest` and asserts on the wire behaviour (status codes, headers and JSON
//! bodies). The RSA key is generated once and shared through a temporary file so
//! the suite stays fast.
//!
//! The tests are the executable form of the acceptance criteria in the design
//! guide: happy paths for every grant plus the errors that must not regress
//! (`invalid_grant`, `invalid_client`, redirect mismatches, PKCE failures, code
//! reuse, refresh rotation, revocation).

use std::path::PathBuf;
use std::sync::OnceLock;

use base64::Engine as _;
use serde_json::Value;

use keyfob_idp::config;
use keyfob_idp::crypto::{KeySet, s256_challenge};
use keyfob_idp::state::AppState;

// ------------------------------------------------------------------ configs

/// Full-featured server: automatic login, password grant and debugging enabled.
const FULL_CONFIG: &str = r#"
server:
  host: 127.0.0.1
  port: {PORT}
debug: true
allow_password_grant: true
allow_token_exchange: true
login:
  mode: auto
  default_user: alice
clients:
  - client_id: spa
    public: true
    redirect_uris: ["{ISSUER}/cb", "{ISSUER}/ui/callback"]
    allowed_scopes: [openid, profile, email, offline_access]
    grant_types: [authorization_code, refresh_token]
    claims:
      tenant: dev
  - client_id: backend
    client_secret: backend-secret
    grant_types: [client_credentials, refresh_token]
    allowed_scopes: [openid, profile]
    claims:
      app_grants:
        - resource-a:read
        - resource-b:read,write
  - client_id: legacy
    client_secret: legacy-secret
    redirect_uris: ["{ISSUER}/cb"]
    allowed_scopes: [openid, profile, email, offline_access]
    grant_types: [password, authorization_code, refresh_token]
  - client_id: exchanger
    client_secret: exchanger-secret
    grant_types: [token_exchange, client_credentials, refresh_token]
    allowed_scopes: [openid, profile, email, offline_access]
    audience: [backend]
users:
  - username: alice
    password: alice123
    email: alice@example.test
    name: Alice Example
    roles: [admin]
    groups: [devs]
  - username: bob
    password: bob123
"#;

/// Minimal server: interactive form login and the password grant disabled.
const FORM_CONFIG: &str = r#"
server:
  host: 127.0.0.1
  port: {PORT}
login:
  mode: form
clients:
  - client_id: spa
    public: true
    redirect_uris: ["{ISSUER}/cb"]
    allowed_scopes: [openid, profile, email, offline_access]
    grant_types: [authorization_code, refresh_token]
users:
  - username: alice
    password: alice123
    email: alice@example.test
    name: Alice Example
"#;

// ------------------------------------------------------------- test fixture

struct TestServer {
    base: String,
    client: reqwest::Client,
    /// Keeps the temporary configuration directory alive for the test.
    _dir: tempfile::TempDir,
}

impl TestServer {
    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    async fn get(&self, path: &str) -> reqwest::Response {
        self.client.get(self.url(path)).send().await.unwrap()
    }

    async fn post_form(&self, path: &str, fields: &[(&str, String)]) -> reqwest::Response {
        self.client
            .post(self.url(path))
            .form(fields)
            .send()
            .await
            .unwrap()
    }
}

/// One RSA key for the whole test binary; written to disk so every server
/// loads it (fast) instead of regenerating thousands of bits per test.
fn shared_key_path() -> PathBuf {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    PATH.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("keyfob-it-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("keys.json");
        KeySet::load_or_generate(&path, true, "RS256").unwrap();
        path
    })
    .clone()
}

async fn start_server(template: &str) -> TestServer {
    keyfob_idp::crypto::install_crypto_provider();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let issuer = format!("http://127.0.0.1:{port}");
    let yaml = template
        .replace("{PORT}", &port.to_string())
        .replace("{ISSUER}", &issuer);

    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("keyfob.yaml");
    std::fs::write(&config_path, &yaml).unwrap();
    let config = config::parse_str(&yaml, "keyfob.yaml").unwrap();

    let (keys, origin) = KeySet::load_or_generate(&shared_key_path(), false, "RS256").unwrap();
    let state = AppState::new(config_path, config, keys, origin);
    let router = keyfob_idp::http::router(state).await;

    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .cookie_store(true)
        .build()
        .unwrap();

    TestServer {
        base: issuer,
        client,
        _dir: dir,
    }
}

// ------------------------------------------------------------------ helpers

fn jwt_payload(token: &str) -> Value {
    let part = token.split('.').nth(1).expect("a JWT payload");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(part)
        .expect("base64url payload");
    serde_json::from_slice(&bytes).expect("JSON payload")
}

fn query_param(url: &str, key: &str) -> Option<String> {
    let url = reqwest::Url::parse(url).ok()?;
    url.query_pairs()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.into_owned())
}

fn location(response: &reqwest::Response) -> String {
    response
        .headers()
        .get(reqwest::header::LOCATION)
        .expect("a Location header")
        .to_str()
        .unwrap()
        .to_string()
}

/// Runs `/authorize` and returns the `Location` of the redirect.
async fn authorize(server: &TestServer, fields: &[(&str, String)]) -> String {
    let response = server
        .client
        .get(server.url("/authorize"))
        .query(fields)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 302, "expected a redirect");
    location(&response)
}

/// Full authorization-code round trip: `/authorize` then `/token`.
async fn obtain_code(server: &TestServer, verifier: &str, nonce: &str) -> String {
    let redirect_uri = server.url("/cb");
    let challenge = s256_challenge(verifier);
    let location = authorize(
        server,
        &[
            ("response_type", "code".into()),
            ("client_id", "spa".into()),
            ("redirect_uri", redirect_uri.clone()),
            ("scope", "openid profile email offline_access".into()),
            ("state", "st-123".into()),
            ("nonce", nonce.into()),
            ("code_challenge", challenge),
            ("code_challenge_method", "S256".into()),
        ],
    )
    .await;
    assert!(location.starts_with(&redirect_uri), "{location}");
    assert_eq!(query_param(&location, "state").as_deref(), Some("st-123"));
    query_param(&location, "code").expect("an authorization code")
}

const VERIFIER: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

/// A user access token for `alice` through the authorization code grant.
async fn spa_access_token(server: &TestServer) -> String {
    let code = obtain_code(server, VERIFIER, "n-1").await;
    let token = server
        .post_form(
            "/token",
            &[
                ("grant_type", "authorization_code".into()),
                ("client_id", "spa".into()),
                ("code", code),
                ("redirect_uri", server.url("/cb")),
                ("code_verifier", VERIFIER.into()),
            ],
        )
        .await
        .json::<Value>()
        .await
        .unwrap();
    token["access_token"].as_str().unwrap().to_string()
}

// ------------------------------------------------------------------- tests

#[tokio::test]
async fn metadata_and_health_are_served() {
    let server = start_server(FULL_CONFIG).await;

    let discovery = server.get("/.well-known/openid-configuration").await;
    assert_eq!(discovery.status(), 200);
    let discovery = discovery.json::<Value>().await.unwrap();
    assert_eq!(discovery["issuer"], server.base);
    assert_eq!(
        discovery["authorization_endpoint"],
        format!("{}/authorize", server.base)
    );
    assert_eq!(
        discovery["token_endpoint"],
        format!("{}/token", server.base)
    );
    assert_eq!(discovery["jwks_uri"], format!("{}/jwks", server.base));
    let grants = discovery["grant_types_supported"].as_array().unwrap();
    assert!(
        grants
            .iter()
            .any(|g| g == "urn:ietf:params:oauth:grant-type:token-exchange"),
        "token exchange should be advertised"
    );

    let oauth_metadata = server.get("/.well-known/oauth-authorization-server").await;
    assert_eq!(oauth_metadata.status(), 200);

    let health = server.get("/healthz").await;
    assert_eq!(health.status(), 200);
    let health = health.json::<Value>().await.unwrap();
    assert_eq!(health["status"], "ok");
}

#[tokio::test]
async fn jwks_exposes_the_active_rsa_key() {
    let server = start_server(FULL_CONFIG).await;
    let jwks = server.get("/jwks").await.json::<Value>().await.unwrap();
    let key = &jwks["keys"][0];
    assert_eq!(key["kty"], "RSA");
    assert_eq!(key["alg"], "RS256");
    assert_eq!(key["use"], "sig");
    assert!(key["kid"].as_str().is_some_and(|kid| !kid.is_empty()));
    assert_eq!(key["e"], "AQAB");

    // Keycloak-compatible alias.
    let alias = server.get("/protocol/openid-connect/certs").await;
    assert_eq!(alias.status(), 200);
}

#[tokio::test]
async fn client_credentials_grant_issues_an_access_token() {
    let server = start_server(FULL_CONFIG).await;
    let response = server
        .post_form(
            "/token",
            &[
                ("grant_type", "client_credentials".into()),
                ("client_id", "backend".into()),
                ("client_secret", "backend-secret".into()),
                ("scope", "openid profile".into()),
            ],
        )
        .await;
    assert_eq!(response.status(), 200);
    let token = response.json::<Value>().await.unwrap();
    assert_eq!(token["token_type"], "Bearer");
    assert!(token["access_token"].as_str().is_some());
    assert!(token["id_token"].is_null(), "no user, so no ID token");
    assert!(
        token["refresh_token"].is_string(),
        "refresh grant is allowed"
    );

    let claims = jwt_payload(token["access_token"].as_str().unwrap());
    assert_eq!(claims["iss"], server.base);
    assert_eq!(claims["sub"], "backend");
    assert_eq!(claims["client_id"], "backend");
    assert_eq!(
        claims["app_grants"],
        serde_json::json!(["resource-a:read", "resource-b:read,write"])
    );
}

#[tokio::test]
async fn client_credentials_rejects_a_wrong_secret() {
    let server = start_server(FULL_CONFIG).await;
    let response = server
        .post_form(
            "/token",
            &[
                ("grant_type", "client_credentials".into()),
                ("client_id", "backend".into()),
                ("client_secret", "wrong".into()),
            ],
        )
        .await;
    assert_eq!(response.status(), 401);
    let body = response.json::<Value>().await.unwrap();
    assert_eq!(body["error"], "invalid_client");
}

#[tokio::test]
async fn client_credentials_rejects_offline_access() {
    let server = start_server(FULL_CONFIG).await;
    let response = server
        .post_form(
            "/token",
            &[
                ("grant_type", "client_credentials".into()),
                ("client_id", "backend".into()),
                ("client_secret", "backend-secret".into()),
                ("scope", "offline_access".into()),
            ],
        )
        .await;
    assert_eq!(response.status(), 400);
    let body = response.json::<Value>().await.unwrap();
    assert_eq!(body["error"], "invalid_scope");
}

#[tokio::test]
async fn password_grant_issues_a_full_token_set() {
    let server = start_server(FULL_CONFIG).await;
    let response = server
        .post_form(
            "/token",
            &[
                ("grant_type", "password".into()),
                ("client_id", "legacy".into()),
                ("client_secret", "legacy-secret".into()),
                ("username", "alice".into()),
                ("password", "alice123".into()),
                ("scope", "openid profile email offline_access".into()),
            ],
        )
        .await;
    assert_eq!(response.status(), 200);
    let token = response.json::<Value>().await.unwrap();
    assert!(token["access_token"].is_string());
    assert!(token["refresh_token"].is_string());
    let id_token = token["id_token"].as_str().expect("an ID token");
    let claims = jwt_payload(id_token);
    assert_eq!(claims["sub"], "alice");
    assert_eq!(claims["email"], "alice@example.test");
    assert_eq!(claims["preferred_username"], "alice");
}

#[tokio::test]
async fn password_grant_rejects_a_wrong_password() {
    let server = start_server(FULL_CONFIG).await;
    let response = server
        .post_form(
            "/token",
            &[
                ("grant_type", "password".into()),
                ("client_id", "legacy".into()),
                ("client_secret", "legacy-secret".into()),
                ("username", "alice".into()),
                ("password", "nope".into()),
            ],
        )
        .await;
    assert_eq!(response.status(), 400);
    let body = response.json::<Value>().await.unwrap();
    assert_eq!(body["error"], "invalid_grant");
}

#[tokio::test]
async fn password_grant_is_disabled_by_default() {
    let server = start_server(FORM_CONFIG).await;
    let response = server
        .post_form(
            "/token",
            &[
                ("grant_type", "password".into()),
                ("client_id", "spa".into()),
                ("username", "alice".into()),
                ("password", "alice123".into()),
            ],
        )
        .await;
    assert_eq!(response.status(), 400);
    let body = response.json::<Value>().await.unwrap();
    assert_eq!(body["error"], "unsupported_grant_type");
}

#[tokio::test]
async fn unknown_grant_type_is_rejected() {
    let server = start_server(FULL_CONFIG).await;
    let response = server
        .post_form(
            "/token",
            &[
                (
                    "grant_type",
                    "urn:ietf:params:oauth:grant-type:device_code".into(),
                ),
                ("client_id", "backend".into()),
                ("client_secret", "backend-secret".into()),
            ],
        )
        .await;
    assert_eq!(response.status(), 400);
    let body = response.json::<Value>().await.unwrap();
    assert_eq!(body["error"], "unsupported_grant_type");
}

#[tokio::test]
async fn authorization_code_flow_with_pkce_succeeds() {
    let server = start_server(FULL_CONFIG).await;
    let code = obtain_code(&server, VERIFIER, "n-abc").await;

    let response = server
        .post_form(
            "/token",
            &[
                ("grant_type", "authorization_code".into()),
                ("client_id", "spa".into()),
                ("code", code),
                ("redirect_uri", server.url("/cb")),
                ("code_verifier", VERIFIER.into()),
            ],
        )
        .await;
    assert_eq!(response.status(), 200);
    let token = response.json::<Value>().await.unwrap();
    assert!(token["access_token"].is_string());
    assert!(
        token["refresh_token"].is_string(),
        "offline_access was granted"
    );

    let claims = jwt_payload(token["id_token"].as_str().unwrap());
    assert_eq!(claims["sub"], "alice");
    assert_eq!(claims["nonce"], "n-abc");
    assert!(
        claims["at_hash"].is_string(),
        "ID token must bind the access token"
    );
    assert_eq!(claims["aud"], "spa");
}

#[tokio::test]
async fn public_client_without_pkce_is_redirected_with_an_error() {
    let server = start_server(FULL_CONFIG).await;
    let location = authorize(
        &server,
        &[
            ("response_type", "code".into()),
            ("client_id", "spa".into()),
            ("redirect_uri", server.url("/cb")),
            ("scope", "openid".into()),
            ("state", "xyz".into()),
        ],
    )
    .await;
    assert!(location.starts_with(&server.url("/cb")), "{location}");
    assert_eq!(
        query_param(&location, "error").as_deref(),
        Some("invalid_request")
    );
    assert_eq!(query_param(&location, "state").as_deref(), Some("xyz"));
}

#[tokio::test]
async fn redirect_uri_mismatch_is_shown_as_an_error_page() {
    let server = start_server(FULL_CONFIG).await;
    let response = server
        .client
        .get(server.url("/authorize"))
        .query(&[
            ("response_type", "code"),
            ("client_id", "spa"),
            ("redirect_uri", "http://evil.test/cb"),
            ("scope", "openid"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    let body = response.text().await.unwrap();
    assert!(body.contains("not registered"), "{body}");
}

#[tokio::test]
async fn unknown_client_is_shown_as_an_error_page() {
    let server = start_server(FULL_CONFIG).await;
    let redirect_uri = server.url("/cb");
    let response = server
        .client
        .get(server.url("/authorize"))
        .query(&[
            ("response_type", "code"),
            ("client_id", "ghost"),
            ("redirect_uri", redirect_uri.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    let body = response.text().await.unwrap();
    assert!(body.contains("unknown client_id"), "{body}");
}

#[tokio::test]
async fn an_authorization_code_is_single_use() {
    let server = start_server(FULL_CONFIG).await;
    let code = obtain_code(&server, VERIFIER, "n-1").await;

    let first = server
        .post_form(
            "/token",
            &[
                ("grant_type", "authorization_code".into()),
                ("client_id", "spa".into()),
                ("code", code.clone()),
                ("redirect_uri", server.url("/cb")),
                ("code_verifier", VERIFIER.into()),
            ],
        )
        .await;
    assert_eq!(first.status(), 200);

    let second = server
        .post_form(
            "/token",
            &[
                ("grant_type", "authorization_code".into()),
                ("client_id", "spa".into()),
                ("code", code),
                ("redirect_uri", server.url("/cb")),
                ("code_verifier", VERIFIER.into()),
            ],
        )
        .await;
    assert_eq!(second.status(), 400);
    let body = second.json::<Value>().await.unwrap();
    assert_eq!(body["error"], "invalid_grant");
}

#[tokio::test]
async fn a_wrong_pkce_verifier_is_rejected() {
    let server = start_server(FULL_CONFIG).await;
    let code = obtain_code(&server, VERIFIER, "n-1").await;
    let response = server
        .post_form(
            "/token",
            &[
                ("grant_type", "authorization_code".into()),
                ("client_id", "spa".into()),
                ("code", code),
                ("redirect_uri", server.url("/cb")),
                (
                    "code_verifier",
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
                ),
            ],
        )
        .await;
    assert_eq!(response.status(), 400);
    let body = response.json::<Value>().await.unwrap();
    assert_eq!(body["error"], "invalid_grant");
}

#[tokio::test]
async fn refresh_tokens_rotate_and_replays_are_detected() {
    let server = start_server(FULL_CONFIG).await;
    let code = obtain_code(&server, VERIFIER, "n-1").await;
    let first = server
        .post_form(
            "/token",
            &[
                ("grant_type", "authorization_code".into()),
                ("client_id", "spa".into()),
                ("code", code),
                ("redirect_uri", server.url("/cb")),
                ("code_verifier", VERIFIER.into()),
            ],
        )
        .await
        .json::<Value>()
        .await
        .unwrap();
    let original = first["refresh_token"].as_str().unwrap().to_string();

    let refreshed = server
        .post_form(
            "/token",
            &[
                ("grant_type", "refresh_token".into()),
                ("client_id", "spa".into()),
                ("refresh_token", original.clone()),
            ],
        )
        .await;
    assert_eq!(refreshed.status(), 200);
    let refreshed = refreshed.json::<Value>().await.unwrap();
    let rotated = refreshed["refresh_token"].as_str().unwrap().to_string();
    assert_ne!(original, rotated, "the refresh token must rotate");

    // Replaying the consumed token revokes the whole family and fails.
    let replay = server
        .post_form(
            "/token",
            &[
                ("grant_type", "refresh_token".into()),
                ("client_id", "spa".into()),
                ("refresh_token", original),
            ],
        )
        .await;
    assert_eq!(replay.status(), 400);
    let replay = replay.json::<Value>().await.unwrap();
    assert_eq!(replay["error"], "invalid_grant");

    // The freshly rotated token was invalidated by the family revocation.
    let after = server
        .post_form(
            "/token",
            &[
                ("grant_type", "refresh_token".into()),
                ("client_id", "spa".into()),
                ("refresh_token", rotated),
            ],
        )
        .await;
    assert_eq!(after.status(), 400);
}

#[tokio::test]
async fn introspection_reflects_revocation() {
    let server = start_server(FULL_CONFIG).await;
    let token = server
        .post_form(
            "/token",
            &[
                ("grant_type", "client_credentials".into()),
                ("client_id", "backend".into()),
                ("client_secret", "backend-secret".into()),
            ],
        )
        .await
        .json::<Value>()
        .await
        .unwrap();
    let access_token = token["access_token"].as_str().unwrap().to_string();

    let active = server
        .post_form(
            "/introspect",
            &[
                ("client_id", "backend".into()),
                ("client_secret", "backend-secret".into()),
                ("token", access_token.clone()),
            ],
        )
        .await
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(active["active"], true);
    assert_eq!(active["client_id"], "backend");

    let revoked = server
        .post_form(
            "/revoke",
            &[
                ("client_id", "backend".into()),
                ("client_secret", "backend-secret".into()),
                ("token", access_token.clone()),
            ],
        )
        .await;
    assert_eq!(revoked.status(), 200);

    let inactive = server
        .post_form(
            "/introspect",
            &[
                ("client_id", "backend".into()),
                ("client_secret", "backend-secret".into()),
                ("token", access_token),
            ],
        )
        .await
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(inactive["active"], false);
}

#[tokio::test]
async fn userinfo_returns_the_granted_claims() {
    let server = start_server(FULL_CONFIG).await;
    let code = obtain_code(&server, VERIFIER, "n-1").await;
    let token = server
        .post_form(
            "/token",
            &[
                ("grant_type", "authorization_code".into()),
                ("client_id", "spa".into()),
                ("code", code),
                ("redirect_uri", server.url("/cb")),
                ("code_verifier", VERIFIER.into()),
            ],
        )
        .await
        .json::<Value>()
        .await
        .unwrap();
    let access_token = token["access_token"].as_str().unwrap();

    let response = server
        .client
        .get(server.url("/userinfo"))
        .bearer_auth(access_token)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let claims = response.json::<Value>().await.unwrap();
    assert_eq!(claims["sub"], "alice");
    assert_eq!(claims["preferred_username"], "alice");
    assert_eq!(claims["email"], "alice@example.test");
    assert_eq!(claims["tenant"], "dev");

    // An ID token is not an access token and must be rejected.
    let id_token = token["id_token"].as_str().unwrap();
    let rejected = server
        .client
        .get(server.url("/userinfo"))
        .bearer_auth(id_token)
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), 401);
}

#[tokio::test]
async fn token_exchange_impersonates_a_user() {
    let server = start_server(FULL_CONFIG).await;
    let subject = spa_access_token(&server).await;

    let response = server
        .post_form(
            "/token",
            &[
                (
                    "grant_type",
                    "urn:ietf:params:oauth:grant-type:token-exchange".into(),
                ),
                ("client_id", "exchanger".into()),
                ("client_secret", "exchanger-secret".into()),
                ("subject_token", subject),
                (
                    "subject_token_type",
                    "urn:ietf:params:oauth:token-type:access_token".into(),
                ),
            ],
        )
        .await;
    assert_eq!(response.status(), 200);
    let body = response.json::<Value>().await.unwrap();
    assert_eq!(
        body["issued_token_type"],
        "urn:ietf:params:oauth:token-type:access_token"
    );
    assert!(
        body["refresh_token"].is_null(),
        "no refresh token on exchange"
    );

    let claims = jwt_payload(body["access_token"].as_str().unwrap());
    assert_eq!(claims["sub"], "alice");
    assert_eq!(claims["client_id"], "exchanger");
    assert_eq!(claims["iss"], server.base);
    assert!(claims.get("act").is_none());
}

#[tokio::test]
async fn token_exchange_reports_delegation_in_the_act_claim() {
    let server = start_server(FULL_CONFIG).await;
    let subject = spa_access_token(&server).await;
    let actor = server
        .post_form(
            "/token",
            &[
                ("grant_type", "client_credentials".into()),
                ("client_id", "backend".into()),
                ("client_secret", "backend-secret".into()),
                ("scope", "openid".into()),
            ],
        )
        .await
        .json::<Value>()
        .await
        .unwrap()["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    let response = server
        .post_form(
            "/token",
            &[
                (
                    "grant_type",
                    "urn:ietf:params:oauth:grant-type:token-exchange".into(),
                ),
                ("client_id", "exchanger".into()),
                ("client_secret", "exchanger-secret".into()),
                ("subject_token", subject),
                (
                    "subject_token_type",
                    "urn:ietf:params:oauth:token-type:access_token".into(),
                ),
                ("actor_token", actor),
                (
                    "actor_token_type",
                    "urn:ietf:params:oauth:token-type:access_token".into(),
                ),
            ],
        )
        .await;
    assert_eq!(response.status(), 200);
    let body = response.json::<Value>().await.unwrap();
    let claims = jwt_payload(body["access_token"].as_str().unwrap());
    assert_eq!(claims["sub"], "alice");
    assert_eq!(claims["act"]["sub"], "backend");
    assert_eq!(claims["act"]["iss"], server.base);
}

#[tokio::test]
async fn token_exchange_rejects_an_unknown_subject_token() {
    let server = start_server(FULL_CONFIG).await;
    let response = server
        .post_form(
            "/token",
            &[
                (
                    "grant_type",
                    "urn:ietf:params:oauth:grant-type:token-exchange".into(),
                ),
                ("client_id", "exchanger".into()),
                ("client_secret", "exchanger-secret".into()),
                ("subject_token", "not-a-token".into()),
                (
                    "subject_token_type",
                    "urn:ietf:params:oauth:token-type:access_token".into(),
                ),
            ],
        )
        .await;
    assert_eq!(response.status(), 400);
    let body = response.json::<Value>().await.unwrap();
    assert_eq!(body["error"], "invalid_grant");
}

#[tokio::test]
async fn token_exchange_is_disabled_without_the_flag() {
    let server = start_server(FORM_CONFIG).await;
    let response = server
        .post_form(
            "/token",
            &[
                (
                    "grant_type",
                    "urn:ietf:params:oauth:grant-type:token-exchange".into(),
                ),
                ("client_id", "spa".into()),
                ("subject_token", "whatever".into()),
                (
                    "subject_token_type",
                    "urn:ietf:params:oauth:token-type:access_token".into(),
                ),
            ],
        )
        .await;
    assert_eq!(response.status(), 400);
    let body = response.json::<Value>().await.unwrap();
    assert_eq!(body["error"], "unsupported_grant_type");
}

#[tokio::test]
async fn form_login_establishes_a_session_for_authorization() {
    let server = start_server(FORM_CONFIG).await;
    let redirect_uri = server.url("/cb");

    // Without a session the authorization endpoint shows the login form.
    let challenge = s256_challenge(VERIFIER);
    let return_to = format!(
        "/authorize?response_type=code&client_id=spa&redirect_uri={}&scope=openid%20profile&state=s1&code_challenge={challenge}&code_challenge_method=S256",
        urlencode(&redirect_uri)
    );
    let page = server
        .client
        .get(server.url("/authorize"))
        .query(&[
            ("response_type", "code"),
            ("client_id", "spa"),
            ("redirect_uri", redirect_uri.as_str()),
            ("scope", "openid profile"),
            ("state", "s1"),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(page.status(), 200);
    let html = page.text().await.unwrap();
    assert!(html.contains("<form"), "{html}");
    assert!(html.contains("alice"), "{html}");

    // Submit the form; the session cookie is stored by the client.
    let login = server
        .post_form(
            "/login",
            &[
                ("username", "alice".into()),
                ("password", "alice123".into()),
                ("return_to", return_to),
                ("client_id", "spa".into()),
                ("scopes", "openid profile".into()),
            ],
        )
        .await;
    assert_eq!(login.status(), 302);
    let cookie = login
        .headers()
        .get(reqwest::header::SET_COOKIE)
        .expect("a session cookie")
        .to_str()
        .unwrap();
    assert!(cookie.starts_with("keyfob_session="), "{cookie}");

    // Retrying the authorization request now redirects with a code.
    let location = authorize(
        &server,
        &[
            ("response_type", "code".into()),
            ("client_id", "spa".into()),
            ("redirect_uri", redirect_uri.clone()),
            ("scope", "openid profile".into()),
            ("state", "s1".into()),
            ("code_challenge", challenge),
            ("code_challenge_method", "S256".into()),
        ],
    )
    .await;
    assert!(location.starts_with(&redirect_uri), "{location}");
    assert!(query_param(&location, "code").is_some());
}

#[tokio::test]
async fn login_rejects_bad_credentials() {
    let server = start_server(FORM_CONFIG).await;
    let response = server
        .post_form(
            "/login",
            &[
                ("username", "alice".into()),
                ("password", "wrong".into()),
                ("return_to", "/".into()),
            ],
        )
        .await;
    assert_eq!(response.status(), 200);
    let html = response.text().await.unwrap();
    assert!(html.contains("Invalid username or password"), "{html}");
}

#[tokio::test]
async fn home_page_and_ui_info_are_served() {
    let server = start_server(FULL_CONFIG).await;

    let home = server.get("/").await;
    assert_eq!(home.status(), 200);
    let html = home.text().await.unwrap();
    assert!(html.contains("Token generator"), "{html}");

    let info = server.get("/ui/info").await.json::<Value>().await.unwrap();
    assert_eq!(info["issuer"], server.base);
    assert_eq!(info["login_mode"], "auto");
    assert_eq!(info["allow_password_grant"], true);
    assert!(
        info["clients"]
            .as_array()
            .is_some_and(|clients| clients.iter().any(|c| c["client_id"] == "spa"))
    );
    assert!(
        info["users"]
            .as_array()
            .is_some_and(|users| users.iter().any(|u| u["username"] == "alice"))
    );
    // Secrets are never exposed unless explicitly enabled.
    assert!(info["prefill_secrets"] == false);
    assert!(
        info["clients"]
            .as_array()
            .unwrap()
            .iter()
            .all(|client| client["client_secret"].is_null())
    );
}

#[tokio::test]
async fn debug_endpoint_lists_recent_tokens() {
    let server = start_server(FULL_CONFIG).await;
    server
        .post_form(
            "/token",
            &[
                ("grant_type", "client_credentials".into()),
                ("client_id", "backend".into()),
                ("client_secret", "backend-secret".into()),
            ],
        )
        .await;
    let debug = server
        .get("/debug/tokens")
        .await
        .json::<Value>()
        .await
        .unwrap();
    assert!(debug["count"].as_u64().unwrap_or(0) >= 1);
    assert!(debug["tokens"].as_array().is_some_and(|t| !t.is_empty()));
}

#[tokio::test]
async fn unknown_routes_return_404() {
    let server = start_server(FULL_CONFIG).await;
    let response = server.get("/does-not-exist").await;
    assert_eq!(response.status(), 404);
}

fn urlencode(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char)
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}
