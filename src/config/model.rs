//! Serde models for `keyfob.yaml`.
//!
//! Every section has sensible defaults; only `clients` and (depending on the
//! enabled flows) `users` are mandatory. Unknown fields are rejected so typos
//! produce an immediate, located error instead of being silently ignored.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use super::duration::de_duration;

fn default_host() -> String {
    "127.0.0.1".to_string()
}

fn default_port() -> u16 {
    9000
}

fn default_true() -> bool {
    true
}

fn default_access_ttl() -> Duration {
    Duration::from_secs(15 * 60)
}

fn default_refresh_ttl() -> Duration {
    Duration::from_secs(8 * 60 * 60)
}

fn default_id_ttl() -> Duration {
    Duration::from_secs(15 * 60)
}

fn default_key_path() -> PathBuf {
    PathBuf::from(".keyfob").join("keys.json")
}

pub(crate) fn default_allowed_scopes() -> Vec<String> {
    ["openid", "profile", "email", "offline_access"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

fn default_origins() -> Vec<String> {
    vec!["*".to_string()]
}

/// Root of the configuration file.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub server: ServerCfg,
    #[serde(default)]
    pub keys: KeysCfg,
    #[serde(default)]
    pub tokens: TokensCfg,
    #[serde(default)]
    pub ui: UiCfg,
    #[serde(default)]
    pub login: LoginCfg,
    #[serde(default)]
    pub cors: CorsCfg,
    /// Expose `GET /debug/tokens` with the recently issued tokens.
    #[serde(default)]
    pub debug: bool,
    /// Enables the deprecated Resource Owner Password Credentials grant.
    #[serde(default)]
    pub allow_password_grant: bool,
    /// Enables the Token Exchange grant (RFC 8693).
    #[serde(default)]
    pub allow_token_exchange: bool,
    #[serde(default)]
    pub clients: Vec<ClientCfg>,
    #[serde(default)]
    pub users: Vec<UserCfg>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerCfg {
    /// Interface to bind. Defaults to loopback; anything else logs a warning.
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    /// Issuer identifier. Deduced from `host` and `port` when omitted.
    pub issuer: Option<String>,
    /// Serve HTTPS with an automatically generated self-signed certificate.
    #[serde(default)]
    pub tls: bool,
}

impl Default for ServerCfg {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
            issuer: None,
            tls: false,
        }
    }
}

impl ServerCfg {
    /// The issuer identifier used in discovery, tokens and cookies.
    ///
    /// When not set explicitly it is derived from the bind address and port.
    /// Wildcard addresses (`0.0.0.0`, `::`) become `localhost` because they are
    /// not valid issuer identifiers.
    pub fn issuer(&self) -> String {
        if let Some(issuer) = &self.issuer {
            return issuer.trim_end_matches('/').to_string();
        }
        let host = match self.host.as_str() {
            "0.0.0.0" | "::" | "[::]" => "localhost",
            other => other,
        };
        // Bracket bare IPv6 literals so the URL stays parseable.
        let host = if host.contains(':') && !host.starts_with('[') {
            format!("[{host}]")
        } else {
            host.to_string()
        };
        let scheme = if self.tls { "https" } else { "http" };
        format!("{scheme}://{host}:{}", self.port)
    }

    /// True when the server listens on a loopback address.
    pub fn is_loopback(&self) -> bool {
        matches!(
            self.host.as_str(),
            "127.0.0.1" | "localhost" | "::1" | "[::1]"
        ) || self.host.starts_with("127.")
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysCfg {
    /// Signature algorithm. Only `RS256` is supported in this version.
    #[serde(default = "rs256")]
    pub algorithm: String,
    /// Persist the generated key under `path` so restarts keep tokens valid.
    #[serde(default = "default_true")]
    pub persist: bool,
    /// Where the persisted key lives (JSON).
    #[serde(default = "default_key_path")]
    pub path: PathBuf,
}

fn rs256() -> String {
    "RS256".to_string()
}

impl Default for KeysCfg {
    fn default() -> Self {
        Self {
            algorithm: rs256(),
            persist: true,
            path: default_key_path(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokensCfg {
    #[serde(default = "default_access_ttl", deserialize_with = "de_duration")]
    pub access_ttl: Duration,
    #[serde(default = "default_refresh_ttl", deserialize_with = "de_duration")]
    pub refresh_ttl: Duration,
    #[serde(default = "default_id_ttl", deserialize_with = "de_duration")]
    pub id_ttl: Duration,
    /// Issue a new refresh token on every refresh (recommended).
    #[serde(default = "default_true")]
    pub rotate_refresh: bool,
}

impl Default for TokensCfg {
    fn default() -> Self {
        Self {
            access_ttl: default_access_ttl(),
            refresh_ttl: default_refresh_ttl(),
            id_ttl: default_id_ttl(),
            rotate_refresh: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UiCfg {
    /// Home page and token generator at `/`.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Dev-only: prefill confidential client secrets in the token generator.
    #[serde(default)]
    pub prefill_secrets: bool,
}

impl Default for UiCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            prefill_secrets: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LoginMode {
    /// Username and password form.
    #[default]
    Form,
    /// One-click user picker without typing a password.
    Picker,
    /// No login screen: authenticate as `default_user` (or the first user).
    Auto,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginCfg {
    #[serde(default)]
    pub mode: LoginMode,
    /// Directory with custom `login.html` / `error.html` templates.
    pub template_dir: Option<PathBuf>,
    /// User authenticated by `login.mode: auto` (defaults to the first user).
    pub default_user: Option<String>,
}

impl Default for LoginCfg {
    fn default() -> Self {
        Self {
            mode: LoginMode::Form,
            template_dir: None,
            default_user: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorsCfg {
    /// Send permissive CORS headers (needed by browser SPAs on another origin).
    #[serde(default)]
    pub enabled: bool,
    /// Allowed origins. `["*"]` allows any origin unless credentials are used.
    #[serde(default = "default_origins")]
    pub origins: Vec<String>,
    /// Allow cookies/credentials (forces explicit origins; `*` is reflected).
    #[serde(default)]
    pub allow_credentials: bool,
}

impl Default for CorsCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            origins: default_origins(),
            allow_credentials: false,
        }
    }
}

/// OAuth 2.0 grant types supported by a client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantType {
    AuthorizationCode,
    ClientCredentials,
    RefreshToken,
    Password,
    TokenExchange,
}

impl GrantType {
    /// The value sent as `grant_type` on the token endpoint.
    ///
    /// It matches the YAML name for the standard grants; Token Exchange uses
    /// the URN mandated by RFC 8693.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AuthorizationCode => "authorization_code",
            Self::ClientCredentials => "client_credentials",
            Self::RefreshToken => "refresh_token",
            Self::Password => "password",
            Self::TokenExchange => "urn:ietf:params:oauth:grant-type:token-exchange",
        }
    }

    /// The name used in `keyfob.yaml` (`grant_types`) and in user-facing hints.
    pub fn config_name(self) -> &'static str {
        match self {
            Self::AuthorizationCode => "authorization_code",
            Self::ClientCredentials => "client_credentials",
            Self::RefreshToken => "refresh_token",
            Self::Password => "password",
            Self::TokenExchange => "token_exchange",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientCfg {
    pub client_id: String,
    /// Plaintext secret (development) or omitted for public clients.
    pub client_secret: Option<String>,
    /// Public client: no secret, PKCE is always required.
    #[serde(default)]
    pub public: bool,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub post_logout_redirect_uris: Vec<String>,
    /// Scopes this client may request. Defaults to `openid profile email offline_access`.
    pub allowed_scopes: Option<Vec<String>>,
    /// Grants this client may use. Defaults based on secret/redirect URIs.
    pub grant_types: Option<Vec<GrantType>>,
    /// Values used for the `aud` claim of issued access tokens.
    #[serde(default)]
    pub audience: Vec<String>,
    /// Skip the login screen for this client (uses `login.default_user`).
    #[serde(default)]
    pub auto_approve: bool,
}

impl ClientCfg {
    /// Effective allowed scopes, applying the default when not configured.
    pub fn scopes(&self) -> Vec<String> {
        self.allowed_scopes
            .clone()
            .unwrap_or_else(default_allowed_scopes)
    }

    /// Effective grants, inferred from the client shape when not configured.
    pub fn grants(&self) -> Vec<GrantType> {
        if let Some(grants) = &self.grant_types {
            return grants.clone();
        }
        let mut grants = Vec::new();
        if !self.redirect_uris.is_empty() {
            grants.push(GrantType::AuthorizationCode);
        }
        if self.is_confidential() {
            grants.push(GrantType::ClientCredentials);
        }
        if !self.redirect_uris.is_empty() || self.is_confidential() {
            grants.push(GrantType::RefreshToken);
        }
        grants
    }

    pub fn allows_scope(&self, scope: &str) -> bool {
        self.scopes().iter().any(|s| s == scope)
    }

    pub fn allows_grant(&self, grant: GrantType) -> bool {
        self.grants().contains(&grant)
    }

    pub fn is_confidential(&self) -> bool {
        !self.public && self.client_secret.is_some()
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserCfg {
    pub username: String,
    /// Plaintext password (development) or an argon2 PHC hash (`$argon2...`).
    pub password: String,
    pub email: Option<String>,
    pub name: Option<String>,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    /// Extra claims merged into the ID token. String values are rendered as
    /// minijinja templates with the user as context, e.g. `{{username}}@test`.
    #[serde(default)]
    pub claims: BTreeMap<String, serde_json::Value>,
}

impl UserCfg {
    pub fn is_password_hash(&self) -> bool {
        self.password.starts_with("$argon2")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issuer_deduced_from_host_and_port() {
        let cfg = ServerCfg::default();
        assert_eq!(cfg.issuer(), "http://127.0.0.1:9000");
    }

    #[test]
    fn wildcard_bind_uses_localhost_as_issuer() {
        let cfg = ServerCfg {
            host: "0.0.0.0".into(),
            ..ServerCfg::default()
        };
        assert_eq!(cfg.issuer(), "http://localhost:9000");
        assert!(!cfg.is_loopback());
    }

    #[test]
    fn explicit_issuer_is_normalized() {
        let cfg = ServerCfg {
            issuer: Some("https://idp.test/".into()),
            ..ServerCfg::default()
        };
        assert_eq!(cfg.issuer(), "https://idp.test");
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let err = serde_yaml_ng::from_str::<Config>("servere:\n  port: 1").unwrap_err();
        assert!(err.to_string().contains("servere"), "{err}");
    }
}
