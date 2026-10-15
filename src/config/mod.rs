//! Loading, validation and hot-reload support for `keyfob.yaml`.
//!
//! Precedence: CLI flags, then `KEYFOB_*` environment variables, then the YAML
//! file, then built-in defaults. Validation errors carry the field path (for
//! example `clients[0].redirect_uris`) so they are actionable.

pub mod duration;
mod example;
mod model;

pub use model::*;

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use thiserror::Error;

/// File names probed in the current directory when no config is given.
pub const CONFIG_FILE_NAMES: [&str; 2] = ["keyfob.yaml", "keyfob.yml"];

/// The minimal example written by `keyfob init`.
pub const EXAMPLE_CONFIG: &str = example::EXAMPLE;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error(
        "configuration file not found: {path}\n\
         Run `keyfob init` to create an example keyfob.yaml, or pass --config <path>"
    )]
    NotFound { path: String },

    #[error("cannot read configuration file {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("invalid configuration in {path}:\n  - {}", errors.join("\n  - "))]
    Validation { path: String, errors: Vec<String> },

    #[error("{path}{location}: {message}")]
    Parse {
        path: String,
        location: String,
        message: String,
    },

    #[error("invalid value of environment variable {var}: '{value}' ({hint})")]
    Env {
        var: &'static str,
        value: String,
        hint: String,
    },
}

/// Locates the configuration file to use.
///
/// Order: explicit path, `KEYFOB_CONFIG`, then `keyfob.yaml` / `keyfob.yml` in
/// the current directory.
pub fn find_config(explicit: Option<PathBuf>) -> Result<PathBuf, ConfigError> {
    if let Some(path) = explicit {
        return Ok(path);
    }
    if let Ok(path) = std::env::var("KEYFOB_CONFIG")
        && !path.trim().is_empty()
    {
        return Ok(PathBuf::from(path));
    }
    for name in CONFIG_FILE_NAMES {
        let candidate = Path::new(name);
        if candidate.is_file() {
            return Ok(candidate.to_path_buf());
        }
    }
    Err(ConfigError::NotFound {
        path: CONFIG_FILE_NAMES.join(" or ").to_string(),
    })
}

/// Loads and validates the configuration file at `path`.
pub fn load(path: &Path) -> Result<Config, ConfigError> {
    let content = std::fs::read_to_string(path).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            ConfigError::NotFound {
                path: path.display().to_string(),
            }
        } else {
            ConfigError::Read {
                path: path.display().to_string(),
                source,
            }
        }
    })?;
    parse_str(&content, &path.display().to_string())
}

/// Parses configuration content that is already in memory (used by `validate`
/// and by the tests).
pub fn parse_str(content: &str, origin: &str) -> Result<Config, ConfigError> {
    let deserializer = serde_yaml_ng::Deserializer::from_str(content);
    let mut config: Config = serde_path_to_error::deserialize(deserializer).map_err(|err| {
        let path = err.path().to_string();
        let location = if path.is_empty() || path == "." {
            String::new()
        } else {
            format!(" ({path})")
        };
        ConfigError::Parse {
            path: origin.to_string(),
            location,
            message: err.into_inner().to_string(),
        }
    })?;

    apply_env(&mut config)?;

    let errors = validate(&config);
    if errors.is_empty() {
        Ok(config)
    } else {
        Err(ConfigError::Validation {
            path: origin.to_string(),
            errors,
        })
    }
}

/// Applies `KEYFOB_*` environment variable overrides on top of the YAML value.
fn apply_env(config: &mut Config) -> Result<(), ConfigError> {
    fn var(name: &'static str) -> Option<String> {
        std::env::var(name)
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    }

    fn parse_bool(var_name: &'static str, value: &str) -> Result<bool, ConfigError> {
        match value.to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" | "on" => Ok(true),
            "false" | "0" | "no" | "off" => Ok(false),
            other => Err(ConfigError::Env {
                var: var_name,
                value: other.to_string(),
                hint: "expected true or false".to_string(),
            }),
        }
    }

    if let Some(value) = var("KEYFOB_HOST") {
        config.server.host = value;
    }
    if let Some(value) = var("KEYFOB_PORT") {
        config.server.port = value.parse().map_err(|_| ConfigError::Env {
            var: "KEYFOB_PORT",
            value: value.clone(),
            hint: "expected an integer between 1 and 65535".to_string(),
        })?;
    }
    if let Some(value) = var("KEYFOB_ISSUER") {
        config.server.issuer = Some(value);
    }
    if let Some(value) = var("KEYFOB_TLS") {
        config.server.tls = parse_bool("KEYFOB_TLS", &value)?;
    }
    if let Some(value) = var("KEYFOB_DEBUG") {
        config.debug = parse_bool("KEYFOB_DEBUG", &value)?;
    }
    if let Some(value) = var("KEYFOB_ALLOW_PASSWORD_GRANT") {
        config.allow_password_grant = parse_bool("KEYFOB_ALLOW_PASSWORD_GRANT", &value)?;
    }
    if let Some(value) = var("KEYFOB_LOGIN_MODE") {
        config.login.mode = match value.to_ascii_lowercase().as_str() {
            "form" => LoginMode::Form,
            "picker" => LoginMode::Picker,
            "auto" => LoginMode::Auto,
            other => {
                return Err(ConfigError::Env {
                    var: "KEYFOB_LOGIN_MODE",
                    value: other.to_string(),
                    hint: "expected form, picker or auto".to_string(),
                });
            }
        };
    }
    Ok(())
}

/// Validates the configuration and returns every problem found, each prefixed
/// with the path of the offending field.
pub fn validate(config: &Config) -> Vec<String> {
    let mut errors = Vec::new();
    validate_server(config, &mut errors);
    validate_keys(config, &mut errors);
    validate_tokens(config, &mut errors);
    validate_cors(config, &mut errors);
    validate_clients(config, &mut errors);
    validate_users(config, &mut errors);
    validate_login(config, &mut errors);
    errors
}

fn validate_server(config: &Config, errors: &mut Vec<String>) {
    if config.server.host.trim().is_empty() {
        errors.push("server.host: must not be empty".to_string());
    }
    if config.server.port == 0 {
        errors.push("server.port: must be between 1 and 65535; use 0 only in tests".to_string());
    }
    let issuer = config.server.issuer();
    if !issuer.starts_with("http://") && !issuer.starts_with("https://") {
        errors.push(format!(
            "server.issuer: must be an absolute http(s) URL starting with http:// or https:// (got '{issuer}')"
        ));
    }
    if issuer.contains(char::is_whitespace) {
        errors.push(format!(
            "server.issuer: must not contain whitespace (got '{issuer}')"
        ));
    }
}

fn validate_keys(config: &Config, errors: &mut Vec<String>) {
    if !config.keys.algorithm.eq_ignore_ascii_case("rs256") {
        errors.push(format!(
            "keys.algorithm: '{}' is not supported; use RS256 \
             (ES256 and EdDSA are planned for a later release)",
            config.keys.algorithm
        ));
    }
}

fn validate_tokens(config: &Config, errors: &mut Vec<String>) {
    for (field, ttl) in [
        ("tokens.access_ttl", config.tokens.access_ttl),
        ("tokens.refresh_ttl", config.tokens.refresh_ttl),
        ("tokens.id_ttl", config.tokens.id_ttl),
    ] {
        if ttl.is_zero() {
            errors.push(format!("{field}: must be greater than zero (e.g. 15m, 8h)"));
        }
    }
    if config.tokens.refresh_ttl < config.tokens.access_ttl {
        errors.push(format!(
            "tokens.refresh_ttl ({}) must be greater than or equal to tokens.access_ttl ({})",
            humantime(&config.tokens.refresh_ttl),
            humantime(&config.tokens.access_ttl)
        ));
    }
}

fn validate_cors(config: &Config, errors: &mut Vec<String>) {
    if config.cors.enabled && config.cors.origins.is_empty() {
        errors.push(
            "cors.origins: must not be empty when cors.enabled is true (use [\"*\"] for any origin)"
                .to_string(),
        );
    }
}

fn validate_clients(config: &Config, errors: &mut Vec<String>) {
    if config.clients.is_empty() {
        errors.push(
            "clients: at least one client is required \
             (run `keyfob init` to generate an example configuration)"
                .to_string(),
        );
    }

    let mut seen_ids: HashSet<&str> = HashSet::new();
    for (index, client) in config.clients.iter().enumerate() {
        let id = client.client_id.trim();
        if id.is_empty() {
            errors.push(format!("clients[{index}].client_id: must not be empty"));
        } else if !seen_ids.insert(id) {
            errors.push(format!(
                "clients[{index}].client_id: duplicate client_id '{id}'"
            ));
        }

        if client.public && client.client_secret.is_some() {
            errors.push(format!(
                "clients[{index}]: a public client cannot have a client_secret \
                 (remove the secret, or remove `public: true`)"
            ));
        }
        if !client.public && client.client_secret.is_none() {
            errors.push(format!(
                "clients[{index}].client_secret: required for confidential clients \
                 (or set `public: true` for a PKCE-only client)"
            ));
        }

        if let Some(scopes) = &client.allowed_scopes {
            if scopes.is_empty() {
                errors.push(format!(
                    "clients[{index}].allowed_scopes: must not be empty; \
                     remove the key to use the default scopes"
                ));
            }
            for (position, scope) in scopes.iter().enumerate() {
                if scope.trim().is_empty() {
                    errors.push(format!(
                        "clients[{index}].allowed_scopes[{position}]: must not be empty"
                    ));
                }
            }
        }

        for grant in client.grants() {
            match grant {
                GrantType::AuthorizationCode if client.redirect_uris.is_empty() => {
                    errors.push(format!(
                        "clients[{index}].redirect_uris: at least one redirect URI is required \
                         for the authorization_code grant"
                    ));
                }
                GrantType::ClientCredentials if client.public => {
                    errors.push(format!(
                        "clients[{index}]: the client_credentials grant requires a confidential \
                         client (remove `public: true`)"
                    ));
                }
                GrantType::Password if !config.allow_password_grant => {
                    errors.push(format!(
                        "clients[{index}].grant_types: the password grant requires \
                         `allow_password_grant: true` at the top level"
                    ));
                }
                _ => {}
            }
        }

        for (field, uris) in [
            ("redirect_uris", &client.redirect_uris),
            (
                "post_logout_redirect_uris",
                &client.post_logout_redirect_uris,
            ),
        ] {
            for (position, uri) in uris.iter().enumerate() {
                if !is_plausible_uri(uri) {
                    errors.push(format!(
                        "clients[{index}].{field}[{position}]: '{uri}' is not a valid absolute URI \
                         (expected e.g. http://localhost:3000/callback or com.example.app:/callback)"
                    ));
                }
            }
        }
    }
}

fn validate_users(config: &Config, errors: &mut Vec<String>) {
    let needs_users = config.allow_password_grant
        || config
            .clients
            .iter()
            .any(|client| client.allows_grant(GrantType::AuthorizationCode));

    if config.users.is_empty() {
        if needs_users {
            errors.push(
                "users: at least one user is required by the enabled flows \
                 (authorization_code login or the password grant); add a user \
                 under `users:` or disable those flows"
                    .to_string(),
            );
        }
        return;
    }

    let mut seen: HashSet<&str> = HashSet::new();
    for (index, user) in config.users.iter().enumerate() {
        let username = user.username.trim();
        if username.is_empty() {
            errors.push(format!("users[{index}].username: must not be empty"));
        } else if !seen.insert(username) {
            errors.push(format!(
                "users[{index}].username: duplicate username '{username}'"
            ));
        }
        if user.password.is_empty() {
            errors.push(format!(
                "users[{index}].password: must not be empty \
                 (plaintext is fine for development, or an argon2 hash starting with $argon2)"
            ));
        }
    }

    if let Some(default_user) = &config.login.default_user
        && !config.users.iter().any(|u| u.username == *default_user)
    {
        let known = config
            .users
            .iter()
            .map(|u| u.username.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        errors.push(format!(
            "login.default_user: unknown user '{default_user}'; configured users: {known}"
        ));
    }
}

fn validate_login(config: &Config, errors: &mut Vec<String>) {
    if let Some(dir) = &config.login.template_dir
        && !dir.is_dir()
    {
        errors.push(format!(
            "login.template_dir: directory not found: {} \
             (create it with login.html / error.html, or remove the setting)",
            dir.display()
        ));
    }
}

/// Non-fatal configuration issues surfaced at startup and in `/ui/info`.
pub fn warnings(config: &Config) -> Vec<String> {
    let mut warnings = Vec::new();

    if !config.server.is_loopback() {
        warnings.push(format!(
            "server.host: listening on {} — keyfob-idp is a development tool and must not \
             be exposed",
            config.server.host
        ));
    }

    let plaintext = config
        .users
        .iter()
        .filter(|user| !user.is_password_hash())
        .count();
    if plaintext > 0 {
        warnings.push(format!(
            "{plaintext} user password(s) are stored in plaintext in the configuration; \
             acceptable for development — use `keyfob hash-password` for argon2 hashes"
        ));
    }

    if config.ui.prefill_secrets {
        warnings.push(
            "ui.prefill_secrets: enabled — client secrets are pre-filled in the browser \
             (development only)"
                .to_string(),
        );
    }

    if config.debug {
        warnings
            .push("debug: enabled — GET /debug/tokens exposes recently issued tokens".to_string());
    }

    if config.allow_password_grant {
        warnings.push(
            "allow_password_grant: enabled — the deprecated resource owner password grant is \
             active"
                .to_string(),
        );
    }

    if config.cors.enabled && config.cors.origins.iter().any(|o| o == "*") {
        warnings.push("cors: enabled with origins: [\"*\"]".to_string());
    }

    if config.login.mode == LoginMode::Picker {
        warnings.push(
            "login.mode: picker — configured users can sign in with one click and no password"
                .to_string(),
        );
    }

    warnings
}

/// Light check that a redirect URI is an absolute URI (no full RFC 3986 parse;
/// exact string matching is enforced later at the authorize endpoint).
fn is_plausible_uri(uri: &str) -> bool {
    if uri.is_empty() || uri.contains(char::is_whitespace) {
        return false;
    }
    let Some((scheme, _rest)) = uri.split_once(':') else {
        return false;
    };
    let mut chars = scheme.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_alphabetic()
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

fn humantime(ttl: &std::time::Duration) -> String {
    let secs = ttl.as_secs();
    if secs.is_multiple_of(86_400) && secs >= 86_400 {
        format!("{}d", secs / 86_400)
    } else if secs.is_multiple_of(3_600) && secs >= 3_600 {
        format!("{}h", secs / 3_600)
    } else if secs.is_multiple_of(60) && secs >= 60 {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
server:
  port: 9000
clients:
  - client_id: my-backend
    client_secret: dev-secret
    grant_types: [client_credentials, refresh_token]
users:
  - username: alice
    password: alice123
"#;

    #[test]
    fn minimal_config_parses() {
        let config = parse_str(MINIMAL, "test.yaml").unwrap();
        assert_eq!(config.server.port, 9000);
        assert_eq!(config.clients.len(), 1);
        assert_eq!(config.tokens.access_ttl.as_secs(), 900);
        assert_eq!(config.keys.algorithm, "RS256");
    }

    #[test]
    fn defaults_apply_to_missing_sections() {
        let config = parse_str(
            "clients:\n  - client_id: api\n    client_secret: s",
            "test.yaml",
        )
        .unwrap();
        assert_eq!(config.server.host, "127.0.0.1");
        assert!(config.ui.enabled);
        assert_eq!(config.login.mode, LoginMode::Form);
    }

    #[test]
    fn error_includes_field_path() {
        let yaml = "clients:\n  - client_id: x\n    redirect_uris: not-a-list\nusers: []";
        let err = parse_str(yaml, "test.yaml").unwrap_err();
        let text = err.to_string();
        assert!(text.contains("clients[0].redirect_uris"), "got: {text}");
    }

    #[test]
    fn unknown_field_is_rejected_with_location() {
        let yaml = "server:\n  prot: 9000\n";
        let err = parse_str(yaml, "test.yaml").unwrap_err();
        let text = err.to_string();
        assert!(text.contains("prot"), "got: {text}");
    }

    #[test]
    fn missing_clients_is_an_error() {
        let err = parse_str("users: []", "test.yaml").unwrap_err();
        assert!(err.to_string().contains("clients: at least one client"));
    }

    #[test]
    fn users_required_only_for_flows_that_need_them() {
        // Client credentials only: no users needed.
        parse_str(
            "clients:\n  - client_id: api\n    client_secret: s\n    grant_types: [client_credentials]",
            "test.yaml",
        )
        .unwrap();

        // Authorization code without users: error.
        let err = parse_str(
            "clients:\n  - client_id: spa\n    public: true\n    redirect_uris: [http://localhost/cb]",
            "test.yaml",
        )
        .unwrap_err();
        assert!(err.to_string().contains("users: at least one user"));
    }

    #[test]
    fn public_client_cannot_have_secret() {
        let err = parse_str(
            "clients:\n  - client_id: spa\n    public: true\n    client_secret: nope\n    redirect_uris: [http://localhost/cb]\nusers:\n  - username: a\n    password: b",
            "test.yaml",
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("public client cannot have a client_secret")
        );
    }

    #[test]
    fn duplicate_ids_are_reported_with_index() {
        let err = parse_str(
            "clients:\n  - client_id: dup\n    client_secret: a\n  - client_id: dup\n    client_secret: b\nusers:\n  - username: a\n    password: b",
            "test.yaml",
        )
        .unwrap_err();
        assert!(err.to_string().contains("clients[1].client_id: duplicate"));
    }

    #[test]
    fn invalid_duration_reports_field() {
        let err = parse_str(
            "tokens:\n  access_ttl: 15x\nclients: []\nusers: []",
            "test.yaml",
        )
        .unwrap_err();
        assert!(err.to_string().contains("access_ttl"), "{err}");
    }

    #[test]
    fn invalid_redirect_uri_is_rejected() {
        let err = parse_str(
            "clients:\n  - client_id: spa\n    public: true\n    redirect_uris: ['not a uri']\nusers:\n  - username: a\n    password: b",
            "test.yaml",
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("clients[0].redirect_uris[0]: 'not a uri' is not a valid"),
            "{err}"
        );
    }

    #[test]
    fn password_grant_requires_global_flag() {
        let err = parse_str(
            "clients:\n  - client_id: cli\n    client_secret: s\n    grant_types: [password]\nusers:\n  - username: a\n    password: b",
            "test.yaml",
        )
        .unwrap_err();
        assert!(err.to_string().contains("allow_password_grant: true"));
    }

    #[test]
    fn warnings_mention_plaintext_passwords_and_debug() {
        let config = parse_str(
            "debug: true\nclients:\n  - client_id: api\n    client_secret: s\nusers:\n  - username: a\n    password: b",
            "test.yaml",
        )
        .unwrap();
        let warnings = warnings(&config);
        assert!(warnings.iter().any(|w| w.contains("plaintext")));
        assert!(warnings.iter().any(|w| w.contains("/debug/tokens")));
    }

    #[test]
    fn shipped_examples_are_valid() {
        for name in ["keyfob.minimal.yaml", "keyfob.full.yaml"] {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("examples")
                .join(name);
            load(&path).unwrap_or_else(|err| panic!("examples/{name} must load: {err}"));
        }
    }

    #[test]
    fn init_example_is_valid() {
        parse_str(EXAMPLE_CONFIG, "keyfob init").unwrap();
    }

    #[test]
    fn plausible_uris() {
        assert!(is_plausible_uri("http://localhost:3000/cb"));
        assert!(is_plausible_uri("https://app.test/oauth/cb"));
        assert!(is_plausible_uri("com.example.app:/callback"));
        assert!(is_plausible_uri("myapp://callback"));
        assert!(!is_plausible_uri("no-scheme"));
        assert!(!is_plausible_uri(""));
        assert!(!is_plausible_uri("http://has space"));
        assert!(!is_plausible_uri("1bad://x"));
    }
}
