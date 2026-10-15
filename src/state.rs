//! Runtime state shared by the HTTP handlers.
//!
//! [`Runtime`] is the *resolved* configuration: clients (including the internal
//! `keyfob-ui` client), the issuer and the advertised capability lists. It is
//! swapped atomically when the YAML file is reloaded, so in-flight requests
//! always see a consistent snapshot.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use serde::Serialize;
use tokio::sync::RwLock;

use crate::config::{ClientCfg, Config, ConfigError, GrantType, UserCfg, warnings};
use crate::crypto::{KeyOrigin, KeySet};
use crate::store::Store;
use crate::ui::Templates;

/// Client id of the built-in public client used by the token generator UI.
pub const INTERNAL_UI_CLIENT_ID: &str = "keyfob-ui";

/// Standard scopes always advertised, in this order.
const STANDARD_SCOPES: [&str; 4] = ["openid", "profile", "email", "offline_access"];

/// Resolved configuration used at request time.
#[derive(Debug)]
pub struct Runtime {
    pub config: Config,
    pub issuer: String,
    /// Configured clients plus the internal UI client, in configuration order.
    pub clients: Vec<ClientCfg>,
    pub internal_clients: BTreeSet<String>,
    pub scopes_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    index: HashMap<String, usize>,
}

impl Runtime {
    /// Resolves the raw configuration: derives the issuer, registers the
    /// internal UI client and computes the advertised capabilities.
    pub fn build(config: Config) -> Self {
        let issuer = config.server.issuer();

        let mut clients = config.clients.clone();
        let mut internal_clients = BTreeSet::new();

        if config.ui.enabled && !clients.iter().any(|c| c.client_id == INTERNAL_UI_CLIENT_ID) {
            clients.push(internal_ui_client(&issuer));
            internal_clients.insert(INTERNAL_UI_CLIENT_ID.to_string());
        }

        let index = clients
            .iter()
            .enumerate()
            .map(|(position, client)| (client.client_id.clone(), position))
            .collect();

        let mut scopes_supported: Vec<String> =
            STANDARD_SCOPES.iter().map(|s| s.to_string()).collect();
        for client in &clients {
            for scope in client.scopes() {
                if !scopes_supported.contains(&scope) {
                    scopes_supported.push(scope);
                }
            }
        }

        let mut grant_types_supported: Vec<String> = Vec::new();
        for grant in [
            GrantType::AuthorizationCode,
            GrantType::ClientCredentials,
            GrantType::RefreshToken,
            GrantType::Password,
        ] {
            if clients.iter().any(|client| client.allows_grant(grant))
                && !grant_types_supported.iter().any(|g| g == grant.as_str())
            {
                grant_types_supported.push(grant.as_str().to_string());
            }
        }

        Self {
            config,
            issuer,
            clients,
            internal_clients,
            scopes_supported,
            grant_types_supported,
            index,
        }
    }

    pub fn client(&self, client_id: &str) -> Option<&ClientCfg> {
        self.index
            .get(client_id)
            .map(|position| &self.clients[*position])
    }

    pub fn is_internal_client(&self, client_id: &str) -> bool {
        self.internal_clients.contains(client_id)
    }

    pub fn user(&self, username: &str) -> Option<&UserCfg> {
        self.config
            .users
            .iter()
            .find(|user| user.username == username)
    }

    pub fn users(&self) -> &[UserCfg] {
        &self.config.users
    }

    /// User used by `login.mode: auto` and by `auto_approve` clients.
    pub fn default_login_user(&self) -> Option<&UserCfg> {
        match &self.config.login.default_user {
            Some(username) => self.user(username),
            None => self.config.users.first(),
        }
    }

    /// The `keyfob-ui` client, when the UI is enabled.
    pub fn internal_ui_client(&self) -> Option<&ClientCfg> {
        if self.config.ui.enabled {
            self.client(INTERNAL_UI_CLIENT_ID)
        } else {
            None
        }
    }
}

/// Public PKCE client backing the built-in token generator.
pub fn internal_ui_client(issuer: &str) -> ClientCfg {
    ClientCfg {
        client_id: INTERNAL_UI_CLIENT_ID.to_string(),
        client_secret: None,
        public: true,
        redirect_uris: vec![format!("{issuer}/ui/callback")],
        post_logout_redirect_uris: vec![issuer.to_string()],
        allowed_scopes: Some(STANDARD_SCOPES.iter().map(|s| s.to_string()).collect()),
        grant_types: Some(vec![GrantType::AuthorizationCode, GrantType::RefreshToken]),
        audience: Vec::new(),
        auto_approve: false,
    }
}

/// Outcome of the last configuration load; surfaced in `/ui/info`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ReloadStatus {
    /// Unix timestamp of the last successful load.
    pub loaded_at: Option<i64>,
    /// Unix timestamp of the last attempt (successful or not).
    pub last_attempt_at: Option<i64>,
    /// Error message of the last failed attempt, if any.
    pub last_error: Option<String>,
}

impl ReloadStatus {
    pub fn mark_success(&mut self, now: i64) {
        self.loaded_at = Some(now);
        self.last_attempt_at = Some(now);
        self.last_error = None;
    }

    pub fn mark_failure(&mut self, now: i64, error: String) {
        self.last_attempt_at = Some(now);
        self.last_error = Some(error);
    }
}

/// Everything the HTTP layer needs; cheap to clone.
#[derive(Clone)]
pub struct AppState {
    runtime: Arc<RwLock<Arc<Runtime>>>,
    pub keys: Arc<KeySet>,
    pub key_origin: KeyOrigin,
    pub store: Arc<Store>,
    pub started_at: Instant,
    pub started_wall: i64,
    pub config_path: PathBuf,
    pub reload: Arc<RwLock<ReloadStatus>>,
    templates: Arc<RwLock<Arc<Templates>>>,
}

impl AppState {
    pub fn new(config_path: PathBuf, config: Config, keys: KeySet, key_origin: KeyOrigin) -> Self {
        let templates = Templates::load(config.login.template_dir.as_deref());
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let mut reload = ReloadStatus::default();
        reload.mark_success(now);

        Self {
            runtime: Arc::new(RwLock::new(Arc::new(Runtime::build(config)))),
            keys: Arc::new(keys),
            key_origin,
            store: Arc::new(Store::new()),
            started_at: Instant::now(),
            started_wall: now,
            config_path,
            reload: Arc::new(RwLock::new(reload)),
            templates: Arc::new(RwLock::new(templates)),
        }
    }

    /// Current runtime snapshot.
    pub async fn runtime(&self) -> Arc<Runtime> {
        self.runtime.read().await.clone()
    }

    pub async fn templates(&self) -> Arc<Templates> {
        self.templates.read().await.clone()
    }

    pub async fn reload_status(&self) -> ReloadStatus {
        self.reload.read().await.clone()
    }

    pub async fn is_reload_failed(&self) -> bool {
        self.reload.read().await.last_error.is_some()
    }

    /// Reloads the YAML file. On failure the previous configuration is kept and
    /// the error is recorded (and returned) instead of aborting.
    pub async fn reload_config(&self) -> Result<(), ConfigError> {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        match crate::config::load(&self.config_path) {
            Ok(config) => {
                for warning in warnings(&config) {
                    tracing::warn!(warning = %warning, "configuration warning");
                }
                let templates = Templates::load(config.login.template_dir.as_deref());
                let runtime = Arc::new(Runtime::build(config));
                *self.runtime.write().await = runtime;
                *self.templates.write().await = templates;
                self.reload.write().await.mark_success(now);
                tracing::info!(
                    path = %self.config_path.display(),
                    "configuration reloaded"
                );
                Ok(())
            }
            Err(error) => {
                self.reload
                    .write()
                    .await
                    .mark_failure(now, error.to_string());
                tracing::error!(
                    path = %self.config_path.display(),
                    error = %error,
                    "configuration reload failed; keeping the previous configuration"
                );
                Err(error)
            }
        }
    }
}

/// Configuration warnings for the currently loaded file (shown in `/ui/info`).
pub async fn current_warnings(state: &AppState) -> Vec<String> {
    let runtime = state.runtime().await;
    warnings(&runtime.config)
}

/// Validates a config file without starting the server (`keyfob validate`).
pub fn validate_file(path: &Path) -> Result<Vec<String>, ConfigError> {
    let config = crate::config::load(path)?;
    Ok(warnings(&config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;

    fn config() -> Config {
        config::parse_str(
            r#"
clients:
  - client_id: my-spa
    public: true
    redirect_uris: [http://localhost:3000/cb]
  - client_id: my-backend
    client_secret: dev-secret
    grant_types: [client_credentials]
users:
  - username: alice
    password: alice123
"#,
            "test.yaml",
        )
        .unwrap()
    }

    #[test]
    fn internal_ui_client_is_registered() {
        let runtime = Runtime::build(config());
        let ui = runtime.internal_ui_client().expect("ui client");
        assert_eq!(ui.client_id, "keyfob-ui");
        assert!(ui.public);
        assert!(runtime.is_internal_client("keyfob-ui"));
        assert_eq!(
            ui.redirect_uris,
            vec![format!("{}/ui/callback", runtime.issuer)]
        );
        // Preserves configuration order and appends the internal client last.
        assert_eq!(runtime.clients[0].client_id, "my-spa");
        assert_eq!(runtime.clients.last().unwrap().client_id, "keyfob-ui");
    }

    #[test]
    fn capabilities_are_unions_of_client_settings() {
        let runtime = Runtime::build(config());
        assert!(runtime.scopes_supported.contains(&"openid".to_string()));
        assert_eq!(
            runtime.grant_types_supported,
            vec!["authorization_code", "client_credentials", "refresh_token"]
        );
    }

    #[test]
    fn default_login_user_prefers_the_configured_one() {
        let mut config = config();
        config.login.default_user = Some("alice".into());
        let runtime = Runtime::build(config);
        assert_eq!(runtime.default_login_user().unwrap().username, "alice");
    }
}
