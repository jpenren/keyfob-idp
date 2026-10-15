//! Command line interface: `keyfob run`, `validate`, `init`, `hash-password`,
//! `gen-keys` and `token`.
//!
//! Option precedence is CLI flags, then `KEYFOB_*` environment variables, then
//! the YAML file, then built-in defaults. Environment variables are applied by
//! the configuration loader; the CLI flags are applied on top here.

use std::io::Write as _;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};
use thiserror::Error;

use crate::config::{self, Config};
use crate::crypto::keys::KeyError;
use crate::crypto::{DEFAULT_KEY_BITS, KeySet, constant_time_eq, hash_password};
use crate::oauth::{ErrorCode, OAuthError};
use crate::state::{AppState, INTERNAL_UI_CLIENT_ID};
use crate::store::Store;

/// Errors surfaced by the CLI.
#[derive(Debug, Error)]
pub enum CliError {
    #[error(transparent)]
    Config(#[from] config::ConfigError),

    #[error(transparent)]
    Keys(#[from] KeyError),

    #[error(transparent)]
    OAuth(#[from] OAuthError),

    #[error(transparent)]
    Password(#[from] crate::crypto::password::PasswordError),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Message(String),
}

impl CliError {
    fn message(message: impl Into<String>) -> Self {
        Self::Message(message.into())
    }
}

/// Log output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LogFormat {
    Text,
    Json,
}

/// A local OAuth 2.0 / OpenID Connect provider for development.
#[derive(Debug, Parser)]
#[command(name = "keyfob", version, about, long_about = None)]
struct Cli {
    /// Path to the configuration file (defaults to ./keyfob.yaml or ./keyfob.yml).
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    /// Log output format.
    #[arg(long, global = true, value_enum, default_value_t = LogFormat::Text)]
    log_format: LogFormat,

    /// Only log warnings and errors.
    #[arg(long, global = true)]
    quiet: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start the server.
    Run(RunArgs),
    /// Validate the configuration file without starting the server.
    Validate,
    /// Write an example keyfob.yaml.
    Init(InitArgs),
    /// Hash a password with argon2.
    HashPassword(HashPasswordArgs),
    /// Generate (or regenerate) the signing key.
    GenKeys(GenKeysArgs),
    /// Issue a token to stdout for quick tests.
    Token(TokenArgs),
}

#[derive(Debug, Args)]
struct RunArgs {
    /// Interface to bind (overrides the configuration).
    #[arg(long)]
    host: Option<String>,
    /// Port to bind (overrides the configuration).
    #[arg(long)]
    port: Option<u16>,
    /// Issuer identifier (overrides the configuration).
    #[arg(long)]
    issuer: Option<String>,
    /// Serve HTTPS with a self-signed certificate (overrides the configuration).
    #[arg(long)]
    tls: bool,
    /// Do not reload the configuration file when it changes.
    #[arg(long)]
    no_watch: bool,
}

#[derive(Debug, Args)]
struct InitArgs {
    /// Destination file.
    #[arg(long, default_value = "keyfob.yaml")]
    path: PathBuf,
    /// Overwrite the file if it already exists.
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Args)]
struct HashPasswordArgs {
    /// Password to hash. Read from stdin when omitted.
    #[arg(long)]
    password: Option<String>,
}

#[derive(Debug, Args)]
struct GenKeysArgs {
    /// Overwrite an existing key file (invalidates previously issued tokens).
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Args)]
struct TokenArgs {
    /// Client id to issue the token for.
    #[arg(long)]
    client: String,
    /// User to impersonate (requires a configured user).
    #[arg(long)]
    user: Option<String>,
    /// Client secret (confidential clients). Also read from KEYFOB_CLIENT_SECRET.
    #[arg(long, env = "KEYFOB_CLIENT_SECRET")]
    secret: Option<String>,
    /// Space-separated scopes (defaults to the client's allowed scopes).
    #[arg(long)]
    scope: Option<String>,
    /// Print the full token response as JSON instead of just the access token.
    #[arg(long)]
    json: bool,
}

/// Entry point used by `main`.
pub fn run() -> Result<(), CliError> {
    // rustls has no compiled-in default provider; install `ring` first.
    crate::crypto::install_crypto_provider();

    let cli = Cli::parse();
    init_tracing(cli.log_format, cli.quiet)?;

    match cli.command {
        Command::Run(args) => block_on(run_server(cli.config, args))?,
        Command::Validate => validate(cli.config),
        Command::Init(args) => init(&args),
        Command::HashPassword(args) => hash_password_command(&args),
        Command::GenKeys(args) => gen_keys(cli.config, &args),
        Command::Token(args) => block_on(run_token(cli.config, args))?,
    }
}

fn init_tracing(format: LogFormat, quiet: bool) -> Result<(), CliError> {
    use tracing_subscriber::EnvFilter;

    let default_level = if quiet { "warn" } else { "info" };
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("keyfob_idp={default_level},warn")));

    let result = match format {
        LogFormat::Text => tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .try_init(),
        LogFormat::Json => tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .try_init(),
    };
    result.map_err(|error| CliError::message(format!("failed to initialise logging: {error}")))
}

fn block_on<F: std::future::Future>(future: F) -> Result<F::Output, CliError> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    Ok(runtime.block_on(future))
}

// --------------------------------------------------------------------- run

async fn run_server(config_path: Option<PathBuf>, args: RunArgs) -> Result<(), CliError> {
    let path = config::find_config(config_path)?;
    let mut config = config::load(&path)?;
    apply_overrides(&mut config, &args);

    let mut warnings = config::warnings(&config);
    if args.tls {
        warnings.push(
            "server.tls: enabled with a self-signed certificate — browsers will warn, and \
             clients must trust it explicitly"
                .to_string(),
        );
    }
    for warning in &warnings {
        tracing::warn!(warning = %warning, "configuration warning");
    }

    let (keys, origin) = KeySet::load_or_generate(
        &config.keys.path,
        config.keys.persist,
        &config.keys.algorithm,
    )?;

    let host = config.server.host.clone();
    let port = config.server.port;
    let issuer = config.server.issuer();
    let tls = config.server.tls;
    let watch = !args.no_watch;
    let path_for_state = path.clone();

    let state = AppState::new(path_for_state, config, keys, origin);

    spawn_cleanup(state.clone());
    if watch {
        spawn_config_watcher(state.clone());
    }

    let router = crate::http::router(state.clone()).await;
    let addr = resolve_addr(&host, port).await?;

    banner(&issuer, &addr, tls);

    let handle = axum_server::Handle::new();
    let shutdown_handle = handle.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            tracing::info!("shutdown signal received");
            shutdown_handle.graceful_shutdown(Some(Duration::from_secs(5)));
        }
    });

    if tls {
        let tls_config = self_signed_tls().await?;
        axum_server::bind_rustls(addr, tls_config)
            .handle(handle)
            .serve(router.into_make_service())
            .await?;
    } else {
        axum_server::bind(addr)
            .handle(handle)
            .serve(router.into_make_service())
            .await?;
    }

    tracing::info!("server stopped");
    Ok(())
}

fn apply_overrides(config: &mut Config, args: &RunArgs) {
    if let Some(host) = &args.host {
        config.server.host = host.clone();
    }
    if let Some(port) = args.port {
        config.server.port = port;
    }
    if let Some(issuer) = &args.issuer {
        config.server.issuer = Some(issuer.clone());
    }
    if args.tls {
        config.server.tls = true;
    }
}

fn banner(issuer: &str, addr: &SocketAddr, tls: bool) {
    let scheme = if tls { "https" } else { "http" };
    println!();
    println!("keyfob-idp is a development tool. Do not use it in production.");
    println!("  Issuer:  {issuer}");
    println!("  UI:      {issuer}/  (server info and token generator)");
    println!("  Listen:  {scheme}://{addr}");
    println!();
    let _ = std::io::stdout().flush();
}

async fn resolve_addr(host: &str, port: u16) -> Result<SocketAddr, CliError> {
    if let Ok(addr) = format!("{host}:{port}").parse::<SocketAddr>() {
        return Ok(addr);
    }
    let mut resolved = tokio::net::lookup_host((host, port)).await?;
    resolved
        .next()
        .ok_or_else(|| CliError::message(format!("cannot resolve host '{host}'")))
}

async fn self_signed_tls() -> Result<axum_server::tls_rustls::RustlsConfig, CliError> {
    let names = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ];
    let certified = rcgen::generate_simple_self_signed(names)
        .map_err(|error| CliError::message(format!("failed to generate a certificate: {error}")))?;
    let cert_pem = certified.cert.pem();
    let key_pem = certified.signing_key.serialize_pem();
    let config = axum_server::tls_rustls::RustlsConfig::from_pem(
        cert_pem.into_bytes(),
        key_pem.into_bytes(),
    )
    .await?;
    Ok(config)
}

/// Removes expired authorization codes, sessions and revocations periodically.
fn spawn_cleanup(state: AppState) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        interval.tick().await; // the first tick completes immediately
        loop {
            interval.tick().await;
            let now = time::OffsetDateTime::now_utc().unix_timestamp();
            let stats = state.store.cleanup(now).await;
            if stats.total() > 0 {
                tracing::debug!(
                    codes = stats.codes,
                    refresh_tokens = stats.refresh_tokens,
                    sessions = stats.sessions,
                    revoked = stats.revoked,
                    "expired state cleaned up"
                );
            }
        }
    });
}

/// Watches the configuration file and reloads it on change (debounced).
fn spawn_config_watcher(state: AppState) {
    use notify::{RecursiveMode, Watcher as _};

    tokio::spawn(async move {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(16);
        let sender = tx.clone();
        let mut watcher = match notify::recommended_watcher(
            move |event: notify::Result<notify::Event>| {
                if let Ok(event) = event
                    && (event.kind.is_modify() || event.kind.is_create() || event.kind.is_remove())
                {
                    let _ = sender.blocking_send(());
                }
            },
        ) {
            Ok(watcher) => watcher,
            Err(error) => {
                tracing::warn!(error = %error, "hot reload disabled: cannot watch the configuration");
                return;
            }
        };

        // Watch the parent directory: editors often replace the file, which
        // would silently drop a watch on the file itself.
        let path = state.config_path.clone();
        let directory = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        if let Err(error) = watcher.watch(&directory, RecursiveMode::NonRecursive) {
            tracing::warn!(error = %error, "hot reload disabled: cannot watch {directory:?}");
            return;
        }
        tracing::info!(path = %path.display(), "watching the configuration file for changes");

        let file_name = path.file_name().map(|name| name.to_owned());
        loop {
            if rx.recv().await.is_none() {
                return;
            }
            // Debounce: drain further events for a short window.
            while let Ok(Some(())) =
                tokio::time::timeout(Duration::from_millis(300), rx.recv()).await
            {}
            // Ignore events for other files.
            if !file_name
                .as_deref()
                .map(|name| path.ends_with(name))
                .unwrap_or(true)
            {
                continue;
            }
            if let Err(error) = state.reload_config().await {
                tracing::warn!(error = %error, "reload failed; still serving the previous configuration");
            }
        }
    });
}

// ---------------------------------------------------------------- commands

fn validate(config_path: Option<PathBuf>) -> Result<(), CliError> {
    let path = config::find_config(config_path)?;
    let config = config::load(&path)?;
    println!("Configuration OK: {}", path.display());
    for warning in config::warnings(&config) {
        println!("warning: {warning}");
    }
    print_summary(&config);
    Ok(())
}

fn print_summary(config: &Config) {
    println!("  issuer: {}", config.server.issuer());
    println!(
        "  clients: {}",
        config
            .clients
            .iter()
            .map(|client| client.client_id.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!(
        "  users: {}",
        config
            .users
            .iter()
            .map(|user| user.username.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!("  login mode: {:?}", config.login.mode);
    if config.ui.enabled {
        println!("  ui: enabled (an internal {INTERNAL_UI_CLIENT_ID} client is registered)");
    }
}

fn init(args: &InitArgs) -> Result<(), CliError> {
    if args.path.exists() && !args.force {
        return Err(CliError::message(format!(
            "{} already exists; use --force to overwrite it",
            args.path.display()
        )));
    }
    std::fs::write(&args.path, config::EXAMPLE_CONFIG)?;
    println!("Wrote {}", args.path.display());
    println!("Start the server with: keyfob run");
    Ok(())
}

fn hash_password_command(args: &HashPasswordArgs) -> Result<(), CliError> {
    let password = match &args.password {
        Some(password) => password.clone(),
        None => read_password()?,
    };
    if password.is_empty() {
        return Err(CliError::message("the password must not be empty"));
    }
    let hash = hash_password(&password)?;
    println!("{hash}");
    Ok(())
}

fn read_password() -> Result<String, CliError> {
    eprint!("Password: ");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

fn gen_keys(config_path: Option<PathBuf>, args: &GenKeysArgs) -> Result<(), CliError> {
    let path = config::find_config(config_path)?;
    let config = config::load(&path)?;
    let key_path = &config.keys.path;
    if key_path.exists() && !args.force {
        return Err(CliError::message(format!(
            "{} already exists; use --force to replace it (this invalidates existing tokens)",
            key_path.display()
        )));
    }
    let keys = KeySet::generate(&config.keys.algorithm, DEFAULT_KEY_BITS)?;
    keys.save(key_path)?;
    println!("Wrote {}", key_path.display());
    println!("  kid: {}", keys.kid());
    println!("  algorithm: {}", keys.algorithm_name());
    Ok(())
}

async fn run_token(config_path: Option<PathBuf>, args: TokenArgs) -> Result<(), CliError> {
    let path = config::find_config(config_path)?;
    let config = config::load(&path)?;
    let (keys, _origin) = KeySet::load_or_generate(
        &config.keys.path,
        config.keys.persist,
        &config.keys.algorithm,
    )?;
    let runtime = crate::state::Runtime::build(config);
    let store = Store::new();

    let client = runtime
        .client(&args.client)
        .ok_or_else(|| CliError::message(format!("unknown client '{}'", args.client)))?;

    // Authenticate confidential clients the same way the token endpoint would.
    if client.is_confidential() {
        let expected = client.client_secret.as_deref().unwrap_or_default();
        match args.secret.as_deref() {
            Some(secret) if constant_time_eq(secret, expected) => {}
            _ => {
                return Err(CliError::message(format!(
                    "client '{}' is confidential: pass --secret or set KEYFOB_CLIENT_SECRET",
                    args.client
                )));
            }
        }
    }

    let user = match &args.user {
        Some(username) => Some(
            runtime
                .user(username)
                .ok_or_else(|| CliError::message(format!("unknown user '{username}'")))?,
        ),
        None => None,
    };

    let mut scopes = crate::oauth::scope::resolve_scopes(client, args.scope.as_deref())?;
    if user.is_none()
        && scopes
            .iter()
            .any(|scope| scope == crate::oauth::scope::OFFLINE_ACCESS)
    {
        return Err(CliError::from(OAuthError::new(
            ErrorCode::InvalidScope,
            "offline_access is not available without a user",
        )));
    }
    // A user implies an interactive-style grant; without one it is machine to
    // machine. Either way the label is only used by /debug/tokens.
    let grant_type = if user.is_some() {
        "cli:user"
    } else {
        "cli:client"
    };
    if user.is_none() {
        scopes.retain(|scope| scope != crate::oauth::scope::OFFLINE_ACCESS);
    }

    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let issued = crate::oauth::token::issue_direct(
        &runtime, &keys, &store, client, user, scopes, grant_type, now,
    )
    .await?;

    if args.json {
        let mut body = serde_json::json!({
            "access_token": issued.access_token,
            "token_type": "Bearer",
            "expires_in": issued.access_expires_in,
            "scope": issued.scopes.join(" "),
        });
        if let Some(id_token) = issued.id_token {
            body["id_token"] = serde_json::json!(id_token);
        }
        if let Some(refresh_token) = issued.refresh_token {
            body["refresh_token"] = serde_json::json!(refresh_token);
        }
        println!("{}", serde_json::to_string_pretty(&body)?);
    } else {
        println!("{}", issued.access_token);
        if let Some(refresh_token) = &issued.refresh_token {
            eprintln!("refresh_token: {refresh_token}");
        }
        if let Some(id_token) = &issued.id_token {
            eprintln!("id_token: {id_token}");
        }
    }
    Ok(())
}
