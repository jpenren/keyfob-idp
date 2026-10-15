//! HTTP layer: the axum router and request handlers.
//!
//! The handlers are thin adapters over the `oauth` domain module. Error
//! responses follow RFC 6749 (JSON with `error` / `error_description` and
//! `Cache-Control: no-store`), except at the authorization endpoint where the
//! error is either redirected back to the client or shown as an HTML page.

pub mod authorize;
pub mod metadata;
pub mod support;
pub mod token;

use axum::Router;
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::get;
use tower_http::cors::{AllowOrigin, CorsLayer};

use crate::config::CorsCfg;
use crate::state::AppState;

/// Builds the router for the given state.
pub async fn router(state: AppState) -> Router {
    let cors = {
        let runtime = state.runtime().await;
        cors_layer(&runtime.config.cors)
    };

    let router = Router::new()
        .route("/", get(metadata::home))
        .route("/healthz", get(metadata::healthz))
        .route(
            "/.well-known/openid-configuration",
            get(metadata::discovery),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(metadata::authorization_server_metadata),
        )
        .route("/jwks", get(metadata::jwks))
        // Keycloak-compatible alias for the JWKS document.
        .route("/protocol/openid-connect/certs", get(metadata::jwks))
        .route(
            "/authorize",
            get(authorize::authorize_get).post(authorize::authorize_post),
        )
        .route(
            "/login",
            get(authorize::login_page).post(authorize::login_submit),
        )
        .route("/token", axum::routing::post(token::token))
        .route("/userinfo", get(token::userinfo).post(token::userinfo))
        .route(
            "/introspect",
            axum::routing::post(token::introspect_endpoint),
        )
        .route("/revoke", axum::routing::post(token::revoke_endpoint))
        .route(
            "/logout",
            get(metadata::logout_get).post(metadata::logout_post),
        )
        .route("/ui/info", get(metadata::ui_info))
        .route("/ui/callback", get(metadata::ui_callback))
        .route("/debug/tokens", get(metadata::debug_tokens))
        .fallback(fallback);

    match cors {
        Some(cors) => router.layer(cors).with_state(state),
        None => router.with_state(state),
    }
}

/// 404 for anything that is not a known route.
async fn fallback() -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        "Not found",
    )
}

/// CORS layer derived from the configuration. CORS settings are applied at
/// startup; changing them requires a restart.
fn cors_layer(config: &CorsCfg) -> Option<CorsLayer> {
    if !config.enabled {
        return None;
    }

    let wildcard = config.origins.iter().any(|origin| origin == "*");
    let origin = if wildcard {
        if config.allow_credentials {
            // `Access-Control-Allow-Origin: *` is invalid with credentials, so
            // reflect the request origin instead.
            AllowOrigin::mirror_request()
        } else {
            AllowOrigin::any()
        }
    } else {
        let origins: Vec<HeaderValue> = config
            .origins
            .iter()
            .filter_map(|origin| origin.parse().ok())
            .collect();
        AllowOrigin::list(origins)
    };

    let layer = CorsLayer::new()
        .allow_origin(origin)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE, header::ACCEPT]);

    if config.allow_credentials {
        Some(layer.allow_credentials(true))
    } else {
        Some(layer)
    }
}
