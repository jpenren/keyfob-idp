//! keyfob-idp: a local OAuth 2.0 / OpenID Connect identity provider for
//! development and testing. Never run it in production.
#![forbid(unsafe_code)]

pub mod cli;
pub mod config;
pub mod crypto;
pub mod http;
pub mod oauth;
pub mod oidc;
pub mod state;
pub mod store;
pub mod ui;
