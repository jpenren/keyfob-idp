//! Domain logic for the OAuth 2.0 / OIDC endpoints.
//!
//! This module is deliberately free of any dependency on axum: it validates
//! requests, authenticates clients, issues and revokes tokens and can be tested
//! without a network. The `http` module is a thin adapter on top of it.

pub mod auth;
pub mod authorize;
pub mod encoding;
pub mod error;
pub mod introspect;
pub mod scope;
pub mod token;

pub use auth::{Credentials, authenticate};
pub use authorize::{AuthorizeFailure, AuthorizePlan, AuthorizeRequest, Prompt};
pub use error::{ErrorCode, OAuthError};
pub use introspect::{introspect, revoke};
pub use token::{IssuedTokens, TokenExchange, exchange};
