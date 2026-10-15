//! OpenID Connect pieces: claim construction (ID token, access token,
//! userinfo) and the discovery documents.

pub mod claims;
pub mod discovery;

pub use claims::{
    ClaimsInput, RESERVED_CLAIMS, access_token_claims, at_hash, custom_claims, has_scope,
    id_token_claims, render_template, resolved_email, resolved_name, userinfo_claims,
};
pub use discovery::{oauth_authorization_server, openid_configuration};
