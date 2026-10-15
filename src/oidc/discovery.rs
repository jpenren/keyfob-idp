//! OpenID Connect Discovery 1.0 and OAuth 2.0 Authorization Server Metadata
//! (RFC 8414) documents.

use serde_json::{Value, json};

use crate::crypto::KeySet;
use crate::state::Runtime;

/// Claims advertised as supported in the discovery document.
pub const CLAIMS_SUPPORTED: [&str; 14] = [
    "iss",
    "sub",
    "aud",
    "exp",
    "iat",
    "auth_time",
    "nonce",
    "name",
    "preferred_username",
    "email",
    "email_verified",
    "roles",
    "groups",
    "sid",
];

fn endpoint(issuer: &str, path: &str) -> String {
    format!("{issuer}{path}")
}

/// `GET /.well-known/openid-configuration`
pub fn openid_configuration(runtime: &Runtime, keys: &KeySet) -> Value {
    let issuer = &runtime.issuer;

    json!({
        "issuer": issuer,
        "authorization_endpoint": endpoint(issuer, "/authorize"),
        "token_endpoint": endpoint(issuer, "/token"),
        "userinfo_endpoint": endpoint(issuer, "/userinfo"),
        "jwks_uri": endpoint(issuer, "/jwks"),
        "introspection_endpoint": endpoint(issuer, "/introspect"),
        "revocation_endpoint": endpoint(issuer, "/revoke"),
        "end_session_endpoint": endpoint(issuer, "/logout"),

        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": runtime.grant_types_supported,
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": [keys.algorithm_name()],
        "scopes_supported": runtime.scopes_supported,
        "claims_supported": CLAIMS_SUPPORTED,

        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
            "none"
        ],
        "introspection_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
            "none"
        ],
        "revocation_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
            "none"
        ],
        "code_challenge_methods_supported": ["S256"],

        "claims_parameter_supported": false,
        "request_parameter_supported": false,
        "request_uri_parameter_supported": false,
        "require_request_uri_registration": false,
    })
}

/// `GET /.well-known/oauth-authorization-server` (RFC 8414).
///
/// RFC 8414 allows additional members, so the OpenID document is reused: this
/// keeps both endpoints consistent for clients that read either one.
pub fn oauth_authorization_server(runtime: &Runtime, keys: &KeySet) -> Value {
    openid_configuration(runtime, keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use crate::crypto::keys::DEFAULT_KEY_BITS;

    fn runtime() -> Runtime {
        let config = config::parse_str(
            r#"
clients:
  - client_id: my-spa
    public: true
    redirect_uris: [http://localhost:3000/cb]
  - client_id: my-backend
    client_secret: dev-secret
    grant_types: [client_credentials, refresh_token]
users:
  - username: alice
    password: alice123
"#,
            "test.yaml",
        )
        .unwrap();
        Runtime::build(config)
    }

    #[test]
    fn discovery_lists_all_endpoints() {
        let keys = KeySet::generate("RS256", DEFAULT_KEY_BITS).unwrap();
        let runtime = runtime();
        let document = openid_configuration(&runtime, &keys);

        assert_eq!(document["issuer"], "http://127.0.0.1:9000");
        assert_eq!(
            document["authorization_endpoint"],
            "http://127.0.0.1:9000/authorize"
        );
        assert!(document["jwks_uri"].as_str().unwrap().ends_with("/jwks"));
        assert_eq!(document["response_types_supported"][0], "code");
        assert_eq!(
            document["id_token_signing_alg_values_supported"][0],
            "RS256"
        );
        assert_eq!(document["code_challenge_methods_supported"][0], "S256");
        assert_eq!(document["subject_types_supported"][0], "public");

        let grants = document["grant_types_supported"].as_array().unwrap();
        assert!(grants.iter().any(|g| g == "authorization_code"));
        assert!(grants.iter().any(|g| g == "client_credentials"));

        let scopes = document["scopes_supported"].as_array().unwrap();
        assert!(scopes.iter().any(|s| s == "openid"));

        // Non-loopback-safe defaults are advertised honestly.
        assert_eq!(document["claims_parameter_supported"], false);
    }

    #[test]
    fn password_grant_is_advertised_only_when_enabled() {
        let keys = KeySet::generate("RS256", DEFAULT_KEY_BITS).unwrap();
        let runtime = runtime();
        let document = openid_configuration(&runtime, &keys);
        let grants = document["grant_types_supported"].as_array().unwrap();
        assert!(!grants.iter().any(|g| g == "password"));
    }
}
