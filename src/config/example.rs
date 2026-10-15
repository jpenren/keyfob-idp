//! The example configuration written by `keyfob init`.
//!
//! Kept short on purpose: the design goal is a working configuration of fewer
//! than 20 lines of actual content. `examples/keyfob.full.yaml` documents every
//! option.

pub const EXAMPLE: &str = r#"# keyfob.yaml — local OAuth 2.0 / OIDC provider for development.
# Documentation: https://github.com/OWNER/keyfob-idp (see docs/configuration.md)
server:
  host: 127.0.0.1
  port: 9000
  # issuer: http://localhost:9000   # deduced from host and port when omitted

clients:
  # Public SPA using Authorization Code + PKCE.
  - client_id: my-spa
    public: true
    redirect_uris:
      - http://localhost:3000/callback
    post_logout_redirect_uris:
      - http://localhost:3000

  # Confidential backend using client credentials and refresh tokens.
  - client_id: my-backend
    client_secret: dev-secret
    grant_types: [authorization_code, client_credentials, refresh_token]
    redirect_uris:
      - http://localhost:8080/login/oauth2/code/keyfob
    audience: [my-api]

users:
  - username: alice
    password: alice123          # or an argon2 hash ($argon2...) from `keyfob hash-password`
    email: alice@example.test
    name: Alice Doe
    roles: [admin, user]
    claims:
      department: engineering
      # Keycloak-compatible roles: clients that read `realm_access.roles` and
      # `resource_access.<client_id>.roles` work without changes.
      realm_access:
        roles: [admin, user]
      resource_access:
        my-spa:
          roles: [admin]
  - username: bob
    password: bob123
    email: bob@example.test
    roles: [user]
    claims:
      realm_access:
        roles: [user]
"#;

#[cfg(test)]
mod tests {
    #[test]
    fn example_config_is_valid() {
        let parsed = crate::config::parse_str(super::EXAMPLE, "keyfob.yaml");
        assert!(parsed.is_ok(), "{:?}", parsed.err());
    }
}
