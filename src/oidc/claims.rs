//! OpenID Connect claims: ID token, access token and userinfo payloads.

use std::sync::OnceLock;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use minijinja::{Environment, UndefinedBehavior};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::config::{ClientCfg, UserCfg};

/// Claims that providers own; user-defined claims may not override them.
pub const RESERVED_CLAIMS: [&str; 17] = [
    "iss",
    "sub",
    "aud",
    "exp",
    "iat",
    "nbf",
    "jti",
    "auth_time",
    "nonce",
    "at_hash",
    "azp",
    "sid",
    "scope",
    "client_id",
    "token_type",
    "act",
    "may_act",
];

fn template_env() -> &'static Environment<'static> {
    static ENV: OnceLock<Environment<'static>> = OnceLock::new();
    ENV.get_or_init(|| {
        let mut env = Environment::new();
        env.set_undefined_behavior(UndefinedBehavior::Lenient);
        env
    })
}

/// Template context exposed to user claim templates.
pub fn user_context(user: &UserCfg) -> Value {
    json!({
        "username": user.username,
        "email": user.email,
        "name": user.name,
        "roles": user.roles,
        "groups": user.groups,
    })
}

/// Renders `source` as a minijinja template; failures fall back to the raw
/// string (and are logged) so a broken claim never breaks token issuance.
pub fn render_template(source: &str, context: &Value) -> String {
    if !source.contains("{{") && !source.contains("{%") {
        return source.to_string();
    }
    template_env()
        .render_str(source, minijinja::value::Serde(context))
        .unwrap_or_else(|err| {
            tracing::warn!(template = source, error = %err, "failed to render claim template");
            source.to_string()
        })
}

/// Values of the custom claims configured for a user, with templates rendered.
pub fn custom_claims(user: &UserCfg) -> Map<String, Value> {
    let context = user_context(user);
    let mut rendered = Map::new();
    for (key, value) in &user.claims {
        let value = match value {
            Value::String(source) => Value::String(render_template(source, &context)),
            other => other.clone(),
        };
        rendered.insert(key.clone(), value);
    }
    rendered
}

/// Values of the custom claims configured for a client.
///
/// Client claims are literal JSON values: they are not rendered as templates,
/// because they describe the application rather than the signed-in user.
pub fn custom_client_claims(client: &ClientCfg) -> Map<String, Value> {
    client
        .claims
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

/// The user's email with templates applied, if configured.
pub fn resolved_email(user: &UserCfg) -> Option<String> {
    user.email
        .as_deref()
        .map(|source| render_template(source, &user_context(user)))
}

/// The user's display name with templates applied, if configured.
pub fn resolved_name(user: &UserCfg) -> Option<String> {
    user.name
        .as_deref()
        .map(|source| render_template(source, &user_context(user)))
}

pub fn has_scope(scopes: &[String], scope: &str) -> bool {
    scopes.iter().any(|candidate| candidate == scope)
}

/// Everything needed to build a token's claim set.
pub struct ClaimsInput<'a> {
    pub issuer: &'a str,
    pub client: &'a ClientCfg,
    pub user: Option<&'a UserCfg>,
    pub scopes: &'a [String],
    pub nonce: Option<&'a str>,
    pub auth_time: i64,
    pub session_id: Option<&'a str>,
    pub now: i64,
    pub ttl_seconds: i64,
    /// Access token, when building the matching ID token (`at_hash`).
    pub access_token: Option<&'a str>,
    /// Delegation chain (`act` claim) for RFC 8693 Token Exchange.
    pub act: Option<&'a Value>,
    /// Overrides the access token audience when it is set (Token Exchange).
    pub audience: Option<&'a [String]>,
    /// Overrides the subject when it is set (Token Exchange).
    pub subject: Option<&'a str>,
}

impl ClaimsInput<'_> {
    fn subject(&self) -> String {
        if let Some(subject) = self.subject {
            return subject.to_string();
        }
        match self.user {
            Some(user) => user.username.clone(),
            None => self.client.client_id.clone(),
        }
    }

    fn audience(&self) -> Value {
        if let Some(audience) = self.audience {
            return json!(audience);
        }
        if self.client.audience.is_empty() {
            json!([self.client.client_id])
        } else {
            json!(&self.client.audience)
        }
    }
}

/// Identity claims gated by the granted scopes, plus roles/groups and the
/// custom claims of the user and the client (always included, this is a
/// development tool).
///
/// Precedence for non-reserved keys: explicit user claims override the claims
/// derived from the user record, and client claims override both. Provider-owned
/// claims (`RESERVED_CLAIMS`) are written afterwards and always win.
fn identity_claims(
    user: Option<&UserCfg>,
    client: Option<&ClientCfg>,
    scopes: &[String],
) -> Map<String, Value> {
    let mut claims = Map::new();
    if let Some(user) = user {
        // Custom claims first: a user may override email or name explicitly.
        for (key, value) in custom_claims(user) {
            claims.insert(key, value);
        }

        if has_scope(scopes, "profile") {
            claims
                .entry("preferred_username".to_string())
                .or_insert_with(|| json!(user.username));
            if let Some(name) = resolved_name(user) {
                claims
                    .entry("name".to_string())
                    .or_insert_with(|| json!(name));
            }
        }

        if has_scope(scopes, "email")
            && let Some(email) = resolved_email(user)
        {
            claims
                .entry("email".to_string())
                .or_insert_with(|| json!(email));
            claims
                .entry("email_verified".to_string())
                .or_insert(json!(true));
        }

        if !user.roles.is_empty() {
            claims
                .entry("roles".to_string())
                .or_insert_with(|| json!(user.roles));
        }
        if !user.groups.is_empty() {
            claims
                .entry("groups".to_string())
                .or_insert_with(|| json!(user.groups));
        }
    }

    // Client claims last: a client may tailor a claim for its own application,
    // and they are the only source for client_credentials tokens.
    if let Some(client) = client {
        for (key, value) in custom_client_claims(client) {
            claims.insert(key, value);
        }
    }

    claims
}

/// Access token payload: JWT with `aud`, `scope`, `roles` and `groups`.
pub fn access_token_claims(input: &ClaimsInput<'_>) -> Value {
    let mut claims = identity_claims(input.user, Some(input.client), input.scopes);

    claims.insert("iss".into(), json!(input.issuer));
    claims.insert("sub".into(), json!(input.subject()));
    claims.insert("aud".into(), input.audience());
    claims.insert("azp".into(), json!(input.client.client_id));
    claims.insert("client_id".into(), json!(input.client.client_id));
    claims.insert("scope".into(), json!(input.scopes.join(" ")));
    claims.insert("iat".into(), json!(input.now));
    claims.insert("nbf".into(), json!(input.now));
    claims.insert("exp".into(), json!(input.now + input.ttl_seconds));
    claims.insert("jti".into(), json!(uuid::Uuid::new_v4().to_string()));
    if let Some(session_id) = input.session_id {
        claims.insert("sid".into(), json!(session_id));
    }
    if let Some(act) = input.act {
        claims.insert("act".into(), act.clone());
    }

    Value::Object(claims)
}

/// ID token payload (OIDC Core 2).
pub fn id_token_claims(input: &ClaimsInput<'_>) -> Value {
    let mut claims = identity_claims(input.user, Some(input.client), input.scopes);

    claims.insert("iss".into(), json!(input.issuer));
    claims.insert("sub".into(), json!(input.subject()));
    claims.insert("aud".into(), json!(input.client.client_id));
    claims.insert("azp".into(), json!(input.client.client_id));
    claims.insert("iat".into(), json!(input.now));
    claims.insert("exp".into(), json!(input.now + input.ttl_seconds));
    claims.insert("auth_time".into(), json!(input.auth_time));
    claims.insert("jti".into(), json!(uuid::Uuid::new_v4().to_string()));
    if let Some(nonce) = input.nonce {
        claims.insert("nonce".into(), json!(nonce));
    }
    if let Some(session_id) = input.session_id {
        claims.insert("sid".into(), json!(session_id));
    }
    if let Some(access_token) = input.access_token {
        claims.insert("at_hash".into(), json!(at_hash(access_token)));
    }

    Value::Object(claims)
}

/// `/userinfo` payload: `sub` plus the claims allowed by the granted scopes and
/// the claims of the client that owns the access token.
pub fn userinfo_claims(
    user: &UserCfg,
    client: Option<&ClientCfg>,
    scopes: &[String],
    subject: &str,
) -> Value {
    let mut claims = identity_claims(Some(user), client, scopes);
    claims.insert("sub".to_string(), json!(subject));
    Value::Object(claims)
}

/// `at_hash` per OIDC Core 3.1.3.6 for RS256 tokens: base64url of the left half
/// of the access token's SHA-256 digest.
pub fn at_hash(access_token: &str) -> String {
    let digest = Sha256::digest(access_token.as_bytes());
    URL_SAFE_NO_PAD.encode(&digest[..digest.len() / 2])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user() -> UserCfg {
        UserCfg {
            username: "alice".into(),
            password: "alice123".into(),
            email: Some("{{username}}@example.test".into()),
            name: Some("Alice Doe".into()),
            roles: vec!["admin".into(), "user".into()],
            groups: vec!["engineering".into()],
            claims: [("department".to_string(), json!("eng"))]
                .into_iter()
                .collect(),
        }
    }

    fn client() -> ClientCfg {
        ClientCfg {
            client_id: "my-spa".into(),
            client_secret: None,
            public: true,
            redirect_uris: vec!["http://localhost:3000/cb".into()],
            post_logout_redirect_uris: vec![],
            allowed_scopes: None,
            grant_types: None,
            audience: vec!["my-api".into()],
            claims: std::collections::BTreeMap::new(),
            auto_approve: false,
        }
    }

    fn scopes() -> Vec<String> {
        ["openid", "profile", "email"]
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    #[test]
    fn email_template_uses_the_username() {
        assert_eq!(resolved_email(&user()).unwrap(), "alice@example.test");
    }

    #[test]
    fn access_token_contains_audience_scope_and_roles() {
        let client = client();
        let user = user();
        let scopes = scopes();
        let claims = access_token_claims(&ClaimsInput {
            issuer: "http://localhost:9000",
            client: &client,
            user: Some(&user),
            scopes: &scopes,
            nonce: None,
            auth_time: 1_000,
            session_id: Some("sess-1"),
            now: 2_000,
            ttl_seconds: 900,
            access_token: None,
            act: None,
            audience: None,
            subject: None,
        });
        assert_eq!(claims["iss"], "http://localhost:9000");
        assert_eq!(claims["sub"], "alice");
        assert_eq!(claims["aud"][0], "my-api");
        assert_eq!(claims["scope"], "openid profile email");
        assert_eq!(claims["roles"][0], "admin");
        assert_eq!(claims["groups"][0], "engineering");
        assert_eq!(claims["department"], "eng");
        assert_eq!(claims["email"], "alice@example.test");
        assert_eq!(claims["exp"], 2_900);
        assert_eq!(claims["sid"], "sess-1");
        assert!(claims["jti"].is_string());
    }

    #[test]
    fn id_token_respects_scopes_and_includes_at_hash() {
        let client = client();
        let user = user();
        let openid_only = vec!["openid".to_string()];
        let claims = id_token_claims(&ClaimsInput {
            issuer: "http://localhost:9000",
            client: &client,
            user: Some(&user),
            scopes: &openid_only,
            nonce: Some("n-1"),
            auth_time: 1_000,
            session_id: Some("sess-1"),
            now: 2_000,
            ttl_seconds: 900,
            access_token: Some("header.payload.signature"),
            act: None,
            audience: None,
            subject: None,
        });
        assert_eq!(claims["aud"], "my-spa");
        assert_eq!(claims["nonce"], "n-1");
        assert_eq!(claims["auth_time"], 1_000);
        assert_eq!(claims["at_hash"], at_hash("header.payload.signature"));
        // profile/email scopes were not granted.
        assert!(claims.get("email").is_none());
        assert!(claims.get("preferred_username").is_none());
        // roles are always included.
        assert_eq!(claims["roles"][0], "admin");
    }

    #[test]
    fn access_token_carries_the_delegation_chain() {
        let client = client();
        let user = user();
        let scopes = vec!["openid".to_string()];
        let act = json!({ "sub": "backend", "iss": "http://localhost:9000" });
        let claims = access_token_claims(&ClaimsInput {
            issuer: "http://localhost:9000",
            client: &client,
            user: Some(&user),
            scopes: &scopes,
            nonce: None,
            auth_time: 0,
            session_id: None,
            now: 0,
            ttl_seconds: 60,
            access_token: None,
            act: Some(&act),
            audience: None,
            subject: None,
        });
        assert_eq!(claims["act"]["sub"], "backend");
    }

    #[test]
    fn access_token_subject_and_audience_can_be_overridden() {
        let client = client();
        let scopes = vec!["openid".to_string()];
        let audience = vec!["my-api".to_string()];
        let claims = access_token_claims(&ClaimsInput {
            issuer: "iss",
            client: &client,
            user: None,
            scopes: &scopes,
            nonce: None,
            auth_time: 0,
            session_id: None,
            now: 0,
            ttl_seconds: 60,
            access_token: None,
            act: None,
            audience: Some(&audience),
            subject: Some("some-service"),
        });
        assert_eq!(claims["sub"], "some-service");
        assert_eq!(claims["aud"][0], "my-api");
    }

    #[test]
    fn custom_claims_cannot_override_reserved_claims() {
        let client = client();
        let mut user = user();
        user.claims.insert("sub".into(), json!("evil"));
        let scopes = scopes();
        let claims = access_token_claims(&ClaimsInput {
            issuer: "http://localhost:9000",
            client: &client,
            user: Some(&user),
            scopes: &scopes,
            nonce: None,
            auth_time: 0,
            session_id: None,
            now: 0,
            ttl_seconds: 60,
            access_token: None,
            act: None,
            audience: None,
            subject: None,
        });
        assert_eq!(claims["sub"], "alice");
    }

    #[test]
    fn client_credentials_subject_is_the_client() {
        let client = client();
        let scopes = vec!["openid".to_string()];
        let claims = access_token_claims(&ClaimsInput {
            issuer: "iss",
            client: &client,
            user: None,
            scopes: &scopes,
            nonce: None,
            auth_time: 0,
            session_id: None,
            now: 10,
            ttl_seconds: 60,
            access_token: None,
            act: None,
            audience: None,
            subject: None,
        });
        assert_eq!(claims["sub"], "my-spa");
        assert!(claims["roles"].is_null());
    }

    #[test]
    fn userinfo_only_exposes_granted_scopes() {
        let user = user();
        let client = client();
        let claims = userinfo_claims(&user, Some(&client), &["openid".to_string()], "alice");
        assert_eq!(claims["sub"], "alice");
        assert!(claims.get("email").is_none());

        let claims = userinfo_claims(
            &user,
            Some(&client),
            &["openid".to_string(), "email".to_string()],
            "alice",
        );
        assert_eq!(claims["email"], "alice@example.test");
    }

    fn client_with_claims() -> ClientCfg {
        let mut client = client();
        client.claims.insert(
            "app_grants".into(),
            json!(["resource-a:read", "resource-b:read,write"]),
        );
        client
    }

    #[test]
    fn client_claims_reach_the_access_and_id_tokens() {
        let client = client_with_claims();
        let user = user();
        let scopes = scopes();

        let access = access_token_claims(&ClaimsInput {
            issuer: "iss",
            client: &client,
            user: Some(&user),
            scopes: &scopes,
            nonce: None,
            auth_time: 0,
            session_id: None,
            now: 0,
            ttl_seconds: 60,
            access_token: None,
            act: None,
            audience: None,
            subject: None,
        });
        assert_eq!(
            access["app_grants"],
            json!(["resource-a:read", "resource-b:read,write"])
        );

        let id_token = id_token_claims(&ClaimsInput {
            issuer: "iss",
            client: &client,
            user: Some(&user),
            scopes: &scopes,
            nonce: None,
            auth_time: 0,
            session_id: None,
            now: 0,
            ttl_seconds: 60,
            access_token: None,
            act: None,
            audience: None,
            subject: None,
        });
        assert_eq!(
            id_token["app_grants"],
            json!(["resource-a:read", "resource-b:read,write"])
        );
    }

    #[test]
    fn client_claims_are_the_only_identity_claims_for_client_credentials() {
        let client = client_with_claims();
        let claims = access_token_claims(&ClaimsInput {
            issuer: "iss",
            client: &client,
            user: None,
            scopes: &["openid".to_string()],
            nonce: None,
            auth_time: 0,
            session_id: None,
            now: 0,
            ttl_seconds: 60,
            access_token: None,
            act: None,
            audience: None,
            subject: None,
        });
        assert_eq!(claims["app_grants"][0], "resource-a:read");
        assert!(claims.get("email").is_none());
    }

    #[test]
    fn client_claims_override_user_claims_but_not_reserved_ones() {
        let mut client = client_with_claims();
        client
            .claims
            .insert("department".into(), json!("client-eng"));
        client.claims.insert("sub".into(), json!("evil"));
        let user = user();
        let scopes = scopes();
        let claims = access_token_claims(&ClaimsInput {
            issuer: "iss",
            client: &client,
            user: Some(&user),
            scopes: &scopes,
            nonce: None,
            auth_time: 0,
            session_id: None,
            now: 0,
            ttl_seconds: 60,
            access_token: None,
            act: None,
            audience: None,
            subject: None,
        });
        assert_eq!(claims["department"], "client-eng");
        assert_eq!(claims["sub"], "alice");
    }

    #[test]
    fn userinfo_includes_the_client_claims() {
        let client = client_with_claims();
        let claims = userinfo_claims(&user(), Some(&client), &["openid".to_string()], "alice");
        assert_eq!(claims["app_grants"][1], "resource-b:read,write");
    }

    #[test]
    fn at_hash_is_the_left_half_of_sha256() {
        // Digit 0 -> 16 bytes -> 22 base64url characters.
        assert_eq!(at_hash("x").len(), 22);
    }
}
