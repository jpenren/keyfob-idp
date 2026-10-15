//! Token introspection (RFC 7662) and revocation (RFC 7009) logic.

use serde_json::{Map, Value, json};

use crate::crypto::{KeySet, TokenValidation, decode_jwt};
use crate::state::Runtime;
use crate::store::Store;

/// Introspection response for a token that could not be validated.
fn inactive() -> Value {
    json!({ "active": false })
}

/// Introspects an access token (JWT) or a refresh token (opaque).
///
/// A token is active when its signature is valid, it is not expired, it was not
/// revoked and it was issued by this server.
pub async fn introspect(
    runtime: &Runtime,
    keys: &KeySet,
    store: &Store,
    token: &str,
    now: i64,
) -> Value {
    // Access tokens are JWTs; decode without enforcing `exp` so we can report
    // the reason (expired tokens are simply inactive).
    if let Ok(claims) = decode_jwt(
        keys,
        token,
        &TokenValidation::new(&runtime.issuer).allow_expired(),
    ) {
        let exp = claims.get("exp").and_then(Value::as_i64).unwrap_or(0);
        let jti = claims.get("jti").and_then(Value::as_str);
        let revoked = match jti {
            Some(jti) => store.is_access_token_revoked(jti).await,
            None => true,
        };
        if exp <= now || revoked {
            return inactive();
        }
        return access_token_response(&claims, now);
    }

    // Fall back to refresh tokens (opaque strings).
    if let Some(entry) = store.get_refresh_token(token).await {
        if entry.expires_at <= now || entry.revoked {
            return inactive();
        }
        let mut response = Map::new();
        response.insert("active".into(), json!(true));
        response.insert("token_type".into(), json!("refresh_token"));
        response.insert("client_id".into(), json!(entry.client_id));
        response.insert("username".into(), json!(entry.username));
        response.insert("scope".into(), json!(entry.scopes.join(" ")));
        response.insert("exp".into(), json!(entry.expires_at));
        response.insert("iat".into(), json!(entry.issued_at));
        response.insert("iss".into(), json!(runtime.issuer));
        return Value::Object(response);
    }

    inactive()
}

fn access_token_response(claims: &Value, now: i64) -> Value {
    let mut response = Map::new();
    response.insert("active".into(), json!(true));
    response.insert("token_type".into(), json!("Bearer"));
    for key in [
        "scope",
        "client_id",
        "username",
        "sub",
        "aud",
        "iss",
        "exp",
        "iat",
        "nbf",
        "jti",
    ] {
        if let Some(value) = claims.get(key) {
            response.insert(key.into(), value.clone());
        }
    }
    // `iat`/`nbf` in the past are fine; only surface the remaining lifetime.
    response.insert(
        "exp_in".into(),
        json!(claims.get("exp").and_then(Value::as_i64).unwrap_or(now) - now),
    );
    Value::Object(response)
}

/// Revokes a token. Both access (JWT) and refresh (opaque) tokens are handled;
/// unknown tokens are ignored, as required by RFC 7009.
pub async fn revoke(runtime: &Runtime, keys: &KeySet, store: &Store, token: &str) {
    if let Ok(claims) = decode_jwt(
        keys,
        token,
        &TokenValidation::new(&runtime.issuer).allow_expired(),
    ) && let (Some(jti), Some(exp)) = (
        claims.get("jti").and_then(Value::as_str),
        claims.get("exp").and_then(Value::as_i64),
    ) {
        store.revoke_access_token(jti, exp).await;
        return;
    }
    if store.remove_refresh_token(token).await.is_some() {
        return;
    }
    tracing::debug!("revocation request for an unknown token; ignored");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;
    use crate::crypto::{DEFAULT_KEY_BITS, KeySet, encode_jwt};
    use crate::store::Store;

    fn runtime() -> Runtime {
        let config = config::parse_str(
            r#"
clients:
  - client_id: backend
    client_secret: s
    grant_types: [client_credentials]
users:
  - username: alice
    password: alice123
"#,
            "test.yaml",
        )
        .unwrap();
        Runtime::build(config)
    }

    fn access_token(keys: &KeySet, jti: &str, exp: i64) -> String {
        encode_jwt(
            keys,
            &json!({
                "iss": "http://127.0.0.1:9000",
                "sub": "backend",
                "client_id": "backend",
                "scope": "api",
                "jti": jti,
                "iat": 1_000,
                "exp": exp,
            }),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn introspects_an_active_token() {
        let runtime = runtime();
        let keys = KeySet::generate("RS256", DEFAULT_KEY_BITS).unwrap();
        let store = Store::new();
        let token = access_token(&keys, "jti-1", 2_000);

        let response = introspect(&runtime, &keys, &store, &token, 1_500).await;
        assert_eq!(response["active"], true);
        assert_eq!(response["client_id"], "backend");
        assert_eq!(response["scope"], "api");
        assert_eq!(response["exp_in"], 500);
    }

    #[tokio::test]
    async fn expired_and_revoked_tokens_are_inactive() {
        let runtime = runtime();
        let keys = KeySet::generate("RS256", DEFAULT_KEY_BITS).unwrap();
        let store = Store::new();

        let expired = access_token(&keys, "jti-2", 1_000);
        assert_eq!(
            introspect(&runtime, &keys, &store, &expired, 1_100).await["active"],
            false
        );

        let revoked = access_token(&keys, "jti-3", 5_000);
        store.revoke_access_token("jti-3", 5_000).await;
        assert_eq!(
            introspect(&runtime, &keys, &store, &revoked, 1_100).await["active"],
            false
        );
    }

    #[tokio::test]
    async fn revoke_makes_a_token_inactive() {
        let runtime = runtime();
        let keys = KeySet::generate("RS256", DEFAULT_KEY_BITS).unwrap();
        let store = Store::new();
        let token = access_token(&keys, "jti-4", 5_000);

        revoke(&runtime, &keys, &store, &token).await;
        let response = introspect(&runtime, &keys, &store, &token, 1_100).await;
        assert_eq!(response["active"], false);
    }

    #[tokio::test]
    async fn unknown_tokens_are_inactive_and_ignored() {
        let runtime = runtime();
        let keys = KeySet::generate("RS256", DEFAULT_KEY_BITS).unwrap();
        let store = Store::new();
        assert_eq!(
            introspect(&runtime, &keys, &store, "nope", 1_100).await["active"],
            false
        );
        // Revoking an unknown token is a no-op.
        revoke(&runtime, &keys, &store, "nope").await;
    }
}
