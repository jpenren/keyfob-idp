//! Scope parsing and resolution.

use crate::config::ClientCfg;

use super::error::OAuthError;

/// The `offline_access` scope, which gates refresh tokens for public clients.
pub const OFFLINE_ACCESS: &str = "offline_access";

/// Splits a `scope` parameter into deduplicated, order-preserving values.
pub fn parse_scopes(scope: Option<&str>) -> Vec<String> {
    let mut scopes = Vec::new();
    if let Some(scope) = scope {
        for candidate in scope.split_whitespace() {
            if !scopes.iter().any(|existing| existing == candidate) {
                scopes.push(candidate.to_string());
            }
        }
    }
    scopes
}

/// Resolves the effective scope set for a client.
///
/// When `requested` is empty the client's allowed scopes are used, minus
/// `offline_access` (a refresh token must be asked for explicitly). Requested
/// scopes the client is not allowed to use are rejected with `invalid_scope`.
pub fn resolve_scopes(
    client: &ClientCfg,
    requested: Option<&str>,
) -> Result<Vec<String>, OAuthError> {
    let parsed = parse_scopes(requested);
    if parsed.is_empty() {
        let default = client
            .scopes()
            .into_iter()
            .filter(|scope| scope != OFFLINE_ACCESS)
            .collect();
        return Ok(default);
    }

    for scope in &parsed {
        if !client.allows_scope(scope) {
            let allowed = client.scopes().join(" ");
            return Err(OAuthError::invalid_scope(format!(
                "scope '{scope}' is not allowed for client '{}'",
                client.client_id
            ))
            .with_hint(format!("Allowed scopes for this client: {allowed}")));
        }
    }
    Ok(parsed)
}

/// Narrows `new` to a subset of `original` (refresh token scope reduction).
/// An empty `new` keeps the original scope.
pub fn narrow_scopes(
    client: &ClientCfg,
    original: &[String],
    requested: Option<&str>,
) -> Result<Vec<String>, OAuthError> {
    let parsed = parse_scopes(requested);
    if parsed.is_empty() {
        return Ok(original.to_vec());
    }
    let resolved = resolve_scopes(client, requested)?;
    for scope in &resolved {
        if !original.iter().any(|existing| existing == scope) {
            return Err(OAuthError::invalid_scope(format!(
                "scope '{scope}' was not part of the original grant"
            )));
        }
    }
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ClientCfg;

    fn client(scopes: Option<Vec<String>>) -> ClientCfg {
        ClientCfg {
            client_id: "c".into(),
            client_secret: Some("s".into()),
            public: false,
            redirect_uris: vec!["http://localhost/cb".into()],
            post_logout_redirect_uris: vec![],
            allowed_scopes: scopes,
            grant_types: None,
            audience: vec![],
            auto_approve: false,
        }
    }

    #[test]
    fn parses_and_deduplicates() {
        assert_eq!(parse_scopes(None), Vec::<String>::new());
        assert_eq!(
            parse_scopes(Some("openid  openid profile")),
            vec!["openid", "profile"]
        );
    }

    #[test]
    fn default_excludes_offline_access() {
        let scopes = resolve_scopes(&client(None), None).unwrap();
        assert!(scopes.contains(&"openid".to_string()));
        assert!(!scopes.contains(&OFFLINE_ACCESS.to_string()));
    }

    #[test]
    fn requested_scopes_must_be_allowed() {
        let error = resolve_scopes(&client(None), Some("openid admin")).unwrap_err();
        assert_eq!(error.code, super::super::error::ErrorCode::InvalidScope);
        assert!(resolve_scopes(&client(None), Some("openid")).is_ok());
    }

    #[test]
    fn narrowing_cannot_add_scopes() {
        let original = vec!["openid".to_string()];
        let error = narrow_scopes(&client(None), &original, Some("openid profile")).unwrap_err();
        assert_eq!(error.code, super::super::error::ErrorCode::InvalidScope);
        let narrowed = narrow_scopes(&client(None), &original, Some("openid")).unwrap();
        assert_eq!(narrowed, vec!["openid"]);
        // Empty request keeps the original set.
        assert_eq!(
            narrow_scopes(&client(None), &original, None).unwrap(),
            original
        );
    }
}
