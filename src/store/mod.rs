//! In-memory state: authorization codes, refresh tokens, browser sessions,
//! revoked token ids and the recent-token ring buffer used by `/debug/tokens`.
//!
//! No database, no persistence: everything lives in memory and disappears on
//! restart. Expired entries are removed by a periodic cleanup task.

use std::collections::{HashMap, VecDeque};

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

/// Maximum number of tokens kept for `GET /debug/tokens`.
pub const RECENT_TOKENS_CAPACITY: usize = 50;

/// Authorization code, single use, bound to the client and redirect URI.
#[derive(Debug, Clone, Serialize)]
pub struct AuthCode {
    pub code: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub username: String,
    pub scopes: Vec<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    #[serde(skip)]
    pub session_id: Option<String>,
    #[serde(skip)]
    pub auth_time: i64,
    #[serde(skip)]
    pub expires_at: i64,
}

/// Refresh token (rotating or not) with the identity it represents.
#[derive(Debug, Clone, Serialize)]
pub struct RefreshToken {
    pub token: String,
    pub client_id: String,
    pub username: String,
    pub scopes: Vec<String>,
    /// Token family used to detect replay after rotation.
    #[serde(skip)]
    pub family: String,
    #[serde(skip)]
    pub auth_time: i64,
    #[serde(skip)]
    pub session_id: Option<String>,
    #[serde(skip)]
    pub issued_at: i64,
    #[serde(skip)]
    pub expires_at: i64,
    #[serde(skip)]
    pub revoked: bool,
}

/// Browser login session referenced by the `keyfob_session` cookie.
#[derive(Debug, Clone)]
pub struct Session {
    pub id: String,
    pub username: String,
    pub auth_time: i64,
    pub expires_at: i64,
}

/// One entry of the `/debug/tokens` ring buffer.
#[derive(Debug, Clone, Serialize)]
pub struct RecentToken {
    pub issued_at: i64,
    pub grant_type: String,
    pub client_id: String,
    pub username: Option<String>,
    pub scopes: Vec<String>,
    pub access_token: Option<String>,
    pub id_token: Option<String>,
    pub refresh_token: Option<String>,
}

/// Token revoked before its natural expiry (access tokens are stateless JWTs).
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
pub struct RevokedToken {
    pub exp: i64,
}

#[derive(Debug, Default)]
struct Inner {
    codes: HashMap<String, AuthCode>,
    refresh: HashMap<String, RefreshToken>,
    sessions: HashMap<String, Session>,
    revoked: HashMap<String, RevokedToken>,
    recent: VecDeque<RecentToken>,
}

/// Result of a periodic cleanup pass; used for logging.
#[derive(Debug, Default, Clone, Copy)]
pub struct CleanupStats {
    pub codes: usize,
    pub refresh_tokens: usize,
    pub sessions: usize,
    pub revoked: usize,
}

impl CleanupStats {
    pub fn total(&self) -> usize {
        self.codes + self.refresh_tokens + self.sessions + self.revoked
    }
}

/// All server state. Cheap to clone: every field is behind an `Arc` at
/// `AppState` level.
#[derive(Debug, Default)]
pub struct Store {
    inner: RwLock<Inner>,
}

impl Store {
    pub fn new() -> Self {
        Self::default()
    }

    // ---------------------------------------------------------------- codes

    pub async fn insert_code(&self, code: AuthCode) {
        self.inner
            .write()
            .await
            .codes
            .insert(code.code.clone(), code);
    }

    /// Removes and returns the code: authorization codes are single use.
    pub async fn take_code(&self, code: &str) -> Option<AuthCode> {
        self.inner.write().await.codes.remove(code)
    }

    // ------------------------------------------------------------- refresh

    pub async fn insert_refresh_token(&self, token: RefreshToken) {
        self.inner
            .write()
            .await
            .refresh
            .insert(token.token.clone(), token);
    }

    pub async fn get_refresh_token(&self, token: &str) -> Option<RefreshToken> {
        self.inner.read().await.refresh.get(token).cloned()
    }

    /// Atomically revokes `old` and stores its rotated replacement.
    pub async fn rotate_refresh_token(&self, old: &str, new: RefreshToken) -> bool {
        let mut inner = self.inner.write().await;
        match inner.refresh.get_mut(old) {
            Some(entry) => {
                entry.revoked = true;
                inner.refresh.insert(new.token.clone(), new);
                true
            }
            None => false,
        }
    }

    /// Removes a refresh token (revocation endpoint).
    pub async fn remove_refresh_token(&self, token: &str) -> Option<RefreshToken> {
        self.inner.write().await.refresh.remove(token)
    }

    /// Revokes every refresh token of a family; returns how many were removed.
    /// Used when a rotated token is replayed.
    pub async fn revoke_refresh_family(&self, family: &str) -> usize {
        let mut inner = self.inner.write().await;
        let before = inner.refresh.len();
        inner.refresh.retain(|_, entry| entry.family != family);
        before - inner.refresh.len()
    }

    // ------------------------------------------------------------ sessions

    pub async fn insert_session(&self, session: Session) {
        self.inner
            .write()
            .await
            .sessions
            .insert(session.id.clone(), session);
    }

    pub async fn get_session(&self, id: &str) -> Option<Session> {
        self.inner.read().await.sessions.get(id).cloned()
    }

    pub async fn remove_session(&self, id: &str) -> Option<Session> {
        self.inner.write().await.sessions.remove(id)
    }

    // ------------------------------------------------------- revocations

    /// Marks an access token id as revoked until its original expiry.
    pub async fn revoke_access_token(&self, jti: &str, exp: i64) {
        self.inner
            .write()
            .await
            .revoked
            .insert(jti.to_string(), RevokedToken { exp });
    }

    pub async fn is_access_token_revoked(&self, jti: &str) -> bool {
        self.inner.read().await.revoked.contains_key(jti)
    }

    // ----------------------------------------------------------- debugging

    pub async fn record_recent_token(&self, token: RecentToken) {
        let mut inner = self.inner.write().await;
        if inner.recent.len() >= RECENT_TOKENS_CAPACITY {
            inner.recent.pop_front();
        }
        inner.recent.push_back(token);
    }

    /// Recently issued tokens, newest first.
    pub async fn recent_tokens(&self) -> Vec<RecentToken> {
        self.inner
            .read()
            .await
            .recent
            .iter()
            .rev()
            .cloned()
            .collect()
    }

    // ------------------------------------------------------------- cleanup

    /// Drops expired codes, refresh tokens, sessions and revocations.
    pub async fn cleanup(&self, now: i64) -> CleanupStats {
        let mut inner = self.inner.write().await;
        let mut stats = CleanupStats::default();

        let before = inner.codes.len();
        inner.codes.retain(|_, code| code.expires_at > now);
        stats.codes = before - inner.codes.len();

        let before = inner.refresh.len();
        // Revoked (already rotated) entries stay until they expire so that
        // replaying them can be detected and the whole family revoked.
        inner.refresh.retain(|_, token| token.expires_at > now);
        stats.refresh_tokens = before - inner.refresh.len();

        let before = inner.sessions.len();
        inner.sessions.retain(|_, session| session.expires_at > now);
        stats.sessions = before - inner.sessions.len();

        let before = inner.revoked.len();
        inner.revoked.retain(|_, entry| entry.exp > now);
        stats.revoked = before - inner.revoked.len();

        stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code(value: &str, expires_at: i64) -> AuthCode {
        AuthCode {
            code: value.to_string(),
            client_id: "c".into(),
            redirect_uri: "http://localhost/cb".into(),
            username: "alice".into(),
            scopes: vec!["openid".into()],
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            session_id: None,
            auth_time: 1,
            expires_at,
        }
    }

    fn refresh(value: &str, family: &str, expires_at: i64) -> RefreshToken {
        RefreshToken {
            token: value.to_string(),
            client_id: "c".into(),
            username: "alice".into(),
            scopes: vec!["openid".into()],
            family: family.to_string(),
            auth_time: 1,
            session_id: None,
            issued_at: 1,
            expires_at,
            revoked: false,
        }
    }

    #[tokio::test]
    async fn codes_are_single_use() {
        let store = Store::new();
        store.insert_code(code("abc", 100)).await;
        assert!(store.take_code("abc").await.is_some());
        assert!(store.take_code("abc").await.is_none());
    }

    #[tokio::test]
    async fn rotation_marks_the_old_token_revoked() {
        let store = Store::new();
        store.insert_refresh_token(refresh("old", "fam", 100)).await;
        assert!(
            store
                .rotate_refresh_token("old", refresh("new", "fam", 200))
                .await
        );

        let old = store.get_refresh_token("old").await.unwrap();
        assert!(old.revoked);
        assert!(store.get_refresh_token("new").await.is_some());
    }

    #[tokio::test]
    async fn family_revocation_removes_replays() {
        let store = Store::new();
        store.insert_refresh_token(refresh("a", "fam", 100)).await;
        store.insert_refresh_token(refresh("b", "fam", 100)).await;
        store.insert_refresh_token(refresh("c", "other", 100)).await;
        assert_eq!(store.revoke_refresh_family("fam").await, 2);
        assert!(store.get_refresh_token("c").await.is_some());
    }

    #[tokio::test]
    async fn cleanup_removes_expired_entries() {
        let store = Store::new();
        store.insert_code(code("expired", 10)).await;
        store.insert_code(code("valid", 1_000)).await;
        store
            .insert_refresh_token(refresh("expired", "f", 10))
            .await;
        store
            .insert_session(Session {
                id: "s".into(),
                username: "alice".into(),
                auth_time: 1,
                expires_at: 10,
            })
            .await;
        store.revoke_access_token("jti", 10).await;

        let stats = store.cleanup(100).await;
        assert_eq!(stats.codes, 1);
        assert_eq!(stats.refresh_tokens, 1);
        assert_eq!(stats.sessions, 1);
        assert_eq!(stats.revoked, 1);
        assert!(store.take_code("valid").await.is_some());
    }

    #[tokio::test]
    async fn recent_tokens_are_bounded_and_newest_first() {
        let store = Store::new();
        for index in 0..(RECENT_TOKENS_CAPACITY + 5) {
            store
                .record_recent_token(RecentToken {
                    issued_at: index as i64,
                    grant_type: "client_credentials".into(),
                    client_id: "c".into(),
                    username: None,
                    scopes: vec![],
                    access_token: None,
                    id_token: None,
                    refresh_token: None,
                })
                .await;
        }
        let recent = store.recent_tokens().await;
        assert_eq!(recent.len(), RECENT_TOKENS_CAPACITY);
        assert_eq!(recent[0].issued_at, (RECENT_TOKENS_CAPACITY + 4) as i64);
    }
}
