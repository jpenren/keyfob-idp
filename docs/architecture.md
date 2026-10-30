# Architecture

This document describes how keyfob-idp is put together: the module layout,
the request flows, and the decisions that shape the code. If you are about to
change public behaviour, read this first and record any new decision here.

## Overview

keyfob-idp is a **single cargo crate** (`keyfob-idp`) that produces a
**library and one binary**. The library holds every piece of domain logic and is
covered by unit tests that need no network. The binary (`keyfob`, `src/main.rs`)
is a thin entry point that parses the CLI, installs logging and delegates to
[`src/cli.rs`](../src/cli.rs).

```
src/main.rs ──▶ src/cli.rs ──▶ config / crypto / state / http
                                   │
   ┌───────────────────────────────┼─────────────────────────────┐
   │  domain (no axum)             │            adapters          │
   │  oauth/  oidc/  store/        │  http/     ui/               │
   │  config/ crypto/              │  (axum)    (templates)       │
   └───────────────────────────────┴─────────────────────────────┘
                                   │
                              src/state.rs
                      (Runtime snapshot, AppState, reload)
```

The dependency direction is one-way: `http` depends on `oauth`, `oidc`, `store`,
`crypto` and `state`; the domain modules never depend on `http` or `axum`. That
keeps the protocol logic testable without a listening socket.

## Module map

| Module | Path | Responsibility |
| --- | --- | --- |
| `config` | [`src/config/`](../src/config/) | YAML models, loading, validation, duration parsing, environment overrides, warnings and the example config. |
| `crypto` | [`src/crypto/`](../src/crypto/) | RSA signing keys + JWKS, JWT encode/decode, argon2 password hashing, constant-time comparison, PKCE `S256`, random tokens. |
| `store` | [`src/store/`](../src/store/) | Pure in-memory state: authorization codes, refresh tokens (with families), sessions, revoked `jti`s and the recent-token ring buffer for `/debug/tokens`. |
| `oauth` | [`src/oauth/`](../src/oauth/) | Grant logic and RFC behaviour: `/token`, `/authorize`, client authentication, scopes, introspection (RFC 7662) and revocation (RFC 7009). |
| `oidc` | [`src/oidc/`](../src/oidc/) | Claim construction (access token, ID token, userinfo) and the discovery documents (OIDC Discovery 1.0 / RFC 8414). |
| `http` | [`src/http/`](../src/http/) | The axum router and thin handlers that parse requests, call the domain and serialise responses. |
| `ui` | [`src/ui/`](../src/ui/) | Templates embedded with `include_str!`, with an optional on-disk override. The brand mark is inlined as SVG, so the pages reference no external assets. |
| `cli` | [`src/cli.rs`](../src/cli.rs) | `run`, `validate`, `init`, `hash-password`, `gen-keys`, `token`; hot-reload watcher and the cleanup task. |
| `state` | [`src/state.rs`](../src/state.rs) | `Runtime` (resolved config), `AppState` (shared server state) and hot reload. |

### `config`

[`src/config/model.rs`](../src/config/model.rs) contains the serde structs for
`keyfob.yaml`. The issuer is derived from `server.host` + `server.port` when
`server.issuer` is omitted. [`src/config/duration.rs`](../src/config/duration.rs)
parses human-friendly TTLs (`30s`, `15m`, `8h`, `7d`; a bare number is seconds).
The loader applies `KEYFOB_*` environment variables on top of the file, and
`validate`/warnings are surfaced by `keyfob validate` and `/ui/info`.

### `crypto`

- Signing is **RS256 only**. [`src/crypto/keys.rs`](../src/crypto/keys.rs)
  generates a 2048-bit RSA key, derives `kid` as the **RFC 7638 JWK thumbprint**
  (SHA-256 over `{"e":…,"kty":"RSA","n":…}`) and serves the public half as a JWK
  Set at `/jwks`.
- [`src/crypto/jwt.rs`](../src/crypto/jwt.rs) wraps `jsonwebtoken` for encoding
  and decoding.
- [`src/crypto/password.rs`](../src/crypto/password.rs) hashes and verifies
  argon2 PHC strings and provides `constant_time_eq`.
- [`src/crypto/pkce.rs`](../src/crypto/pkce.rs) implements PKCE; only `S256` is
  accepted.
- [`src/crypto/random.rs`](../src/crypto/random.rs) issues opaque tokens and
  identifiers.

### `store`

Everything lives in [`src/store/mod.rs`](../src/store/mod.rs): `HashMap`s behind
a `tokio::sync::RwLock`, wrapped in `Arc<Store>`. There is no database and no
persistence. A background task in `cli.rs` calls `Store::cleanup` every 60
seconds to drop expired codes, refresh tokens, sessions and revocations.

### `oauth`

Domain logic, deliberately **axum-free**. [`src/oauth/error.rs`](../src/oauth/error.rs)
defines `OAuthError` / `ErrorCode` with `.status()`; the HTTP layer decides
whether an error becomes a JSON body or a redirect.
[`src/oauth/token.rs`](../src/oauth/token.rs) implements the standard grants plus
RFC 8693 token exchange,
[`src/oauth/authorize.rs`](../src/oauth/authorize.rs) validates authorization
requests and mints codes, and [`src/oauth/auth.rs`](../src/oauth/auth.rs) handles
client authentication.

### `oidc`

[`src/oidc/claims.rs`](../src/oidc/claims.rs) builds the claim sets and
[`src/oidc/discovery.rs`](../src/oidc/discovery.rs) renders the discovery
documents.

### `http`

[`src/http/mod.rs`](../src/http/mod.rs) is the router. Handlers are split by
area: `authorize`, `token`, `metadata` and the shared `support` helpers. The
fallback returns a plain-text `404`.

## Request flows

### Authorization Code + PKCE

```
browser ──GET /authorize──▶ authorize_get
                              │ validate client / redirect_uri / scope / PKCE
                              │ (no session?) ──▶ login page (GET /login)
                              ▼
browser ──POST /login─────▶ login_submit ──▶ check password (argon2)
                              │ create session cookie (keyfob_session)
                              ▼
                           redirect to redirect_uri?code=…&state=…
                              │
client  ──POST /token──────▶ token (grant_type=authorization_code)
                              │ client auth, PKCE verify, single-use code
                              ▼
                    { access_token, id_token, refresh_token? }
```

1. `GET /authorize` validates everything it can before trusting the client. If
   the `client_id` or `redirect_uri` is invalid, it renders an HTML error page
   (`AuthorizeFailure::Fatal`) instead of redirecting. After the client is
   trusted, errors are returned to the client by redirect.
2. If there is no valid session, the login page is shown. `login.mode` controls
   it: `form` (password form), `picker` (choose a user) or `auto` (no screen,
   authenticate as `login.default_user`). Clients with `auto_approve: true` skip
   the interactive step.
3. The authorization code is stored with the `client_id`, `redirect_uri`,
   `code_challenge`, scopes, `nonce` and session id. It is **single use** and
   expires after 60 seconds (`CODE_TTL_SECONDS`).
4. `POST /token` with `grant_type=authorization_code` re-authenticates the
   client, verifies the PKCE `code_verifier` against the stored challenge,
   consumes the code and issues tokens.

### Client Credentials

```
client ──POST /token (grant_type=client_credentials)──▶ token
          Basic auth or client_secret_post
          no user; sub = client_id
```

There is no user, so no ID token is produced even when `openid` is requested.
`offline_access` is rejected for this grant. A refresh token is minted only for
confidential clients that allow `refresh_token`.

### Refresh Token

`grant_type=refresh_token` looks up the opaque refresh token, checks it belongs
to the same client, then rotates it when `tokens.rotate_refresh` is enabled. A
rotated token records its **family**; replaying an already-used token revokes
the entire family (`Store::revoke_refresh_family`) and returns `invalid_grant`.
This is standard rotating-refresh-token replay detection.

### Token Exchange (RFC 8693)

```
client ──POST /token (grant_type=urn:…:token-exchange)──▶ token
          subject_token + subject_token_type
          optional actor_token + actor_token_type
          optional requested_token_type / scope / resource / audience
```

The exchange is gated twice: `allow_token_exchange: true` at the top level and
`token_exchange` in the client's `grant_types`. The subject token is validated
like an introspection target — JWT signature, issuer and `exp` against the
request clock, then `jti` revocation for access tokens, or a store lookup for
opaque refresh tokens (which must belong to the authenticating client and can
never act as the actor). Scopes only ever narrow. `resource` / `audience` must
match the client's configured `audience` (or its own `client_id`) or the request
fails with `invalid_target`; when accepted, they override the access token `aud`.
Without an `actor_token` the server impersonates the subject; with one it adds an
`act` claim (`sub` and `iss` of the actor, with the actor's own `act` nested for
a delegation chain). A refresh token is never minted.

### Token shapes

| Token | Key claims |
| --- | --- |
| Access token | `iss`, `sub` (user or `client_id`), `aud` (defaults to `[client_id]`, or `client.audience`), `azp`, `client_id`, `scope`, `iat`, `nbf`, `exp`, `jti`, optional `sid` and `act` (delegation), plus identity and client claims. |
| ID token | `iss`, `sub`, `aud` (= `client_id`), `azp`, `iat`, `exp`, `auth_time`, `jti`, optional `nonce`, `sid` and `at_hash`, plus identity and client claims. Only issued when the `openid` scope and a user are present. |
| Userinfo | `sub` plus the identity claims allowed by the granted scopes and the client claims. |

Identity claims are gated by scope: `profile` yields `preferred_username` /
`name`, `email` yields `email` / `email_verified`. `roles` and `groups` and any
custom `claims` (from the user or the client) are always included (this is a
development tool). Custom claims cannot override reserved claims
(`RESERVED_CLAIMS` in `oidc/claims.rs`). User claim values may contain minijinja
templates such as `{{username}}@example.test`; client claim values are literal
JSON.

## State, concurrency and hot reload

- [`AppState`](../src/state.rs) is cheap to clone: it wraps the current
  `Runtime` in `Arc<RwLock<Arc<Runtime>>>`, plus `Arc<KeySet>` and
  `Arc<Store>`.
- On every request the handler takes a consistent snapshot with
  `state.runtime().await`, so a reload never leaves a request with half-old,
  half-new configuration.
- When the YAML file changes (watched via `notify`, debounced 300 ms), the
  loader re-reads and re-validates it. **On failure the previous configuration
  keeps serving** and the error is recorded in `ReloadStatus` (visible in
  `/ui/info`). On success the `Runtime` and templates are swapped atomically.
- CORS is the one exception: the `CorsLayer` is built once at startup, so
  changing `cors` requires a restart. This is documented in the config and in
  `/ui/info`.

## Decision log

Each entry records the decision and the reason it was made. Follow these unless
a new decision explicitly supersedes them.

1. **Single crate with a lib + bin.** The library keeps the domain testable
   without the binary; the binary stays tiny. `autobins = false`, so only
   `src/main.rs` builds a binary.
2. **In-memory state only.** No database and no persistence of tokens. The tool
   is for development; restarting should give a clean slate. The only file
   written is the signing key.
3. **Signing key persisted as JSON with mode 0600.** The key is stored at
   `keys.path` (default `.keyfob/keys.json`) so tokens survive a restart.
   On Unix the file is restricted to the owner (`restrict_permissions`); on
   Windows the parent-directory ACLs are inherited. `keys.persist: false` makes
   the key ephemeral. `kid` is the RFC 7638 thumbprint, so rotating keys
   produces a stable, standards-based identifier.
4. **Domain logic has no `axum` dependency.** `oauth`, `oidc`, `store`,
   `config` and `crypto` can be unit-tested without a network, and the HTTP
   layer stays a thin adapter.
5. **Typed errors with `thiserror`; `anyhow` only in `main`.** The domain uses
   `OAuthError`, `ConfigError`, `KeyError`, `PasswordError`, `CliError`, etc.
   `anyhow` is confined to `fn main() -> anyhow::Result<()>`, where context is
   useful and no caller needs to match on the error.
6. **No `unwrap` / `expect` on request paths.** Handler and domain code returns
   `Result`. Panics would abort the request (or the process with
   `panic = "abort"`). `#![forbid(unsafe_code)]` is set in both `src/lib.rs` and
   `src/main.rs`.
7. **Secrets compared in constant time (`subtle`).** Client secrets (Basic and
   form) and other secret comparisons use `constant_time_eq`, avoiding timing
   leaks.
8. **Exact `redirect_uri` matching.** The redirect URI must match a registered
   value exactly; there is no prefix or wildcard matching.
9. **PKCE `S256` is mandatory for public clients; `plain` is disabled.** Public
   clients cannot keep a secret, so PKCE is required. `plain` offers no
   protection against a code interception and is rejected.
10. **No implicit flow.** Only `response_type=code` is supported. Implicit is
    deprecated for browser apps and leaks tokens in URLs.
11. **Default bind is `127.0.0.1`.** The server is not reachable off-host by
    default. Windows is a first-class target: no hand-written path separators
    and no OS-specific APIs without a portable fallback.
12. **Never log passwords or client secrets.** Tokens are only exposed through
    `/debug/tokens` when `debug: true`. Startup prints a development-only
    warning, and the home page shows it permanently.
13. **TLS uses `rustls` with the `ring` provider.** `Cargo.toml` pins
    `rustls` with `features = ["ring"]` and `axum-server` with
    `tls-rustls-no-provider`, and `crypto::install_crypto_provider()` installs
    the ring provider before the server starts. This avoids `openssl` and the
    `aws-lc-rs` C toolchain, keeping the Windows build simple. `--tls` generates
    a self-signed certificate with `rcgen` for `localhost` / `127.0.0.1` / `::1`.
14. **CORS is applied at startup only.** The layer is built once from
    `cors` config; changing it needs a restart. Keeping it out of the hot-reload
    path avoids rebuilding the router (and losing connections) on every file
    save.
15. **Hot reload keeps the previous configuration on invalid input.** A broken
    edit must not take down a running dev server; the error is logged and shown
    in `/ui/info`, and the last good config keeps serving.
16. **Release profile optimised for size.** `opt-level = "z"`, `lto = true`,
    `codegen-units = 1`, `strip = true`, `panic = "abort"`. The tool is small by
    design; `panic = "abort"` is acceptable because request paths do not panic.
17. **Authorization codes are single use and bound** to `client_id`,
    `redirect_uri` and `code_challenge`, with a 60-second TTL.
18. **Refresh tokens rotate with family revocation.** Replay of a rotated token
    revokes the whole family, limiting the damage of a stolen refresh token.
19. **Access token `aud` defaults to `[client_id]`.** A client can override it
    with `audience`; this keeps tokens usable by a resource server that the dev
    configured explicitly.
20. **The internal `keyfob-ui` client is registered automatically** when
    `ui.enabled`. It is a public PKCE client whose redirect URI is
    `<issuer>/ui/callback`; it backs the embedded token generator and is not
    meant to be used by real applications.
21. **Release assets use stable, unversioned file names.** `.github/workflows/release.yml`
    publishes `keyfob-linux-x86_64.tar.gz`, `keyfob-windows-x86_64.zip`,
    `keyfob-macos-arm64.tar.gz`, `keyfob-macos-x86_64.tar.gz`,
    `keyfob-src.tar.gz` / `keyfob-src.zip` and a `SHA256SUMS` file, so
    `.../releases/latest/download/<asset>` always resolves to the newest build
    without knowing the tag. The version stays visible inside the archive
    (`keyfob-<tag>-<target>/`), and the workflow refuses to publish when the tag
    does not match `Cargo.toml`.
22. **Token exchange is opt-in and never issues refresh tokens.** RFC 8693 is
    gated behind `allow_token_exchange: true` plus the per-client
    `token_exchange` grant, like the password grant. Only access tokens can be
    requested, scopes never widen, `resource` / `audience` must be pre-approved
    per client (`invalid_target` otherwise), and no refresh token is minted —
    an exchange is a short-lived projection of an existing identity, not a new
    session. Delegation is expressed with the standard `act` claim.

## Related reading

- [`docs/configuration.md`](configuration.md) — every key and environment variable.
- [`docs/endpoints.md`](endpoints.md) — the HTTP surface and error codes.
- [`docs/getting-started.md`](getting-started.md) — quick start.
- [`docs/comparison.md`](comparison.md) — how it compares to Keycloak and Dex.
