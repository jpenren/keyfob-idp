# HTTP endpoints

Every endpoint below is served by the router in
[`src/http/mod.rs`](../src/http/mod.rs). Responses that can carry sensitive
data (token, userinfo, introspection, discovery, health, `/ui/info`) are sent
with `Cache-Control: no-store` (and `Pragma: no-cache`), as required by
RFC 6749 §5.1. Unknown routes return `404 Not found` as `text/plain`. The
authorization endpoint returns `302 Found`; the login and logout endpoints
return `302` or an HTML page.

Base URL is the **issuer** — `http://127.0.0.1:9000` in the default
configuration. All paths are absolute and relative to the issuer.

## Route table

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/` | Home page + embedded token generator (404 when `ui.enabled: false`). |
| `GET` | `/healthz` | Health probe for scripts and containers. |
| `GET` | `/.well-known/openid-configuration` | OpenID Connect Discovery 1.0 document. |
| `GET` | `/.well-known/oauth-authorization-server` | OAuth 2.0 Authorization Server Metadata (RFC 8414). |
| `GET` | `/jwks` | JSON Web Key Set (RFC 7517). |
| `GET` | `/protocol/openid-connect/certs` | Keycloak-compatible alias of `/jwks`. |
| `GET`, `POST` | `/authorize` | Authorization endpoint (RFC 6749 + PKCE RFC 7636). |
| `GET`, `POST` | `/login` | Interactive login form and submission. |
| `POST` | `/token` | Token endpoint (RFC 6749). |
| `GET`, `POST` | `/userinfo` | OpenID Connect UserInfo (OIDC Core §5.3). |
| `POST` | `/introspect` | Token introspection (RFC 7662). |
| `POST` | `/revoke` | Token revocation (RFC 7009). |
| `GET`, `POST` | `/logout` | OIDC RP-initiated logout. |
| `GET` | `/ui/info` | JSON document powering the home page. |
| `GET` | `/ui/callback` | Redirect target of the token generator's authorization code flow. |
| `GET` | `/debug/tokens` | Recently issued tokens — **only when `debug: true`**. |

## Discovery documents

### `GET /.well-known/openid-configuration`

Returns the OpenID Connect metadata document. Its content is built in
[`src/oidc/discovery.rs`](../src/oidc/discovery.rs); endpoint URLs and both
capability lists are derived from the resolved configuration.

```json
{
  "issuer": "http://127.0.0.1:9000",
  "authorization_endpoint": "http://127.0.0.1:9000/authorize",
  "token_endpoint": "http://127.0.0.1:9000/token",
  "userinfo_endpoint": "http://127.0.0.1:9000/userinfo",
  "jwks_uri": "http://127.0.0.1:9000/jwks",
  "introspection_endpoint": "http://127.0.0.1:9000/introspect",
  "revocation_endpoint": "http://127.0.0.1:9000/revoke",
  "end_session_endpoint": "http://127.0.0.1:9000/logout",
  "response_types_supported": ["code"],
  "response_modes_supported": ["query"],
  "grant_types_supported": ["authorization_code", "client_credentials", "refresh_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "scopes_supported": ["openid", "profile", "email", "offline_access"],
  "claims_supported": [
    "iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "name",
    "preferred_username", "email", "email_verified", "roles", "groups", "sid"
  ],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
  "introspection_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
  "revocation_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
  "code_challenge_methods_supported": ["S256"],
  "claims_parameter_supported": false,
  "request_parameter_supported": false,
  "request_uri_parameter_supported": false,
  "require_request_uri_registration": false
}
```

Notes:

- `grant_types_supported` is the union of the grants allowed by the configured
  clients (plus the internal UI client), in the order `authorization_code`,
  `client_credentials`, `refresh_token`, `password`,
  `urn:ietf:params:oauth:grant-type:token-exchange`. `password` appears only
  when `allow_password_grant: true` and a client allows it; token exchange only
  when `allow_token_exchange: true` and a client allows it.
- `scopes_supported` is the four standard scopes plus any additional scope named
  in a client's `allowed_scopes`.
- `id_token_signing_alg_values_supported` is always `["RS256"]`.
- `code_challenge_methods_supported` is `["S256"]` only — `plain` is disabled.

### `GET /.well-known/oauth-authorization-server`

RFC 8414 allows additional members, so this endpoint returns **exactly the same
document** as the OpenID one. This keeps both metadata endpoints consistent for
clients that read either.

### `GET /jwks` and `GET /protocol/openid-connect/certs`

Both return the same RFC 7517 JWK Set with the single active signing key:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
      "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx...",
      "e": "AQAB"
    }
  ]
}
```

The `kid` is the RFC 7638 thumbprint of the key. `/jwks` is advertised in
discovery; the `/protocol/openid-connect/certs` alias exists for clients that
hard-code the Keycloak path.

## Authorization endpoint

### `GET /authorize` (also `POST`)

Validates the request and either redirects back with an authorization code or
shows the login page. Validation lives in
[`src/oauth/authorize.rs`](../src/oauth/authorize.rs).

Parameters:

| Parameter | Required | Meaning |
| --- | --- | --- |
| `response_type` | yes | Only `code` is supported. Anything else yields `unsupported_response_type`. |
| `client_id` | yes | Must match a configured client. |
| `redirect_uri` | conditional | Must match a registered URI exactly. Required when the client registers more than one; when exactly one is registered it may be omitted. |
| `scope` | no | Space-separated. Requesting a scope the client is not allowed yields `invalid_scope`. |
| `state` | recommended | Echoed back on both success and error. |
| `nonce` | recommended | Bound into the ID token. |
| `code_challenge` | for public clients | The S256 challenge (43 base64url characters). Mandatory for public clients. |
| `code_challenge_method` | no | Only `S256` (default when `code_challenge` is present). `plain` is rejected. |
| `prompt` | no | `none`, `login`, `consent` or `select_account`. `login`/`select_account` force re-authentication; `none` never shows a form. |
| `login_hint` | no | Accepted; advisory only. |
| `max_age` | no | Maximum age in seconds since the last authentication; forces a new login when exceeded. Must be an integer. |

Success redirect:

```
HTTP/1.1 302 Found
Location: http://localhost:3000/callback?code=<CODE>&state=xyz
```

Errors are handled in two ways:

- If the failure is detected **before** the client and redirect URI are trusted
  (missing `client_id`, unknown client, unregistered `redirect_uri`), the server
  renders the HTML error page (`error.html`) with the matching HTTP status
  (typically `400`).
- Otherwise the error is redirected back to the client's redirect URI carrying
  `error`, `error_description` and `state`:

  ```
  Location: http://localhost:3000/callback?error=invalid_request&error_description=...&state=xyz
  ```

When no session exists and the mode is `form`, the login page is rendered
(`200`). With `login.mode: auto` or a client with `auto_approve: true`, the
request is authenticated immediately.

## Login

### `GET /login`

Renders the login page. Query parameters `client_id` and `scope` are shown to
the user as context; `return_to` (or the request query) is preserved.

### `POST /login`

`application/x-www-form-urlencoded` body:

| Field | Meaning |
| --- | --- |
| `username` | Required. |
| `password` | Required in `form` mode; ignored in `picker` mode. |
| `return_to` | Local path to redirect to after login (defaults to `/`). Must be a same-site path starting with `/` and must not begin with `//` or contain `://`; otherwise the request is rejected. |
| `client_id`, `scopes` | Context copied back into the form. |

On success the server sets the `keyfob_session` cookie and responds with `302`
to `return_to`. The cookie is `HttpOnly`, `SameSite=Lax`, and `Secure` only
when TLS is enabled; its max-age is `tokens.refresh_ttl`. On failure the form is
re-rendered with `200` and an error message.

## Token endpoint

### `POST /token`

`application/x-www-form-urlencoded`. Client authentication uses either
`client_secret_basic` (`Authorization: Basic ...`) or `client_secret_post`
(`client_id` / `client_secret` form fields); public clients send `client_id`
only. Secrets are compared in constant time.

Supported grants:

| `grant_type` | Required parameters | Notes |
| --- | --- | --- |
| `authorization_code` | `code`, `redirect_uri`, `code_verifier` (if a challenge was used) | The code is single use and expires after 60 seconds. It is bound to the client, redirect URI and PKCE challenge. |
| `client_credentials` | — | Requires a confidential client. Rejects `offline_access`. No ID token is issued. |
| `refresh_token` | `refresh_token` | Optional `scope` may only narrow the original grant. Rotates by default; replaying a consumed token revokes the family. |
| `password` | `username`, `password` | Deprecated ROPC grant. Only when `allow_password_grant: true` and the client lists `password`. |
| `urn:ietf:params:oauth:grant-type:token-exchange` | `subject_token`, `subject_token_type` | RFC 8693 token exchange. Only when `allow_token_exchange: true` and the client lists `token_exchange`. Optional `actor_token` + `actor_token_type` (delegation), `requested_token_type`, `scope`, `resource`, `audience`. Always returns `issued_token_type` and never a `refresh_token`. |

Example (client credentials):

```sh
curl -sS -X POST http://127.0.0.1:9000/token \
  -d grant_type=client_credentials \
  -d client_id=my-backend \
  -d client_secret=dev-secret \
  -d scope="openid profile"
```

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6Ik...",
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "openid profile",
  "refresh_token": "0h5n...Q"
}
```

Example (authorization code + PKCE):

```sh
curl -sS -X POST http://127.0.0.1:9000/token \
  -d grant_type=authorization_code \
  -d client_id=my-spa \
  -d code=<CODE> \
  -d redirect_uri=http://localhost:3000/callback \
  -d code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

An `id_token` is included when the request is bound to a user **and** the
`openid` scope was granted (all grants except client credentials). A
`refresh_token` is included only when the client allows the `refresh_token`
grant and (for public clients) `offline_access` was granted.

Example (token exchange, delegation):

```sh
curl -sS -X POST http://127.0.0.1:9000/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d client_id=my-gateway \
  -d client_secret=gateway-secret \
  -d subject_token=<ACCESS_TOKEN> \
  -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
  -d actor_token=<ACTOR_ACCESS_TOKEN> \
  -d actor_token_type=urn:ietf:params:oauth:token-type:access_token
```

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6Ik...",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "openid profile"
}
```

The subject token must be an unexpired token issued by this server. Accepted
`*_token_type` values are `access_token`, `jwt`, `id_token` and `refresh_token`;
a `refresh_token` subject must belong to the authenticating client, and a
refresh token cannot be used as an actor. Scopes only ever narrow. Requested
`resource` / `audience` values must match the client's configured `audience` (or
its own `client_id`), otherwise the request fails with `invalid_target`. With an
`actor_token` the issued access token carries an `act` claim (`sub` and `iss` of
the actor, with the actor's own `act` nested inside); without one the server
impersonates the subject.

## UserInfo

### `GET` / `POST /userinfo`

Accepts the access token as `Authorization: Bearer <token>` or as the
`access_token` query/form parameter (GET form uses the query string). Only
**access tokens** are accepted: because only access tokens carry `client_id`,
an ID token is rejected with `invalid_token`. Revoked tokens are rejected. A
`client_credentials` token has no user and is rejected.

```sh
curl -sS http://127.0.0.1:9000/userinfo \
  -H "Authorization: Bearer <ACCESS_TOKEN>"
```

```json
{
  "sub": "alice",
  "preferred_username": "alice",
  "name": "Alice Doe",
  "email": "alice@example.test",
  "email_verified": true,
  "roles": ["admin", "user"],
  "groups": ["engineering"]
}
```

The returned claims are gated by the granted scopes: `profile` adds
`preferred_username` and `name`, `email` adds `email` and `email_verified`.
`roles` and `groups` are always included when non-empty. Errors use the
RFC 6750 bearer form: JSON body plus a `WWW-Authenticate: Bearer ...` header.

## Introspection

### `POST /introspect`

RFC 7662. Requires client authentication. The `token` parameter is required.

```sh
curl -sS -X POST http://127.0.0.1:9000/introspect \
  -d client_id=my-backend \
  -d client_secret=dev-secret \
  -d token=<TOKEN>
```

Active access token:

```json
{
  "active": true,
  "token_type": "Bearer",
  "scope": "openid profile",
  "client_id": "my-backend",
  "sub": "my-backend",
  "aud": ["my-backend"],
  "iss": "http://127.0.0.1:9000",
  "exp": 1718000000,
  "iat": 1717999100,
  "nbf": 1717999100,
  "jti": "…",
  "exp_in": 900
}
```

Opaque refresh tokens are introspected too (`token_type: "refresh_token"`).
Expired, revoked, unknown or wrongly signed tokens return `{ "active": false }`
with HTTP `200`. A token is active only if the signature is valid, it is not
expired, it was not revoked and it was issued by this server.

## Revocation

### `POST /revoke`

RFC 7009. Requires client authentication and a `token` parameter. Revoking an
access token records its `jti` until the original `exp`; revoking a refresh
token removes it. Unknown tokens are ignored.

```sh
curl -sS -X POST http://127.0.0.1:9000/revoke \
  -d client_id=my-backend \
  -d client_secret=dev-secret \
  -d token=<TOKEN>
```

The response is `200` with an empty body (even for unknown tokens, per the
RFC), with `Cache-Control: no-store`.

## Logout

### `GET` / `POST /logout`

OIDC RP-initiated logout. Ends the browser session referenced by the
`keyfob_session` cookie and clears the cookie.

| Parameter | Meaning |
| --- | --- |
| `post_logout_redirect_uri` | Where to redirect after logout. Only honoured if it is registered for the client. |
| `client_id` | Identifies the client whose registered URIs are checked. |
| `id_token_hint` | Alternative to `client_id`: the audience of the (possibly expired) ID token identifies the client. |
| `state` | Appended to the redirect as `state`. |

If a valid, registered `post_logout_redirect_uri` is supplied, the response is
`302` to that URI. Otherwise an HTML confirmation page (`logout.html`) is
rendered with `200`.

## UI endpoints

### `GET /` and `GET /ui/info`

`/` renders the home page with the embedded token generator. `/ui/info`
returns the JSON that powers it. Both return `404` when `ui.enabled: false`.

The page is self-contained: the logo is inlined as SVG, follows the light/dark
browser colour scheme and references no external assets.

`/ui/info` fields include: `version`, `os`, `arch`, `uptime_seconds`,
`started_at`, `config_path`, `config_loaded_at`, `config_last_attempt_at`,
`config_error`, `warnings`, `issuer`, `tls`, `loopback`, `debug`,
`allow_password_grant`, `allow_token_exchange`, `login_mode`, `prefill_secrets`,
`algorithm`, `kid`, `key_origin`, `grants`, `scopes`, `clients`, `users` and
`endpoints`.

Each client entry reports `client_id`, `type` (`internal`, `public` or
`confidential`), `public`, `redirect_uris`, `post_logout_redirect_uris`,
`audience`, `scopes`, `grants`, `auto_approve` and — **only** when
`ui.prefill_secrets` is enabled *and* the server is bound to loopback —
`client_secret`. Each user entry reports `username`, `email`, `name`, `roles`
and `groups`; passwords and password hashes are never exposed.

### `GET /ui/callback`

The redirect target registered for the internal `keyfob-ui` client. It reads
the `code`/`error` from the query string, exchanges the code at `/token` using
the PKCE verifier stored in the browser, and reports the tokens back to the
token generator (via `postMessage` or `sessionStorage`). A client can only be
used from the authorization-code tab when it registers `<origin>/ui/callback`
as one of its `redirect_uris`.

### `GET /debug/tokens`

Returns the 50 most recently issued tokens (newest first), with `count` and a
`tokens` array. **Only when `debug: true`**; otherwise `404`. This endpoint
exposes live access, ID and refresh tokens — never enable it on a shared or
network-exposed machine.

```json
{
  "count": 1,
  "tokens": [
    {
      "issued_at": 1717999100,
      "grant_type": "client_credentials",
      "client_id": "my-backend",
      "username": null,
      "scopes": ["openid", "profile"],
      "access_token": "eyJ...",
      "id_token": null,
      "refresh_token": "0h5n..."
    }
  ]
}
```

## Health

### `GET /healthz`

```json
{ "status": "ok", "version": "0.1.0", "uptime_seconds": 42 }
```

Always `200`, with `Cache-Control: no-store`.

## Error codes

Error codes are defined in [`src/oauth/error.rs`](../src/oauth/error.rs). The
token, introspection and revocation endpoints return RFC 6749 JSON bodies
(`{"error": "...", "error_description": "..."}`) with `Cache-Control: no-store`.
`/userinfo` uses the same body plus a `WWW-Authenticate` header. The
authorization endpoint redirects the error back or shows an HTML page.

| `error` | HTTP status | Typical cause |
| --- | --- | --- |
| `invalid_request` | 400 | Missing or malformed parameter (for example missing `redirect_uri`, bad PKCE challenge, `max_age` not an integer). |
| `invalid_client` | 401 | Unknown client, missing/incorrect secret, or a public client sending a secret. |
| `invalid_grant` | 400 | Code/refresh token unknown, expired, already used, issued to another client, wrong redirect URI, PKCE mismatch, or a token-exchange subject token that is invalid/expired/revoked or bound to another client. |
| `unauthorized_client` | 400 | The client is not allowed to use the requested grant (or `client_credentials` on a public client). |
| `unsupported_grant_type` | 400 | Unknown or disabled grant (for example `password` without `allow_password_grant`, `token_exchange` without `allow_token_exchange`, or a device-code URN). |
| `unsupported_response_type` | 400 | `response_type` other than `code` (implicit is not implemented). |
| `invalid_scope` | 400 | A requested scope is not allowed for the client, scope narrowing adds a scope, or `offline_access` is used with client credentials or token exchange. |
| `invalid_target` | 400 | Token exchange only: the requested `resource` / `audience` is not among the client's configured `audience` values. |
| `access_denied` | 400 | Access was refused. |
| `invalid_token` | 401 | `/userinfo` only: missing/expired/revoked token, an ID token instead of an access token, or no user. |
| `insufficient_scope` | 403 | `/userinfo` only: the token lacks a required scope. |
| `login_required` | 400 | `prompt=none` was requested but there is no active session. |
| `interaction_required` | 400 | An interaction is needed (reserved for interactive flows). |
| `consent_required` | 400 | Consent is needed (reserved; no consent screen is implemented). |
| `temporarily_unavailable` | 503 | The server is temporarily unable to serve the request. |
| `server_error` | 500 | Unexpected internal failure (for example signing failure or a missing default user for automatic login). |

Any `4xx`/`5xx` that is not one of the above uses `server_error` / `400`.
Human-readable hints are shown on the HTML error page and in the UI but are
**never** sent in JSON responses.
