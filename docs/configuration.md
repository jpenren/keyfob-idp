# Configuration reference

keyfob-idp is configured by a single YAML file. Every section has a sensible
default; only `clients` (and `users`, depending on the enabled flows) is
required. Unknown fields are rejected, so a typo produces an immediate error
with the offending field path rather than being silently ignored.

```sh
keyfob validate --config keyfob.yaml   # parse + validate, no server
```

The example written by `keyfob init` lives in
[`src/config/example.rs`](../src/config/example.rs); the annotated reference of
every option is [`examples/keyfob.full.yaml`](../examples/keyfob.full.yaml).

## Precedence

```
CLI flags  >  KEYFOB_* environment variables  >  keyfob.yaml  >  built-in defaults
```

- CLI flags (`--host`, `--port`, `--issuer`, `--tls`) are applied on top of the
  loaded configuration in [`src/cli.rs`](../src/cli.rs).
- `KEYFOB_*` variables are applied on top of the YAML in
  [`apply_env`](../src/config/mod.rs).
- Validation runs after both, so a bad override fails with a located error.

## File discovery

| Order | Source |
| --- | --- |
| 1 | `--config <path>` |
| 2 | `KEYFOB_CONFIG` (if set and non-empty) |
| 3 | `./keyfob.yaml` |
| 4 | `./keyfob.yml` |

## `server`

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `host` | string | `127.0.0.1` | Interface to bind. Anything that is not loopback logs a prominent warning. |
| `port` | integer | `9000` | TCP port. Must be between 1 and 65535. |
| `issuer` | string | derived | Issuer identifier used in discovery, tokens and cookies. Trailing `/` is stripped. When omitted it is derived from `host` and `port` (see below). |
| `tls` | boolean | `false` | Serve HTTPS with an automatically generated self-signed certificate (valid for `localhost`, `127.0.0.1` and `::1`). |

**Issuer derivation.** When `issuer` is omitted the issuer is
`{scheme}://{host}:{port}`, where `scheme` is `https` when `tls: true` and
`http` otherwise. Wildcard bind addresses (`0.0.0.0`, `::`) become
`localhost`, because they are not valid issuer identifiers. A bare IPv6 literal
is wrapped in brackets. Examples (from
[`src/config/model.rs`](../src/config/model.rs)):

- `host: 127.0.0.1`, `port: 9000` → `http://127.0.0.1:9000`
- `host: 0.0.0.0`, `port: 9000` → `http://localhost:9000`
- `issuer: https://idp.test/` → `https://idp.test`

Once a client has been configured against an issuer, changing the host, port or
issuer means clients must be reconfigured. The issuer must match exactly the URL
the client uses.

## `keys`

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `algorithm` | string | `RS256` | Signature algorithm. **Only `RS256` is supported** in this version (ES256 and EdDSA are planned). |
| `persist` | boolean | `true` | When true, the generated key is written to `path` so tokens stay valid across restarts. |
| `path` | path | `.keyfob/keys.json` | Where the key is stored. Created with mode `0600` on Unix. |

The key is a 2048-bit RSA key pair. Its `kid` is the **RFC 7638 JWK
thumbprint** (SHA-256 over `{"e":...,"kty":"RSA","n":...}` with members in
lexical order), so it is stable for a given key regardless of how the file was
written. The persisted JSON contains `kid`, `algorithm`, `private_pem`,
`public_pem` and `created_at`. With `persist: false` the key is regenerated on
every start (`key_origin: ephemeral` in `/ui/info`) and previously issued
tokens stop verifying. Use `keyfob gen-keys --force` to rotate the key
deliberately.

## `tokens`

Durations are written as a number with an optional unit suffix —
`s` seconds, `m` minutes, `h` hours, `d` days. A bare number means seconds.
Examples: `30s`, `15m`, `8h`, `7d`, `45`.

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `access_ttl` | duration | `15m` (900s) | Lifetime of issued access tokens. |
| `refresh_ttl` | duration | `8h` | Lifetime of refresh tokens. Also used as the browser session lifetime. |
| `id_ttl` | duration | `15m` (900s) | Lifetime of issued ID tokens. |
| `rotate_refresh` | boolean | `true` | Issue a new refresh token on every refresh and mark the presented one as consumed. Replaying a consumed token revokes the whole token family. |

Short values are a first-class feature: `access_ttl: 5s` makes it easy to test
refresh behaviour. Validation requires every TTL to be greater than zero and
`refresh_ttl >= access_ttl`.

## `ui`

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `enabled` | boolean | `true` | Serve the home page and token generator at `/`, plus `/ui/info` and `/ui/callback`. When false those routes return 404 and no internal client is registered. |
| `prefill_secrets` | boolean | `false` | **Dev only.** Pre-fill confidential client secrets in the token generator form. Only honoured when the server is bound to loopback; `/ui/info` reports the effective value as `prefill_secrets`. |

## `login`

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `mode` | enum | `form` | Login behaviour: `form`, `picker` or `auto`. |
| `template_dir` | path | — | Directory with custom `login.html` / `error.html` templates. Must exist. Files there override the embedded templates. |
| `default_user` | string | first user | User authenticated by `login.mode: auto` and by clients with `auto_approve: true`. Must name a configured user. |

Login modes:

| Mode | Behaviour |
| --- | --- |
| `form` | Username and password form. Passwords are checked against each user's `password` (argon2 hash or plaintext). |
| `picker` | One-click user picker: clicking a user signs in with no password. Logs a warning because it bypasses authentication. |
| `auto` | No login screen: every authorization request authenticates immediately as `default_user` (or the first configured user). |

## `cors`

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `enabled` | boolean | `false` | Send CORS headers, needed by browser SPAs hosted on another origin. Applied at startup only; changing it requires a restart. |
| `origins` | list of strings | `["*"]` | Allowed origins. Must not be empty when `enabled` is true. |
| `allow_credentials` | boolean | `false` | Allow cookies/credentials. When `origins` contains `*` the request origin is reflected instead of literal `*` (which is invalid with credentials). |

The layer allows methods `GET`, `POST`, `OPTIONS` and the headers
`Authorization`, `Content-Type` and `Accept`.

## Top-level switches

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `debug` | boolean | `false` | Expose `GET /debug/tokens` with the 50 most recently issued tokens. Never enable this on a shared machine. |
| `allow_password_grant` | boolean | `false` | Enable the deprecated Resource Owner Password Credentials grant. Required for any client whose grants include `password`. |
| `allow_token_exchange` | boolean | `false` | Enable the Token Exchange grant (RFC 8693). Required for any client whose grants include `token_exchange`. |
| `clients` | list | required | Client definitions (below). At least one is required. |
| `users` | list | see below | User definitions. Required when `allow_password_grant` is true or any client allows `authorization_code`. |

## `clients[]`

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `client_id` | string | required | Unique identifier. Must not be empty or duplicated. |
| `client_secret` | string | — | Plaintext secret. Required for confidential clients; forbidden for public clients. |
| `public` | boolean | `false` | Public client: no secret, PKCE is always required. |
| `redirect_uris` | list of strings | `[]` | Exact redirect URIs for the authorization code flow. |
| `post_logout_redirect_uris` | list of strings | `[]` | URIs accepted as `post_logout_redirect_uri` at `/logout`. |
| `allowed_scopes` | list of strings | `[openid, profile, email, offline_access]` | Scopes this client may request. Must not be empty or contain empty entries. |
| `grant_types` | list of enum | inferred | Grants this client may use (see below). |
| `audience` | list of strings | `[]` | Values placed in the access token `aud` claim. When empty, `aud` defaults to `[client_id]`. |
| `claims` | map | `{}` | Extra claims merged into the access token, ID token and userinfo for this client. Values are literal JSON: strings, lists or nested objects (see below). |
| `auto_approve` | boolean | `false` | Skip the login screen for this client and authenticate as `login.default_user` (or the first user). |

URI validation is a light check that the value is an absolute URI with a valid
scheme (for example `http://localhost:3000/callback`, `myapp://callback` or
`com.example.app:/callback`); exact matching happens later at `/authorize`.

A client is **confidential** when `public` is false and a `client_secret` is
present. Otherwise it is **public**.

### Grant inference

When `grant_types` is omitted, grants are inferred from the client's shape in
[`ClientCfg::grants`](../src/config/model.rs):

| Condition | Inferred grant |
| --- | --- |
| `redirect_uris` is not empty | `authorization_code` |
| the client is confidential | `client_credentials` |
| `redirect_uris` is not empty **or** the client is confidential | `refresh_token` |

So a public SPA with a redirect URI gets `authorization_code` + `refresh_token`,
and a confidential backend with no redirect URIs gets `client_credentials` +
`refresh_token`. `password` and `token_exchange` are never inferred; they must be
listed explicitly and require `allow_password_grant: true` /
`allow_token_exchange: true` respectively.

Validation ties grants to the client shape:

- `authorization_code` requires at least one `redirect_uris` entry;
- `client_credentials` requires a confidential client (not `public: true`);
- `password` requires `allow_password_grant: true` at the top level;
- `token_exchange` requires `allow_token_exchange: true` at the top level.

### Scopes and `offline_access`

- The default allowed scopes are `openid profile email offline_access`.
- If a request omits `scope`, the client's allowed scopes are used **minus**
  `offline_access` — a refresh token must be requested explicitly.
- Requesting a scope the client is not allowed to use returns `invalid_scope`.
- `offline_access` is rejected with `invalid_scope` by the `client_credentials`
  grant (there is no user to refresh).

### Refresh token rules

A refresh token is minted for a successful grant only when the client both
allows the `refresh_token` grant **and** either is confidential or requested
`offline_access`. In practice:

- confidential clients get refresh tokens without asking;
- public clients must include `offline_access` in the scope.

The token exchange grant never mints a refresh token.

### Token Exchange (RFC 8693)

With `allow_token_exchange: true` and `token_exchange` in a client's
`grant_types`, that client may trade a `subject_token` for a new access token at
`POST /token` (see [endpoints](endpoints.md#post-token)). Supported subject and
actor token types are `access_token`, `jwt`, `id_token` and `refresh_token`.
Scopes are never widened, `resource` / `audience` must name one of the client's
configured `audience` values (or its own `client_id`), and `offline_access` is
always stripped. Supplying an `actor_token` produces delegation: the issued
access token carries an `act` claim naming the actor; without one the exchange
impersonates the subject.

### Client claims

A client may define its own `claims`. They are merged into every token issued
for that client: the access token, the ID token and `/userinfo`. Values are
literal JSON — strings, lists, numbers, booleans or nested objects — and are
**not** rendered as templates; use `users[].claims` for per-user templated
values.

```yaml
clients:
  - client_id: my-api
    client_secret: dev-secret
    grant_types: [client_credentials]
    claims:
      app_grants:
        - resource-a:read
        - resource-b:read,write
```

Precedence for non-reserved keys: client claims override the claims derived
from the user record (`email`, `name`, `roles`, …) and the explicit
`users[].claims`. Provider-owned claims (`iss`, `sub`, `aud`, …) always win.
For `client_credentials` tokens there is no user, so the client claims are the
only identity claims in the token.

## `users[]`

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `username` | string | required | Unique login name and the `sub` claim. Must not be empty or duplicated. |
| `password` | string | required | Plaintext (development) or an argon2 PHC hash starting with `$argon2`. Must not be empty. |
| `email` | string | — | Value of the `email` claim. May be a minijinja template. |
| `name` | string | — | Value of the `name` claim. May be a minijinja template. |
| `roles` | list of strings | `[]` | Value of the `roles` claim (always included when non-empty). |
| `groups` | list of strings | `[]` | Value of the `groups` claim (always included when non-empty). |
| `claims` | map | `{}` | Extra claims merged into the access token, ID token and userinfo. String values are minijinja templates (see below). |

Passwords starting with `$argon2` are verified with argon2; anything else is
compared as plaintext using a constant-time comparison. Create a hash with
`keyfob hash-password`.

### Claim templates

String values inside `claims` (and the `email` and `name` fields) are rendered
as [minijinja](https://docs.rs/minijinja) templates with the user as context.
The context exposes `username`, `email`, `name`, `roles` and `groups`. A
template failure falls back to the raw string and logs a warning, so a broken
claim never breaks token issuance.

```yaml
users:
  - username: alice
    password: alice123
    email: "{{ username }}@example.test"   # -> alice@example.test
    name: Alice Doe
    roles: [admin, user]
    groups: [engineering]
    claims:
      department: engineering
      email_domain: "{{ email | default('example.test') }}"
```

### Keycloak-compatible roles

Keycloak does not use a top-level `roles` claim: it reports realm roles in
`realm_access.roles` and per-client roles in
`resource_access.<client_id>.roles`. keyfob-idp keeps its flat `roles` and
`groups` claims, but you can add the Keycloak layout with `claims` — nested
objects pass through unchanged (only top-level strings are templated):

```yaml
users:
  - username: alice
    password: alice123
    roles: [admin, user]
    claims:
      realm_access:
        roles: [admin, user]
      resource_access:
        my-spa:            # keyed by client_id
          roles: [admin]
```

This shape is used in `examples/keyfob.full.yaml`, `examples/keyfob.minimal.yaml`
and in the file written by `keyfob init`.

Custom claims may **not** override the claims owned by the provider (`iss`,
`sub`, `aud`, `exp`, `iat`, `nbf`, `jti`, `auth_time`, `nonce`, `at_hash`,
`azp`, `sid`, `scope`, `client_id`, `token_type`, `act`, `may_act`). Profile
claims such as `name`, `preferred_username`, `email`, `email_verified`, `roles`
and `groups` are only filled in from the user record when the custom claims do
not already define them.

## Environment variables

Environment overrides are applied by
[`apply_env`](../src/config/mod.rs) after the YAML is parsed. Variables are
trimmed; an empty value is ignored.

| Variable | Type | Overrides |
| --- | --- | --- |
| `KEYFOB_CONFIG` | path | Configuration file to load (used by file discovery). |
| `KEYFOB_HOST` | string | `server.host` |
| `KEYFOB_PORT` | integer | `server.port` (1–65535) |
| `KEYFOB_ISSUER` | string | `server.issuer` |
| `KEYFOB_TLS` | boolean | `server.tls` |
| `KEYFOB_DEBUG` | boolean | `debug` |
| `KEYFOB_ALLOW_PASSWORD_GRANT` | boolean | `allow_password_grant` |
| `KEYFOB_ALLOW_TOKEN_EXCHANGE` | boolean | `allow_token_exchange` |
| `KEYFOB_LOGIN_MODE` | `form`\|`picker`\|`auto` | `login.mode` |

Boolean values accept `true`/`1`/`yes`/`on` and `false`/`0`/`no`/`off`
(case-insensitive). An invalid value fails with an error naming the variable
and the expected format.

Two further variables are read outside the config loader:

- `KEYFOB_CLIENT_SECRET` — read by `keyfob token --secret` (via clap's `env`
  attribute), so scripts do not have to pass the secret on the command line.
- `RUST_LOG` — standard [`tracing`](https://docs.rs/tracing) filter. When unset
  the default is `keyfob_idp=info,warn` (`keyfob_idp=warn,warn` with
  `--quiet`).

## Validation

`keyfob validate` (and every `keyfob run`) checks, among others:

**server**

- `host` must not be empty.
- `port` must be between 1 and 65535.
- the resolved `issuer` must be an absolute `http://` or `https://` URL with no
  whitespace.

**keys**

- `algorithm` must be `RS256` (case-insensitive).

**tokens**

- every TTL must be greater than zero;
- `refresh_ttl` must be greater than or equal to `access_ttl`.

**cors**

- `origins` must not be empty when `cors.enabled` is true.

**clients**

- at least one client;
- unique, non-empty `client_id`;
- a public client must not have a `client_secret`; a confidential client must
  have one;
- `allowed_scopes`, when present, must not be empty and must not contain empty
  entries;
- authorization-code/client-credentials/password/token-exchange rules
  described above;
- every `redirect_uris` and `post_logout_redirect_uris` value must be a
  plausible absolute URI.

**users**

- at least one user when a flow needs one;
- unique, non-empty `username`; non-empty `password`;
- `login.default_user`, when set, must name a configured user.

**login**

- `login.template_dir`, when set, must be an existing directory.

Validation collects every problem and prints them together, each prefixed with
its field path (for example `clients[0].redirect_uris[0]`).

## Warnings

Some settings are valid but risky. They are logged at startup and listed in
`/ui/info` under `warnings`:

- `server.host` is not loopback — keyfob-idp must not be exposed;
- one or more user passwords are stored in plaintext;
- `ui.prefill_secrets: true`;
- `debug: true` — `/debug/tokens` exposes recently issued tokens;
- `allow_password_grant: true` — the deprecated grant is active;
- `cors.enabled` with `origins: ["*"]`;
- `login.mode: picker` — users sign in without a password.

## Hot reload

`keyfob run` watches the directory containing the configuration file (so
editor file replacement is detected) and reloads on change, debounced by 300 ms.
Reloads keep the previous configuration on any failure:

- on success the new runtime and templates are swapped in atomically and
  `config_loaded_at` is updated;
- on failure the previous configuration keeps serving traffic, the error is
  logged, and `/ui/info` reports it as `config_error` with the timestamp in
  `config_last_attempt_at`. The home page shows a red banner while the last
  reload is failing.

Disable watching with `keyfob run --no-watch`. Custom templates from
`login.template_dir` are reloaded from disk on every render regardless of the
config watcher.

CORS settings are the exception: they are applied when the router is built and
therefore need a restart.
