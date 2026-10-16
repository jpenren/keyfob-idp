# Getting started

**keyfob-idp** is a local OAuth 2.0 / OpenID Connect identity provider for
development and testing. The package is a single Rust crate (`keyfob-idp`)
that builds one binary named `keyfob`. It starts in milliseconds, keeps all
state in memory and is configured with a single YAML file that declares your
clients, users, scopes and claims. There is no database, no container and no
admin console to fight with: point a standard OIDC client at
`http://127.0.0.1:9000` and it will sign users in with real `id_token` and
`access_token` JWTs.

> **Development tool only.** keyfob-idp keeps secrets in plaintext,
> issues tokens without consent screens and stores everything in memory.
> Never expose it to an untrusted network and never use it in production. The
> server prints this warning on every start and the home page shows it
> permanently.

## 60-second quick start

```sh
# 1. Create an example configuration in the current directory.
keyfob init                 # writes ./keyfob.yaml

# 2. Edit keyfob.yaml (clients, users) with your editor of choice.
$EDITOR keyfob.yaml

# 3. Validate it without starting the server.
keyfob validate

# 4. Start the server.
keyfob run
```

Then open **<http://127.0.0.1:9000/>** in a browser. The home page shows the
resolved server configuration and an embedded **token generator** that can run
the interactive grants (client credentials, authorization code + PKCE, refresh
token, password) without writing any `curl`.

`keyfob run` prints a banner with the issuer and the listen address, for
example:

```
keyfob-idp is a development tool. Do not use it in production.
  Issuer:  http://127.0.0.1:9000
  UI:      http://127.0.0.1:9000/  (server info and token generator)
  Listen:  http://127.0.0.1:9000
```

## Minimal configuration

The following 14 lines of content are a complete, valid `keyfob.yaml`: one
public SPA that uses Authorization Code + PKCE and one confidential backend
that uses client credentials and refresh tokens. Everything else uses built-in
defaults.

```yaml
server:
  host: 127.0.0.1
  port: 9000
clients:
  - client_id: my-spa
    public: true
    redirect_uris: [http://localhost:3000/callback]
  - client_id: my-backend
    client_secret: dev-secret
    grant_types: [client_credentials, refresh_token]
users:
  - username: alice
    password: alice123
```

- `issuer` is derived from `host` and `port` when omitted
  (`http://127.0.0.1:9000` here).
- A **public** client has no secret and must use PKCE (`S256`).
- A **confidential** client has a `client_secret` and may use client
  credentials.
- `users` are only required by flows that authenticate a person
  (authorization code, password, interactive login). The public SPA above
  enables authorization code, so at least one user is required.

See [`docs/configuration.md`](configuration.md) for every key, or the annotated
[`examples/keyfob.full.yaml`](../examples/keyfob.full.yaml) and
[`examples/keyfob.minimal.yaml`](../examples/keyfob.minimal.yaml).

## Install and run

The quickest way is to download a prebuilt binary from the
[latest release](https://github.com/jpenren/keyfob-idp/releases/latest)
(`keyfob-linux-x86_64.tar.gz`, `keyfob-windows-x86_64.zip`,
`keyfob-macos-arm64.tar.gz` or `keyfob-macos-x86_64.tar.gz`; sources are
`keyfob-src.tar.gz` / `keyfob-src.zip`). Asset names are stable, so
`.../releases/latest/download/<asset>` always points at the newest build —
replace `latest` with a tag such as `v0.2.0` to pin a version. Each archive
unpacks to a `keyfob-<tag>-<target>/` directory holding the `keyfob` binary, the
example configurations, the README and the licences:

```sh
curl -LO https://github.com/jpenren/keyfob-idp/releases/latest/download/keyfob-linux-x86_64.tar.gz
tar -xzf keyfob-linux-x86_64.tar.gz
install -m 755 keyfob-*/keyfob ~/.local/bin/keyfob
# the archive also ships the example configurations:
keyfob run --config keyfob-*/keyfob.minimal.yaml

# Optional: verify the download against the published checksums
curl -LO https://github.com/jpenren/keyfob-idp/releases/latest/download/SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
```

On Windows extract the `.zip` (`Expand-Archive`) and run `keyfob.exe`; check the
download with `Get-FileHash keyfob-windows-x86_64.zip` against `SHA256SUMS`. On
macOS the binaries are not notarised: right-click → *Open* (or
`xattr -d com.apple.quarantine keyfob`) once.

Alternatively build from source with a stable Rust toolchain. The crate is
`publish = false`:

```sh
# Run directly from the repository.
cargo run -- run

# Or build an optimized binary (see [profile.release] in Cargo.toml).
cargo build --release
./target/release/keyfob run

# Pass an explicit config file anywhere.
cargo run -- run --config examples/keyfob.minimal.yaml
```

The release profile is tuned for size: `opt-level = "z"`, `lto = true`,
`codegen-units = 1`, `strip = true`, `panic = "abort"`.

## Example curl calls

Start from the minimal `keyfob.yaml` above (the `my-backend` client has secret
`dev-secret`).

### Client credentials

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

### Authorization code + PKCE

PKCE requires a `code_verifier` and its `code_challenge`
(`BASE64URL(SHA256(verifier))`). The pair used here is the one from
[RFC 7636 Appendix B](https://www.rfc-editor.org/rfc/rfc7636#appendix-B):

- verifier: `dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk`
- challenge: `E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM`

Open the authorization URL in a browser (you will be asked to sign in as
`alice`):

```
http://127.0.0.1:9000/authorize?response_type=code
  &client_id=my-spa
  &redirect_uri=http://localhost:3000/callback
  &scope=openid%20profile%20email%20offline_access
  &state=xyz
  &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
  &code_challenge_method=S256
```

The browser is redirected to
`http://localhost:3000/callback?code=<CODE>&state=xyz`. Exchange the code:

```sh
curl -sS -X POST http://127.0.0.1:9000/token \
  -d grant_type=authorization_code \
  -d client_id=my-spa \
  -d code=<CODE> \
  -d redirect_uri=http://localhost:3000/callback \
  -d code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

Authorization codes are single use and expire after **60 seconds**.

## CLI subcommands

| Command | Purpose | Key flags |
| --- | --- | --- |
| `keyfob run` | Start the server and watch the config file | `--host`, `--port`, `--issuer`, `--tls`, `--no-watch` |
| `keyfob validate` | Parse and validate the configuration without starting | — |
| `keyfob init` | Write the example `keyfob.yaml` | `--path <file>`, `--force` |
| `keyfob hash-password` | Hash a password with argon2 and print the PHC string | `--password <pw>` (or read from stdin) |
| `keyfob gen-keys` | Generate (or regenerate) the signing key | `--force` |
| `keyfob token` | Issue a token to stdout for quick tests | `--client`, `--user`, `--secret`, `--scope`, `--json` |

Global flags (accepted by every subcommand):

- `--config <path>` — explicit configuration file.
- `--log-format text|json` — log output format (default `text`).
- `--quiet` — only log warnings and errors.

`keyfob hash-password` produces a `$argon2...` PHC string you can paste
directly into a user's `password` field:

```sh
$ keyfob hash-password --password 'alice123'
$argon2id$v=19$m=19456,t=2,p=1$...$...
```

`keyfob token` issues a real token without an HTTP round trip. For a
confidential client pass the secret via `--secret` or the
`KEYFOB_CLIENT_SECRET` environment variable; add `--json` to print the full
token response:

```sh
keyfob token --client my-backend --secret dev-secret --scope "openid profile"
keyfob token --client my-backend --secret dev-secret --user alice --json
```

## Configuration precedence and discovery

When several sources provide the same value, the most specific wins:

```
CLI flags  >  KEYFOB_* environment variables  >  keyfob.yaml  >  built-in defaults
```

The configuration file is located in this order:

1. the `--config <path>` flag, if present;
2. the `KEYFOB_CONFIG` environment variable, if set and non-empty;
3. `keyfob.yaml`, then `keyfob.yml`, in the current directory.

If none is found, the server stops with an actionable error suggesting
`keyfob init`.

Only two environment variables affect more than connection settings:
`KEYFOB_LOGIN_MODE` (`form`, `picker`, `auto`) and `KEYFOB_ALLOW_PASSWORD_GRANT`.
See [`docs/configuration.md`](configuration.md#environment-variables) for the
full list.

## Where to go next

- [`docs/configuration.md`](configuration.md) — every YAML key and environment
  variable, defaults, validation and hot reload.
- [`docs/endpoints.md`](endpoints.md) — every HTTP endpoint with examples.
- [`docs/integrations.md`](integrations.md) — SPA, Spring Boot, Node and curl.
- [`docs/comparison.md`](comparison.md) — honest comparison with Keycloak and
  Dex, and when *not* to use keyfob-idp.
- [`docs/architecture.md`](architecture.md) — module map, request flows and the
  decision log.
