<div align="center">

# keyfob-idp

**A local OAuth 2.0 / OpenID Connect provider for development and testing.**

Start it, get real `id_token` / `access_token` values, and point your app at it —
no Keycloak, no Docker, no account.

[![CI](https://github.com/OWNER/keyfob-idp/actions/workflows/ci.yml/badge.svg)](https://github.com/OWNER/keyfob-idp/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

</div>

> [!WARNING]
> keyfob-idp is a **development tool**. It keeps everything in memory, binds to
> `127.0.0.1` by default and has no production hardening. Never expose it to an
> untrusted network or use it in production.

## Why

You are building a client that needs OIDC and you do not want to run a full
identity provider just to test a login. keyfob-idp is a single static binary
that reads one YAML file, signs RS256 tokens and implements the endpoints a real
client actually uses. The bundled home page doubles as a token generator so you
can try every flow without writing `curl`.

## Quick start

```sh
# 1. Install (from source)
cargo install --path .        # provides the `keyfob` binary

# 2. Write an example configuration
keyfob init                   # creates ./keyfob.yaml

# 3. Validate and run
keyfob validate
keyfob run
```

Open <http://127.0.0.1:9000/> for server information and the token generator.

A working configuration is tiny:

```yaml
# keyfob.yaml
server:
  host: 127.0.0.1
  port: 9000

clients:
  - client_id: my-spa
    public: true
    redirect_uris:
      - http://localhost:3000/callback

  - client_id: my-backend
    client_secret: dev-secret
    grant_types: [client_credentials, refresh_token]

users:
  - username: alice
    password: alice123
    email: alice@example.test
    name: Alice Doe
```

The issuer is deduced from `host` and `port` (`http://127.0.0.1:9000`). Point
your client's `authority` / `issuer-uri` at it and you are done.

## Features

- **Discovery**: `/.well-known/openid-configuration` and
  `/.well-known/oauth-authorization-server`.
- **Grants**: authorization code + PKCE (`S256` mandatory for public clients),
  client credentials, refresh token (rotating) and the deprecated password grant
  (opt-in with `allow_password_grant: true`).
- **Tokens**: RS256 access tokens and ID tokens with `nonce`, `at_hash`,
  `auth_time`, `sid` and `azp`; introspectable and revocable.
- **Keycloak-style JWKS**: `/jwks` and the `/protocol/openid-connect/certs` alias.
- **Users and claims**: login `form` / `picker` / `auto`, custom claims rendered
  as minijinja templates, optional custom templates.
- **Dev ergonomics**: a token generator UI at `/`, hot reload of the YAML,
  `--tls` with a self-signed certificate, optional CORS and `/debug/tokens`.
- **Zero runtime dependencies**: pure Rust, `ring`/`rustls` (no OpenSSL), no
  database, no C toolchain.

## CLI

| Command | Description |
| --- | --- |
| `keyfob run` | Start the server (`--host`, `--port`, `--issuer`, `--tls`, `--no-watch`). |
| `keyfob validate` | Validate the configuration without starting the server (CI-friendly). |
| `keyfob init` | Write an example `keyfob.yaml`. |
| `keyfob hash-password` | Produce an argon2 hash to store in `users[].password`. |
| `keyfob gen-keys` | Generate (or regenerate) the signing key. |
| `keyfob token` | Print a token for quick tests (`--client`, `--user`, `--scope`, `--json`). |

Precedence: CLI flags → `KEYFOB_*` environment variables → YAML → built-in
defaults. The file is discovered as `keyfob.yaml` or `keyfob.yml` in the current
directory (override with `--config` or `KEYFOB_CONFIG`).

## Endpoints

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/.well-known/openid-configuration` | GET | OIDC discovery document |
| `/.well-known/oauth-authorization-server` | GET | RFC 8414 metadata |
| `/jwks` | GET | JSON Web Key Set |
| `/authorize` | GET, POST | Authorization endpoint (code + PKCE) |
| `/login` | GET, POST | Interactive login (form / picker) |
| `/token` | POST | Token endpoint |
| `/userinfo` | GET, POST | OpenID Connect UserInfo |
| `/introspect` | POST | RFC 7662 token introspection |
| `/revoke` | POST | RFC 7009 token revocation |
| `/logout` | GET, POST | RP-initiated logout |
| `/healthz` | GET | Liveness probe |
| `/` | GET | Home page and token generator |
| `/ui/info` | GET | JSON powering the home page |
| `/ui/callback` | GET | Redirect target of the token generator |
| `/debug/tokens` | GET | Recently issued tokens (only with `debug: true`) |

See [`docs/endpoints.md`](docs/endpoints.md) for request/response examples.

## Try a flow

```sh
# Client credentials
curl -s http://127.0.0.1:9000/token \
  -d grant_type=client_credentials \
  -d client_id=my-backend -d client_secret=dev-secret \
  -d scope="openid profile"

# Introspect the access token
curl -s http://127.0.0.1:9000/introspect \
  -d client_id=my-backend -d client_secret=dev-secret -d token="$ACCESS_TOKEN"
```

For a browser flow, open the token generator and pick **Authorization code +
PKCE**; it creates the verifier with WebCrypto, runs the redirect and decrypts
the result for you.

## Documentation

- [Getting started](docs/getting-started.md)
- [Configuration reference](docs/configuration.md)
- [Endpoints](docs/endpoints.md)
- [Integrations](docs/integrations.md) (SPA, Spring Boot, Node)
- [Comparison with Keycloak and Dex](docs/comparison.md)
- [Architecture and decisions](docs/architecture.md)

## When NOT to use keyfob-idp

Use something else if you need any of the following:

- Production or any environment reachable from the internet.
- Persistent users, sessions or tokens across restarts.
- More than one issuer / realm in a single process.
- Clustering, high availability or horizontal scaling.
- Dynamic client registration, device flow, token exchange, PAR/JARM, ES256 or
  EdDSA (all on the roadmap, none implemented yet).
- Full OpenID certification for compliance.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`AGENTS.md`](AGENTS.md). Run
`cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and `cargo test`
before opening a pull request. Security reports go through
[`SECURITY.md`](SECURITY.md).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
