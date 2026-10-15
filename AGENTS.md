# AGENTS.md — working on keyfob-idp

You are a senior Rust engineer implementing and maintaining **keyfob-idp**, a
local OAuth 2.0 / OpenID Connect identity provider for development and testing.
The binary is named `keyfob`.

## Language

Everything in this repository is written in **English**: code, identifiers,
comments, log and error messages, UI text, commit messages, issues, pull
requests and all documentation (`README.md`, `docs/`, `CHANGELOG.md`, this file,
`CONTRIBUTING.md`, `SECURITY.md`) and examples. The design guide
(`Keyfob guía de implementación ... .md`) is in Spanish only as a working
reference — always produce English output, even if asked in another language.

## What this project is (and is not)

- It **is** a zero-setup, in-memory OIDC provider so a developer can get a real
  `id_token` / `access_token` without running Keycloak.
- It **is not** for production. No database, no clustering, no persistence of
  tokens, one issuer, no dynamic client registration.
- Read `docs/architecture.md` before changing public behaviour; record new
  decisions there instead of improvising silently.

## Non-negotiable implementation rules

1. Domain logic (`oauth`, `oidc`, `store`, `config`, `crypto`) must not depend on
   `axum`. It is tested without a network.
2. Typed errors with `thiserror`. `anyhow` is allowed **only** in `main`.
3. No `unwrap` / `expect` on request paths. `#![forbid(unsafe_code)]` stays.
4. Secrets are compared in constant time (`subtle`).
5. Authorization codes are single use and bound to `client_id`, `redirect_uri`
   and `code_challenge`.
6. The session cookie is `HttpOnly`, `SameSite=Lax`, and `Secure` only with TLS.
7. PKCE `S256` is mandatory for public clients; `plain` is disabled. No implicit
   flow. `redirect_uri` must match exactly.
8. Never log passwords or client secrets. Tokens are only exposed by
   `/debug/tokens` when `debug: true`.
9. Default bind is `127.0.0.1`. Do not hardcode Unix-only behaviour; keep Windows
   working (no hand-written path separators, no OS-specific APIs without a
   portable fallback).
10. Against over-engineering: no database, no plugin framework, no abstraction
    that does not have two real uses.

## Dependencies

Before adding a crate, check its latest stable version, maintenance, license
(MIT/Apache-2.0 compatible) and that it does not require `openssl` or a C
toolchain on Windows. Justify every new dependency. TLS uses `rustls` with the
`ring` provider specifically to avoid the `aws-lc-rs` C toolchain; keep it that
way.

## Workflow

1. Work one phase at a time and do not move on until its acceptance criteria are
   met.
2. Write the tests for each endpoint and error first where practical.
3. Small commits using Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`,
   `chore:`, `refactor:`).
4. Before finishing any task run, and keep green:

   ```sh
   cargo fmt --check
   cargo clippy --all-targets -- -D warnings
   cargo test
   ```

   (`cargo` lives in `~/.cargo/bin`; prefix shells with `source "$HOME/.cargo/env" &&`.)

5. User-facing error messages must be actionable: what failed, where, and how to
   fix it.
6. Definition of done for a task: code, tests, documentation, an example under
   `examples/` if configuration changed, and a `CHANGELOG.md` entry.

## Layout

```
src/config/   YAML models, loading, validation, env overrides, warnings
src/crypto/   RSA keys (RS256), JWKS, JWT, argon2, PKCE, random tokens
src/store/    in-memory codes, refresh tokens, sessions, revocations
src/oauth/    grant logic and RFC 6749 / 7009 / 7662 behaviour
src/oidc/     discovery documents, claims, id_token, userinfo
src/state.rs  resolved Runtime, AppState, hot reload
src/http/     axum router and handlers (thin adapters over the domain)
src/ui/       embedded templates (login, error, home, callback, logout)
src/cli.rs    run | validate | init | hash-password | gen-keys | token
templates/    HTML included with include_str!
assets/       logo.svg, logo-dark.svg and social-preview.png
tests/        integration tests against a real server on an ephemeral port
examples/     ready-to-run YAML files
```
