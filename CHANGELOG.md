# Changelog

All notable changes to this project will be documented in this file. This project follows [Keep a Changelog](https://keepachangelog.com/) and [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-10-16

### Added

- **Token exchange (RFC 8693)** as an opt-in grant: `allow_token_exchange: true` at the top level plus `token_exchange` in a client's `grant_types`. A client can trade an `access_token`, `jwt`, `id_token` or `refresh_token` subject for a new access token, with optional delegation via `actor_token` (the issued token carries an `act` claim, nesting the actor's own chain). Scopes only narrow, `resource` / `audience` must match the client's configured `audience` (otherwise `invalid_target`), `offline_access` is always stripped and no refresh token is ever issued. The token endpoint now returns `issued_token_type`. Advertised in discovery as `urn:ietf:params:oauth:grant-type:token-exchange`, with `KEYFOB_ALLOW_TOKEN_EXCHANGE` and an `allow_token_exchange` field in `/ui/info`.
- The README **Quick start** and `docs/getting-started.md` now explain how to download a prebuilt binary from the latest GitHub Release (stable asset names per platform, extraction, PATH install, `SHA256SUMS` verification and the macOS quarantine note) as the recommended path, with `cargo install --path .` / `cargo build --release` as the from-source alternative.
- Project logo in `assets/` (light/dark SVG pair plus a social preview image). The README shows the logo with a `prefers-color-scheme` switch and the home page inlines it as SVG, following the browser theme without any external asset.
- Release workflow (`.github/workflows/release.yml`): pushing a `v*` tag publishes a GitHub Release with `keyfob` binaries for x86_64 Linux, x86_64 Windows, and x86_64/aarch64 macOS (`.tar.gz`, Windows `.zip`), source archives (`.tar.gz`, `.zip`) and a `SHA256SUMS` file, after checking that the tag matches the crate version. Asset names are stable across releases (`keyfob-linux-x86_64.tar.gz`, `keyfob-macos-arm64.tar.gz`, …) so `.../releases/latest/download/<asset>` always resolves to the newest build, while the version stays visible inside the archive as `keyfob-<tag>-<target>/`. The workflow uses the current action majors (`actions/checkout@v7`, `actions/upload-artifact@v7`, `actions/download-artifact@v8`, `softprops/action-gh-release@v3`), matching `ci.yml`.

### Changed

- The home page token generator no longer lists `iat`, `exp`, `nbf` and `auth_time` above the decoded payload; those values now carry a hover tooltip (absolute date and remaining/elapsed time) inside the decoded JSON.
- The home page **Server** section now shows only `Version`, `OS`, `Uptime` and `Issuer`; the `Config`, `Config loaded`, `Login mode`, `Signing`, `Scopes` and `Grants` rows were removed. Those values are still returned by `/ui/info`, and scopes and grants remain per client in the **Clients** table.
- The home page now caps its header, sections and footer at 1216px and centres them, instead of using the full window width.
- Updated `rand` to 0.10 (`rand::rng()`, `rand::fill`, `rand::distr::Alphanumeric`); RSA key generation keeps using the OS-backed `rand_core` 0.6 generator via `rsa::rand_core::OsRng`, now enabled explicitly with the `getrandom` feature of `rsa`.
- Example configurations (`examples/keyfob.minimal.yaml`, `examples/keyfob.full.yaml`) and the file written by `keyfob init` now include Keycloak-compatible `realm_access.roles` and `resource_access.<client_id>.roles` claims.

### Fixed

- The README logo now uses absolute GitHub `raw` URLs instead of relative `assets/...` paths, so it renders in the downloaded source archive and in any Markdown viewer, not only on the repository page.
- The home page token generator no longer fails with `redirect_uri ... is not registered`: the authorization-code tab lists only public clients whose `redirect_uris` contains the generator callback (`<origin>/ui/callback`), shows the others as disabled with the URI to add, preselects a usable client (the internal `keyfob-ui` one by default) and disables the button with an explanation when no client can complete the flow.

## [0.1.0] - 2026-10-15

### Added

- Initial implementation of the local OAuth 2.0 / OIDC identity provider (discovery, JWKS, authorization code + PKCE, client credentials, refresh tokens, introspection, revocation, logout, embedded UI, YAML configuration with hot reload).
- CLI with `run`, `validate`, `init`, `hash-password`, `gen-keys` and `token`, plus optional TLS with a self-signed certificate.
- Documentation under `docs/`, ready-to-run example configurations under `examples/` and a minimal `scratch`-based container image under `docker/`.

[Unreleased]: https://github.com/jpenren/keyfob-idp/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/jpenren/keyfob-idp/releases/tag/v0.2.0
[0.1.0]: https://github.com/jpenren/keyfob-idp/releases/tag/v0.1.0
