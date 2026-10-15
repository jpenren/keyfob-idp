# Changelog

All notable changes to this project will be documented in this file. This project follows [Keep a Changelog](https://keepachangelog.com/) and [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- The README **Quick start** and `docs/getting-started.md` now explain how to download a prebuilt binary from the latest GitHub Release (asset names per platform, extraction, PATH install and the macOS quarantine note) as the recommended path, with `cargo install --path .` / `cargo build --release` as the from-source alternative.
- Project logo in `assets/` (light/dark SVG pair plus a social preview image). The README shows the logo with a `prefers-color-scheme` switch and the home page inlines it as SVG, following the browser theme without any external asset.
- Release workflow (`.github/workflows/release.yml`): pushing a `v*` tag publishes a GitHub Release with `keyfob` binaries for x86_64 Linux, x86_64 Windows, and x86_64/aarch64 macOS (`.tar.gz`, Windows `.zip`) and source archives (`.tar.gz`, `.zip`), after checking that the tag matches the crate version.

### Changed

- The home page **Server** section now shows only `Version`, `OS`, `Uptime` and `Issuer`; the `Config`, `Config loaded`, `Login mode`, `Signing`, `Scopes` and `Grants` rows were removed. Those values are still returned by `/ui/info`, and scopes and grants remain per client in the **Clients** table.
- The home page no longer caps its content at 980px, so the header, sections and footer use the full window width.
- Updated `rand` to 0.10 (`rand::rng()`, `rand::fill`, `rand::distr::Alphanumeric`); RSA key generation keeps using the OS-backed `rand_core` 0.6 generator via `rsa::rand_core::OsRng`, now enabled explicitly with the `getrandom` feature of `rsa`.
- Example configurations (`examples/keyfob.minimal.yaml`, `examples/keyfob.full.yaml`) and the file written by `keyfob init` now include Keycloak-compatible `realm_access.roles` and `resource_access.<client_id>.roles` claims.

### Fixed

- The home page token generator no longer fails with `redirect_uri ... is not registered`: the authorization-code tab lists only public clients whose `redirect_uris` contains the generator callback (`<origin>/ui/callback`), shows the others as disabled with the URI to add, preselects a usable client (the internal `keyfob-ui` one by default) and disables the button with an explanation when no client can complete the flow.

## [0.1.0] - 2026-10-15

### Added

- Initial implementation of the local OAuth 2.0 / OIDC identity provider (discovery, JWKS, authorization code + PKCE, client credentials, refresh tokens, introspection, revocation, logout, embedded UI, YAML configuration with hot reload).
- CLI with `run`, `validate`, `init`, `hash-password`, `gen-keys` and `token`, plus optional TLS with a self-signed certificate.
- Documentation under `docs/`, ready-to-run example configurations under `examples/` and a minimal `scratch`-based container image under `docker/`.

[Unreleased]: https://github.com/OWNER/keyfob-idp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/OWNER/keyfob-idp/releases/tag/v0.1.0
