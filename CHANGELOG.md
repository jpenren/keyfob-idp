# Changelog

All notable changes to this project will be documented in this file. This project follows [Keep a Changelog](https://keepachangelog.com/) and [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- Example configurations (`examples/keyfob.minimal.yaml`, `examples/keyfob.full.yaml`) and the file written by `keyfob init` now include Keycloak-compatible `realm_access.roles` and `resource_access.<client_id>.roles` claims.

## [0.1.0] - 2026-10-15

### Added

- Initial implementation of the local OAuth 2.0 / OIDC identity provider (discovery, JWKS, authorization code + PKCE, client credentials, refresh tokens, introspection, revocation, logout, embedded UI, YAML configuration with hot reload).
- CLI with `run`, `validate`, `init`, `hash-password`, `gen-keys` and `token`, plus optional TLS with a self-signed certificate.
- Documentation under `docs/`, ready-to-run example configurations under `examples/` and a minimal `scratch`-based container image under `docker/`.

[Unreleased]: https://github.com/OWNER/keyfob-idp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/OWNER/keyfob-idp/releases/tag/v0.1.0
