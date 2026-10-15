# Contributing to keyfob-idp

Thanks for your interest in contributing! This document describes how to build,
test, and submit changes.

## Prerequisites

- A stable Rust toolchain installed with [rustup](https://rustup.rs/).
- No C toolchain and no OpenSSL are required. The project deliberately avoids
  native dependencies so it builds out of the box on Linux, macOS, and Windows.

## Running the checks

Before opening a pull request, make sure all of the following pass locally:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

## Commit messages

This project uses [Conventional Commits](https://www.conventionalcommits.org/).
Use one of the following prefixes:

- `feat:` — a new feature
- `fix:` — a bug fix
- `docs:` — documentation only
- `test:` — adding or changing tests
- `chore:` — maintenance, dependencies, tooling

Example: `feat: add refresh token rotation`

## Dependency policy

- Every dependency must be licensed under a license compatible with
  `MIT OR Apache-2.0`.
- Dependencies must not require a C toolchain or OpenSSL, so that builds work on
  Windows without extra setup. OpenSSL-based crates are not allowed.
- Justify every new dependency in the pull request: explain why it is needed and
  why it can't be avoided.

## Test-driven development

Test-driven development (TDD) is preferred: write a failing test first, then the
implementation that makes it pass. New behavior should come with tests.

## Definition of done

A change is considered done when it includes:

- [ ] The code change.
- [ ] Tests covering the new or changed behavior.
- [ ] Documentation updates (including `docs/architecture.md` where relevant).
- [ ] A `CHANGELOG.md` entry under `## [Unreleased]`.

## Cutting a release

Releases are published by CI (`.github/workflows/release.yml`) when a version
tag is pushed:

1. Move the entries under `## [Unreleased]` in `CHANGELOG.md` into a new
   `## [X.Y.Z] - YYYY-MM-DD` section and update the link references.
2. Bump `version` in `Cargo.toml` (the tag must match it exactly).
3. Commit, then tag and push:

   ```sh
   git commit -am "chore: release vX.Y.Z"
   git tag vX.Y.Z
   git push origin main vX.Y.Z
   ```

CI verifies that the tag matches the crate version, builds `keyfob` for
x86_64 Linux, x86_64 Windows, and x86_64/aarch64 macOS, and attaches the
binaries (`.tar.gz`, Windows `.zip`) plus source archives (`.tar.gz`, `.zip`)
to a GitHub Release with generated release notes.

## Scope of a pull request

The project is implemented in phases described in `docs/architecture.md`. Complete
**one implementation phase at a time**; keep pull requests focused on a single
phase rather than mixing phases together.
