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

## Scope of a pull request

The project is implemented in phases described in `docs/architecture.md`. Complete
**one implementation phase at a time**; keep pull requests focused on a single
phase rather than mixing phases together.
