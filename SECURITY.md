# Security Policy

## This is a development-only tool

`keyfob-idp` is a **local development identity provider**. It is designed to
run on a developer machine to emulate an OAuth 2.0 / OpenID Connect provider
during local development and testing.

**Never run `keyfob-idp` in production, on a publicly reachable host, or with
real user data or real credentials.** It does not attempt to provide the
hardening, secret management, or operational guarantees required of a
production identity provider.

By design and out of the box:

- Passwords may be stored and compared in plaintext.
- The server binds to `localhost` only.
- Signing keys may be generated locally and stored on disk in plaintext.

These defaults are intentional and are **not** considered vulnerabilities.

## Supported versions

Only the latest `0.2.x` release line is supported with security fixes.

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| < 0.2.0 | :x:                |

## Reporting a vulnerability

Please **do not** open a public issue for security-sensitive reports.

Report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
via the **Security** tab of the repository:

1. Open the repository on GitHub.
2. Go to the **Security** tab.
3. Click **Report a vulnerability**.

Please include:

- A description of the issue and its impact.
- Steps to reproduce (a minimal proof of concept is ideal).
- The affected version or commit.
- Any suggested remediation, if you have one.

We will acknowledge the report and work with you on a coordinated disclosure.
Since this is a development-only tool, please also consider whether the behavior
is one of the documented, intentional development defaults described above.
