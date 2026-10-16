# Comparison with Keycloak and Dex

This page compares keyfob-idp with two widely used OIDC providers. It is
deliberately factual: keyfob-idp is a **development tool**, and both Keycloak
and Dex are more capable for real workloads. The point of the table is to make
the trade-off explicit, not to argue that one is universally better.

## At a glance

| | **keyfob-idp** | **Keycloak** | **Dex** |
| --- | --- | --- | --- |
| Primary purpose | Local OIDC provider for development and testing | Full identity and access management server | Federated OIDC connector / identity broker |
| Language & runtime | Rust, single static binary (no runtime) | Java, runs on the JVM | Go, single binary |
| Configuration | One `keyfob.yaml` file | Admin console + realm import/export (DB-backed) | A config file and/or Kubernetes CRDs |
| External database | None | Required (for example PostgreSQL) | Optional (etcd/Postgres/Kubernetes CRDs) for some state |
| Startup | Milliseconds | Seconds to tens of seconds | Sub-second to seconds |
| Typical idle RAM | A few MB | Hundreds of MB | Tens of MB |
| User store | Users declared in YAML | Built-in database + federation (LDAP, Kerberos, social) | Delegates to upstream connectors (LDAP, GitHub, OIDC, SAML, …) |
| Identity federation | None | Extensive | This is its main feature |
| Persistence of tokens/codes/sessions | In memory only (lost on restart) | Database-backed, survives restarts and failover | Depends on storage backend |
| Clustering / high availability | None | Yes | Yes (with shared storage) |
| Dynamic client registration (RFC 7591) | Not implemented | Yes | No (clients configured statically) |
| Supported grants | Authorization code + PKCE, client credentials, refresh token, password and token exchange (both opt-in) | Broad (authorization code, client credentials, device, token exchange, …) | Authorization code (+ PKCE), client credentials, device, refresh token |
| Implicit flow | Not implemented (by design) | Available | Available |
| Signing algorithms | RS256 only | RS256/RS384/RS512, ES*, PS*, HS*, EdDSA | RS256 (configurable) |
| Admin UI | None (read-only info + token generator) | Full admin console | Minimal web UI |
| Consent screen | None | Yes | Yes (per connector) |
| MFA / passkeys | None | Yes | No (delegated to upstream) |
| Token customization | YAML users, scopes, roles, groups and templated claims | Mappers, protocol mappers, expressions | Limited |
| Hot reload of configuration | Yes (file watcher) | Via admin API / restart | Via restart or config reload |
| Production readiness | **No** | Yes | Generally yes (purpose-built) |
| License | MIT OR Apache-2.0 | Apache-2.0 | Apache-2.0 |

## Where keyfob-idp is a good fit

- You want a real `id_token` / `access_token` in seconds, with no container,
  no database and no admin console.
- You want the whole tenant (clients, users, scopes, claims) in one file that
  you can commit next to your code and reload while the server runs.
- You are writing tests or a local SPA/backend integration and need a throwaway
  issuer that behaves like the standards say it should.
- You want a built-in UI to click through each grant and see the decoded tokens.

## Where Keycloak or Dex win

- **Production / multi-tenant.** Keycloak and Dex are designed for this;
  keyfob-idp explicitly is not.
- **Federation.** Keycloak brokers LDAP, Kerberos, SAML and social logins; Dex
  is built around connectors to upstream identity providers. keyfob-idp only
  knows the static users in its YAML.
- **Persistence and high availability.** Both competitors can survive a restart
  and run behind a load balancer. keyfob-idp holds all state in one process's
  memory.
- **User lifecycle.** Self-registration, password resets, MFA and consent
  screens exist in Keycloak; they do not exist here.

## When NOT to use keyfob-idp

Use something else if any of the following applies:

- **Production or any external exposure.** There is no hardening, no rate
  limiting and no audit log, and client secrets and (optionally) passwords sit
  in plaintext in the YAML. The server prints this warning on every start. Bind
  it to loopback and keep it there.
- **You need persistence.** Authorization codes, refresh tokens, browser
  sessions and token revocations live **in memory only** and are gone on
  restart. Previously minted JWTs may still verify (when the signing key is
  persisted) but their refresh tokens and revocations are lost.
- **You need clustering or high availability.** A single process, a single
  signer, a single in-memory store. There is no shared state or leader
  election.
- **You need multiple issuers / realms in one process.** keyfob-idp has a
  single issuer; run a separate instance per issuer if you must.
- **You need dynamic client registration (RFC 7591).** Clients are configured
  statically in the YAML. Not implemented.
- **You need the device authorization grant (RFC 8628).** Not implemented.
  Token exchange (RFC 8693) is available as an opt-in grant, but it only issues
  access tokens — no `may_act`, no SAML or JWT assertions and no refresh tokens.
- **You need signing algorithms other than RS256.** ES256 and EdDSA are planned
  but not available; only RS256 is accepted.
- **You need federation, MFA, consent, password reset or a user admin UI.**
  None of these exist.
- **You need a stable token vocabulary across restarts without a persisted
  key.** With `keys.persist: false` the signing key is regenerated on every
  start, invalidating every previously issued token.

If your need is a real identity provider, use Keycloak (full-featured, Java) or
Dex (lightweight federating broker). Reach for keyfob-idp only when you want
a disposable, zero-setup OIDC endpoint for development.
