# Integrations

keyfob-idp implements the standard endpoints that mainstream OIDC clients
expect, so in most cases an integration is just pointing the client at the
issuer. This page collects copy-pasteable configurations for the common cases.

> **The issuer must match exactly.** Whatever URL clients use to reach
> keyfob-idp must be the same string the server advertises as `issuer` and
> puts in the `iss` claim of every token. `http://127.0.0.1:9000` and
> `http://localhost:9000` are different issuers: tokens minted for one are
> rejected by a client configured for the other. Choose one and be consistent,
> or set `server.issuer` explicitly. Runner containers and other machines must
> use an address the client can resolve (for example
> `--issuer http://host.docker.internal:9000`).

The default endpoints (issuer `http://127.0.0.1:9000`) are:

| Endpoint | URL |
| --- | --- |
| Discovery | `http://127.0.0.1:9000/.well-known/openid-configuration` |
| Authorization | `http://127.0.0.1:9000/authorize` |
| Token | `http://127.0.0.1:9000/token` |
| UserInfo | `http://127.0.0.1:9000/userinfo` |
| JWKS | `http://127.0.0.1:9000/jwks` |
| End session | `http://127.0.0.1:9000/logout` |

## Browser SPA: Authorization Code + PKCE

Public SPAs cannot keep a secret, so keyfob-idp **requires PKCE (S256)** for
them. Configure the client as `public: true` with the exact callback URL:

```yaml
clients:
  - client_id: my-spa
    public: true
    redirect_uris:
      - http://localhost:3000/callback
    post_logout_redirect_uris:
      - http://localhost:3000
    allowed_scopes: [openid, profile, email, offline_access]
```

### `oidc-client-ts`

```js
import { UserManager, WebStorageStateStore } from "oidc-client-ts";

const settings = {
  authority: "http://127.0.0.1:9000",            // == the issuer, exactly
  client_id: "my-spa",
  redirect_uri: "http://localhost:3000/callback", // must match redirect_uris exactly
  post_logout_redirect_uri: "http://localhost:3000",
  response_type: "code",
  scope: "openid profile email offline_access",
  automaticSilentRenew: true,
  userStore: new WebStorageStateStore({ store: window.localStorage }),
};

const userManager = new UserManager(settings);

// Sign in
await userManager.signinRedirect();

// In /callback:
const user = await userManager.signinRedirectCallback();
console.log(user.profile);            // ID token claims
console.log(user.access_token);       // access token

// Attach the token to API calls
fetch("http://localhost:5000/api", {
  headers: { Authorization: `Bearer ${user.access_token}` },
});
```

Notes:

- `authority` triggers a fetch of
  `/.well-known/openid-configuration`; no endpoint URLs need to be listed.
- List both `redirect_uri` and any silent-renew callback (for example
  `http://localhost:3000/silent-renew`) in `redirect_uris`.
- `offline_access` is what makes a public client receive a `refresh_token`.
- CORS is not needed for the normal redirect flow, but if the SPA calls the
  `/token`, `/userinfo`, `/introspect` or `/revoke` endpoints with `fetch`, enable
  it in keyfob-idp:

  ```yaml
  cors:
    enabled: true
    origins: ["http://localhost:3000"]
  ```

  CORS settings are applied at startup; restart after changing them.

## Spring Boot / Spring Security OAuth2 client

keyfob-idp only needs the issuer URL. Spring Security performs discovery and
uses its default redirect URI template. Register a confidential client whose
redirect URI matches that template:

```yaml
clients:
  - client_id: my-web
    client_secret: web-secret
    redirect_uris:
      - http://localhost:8080/login/oauth2/code/keyfob
    post_logout_redirect_uris:
      - http://localhost:8080
    allowed_scopes: [openid, profile, email, offline_access]
```

`application.yml`:

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          keyfob:
            client-id: my-web
            client-secret: web-secret
            authorization-grant-type: authorization_code
            # Default template; resolves to
            # http://localhost:8080/login/oauth2/code/keyfob
            redirect-uri: "{baseUrl}/login/oauth2/code/{registrationId}"
            scope: openid, profile, email
            client-name: keyfob
        provider:
          keyfob:
            issuer-uri: http://127.0.0.1:9000
```

`redirect-uri` uses `{baseUrl}` and `{registrationId}` placeholders; the result
must be one of the client's `redirect_uris` in keyfob.yaml, character for
character. Spring Security 6 fetches `/.well-known/openid-configuration` and
the JWKS from the issuer, and validates the ID token signature automatically.

If the Spring app runs in Docker, `localhost` inside the container is not the
host. Point `issuer-uri` at the host (for example
`http://host.docker.internal:9000`) and start keyfob with a matching
`--issuer`.

## Next.js / Node: server-side flow with `openid-client`

For a confidential web app, keep the secret on the server. Client definition:

```yaml
clients:
  - client_id: my-next
    client_secret: next-secret
    redirect_uris:
      - http://localhost:3000/api/callback
    post_logout_redirect_uris:
      - http://localhost:3000
```

With [`openid-client`](https://github.com/panva/openid-client) v6:

```js
import * as client from "openid-client";

const issuer = new URL("http://127.0.0.1:9000");
const config = await client.discovery(issuer, "my-next", "next-secret");

// 1. Start the flow (route: /api/login)
export async function startLogin(res, session) {
  const codeVerifier = client.randomPKCECodeVerifier();
  const codeChallenge = await client.calculatePKCECodeChallenge(codeVerifier);
  const state = client.randomState();

  session.codeVerifier = codeVerifier;
  session.state = state;

  const url = client.buildAuthorizationUrl(config, {
    redirect_uri: "http://localhost:3000/api/callback",
    scope: "openid profile email offline_access",
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
    state,
  });
  res.redirect(url.href);
}

// 2. Handle the callback (route: /api/callback)
export async function handleCallback(req, res, session) {
  const currentUrl = new URL(req.url, "http://localhost:3000");
  const tokens = await client.authorizationCodeGrant(config, currentUrl, {
    pkceCodeVerifier: session.codeVerifier,
    expectedState: session.state,
  });

  const claims = tokens.claims();      // ID token claims: sub, email, name...
  const accessToken = tokens.access_token;
  // Store tokens in the session; never send the refresh token to the browser.
  res.redirect("/");
}
```

For a Next.js server-rendered app, keyfob-idp's `roles` and `groups` claims
are convenient for a quick role check while developing. If your app was written
against Keycloak and reads `realm_access.roles` / `resource_access`, add those
claims in the user configuration instead — see
[configuration.md](configuration.md#keycloak-compatible-roles).

## Plain curl

### Client credentials

```sh
curl -sS -X POST http://127.0.0.1:9000/token \
  -d grant_type=client_credentials \
  -d client_id=my-backend \
  -d client_secret=dev-secret \
  -d scope="openid profile"
```

The same request using HTTP Basic client authentication
(`client_secret_basic`), which is what many SDKs use by default:

```sh
curl -sS -X POST http://127.0.0.1:9000/token \
  -u my-backend:dev-secret \
  -d grant_type=client_credentials \
  -d scope="openid profile"
```

### Introspection

```sh
curl -sS -X POST http://127.0.0.1:9000/introspect \
  -d client_id=my-backend \
  -d client_secret=dev-secret \
  -d token="$ACCESS_TOKEN"
```

Returns `{"active": true, ...}` for a live token and `{"active": false}`
otherwise, always with HTTP `200`.

### Revocation

```sh
curl -sS -X POST http://127.0.0.1:9000/revoke \
  -d client_id=my-backend \
  -d client_secret=dev-secret \
  -d token="$ACCESS_TOKEN"
```

The response is `200` with an empty body.

### UserInfo

```sh
curl -sS http://127.0.0.1:9000/userinfo \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

## Built-in token generator UI

Open <http://127.0.0.1:9000/>. The page reads `/ui/info` and offers a tab per
grant:

| Tab | What it does |
| --- | --- |
| Client credentials | POSTs to `/token` from the browser with the selected client, secret and scopes. |
| Username + password | Visible only when `allow_password_grant: true` (marked *deprecated*). |
| Authorization code + PKCE | Generates a verifier/challenge with WebCrypto, opens `/authorize` in a popup, and exchanges the code at `/ui/callback`. |
| Refresh token | POSTs a pasted refresh token to `/token`. |

For each result the UI shows the raw tokens with copy buttons, the decoded
header and payload, the equivalent `curl` command, and buttons to introspect,
call `/userinfo` and revoke. It is the fastest way to confirm a flow works
before wiring it into real code.

Notes:

- The authorization-code tab uses the internal public client `keyfob-ui`,
  registered automatically when `ui.enabled: true` with redirect URI
  `{issuer}/ui/callback`.
- For a non-loopback bind the UI shows a warning and never pre-fills secrets,
  even with `ui.prefill_secrets: true`.
- WebCrypto requires a secure context: use `http://localhost`,
  `http://127.0.0.1` or HTTPS.
- The UI keeps tokens in the browser tab only; they are lost on reload.
