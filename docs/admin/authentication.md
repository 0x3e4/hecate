# Sign-in (OIDC) & Roles

Hecate can sign people in through your identity provider (IdP) over OpenID Connect and give each of
them a role: **admin**, **editor** or **viewer**. It works with any standards-compliant provider —
Keycloak, Authelia, Authentik, Zitadel, Pocket ID, Microsoft Entra ID and others — because everything
provider-specific is read from the issuer's discovery document.

Sign-in is optional. Without it, Hecate behaves exactly as described in
[Security & Access Control](../security-access-control.md): shared passwords, open reads. With it,
the passwords keep working on top, for scripts and for anyone holding them, and every write in the
[audit log](audit.md) names the person who made it.

## How it works

The backend is the OIDC client; the browser never sees a token.

1. **Sign in** sends the browser to `/api/v1/auth/login`, which redirects to your IdP with the
   Authorization Code flow, **PKCE (S256)**, a random `state` and a random `nonce`. The state, nonce
   and PKCE verifier stay on the server, tied to a short-lived cookie for this browser.
2. After the login the IdP redirects to `/api/v1/auth/callback`. The backend checks `state`, redeems
   the code with the PKCE verifier and its client secret, and validates the ID token: signature
   against the IdP's published keys (a new key is fetched when an unknown `kid` appears, so key
   rotation needs no restart), issuer, audience (and `azp` when present), expiry and issue time with a
   small leeway, and the nonce. Only asymmetric algorithms are accepted — never `none`, never HMAC.
3. The role comes from a claim (`groups` by default). Where the ID token lacks it, or lacks a name or
   e-mail address, the userinfo endpoint fills the gap.
4. The backend creates a **server-side session** in MongoDB (`auth_sessions`) and sets an opaque,
   random cookie: `HttpOnly`, `SameSite=Lax`, `Path=/`, and `Secure` whenever the public URL is
   https. MongoDB stores only the SHA-256 of the cookie value, so the collection alone opens no
   session. The session holds the subject, issuer, name, e-mail, role and the ID token (used as the
   logout hint) — no access or refresh token. When it lapses you sign in again, which also picks up a
   changed role.
5. **Sign out** deletes the session and, when the IdP offers an `end_session_endpoint`, sends the
   browser there to end the IdP session as well (RP-initiated logout). Signing in or out also clears the
   system, target and AI passwords this browser saved, so the next person's writes do not carry them.

Sessions end after `AUTH_SESSION_LIFETIME_HOURS` (default 12) at the latest, or after
`AUTH_SESSION_IDLE_MINUTES` (default 120) without a request. A TTL index removes them from MongoDB.

### Cross-site requests

Now that a cookie authenticates, a write must prove it comes from Hecate's own pages: every
cookie-authenticated `POST` / `PUT` / `PATCH` / `DELETE` needs the `X-Hecate-Request` header (the
web app always sends it) and is refused when the browser marks it `Sec-Fetch-Site: cross-site`. A
page on another site cannot add that header without a CORS preflight, and with the default
`CORS_ORIGINS=*` Hecate never allows credentials cross-origin. `SameSite=Lax` keeps the cookie off
cross-site form posts as well. Reads need no header; they cannot be read back by another site.

Serve the web app and the API from the **same site**. The frontend container takes care of that: it
forwards `/api` to the backend, so both share one origin. A frontend on a different site would not
receive the cookie.

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `OIDC_ISSUER` | (unset) | The issuer URL. Discovery is read from `<issuer>/.well-known/openid-configuration`, and its `issuer` field must match. Setting this and `OIDC_CLIENT_ID` turns sign-in on. |
| `OIDC_CLIENT_ID` | (unset) | The client ID registered at the IdP. |
| `OIDC_CLIENT_SECRET` 🔑 | (unset) | The client secret. Empty makes Hecate a public client that relies on PKCE alone, for IdPs that offer that (Pocket ID). The secret goes as HTTP Basic, or in the body when the IdP supports only `client_secret_post`. |
| `OIDC_SCOPES` | `openid profile email` | Requested scopes. Add `groups` where the IdP hands out groups only for that scope (Authelia, Pocket ID). |
| `OIDC_PROVIDER_LABEL` | `Single sign-on` | Text on the "Sign in with …" button. |
| `OIDC_ROLES_CLAIM` | `groups` | The claim holding group or role names. A dotted path reaches nested claims (`realm_access.roles`); a claim whose name contains dots is matched literally first. A list, a single string, or an object (its keys, as Zitadel sends roles) all work. |
| `OIDC_ADMIN_GROUPS` | (unset) | Comma-separated names that grant **admin**. |
| `OIDC_EDITOR_GROUPS` | (unset) | Comma-separated names that grant **editor**. |
| `OIDC_VIEWER_GROUPS` | (unset) | Comma-separated names that grant **viewer**. Empty means every account the IdP signs in is at least a viewer. |
| `AUTH_REQUIRE_LOGIN` | `true` when OIDC is set | `true`: every API read needs a session or another credential (see below). `false`: reads stay public as without OIDC, and signing in only matters for writes. Has no effect without OIDC. |
| `AUTH_PUBLIC_URL` | (unset) | The URL people open Hecate at, e.g. `https://hecate.example.com`. The redirect URI becomes `<url>/api/v1/auth/callback`, and an https URL makes the cookie `Secure`. **Set it in production.** Without it the URL is taken from the request, believing `X-Forwarded-Proto` / `-Host` only from `TRUSTED_PROXY_IPS`. |
| `AUTH_SESSION_LIFETIME_HOURS` | `12` | Absolute session lifetime. |
| `AUTH_SESSION_IDLE_MINUTES` | `120` | A session unused this long ends; `0` turns the idle limit off. |
| `AUTH_COOKIE_NAME` | `hecate_session` | Name of the session cookie. |
| `OIDC_USE_USERINFO` | `true` | Read the userinfo endpoint for claims the ID token lacks. |
| `OIDC_RP_INITIATED_LOGOUT` | `true` | On sign-out, also end the session at the IdP when it has an `end_session_endpoint`. |
| `OIDC_ALLOWED_ALGS` | `RS256,…,EdDSA` | Accepted ID-token signature algorithms (RSA, RSA-PSS, ECDSA, EdDSA). `none` and `HS*` are dropped even if listed. |
| `OIDC_CLOCK_SKEW_SECONDS` | `60` | Leeway for `exp` / `iat`. |
| `OIDC_TIMEOUT_SECONDS` | `10` | Timeout for calls to the IdP. `HTTP_CA_BUNDLE` applies to them like to every outbound call. |

Register this redirect URI at the IdP: `https://<your host>/api/v1/auth/callback`, and allow
`https://<your host>/` as the post-logout redirect.

Group names are compared case-insensitively, and a leading `/` is ignored (Keycloak's group mapper
sends full paths like `/hecate-admins` unless told otherwise). The highest matching role wins. An
account that matches none of the configured groups is refused with a page that says so, and the
attempt is logged as a failed **Sign-in** in the audit log.

At startup the backend warns (`auth.no_admin_groups`) when `OIDC_ADMIN_GROUPS` is empty, and, outside
development, when `AUTH_PUBLIC_URL` is unset (`auth.public_url_unset`).

## Roles

| Role | Can |
| --- | --- |
| **admin** | Everything the system password opens: the System page, API tokens, deleting targets and scans, target passwords, app settings, advisory feeds, notifications, license policies, backups, syncs and re-syncs. |
| **editor** | Everything a target password opens, on every target: scans, rescans, target settings, VEX, dismissals, VEX sources, SBOM imports; plus new targets, the inventory, saved searches, vulnerability refreshes and AI analyses. |
| **viewer** | Reading. Write buttons answer with a short "requires the editor role" notice. |

### Gate by gate

| Action | Admin | Editor | Viewer | Without a session |
| --- | --- | --- | --- | --- |
| System settings: app settings, advisory feeds, notifications, license policies, VEX triage rules, backup / restore, sync triggers, re-sync | ✓ | – | – | system password |
| API tokens: list, create, revoke | ✓ | – | – | system password (required; this gate never opens on its own) |
| Delete a target or a scan | ✓ | – | – | system password |
| Set, change or clear a target's write password | ✓ | with the current target password | with the current target password | system password, or the current target password |
| Target writes: settings, scanners, rescan, check, cancel, VEX, dismiss, VEX sources, SBOM import into the target | ✓ | ✓ | with the target password | system or target password |
| New targets: `POST /scans/targets`, a manual scan or SBOM import of a target that does not exist yet | ✓ | ✓ | – | system password |
| Finding batches that span several targets | ✓ | ✓ | – | system password |
| Inventory edits and the in-app version report | ✓ | ✓ | – | system password; pipelines use an `inventory:report` token |
| Saved searches | ✓ | ✓ | – | system password |
| Vulnerability refresh, `/lookup` that fetches from upstream | ✓ | ✓ | – | system password |
| AI analyses (CVE, batch, attack path, scan, attack chain) | ✓ + AI password if set | ✓ + AI password if set | – | AI password if set, else system or target password |
| CI scan submission `POST /api/v1/scans` | – | – | – | `SCA_API_KEY` or a `scan:submit` token |
| Reads, when login is required | ✓ | ✓ | ✓ | system password, `SCA_API_KEY` or any API token |

Two rules hold throughout:

- **A role is checked first, the password headers after it.** A viewer who holds a target password,
  or an editor who holds the system password, can still use it; the web app sends whatever you
  unlocked on the System page or typed into a target prompt.
- **A signed-in user with too low a role gets `403`** with the header `X-Auth-Role-Required: admin`
  or `editor`, and the web app shows a notice instead of a password prompt. Someone not signed in gets
  `401` with `X-Auth-Required: login`; when a password would also do, the response carries the usual
  `X-Write-Auth-Required` marker and the password dialog offers **Sign in instead**.

!!! note "The AI password stays a cost lock"
    When `AI_ANALYSIS_PASSWORD` is set, everyone needs it to start an AI analysis, admins included,
    and a viewer is refused even with it. Callers without a session keep the old rule: the AI
    password alone.

!!! warning "With OIDC, the gates no longer open on their own"
    Without OIDC, a gate whose password is not set lets every write through (fail-open). Once sign-in
    is configured, an anonymous write needs a session or a configured password; there is nothing left
    that opens without one. Set `OIDC_ADMIN_GROUPS` before you rely on this, or keep a
    `SYSTEM_PASSWORD` as the way in.

## Reads, scripts and CI

With `AUTH_REQUIRE_LOGIN=true` (the default once OIDC is configured) every `/api/v1` route needs a
caller Hecate can name. A browser shows the sign-in screen; scripts send one of:

| Header | Accepted for reads |
| --- | --- |
| `X-API-Key: <SCA_API_KEY>` | yes |
| `X-API-Key: hct_…` (an API token of any scope) | yes |
| `X-System-Password: …` | yes |
| `X-Target-Password` / `X-AI-Analysis-Password` | only on writes, where the route's own gate checks them |

The CI examples on the **CI/CD** info page already send `X-API-Key` when they poll
`GET /api/v1/scans/{id}`, so a pipeline keeps working unchanged. A token with only the `scan:submit`
scope can read every API route; treat tokens as the read credentials they now are.

These stay open without a session:

- `GET /api/v1/status/health` (container probes)
- `GET /api/v1/config` (the web app learns from it that sign-in is on)
- the shields.io badges `GET /api/v1/scans/{id}/shield` and `GET /api/v1/scans/targets/{id}/shield`
- `/api/v1/auth/*`

The live event stream (`/api/v1/events`) needs the session like any read; the browser sends the
cookie with it. Swagger (`/api/docs`) and the OpenAPI schema describe the API but return no data and
stay reachable; MCP keeps its own OAuth and is not affected by any of this.

With `AUTH_REQUIRE_LOGIN=false` reads stay public. The audit log is then public too, and shows
anonymous readers who did something by name and role, without the e-mail address or IdP subject.

## Behind a reverse proxy

- Set `AUTH_PUBLIC_URL` to the browser-facing URL. It fixes the redirect URI the IdP must accept and
  makes the cookie `Secure`.
- Keep `TRUSTED_PROXY_IPS=frontend` (the gateway is the backend's proxy) and make sure your reverse
  proxy's address is in the frontend's `TRUSTED_PROXIES`; the audit log and the password throttle then
  see the real client address.
- Send every route to the frontend container (the templates in `deploy/reverse-proxy/` do). Do not
  build the frontend with a `VITE_API_BASE_URL` on another site: the session cookie would not reach it.
- If the IdP itself sits behind a TLS-inspecting proxy with a private CA, `HTTP_CA_BUNDLE` covers the
  backend's calls to it.

## Setting up your identity provider

In every case: create a confidential OIDC client (Authorization Code, PKCE S256), register
`https://hecate.example.com/api/v1/auth/callback` as redirect URI and `https://hecate.example.com/` as
post-logout redirect, and decide which groups or roles map to admin, editor and viewer. Replace
`hecate.example.com` with your host throughout.

### Keycloak

1. **Clients → Create client**: type *OpenID Connect*, client ID `hecate`. Turn **Client
   authentication** on, keep **Standard flow**, turn **Direct access grants** off.
2. **Valid redirect URIs**: `https://hecate.example.com/api/v1/auth/callback`; **Valid post logout
   redirect URIs**: `https://hecate.example.com/`.
3. **Advanced → Proof Key for Code Exchange Code Challenge Method**: `S256`.
4. Groups: create `hecate-admins`, `hecate-editors`, `hecate-viewers`. In **Client scopes →
   hecate-dedicated → Add mapper → By configuration → Group Membership**, set the token claim name
   to `groups`, turn **Full group path** off and **Add to ID token** on.
   Realm roles work too: turn **Add to ID token** on for the *realm roles* mapper in the `roles`
   client scope and set `OIDC_ROLES_CLAIM=realm_access.roles` (client roles:
   `resource_access.hecate.roles`).

```dotenv
OIDC_ISSUER=https://keycloak.example.com/realms/acme
OIDC_CLIENT_ID=hecate
OIDC_CLIENT_SECRET=<Credentials tab>
OIDC_PROVIDER_LABEL=Keycloak
OIDC_ADMIN_GROUPS=hecate-admins
OIDC_EDITOR_GROUPS=hecate-editors
OIDC_VIEWER_GROUPS=hecate-viewers
AUTH_PUBLIC_URL=https://hecate.example.com
```

### Authelia

Add a client to `identity_providers.oidc.clients` (Authelia 4.38+ syntax):

```yaml
- client_id: 'hecate'
  client_name: 'Hecate'
  client_secret: '$pbkdf2-sha512$310000$...'   # authelia crypto hash generate pbkdf2
  public: false
  authorization_policy: 'two_factor'
  require_pkce: true
  pkce_challenge_method: 'S256'
  redirect_uris:
    - 'https://hecate.example.com/api/v1/auth/callback'
  scopes: ['openid', 'profile', 'email', 'groups']
  response_types: ['code']
  grant_types: ['authorization_code']
  token_endpoint_auth_method: 'client_secret_basic'
```

Authelia puts the `groups` claim into the userinfo response rather than the ID token; Hecate reads it
from there (`OIDC_USE_USERINFO=true`, the default).

```dotenv
OIDC_ISSUER=https://auth.example.com
OIDC_CLIENT_ID=hecate
OIDC_CLIENT_SECRET=<the plain secret you hashed>
OIDC_SCOPES=openid profile email groups
OIDC_PROVIDER_LABEL=Authelia
OIDC_ADMIN_GROUPS=hecate-admins
OIDC_EDITOR_GROUPS=hecate-editors
```

### Authentik

1. **Applications → Providers → Create → OAuth2/OpenID Provider**: client type *Confidential*,
   redirect URI `https://hecate.example.com/api/v1/auth/callback` (strict).
2. **Signing key**: pick a certificate (e.g. the self-signed one). Without it Authentik signs ID
   tokens with HS256, which Hecate refuses.
3. Create an **Application** with slug `hecate` that uses the provider, and bind the groups that may
   use it. The default `profile` scope mapping already sends a `groups` claim.

```dotenv
OIDC_ISSUER=https://authentik.example.com/application/o/hecate/
OIDC_CLIENT_ID=<Client ID>
OIDC_CLIENT_SECRET=<Client Secret>
OIDC_PROVIDER_LABEL=Authentik
OIDC_ADMIN_GROUPS=hecate-admins
OIDC_EDITOR_GROUPS=hecate-editors
```

Keep the trailing slash in the issuer: it is part of Authentik's issuer value, and discovery must
match it.

### Microsoft Entra ID

1. **App registrations → New registration**, platform **Web**, redirect URI
   `https://hecate.example.com/api/v1/auth/callback`. Add `https://hecate.example.com/` as a second
   redirect URI; Entra only honours a post-logout redirect it knows.
2. **Certificates & secrets → New client secret.**
3. **App roles → Create app role** three times (allowed member types: users/groups), with the values
   `Hecate.Admin`, `Hecate.Editor` and `Hecate.Viewer`.
4. **Enterprise applications → Hecate → Users and groups**: assign people or groups to those roles.
   Set **Assignment required** to *Yes* if only assigned users may sign in at all.
5. Optional: **Token configuration → Add optional claim → ID → email**, so the audit log shows an
   address rather than the UPN.

```dotenv
OIDC_ISSUER=https://login.microsoftonline.com/<tenant-id>/v2.0
OIDC_CLIENT_ID=<Application (client) ID>
OIDC_CLIENT_SECRET=<secret value>
OIDC_PROVIDER_LABEL=Microsoft
OIDC_ROLES_CLAIM=roles
OIDC_ADMIN_GROUPS=Hecate.Admin
OIDC_EDITOR_GROUPS=Hecate.Editor
OIDC_VIEWER_GROUPS=Hecate.Viewer
```

Use the **tenant ID** (a GUID) in the issuer, not a domain name or `common` / `organizations`: the
v2.0 discovery document names the GUID form, and a multi-tenant issuer template cannot be checked.
Prefer **app roles** in the `roles` claim over the `groups` claim: Entra puts groups as object IDs
rather than names, and once a user is in more than 200 groups it drops them from the token in favour
of an overage pointer that would need a Graph call.

### Generic (Zitadel, Pocket ID and others)

Any provider with a discovery document, the Authorization Code flow and asymmetrically signed ID
tokens works. Find out which claim carries groups or roles and point `OIDC_ROLES_CLAIM` at it:

- **Zitadel**: turn on *Assert Roles on Authentication* for the project and set
  `OIDC_ROLES_CLAIM=urn:zitadel:iam:org:project:roles` (an object whose keys are the role names).
- **Pocket ID**: create an OIDC client, add `groups` to `OIDC_SCOPES`, and use the group names. Pocket
  ID also supports public clients with PKCE, so `OIDC_CLIENT_SECRET` may stay empty.

To see what your IdP sends, sign in once with only `OIDC_VIEWER_GROUPS` empty (everyone becomes a
viewer), then compare the claims in your IdP's token preview with the names you configured.

## Passwords and sign-in together

- The system password, target passwords, `SCA_API_KEY` and API tokens keep working everywhere they
  worked before, with or without a session.
- A signed-in **admin** never sees the System or Audit password dialog: the role opens what the
  password would.
- A signed-in user below admin who opens the System page sees the password dialog when a system
  password is set (the escape hatch for whoever holds it), and otherwise a note that changes need
  the admin role.
- The AI page keeps its AI-password dialog whenever an AI password is configured.

## Audit trail

Every write that reaches the API is recorded, allowed or refused, as an **API write** entry: the
actor, method, route template (`/scans/targets/{target_id:path}`), path parameters, HTTP status,
outcome and client IP. The actor is the signed-in user (name, e-mail, role), or the credential that
authorized the request — system password, target password (with the target), API token (with its
name), SCA API key, AI password — or *Anonymous* on an install without any gate. Sign-ins (also failed
ones, with the reason), sign-outs and password-dialog checks get entries of their own. See
[Audit & Observability](audit.md#who-did-it).
