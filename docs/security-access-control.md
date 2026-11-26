# Security & Access Control

Out of the box, Hecate gates writes with **shared-secret passwords** sent as HTTP headers —
proportionate for a single operator or a locked-down internal instance. For a team, connect your
identity provider: [Sign-in (OIDC) & Roles](admin/authentication.md) gives every person an admin,
editor or viewer role, can require a sign-in for reading too, and names the person behind every write
in the audit log. The passwords described here keep working alongside it.

!!! info "Reads are open unless sign-in requires otherwise"
    Browsing, searching, viewing scans, findings, SBOMs and reports needs no password. The exceptions
    are the admin reads: the audit log, the System page's settings (notifications, backups, sync
    states, advisory feeds, server lists) and API tokens need the system password or an admin session, and the AI
    analysis history needs the AI password when one is set. With OIDC and `AUTH_REQUIRE_LOGIN=true`
    (its default), every read needs a session, an API key or the system password.

## The three secrets

| Secret | Env var | Header | Gates |
| --- | --- | --- | --- |
| **Admin password** | `SYSTEM_PASSWORD` | `X-System-Password` | All REST writes (Layer A), the System page, the audit log and API tokens. |
| **AI password** | `AI_ANALYSIS_PASSWORD` | `X-AI-Analysis-Password` | Starting any AI analysis, and listing past ones on the AI analysis page. Required for every role. |
| **Per-target password** | set in the UI (hashed in MongoDB) | `X-Target-Password` | Writes scoped to one SCA target (Layer B). |
| **SCA API key** | `SCA_API_KEY` | `X-API-Key` | The CI/CD scan-submission endpoint `POST /api/v1/scans`. |
| **API token** | created in the UI (hashed in MongoDB) | `X-API-Key` | The routes of its scopes, see [API tokens](#api-tokens). |
| **Scanner secret** | `SCA_SCANNER_SECRET` | `X-Scanner-Secret` | The scanner sidecar's own API, between the backend and the sidecar. |

The password gates are **fail-open**: if the corresponding secret is unset, that gate is a no-op. The
exceptions are `POST /api/v1/scans`, which answers `503` with neither a key nor a token, and token
management, which needs `SYSTEM_PASSWORD` (or a signed-in admin). Once OIDC sign-in is configured,
no gate opens on its own any more: a write needs a sufficient role or a configured password.

### Comparison & brute-force protection

Every secret is compared in **constant time**, and every route that checks one, including the
password-check endpoints (`POST /api/v1/status/system-auth`, `/status/ai-auth`), the target-scoped
writes and `POST /api/v1/scans`, carries a **per-client throttle with lockout**:
after ten failures from the same client within a minute, further attempts are rejected with
`HTTP 429` for five minutes before the secret is even checked. The counter belongs to the secret, not
to the route, so guesses at the system password share one budget across the unlock dialog, the write
gate and every target route. An IPv6 client counts by its /64. A request that carries a valid target
password never compares the admin password at all, so a target owner cannot probe it. This caps online guessing so a weak password can't
be brute-forced at full request rate. The client is identified from the reverse proxy's forwarded
address where present (see [Reverse proxy / real client IP](configuration.md)); the throttle is
in-memory and best-effort — defence in depth, not a substitute for a strong secret, TLS, and network
ACLs.

## Layer A — global admin gate

When `SYSTEM_PASSWORD` is set, every mutating REST endpoint requires `X-System-Password` to match.
This covers targets, scans, findings/VEX, inventory, notifications, license policies, VEX rules, saved
searches, data sync/resync, backup-restore, manual refresh, and AI writes. Exceptions that
self-authorize: `POST /api/v1/scans` (CI key) and `POST /api/v1/status/system-auth` (the password
check itself).

`POST /api/v1/vulnerabilities/lookup` is a read until it would write: finding a stored record stays
public, but fetching a miss from upstream needs the header. An anonymous lookup with the default
`autoSync` therefore answers `401` on a miss. Pass `autoSync: false` for a plain read.

The audit log and the System page's own settings are closed for reading too: the audit log, notification
channels (their Apprise URLs carry tokens), rules and templates, backup exports, sync states and the advisory feed list need the
header (or a signed-in admin). Without `SYSTEM_PASSWORD` and without OIDC they stay open like every
admin gate; with OIDC an anonymous caller is refused even when `AUTH_REQUIRE_LOGIN=false`.

The web UI persists the admin password after you unlock the **System** page and automatically
attaches the header to subsequent writes and to those settings reads — so an admin just unlocks once.

## Layer B — per-target write delegation

You can give an individual SCA target its **own** write password so a target owner can manage
*their* target without the global admin password. A write scoped to a target is authorized if
**either** the admin password matches (override) **or** the target's password verifies.

A target owner can:

- switch auto-scan, choose its scanners and set the application group, run and cancel its scans,
  trigger a `/check`
- import an SBOM into an existing SBOM-import target (a new one needs the admin). The target is
  the one the import writes to: with no `targetName` that is the name inside the SBOM itself, so
  an SBOM naming another target needs that target's password
- change or remove the target's own password
- set VEX status and dismiss its findings
- mark a completed scan as a release and remove the marker (`PUT` / `DELETE /api/v1/scans/{scanId}/release`)
- run scan-scoped AI analysis, unless an AI password is set: then that password decides

A target owner **cannot** delete the target or any of its scans: deleting takes the system password,
since it throws away the history the target password is meant to protect. A scan marked as a release is
refused (`409`) even with the system password until its marker is removed.
The evidence bundle (`GET /api/v1/scans/{scanId}/evidence-bundle`) and the VEX exports are reads, open like
the SBOM export. Nor can an owner touch
other targets or admin-only resources (inventory, notifications, policies, sync, backups). Per-target passwords are stored **hashed** (PBKDF2) in MongoDB and are
never returned by the API — the target only exposes a boolean `writePasswordSet`.

### Managing per-target passwords

- **System → Access Control → Target Access** (admin) — a list of all targets with set/clear controls.
- **Change password** on the target page (`/scans/targets/<id>`, shown on protected targets) — the
  owner sets a new password or removes the protection, authorized by the current one. Whoever uses
  the old password needs the new one afterwards.

The first password on a target always comes from the admin. Without `SYSTEM_PASSWORD` a target that
has no password answers `403` instead of opening to everyone, since anyone could otherwise set one and
lock its owners out; a target that already has one can still be changed by its owner.

A 🔒 badge marks protected targets. When a write can only be authorized by the system password, the
`401` carries `X-Write-Auth-Required: admin` and the UI asks for that password alone; target gates
answer with `1`, which offers the target password as well.

API: `PUT /api/v1/scans/targets/{id}/write-password` (body `{ "password": "…" }`) and
`DELETE /api/v1/scans/targets/{id}/write-password`, each with `X-System-Password` or the current
`X-Target-Password`.

A target's **VEX sources** (`PUT /api/v1/scans/targets/{id}/vex-sources`,
`POST …/vex-sources/apply`) are a target write like any other, so the target password opens them.
Because the backend then fetches a URL a target owner chose, the fetch is held to public hosts: https
only, no credentials in the URL, every address the host resolves to must be public (the same check as
the advisory feeds; `SCA_VEX_SOURCES_ALLOW_PRIVATE_HOSTS=true` lifts it for an intranet host), no
redirects, at most `SCA_VEX_SOURCE_MAX_BYTES`, and a failure is reported only as a short category,
since targets are public.

**Server lists** Hecate fetches for the inventory (`/api/v1/inventory/systems/sources`) are admin-only,
reads included: a list holds a credential and makes the backend send requests. Their URLs take the
advisory feeds' host check (`INVENTORY_LIST_SOURCES_ALLOW_PRIVATE_HOSTS=true` lifts it), no
credentials in the URL (a header instead, sent over https only, never returned), no redirects and a
5 MB cap ([fetched lists](guide/inventory.md#fetched-lists)).

## AI is always gated by the AI password

When `AI_ANALYSIS_PASSWORD` is set, that password **alone** authorizes triggering AI, and the write
gates are not asked as well, so the web UI shows one prompt instead of two:

- **Non-target AI** (CVE investigation, batch, attack-path narrative) → AI password.
- **Scan-scoped AI** (scan analysis, attack-chain narrative) → AI password.

Without an AI password, the same actions fall back to the write gates: the system password for
non-target AI, and the target's write authorization for scan-scoped AI.

## Typical setups

A **single operator** running a private instance can simply set `SYSTEM_PASSWORD` (and
`AI_ANALYSIS_PASSWORD` if AI is enabled), unlock the System page once, and let the UI attach the
headers to every subsequent write. No per-target passwords are needed.

A **shared instance with delegated ownership** keeps the admin password for yourself and hands each
target owner a per-target password from **System → Access Control**. Owners can then manage their own
target — settings, scanners, scans, findings, VEX, scan-scoped AI and its own password — without ever holding the admin password,
and they cannot touch other targets or admin-only resources (inventory, notifications, policies, sync,
backups).

A **CI/CD pipeline** uses neither the admin nor a target password: it holds an API token, or the
`SCA_API_KEY`, in the `X-API-Key` header, independent of the write gate. See
[CI/CD](integrations/cicd.md).

## API tokens

A token goes to one pipeline or tool, opens only what its scopes allow, and can be revoked without
touching the others. Create them on **System → Access Control**.

| Scope | Opens |
| --- | --- |
| `scan:submit` | `POST /api/v1/scans` |
| `inventory:report` | `POST /api/v1/inventory/report` |
| `sbom:import` | `POST /api/v1/scans/import-sbom` and `/import-sbom/upload`, for new targets and SBOM-import targets only ([hosts, nodes and other systems](sca/hosts.md)) |
| `inventory:sync` | `POST /api/v1/inventory/systems/import` and `/import/upload`: server lists for the inventory's systems, a replace can retire systems ([server lists](guide/inventory.md#server-lists)) |

- **The token is shown once.** Hecate stores a SHA-256 hash and the first characters for telling
  tokens apart. A lost token is revoked and replaced.
- **`SCA_API_KEY` keeps working for scans and opens nothing else.** Set it, use tokens, or do both;
  with neither, scan submission answers `503`.
- **The version report takes a token, not the SCA key**, because a report can make CVE matches
  disappear. The system password still works for people.
- **Managing tokens needs `SYSTEM_PASSWORD`**, also for listing them, and answers `403` without it:
  unlike the other gates this one does not open, or anyone could create a token.
- A token without the required scope gets `403`, an unknown, expired or revoked one `401`. Wrong
  tokens count toward the same lockout as wrong passwords.
- The inventory history names the token. `reportedBy` is free text and appears after it in brackets.

## Scanner sidecar

The sidecar has an API of its own: it starts scanners on whatever it is told to fetch, and it holds
`SCANNER_AUTH`. In the compose example only the backend can reach it. As soon as anything else can,
for example when it runs on another host, set the same `SCA_SCANNER_SECRET` on both sides (for
example from `openssl rand -hex 32`) and put TLS in front of it.

With a secret set, every route except `/health` needs the `X-Scanner-Secret` header. A wrong value
shows as an unreachable scanner on the System page, and the backend logs `scanner.secret_rejected`.

The sidecar takes the secret out of its environment at startup, so scanners do not inherit it. A
compromised scanner can still read it from `/proc/1/environ`, but it only opens the sidecar that
scanner is already running in, so use a different value per deployment.

## What this is not

The passwords are a shared-secret gate, **not** user-level authentication (that is what
[OIDC sign-in](admin/authentication.md) adds), and none of it encrypts traffic. For a live
deployment, pair it with:

- **TLS** at the reverse proxy — ready-to-adapt nginx / Caddy / Traefik templates (with a
  hardened security-header set) live in `deploy/reverse-proxy/`.
- **No direct path to the backend.** The frontend container is the gateway for `/api` and `/mcp`,
  so the backend publishes no port in the shipped compose file. Keep it that way: a published
  backend port bypasses the reverse proxy's TLS and headers. The backend trusts forwarded client
  addresses only from the gateway (`TRUSTED_PROXY_IPS=hecate-frontend`), not from the scanner or other
  containers on the same network.
- **Network ACLs** / VPN to limit who can reach the API at all.
- **Scoped CORS** via `CORS_ORIGINS` (see [Environment Variables](configuration.md)). Reads are open by
  design, so the `*` default lets any browser origin read the API; set explicit origin(s) to keep
  cross-origin reads scoped to your own frontend.

MCP writes are independent: they require the OAuth `mcp:write` scope (granted by
`MCP_WRITE_IP_SAFELIST`), not these passwords.
