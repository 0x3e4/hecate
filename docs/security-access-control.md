# Security & Access Control

Hecate is a single-operator-friendly tool. It does not (yet) have user accounts or an identity
service; access is gated by **shared-secret passwords** sent as HTTP headers. This is an interim
model — proportionate for a locked-down internal instance — and is designed to be replaced cleanly
by a real identity service later.

!!! info "Reads are always open"
    Only mutating requests (`POST` / `PUT` / `PATCH` / `DELETE`) are gated. Browsing, searching,
    viewing scans, findings, SBOMs and reports never requires a password.

## The three secrets

| Secret | Env var | Header | Gates |
| --- | --- | --- | --- |
| **Admin password** | `SYSTEM_PASSWORD` | `X-System-Password` | All REST writes (Layer A) and System-page access. |
| **AI password** | `AI_ANALYSIS_PASSWORD` | `X-AI-Analysis-Password` | Triggering any AI analysis — the always-required final layer. |
| **Per-target password** | set in the UI (hashed in MongoDB) | `X-Target-Password` | Writes scoped to one SCA target (Layer B). |
| **SCA API key** | `SCA_API_KEY` | `X-API-Key` | The CI/CD scan-submission endpoint `POST /api/v1/scans`. |
| **API token** | created in the UI (hashed in MongoDB) | `X-API-Key` | The routes of its scopes, see [API tokens](#api-tokens). |
| **Scanner secret** | `SCA_SCANNER_SECRET` | `X-Scanner-Secret` | The scanner sidecar's own API, between the backend and the sidecar. |

The password gates are **fail-open**: if the corresponding secret is unset, that gate is a no-op. The
exceptions are `POST /api/v1/scans`, which answers `503` with neither a key nor a token, and token
management, which needs `SYSTEM_PASSWORD`.

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
This covers targets, scans, findings/VEX, inventory, notifications, license policies, saved
searches, data sync/resync, backup-restore, manual refresh, and AI writes. Exceptions that
self-authorize: `POST /api/v1/scans` (CI key) and `POST /api/v1/status/system-auth` (the password
check itself).

`POST /api/v1/vulnerabilities/lookup` is a read until it would write: finding a stored record stays
public, but fetching a miss from upstream needs the header. An anonymous lookup with the default
`autoSync` therefore answers `401` on a miss. Pass `autoSync: false` for a plain read.

The web UI persists the admin password after you unlock the **System** page and automatically
attaches the header to subsequent writes — so an admin just unlocks once.

## Layer B — per-target write delegation

You can give an individual SCA target its **own** write password so a target owner can manage
*their* target without the global admin password. A write scoped to a target is authorized if
**either** the admin password matches (override) **or** the target's password verifies.

A target owner can:

- edit the target's settings, run/cancel/delete its scans, trigger a `/check`
- set VEX status and dismiss its findings
- run scan-scoped AI analysis, unless an AI password is set: then that password decides

A target owner **cannot** touch other targets or admin-only resources (inventory, notifications,
policies, sync, backups). Per-target passwords are stored **hashed** (PBKDF2) in MongoDB and are
never returned by the API — the target only exposes a boolean `writePasswordSet`.

### Managing per-target passwords (admin)

Setting or clearing a target password is always an admin action:

- **System → Access Control → Target Access** — a list of all targets with set/clear controls.

The per-target detail page (`/scans/targets/<id>`) shows a 🔒 badge when a target is protected, but
passwords are configured only from System → Access Control.

A 🔒 badge marks protected targets. Managing target passwords requires `SYSTEM_PASSWORD`: like
API tokens, these two endpoints answer `403` when it is unset rather than opening to everyone, since
anyone could otherwise clear a target's password and then write to it.

API: `PUT /api/v1/scans/targets/{id}/write-password` (body `{ "password": "…" }`) and
`DELETE /api/v1/scans/targets/{id}/write-password`.

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
target — settings, scans, findings, VEX, and scan-scoped AI — without ever holding the admin password,
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

This is a shared-secret gate, **not** user-level authentication, and it does **not** encrypt
traffic. For a live deployment, pair it with:

- **TLS** at the reverse proxy — ready-to-adapt nginx / Caddy / Traefik templates (with a
  hardened security-header set) live in `deploy/reverse-proxy/`.
- **Network ACLs** / VPN to limit who can reach the API at all.
- **Scoped CORS** via `CORS_ORIGINS` (see [Configuration](configuration.md)). Reads are open by
  design, so the `*` default lets any browser origin read the API; set explicit origin(s) to keep
  cross-origin reads scoped to your own frontend.

MCP writes are independent: they require the OAuth `mcp:write` scope (granted by
`MCP_WRITE_IP_SAFELIST`), not these passwords.
