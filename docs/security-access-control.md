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

All gates are **fail-open**: if the corresponding secret is unset, that gate is a no-op.

## Layer A — global admin gate

When `SYSTEM_PASSWORD` is set, every mutating REST endpoint requires `X-System-Password` to match.
This covers targets, scans, findings/VEX, inventory, notifications, license policies, saved
searches, data sync/resync, backup-restore, manual refresh, and AI writes. Exceptions that
self-authorize: `POST /api/v1/scans` (CI key) and `POST /api/v1/status/system-auth` (the password
check itself).

The web UI persists the admin password after you unlock the **System** page and automatically
attaches the header to subsequent writes — so an admin just unlocks once.

## Layer B — per-target write delegation

You can give an individual SCA target its **own** write password so a target owner can manage
*their* target without the global admin password. A write scoped to a target is authorized if
**either** the admin password matches (override) **or** the target's password verifies.

A target owner can:

- edit the target's settings, run/cancel/delete its scans, trigger a `/check`
- set VEX status and dismiss its findings
- run scan-scoped AI analysis (still requires the AI password too)

A target owner **cannot** touch other targets or admin-only resources (inventory, notifications,
policies, sync, backups). Per-target passwords are stored **hashed** (PBKDF2) in MongoDB and are
never returned by the API — the target only exposes a boolean `writePasswordSet`.

### Managing per-target passwords (admin)

Setting or clearing a target password is always an admin action:

- **System → Access Control → Target Access** — a list of all targets with set/clear controls.

The per-target detail page (`/scans/targets/<id>`) shows a 🔒 badge when a target is protected, but
passwords are configured only from System → Access Control.

A 🔒 badge marks protected targets. To use per-target passwords meaningfully, set
`SYSTEM_PASSWORD` so these management endpoints are admin-gated.

API: `PUT /api/v1/scans/targets/{id}/write-password` (body `{ "password": "…" }`) and
`DELETE /api/v1/scans/targets/{id}/write-password`.

## AI is always gated by the AI password

When `AI_ANALYSIS_PASSWORD` is set, the AI password is **always required** to trigger AI —
independent of the write gate, as the final layer:

- **Non-target AI** (CVE investigation, batch, attack-path narrative) → admin write gate **+** AI password.
- **Scan-scoped AI** (scan analysis, attack-chain narrative) → the target's write authorization **+** AI password.

So with both a write password and the AI password configured, you cannot trigger AI without the AI
password — and you also need the relevant write access. The web UI sends both headers
automatically once you've unlocked.

## Typical setups

A **single operator** running a private instance can simply set `SYSTEM_PASSWORD` (and
`AI_ANALYSIS_PASSWORD` if AI is enabled), unlock the System page once, and let the UI attach the
headers to every subsequent write. No per-target passwords are needed.

A **shared instance with delegated ownership** keeps the admin password for yourself and hands each
target owner a per-target password from **System → Access Control**. Owners can then manage their own
target — settings, scans, findings, VEX, and scan-scoped AI — without ever holding the admin password,
and they cannot touch other targets or admin-only resources (inventory, notifications, policies, sync,
backups).

A **CI/CD pipeline** uses neither the admin nor a target password: it submits scans with the
`SCA_API_KEY` via the `X-API-Key` header, which is independent of the write gate. See
[CI/CD](integrations/cicd.md).

## What this is not

This is a shared-secret gate, **not** user-level authentication, and it does **not** encrypt
traffic. For a live deployment, pair it with:

- **TLS** at the reverse proxy.
- **Network ACLs** / VPN to limit who can reach the API at all.

MCP writes are independent: they require the OAuth `mcp:write` scope (granted by
`MCP_WRITE_IP_SAFELIST`), not these passwords.
