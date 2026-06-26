# Changelog

This page mirrors the project changelog in full. The canonical source lives in the repository at
[`CHANGELOG.md`](https://github.com/0x3e4/hecate/blob/main/CHANGELOG.md); GitHub Releases are
generated from it on every semver tag. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

!!! tip "Check your running version"
    The in-app **Support** page compares your running build SHA against the latest published image
    and tells you whether an update is available. See [Getting Started](getting-started.md#updating)
    for the upgrade command.

## [Unreleased]

### Added

### Changed

### Fixed

## [1.4.0] - 2026-06-26

### Added

- **SBOM changes** card on the scan-target detail page: shows how the software bill of materials changed between the target's two most-recent completed scans — components added, version-updated (`old → new`), and removed — annotated with the latest scan's date and commit short-hash. Shows a baseline line for targets with a single completed scan. Backed by a new `GET /api/v1/scans/targets/{id}/sbom-diff` endpoint.
- **Advisory fix hint in scan findings**: the Findings tab now surfaces a vulnerability's unaffected/patched versions (from the advisory's impacted-products data) as a teal "adv" chip next to the scanner's own fix version — filling the gap when a scanner reports no fix. Computed at read time, so it always reflects the current vulnerability database.
- **"Affected in your scans" block** on the vulnerability detail page (red, mirroring the "Affected in your environment" inventory callout): lists the SCA scan targets affected by this CVE (or its aliases), each linking to the covering scan. Two kinds of match — a confirmed scan **finding** (with scanner + fix), or an **SBOM** match where the package is in the target's latest scan at an affected version but the scan predates the advisory (tagged *in SBOM · rescan to confirm*), so newly-published CVEs surface even without a re-scan.

### Changed

- Documentation sync for the SBOM-changes card, the advisory fix hint in findings, and the affected-scans block on CVE detail.
- Dependency bumps. Backend: `mcp` 1.28.0 → 1.28.1, `click` 8.4.1 → 8.4.2, `typer` 0.26.7 → 0.26.8, `google-auth` 2.55.0 → 2.55.1, `anyio` 4.14.0 → 4.14.1, `coverage` 7.14.2 → 7.14.3. Scanner: `fastapi` 0.138.0 → 0.138.1, `anyio` 4.14.0 → 4.14.1, `click` 8.4.1 → 8.4.2. Frontend: `dompurify` 3.4.8 → 3.4.10, `es-toolkit` 1.47.0 → 1.47.1, `ts-dedent` 2.2.0 → 2.3.0, plus transitive refreshes (`acorn`, `caniuse-lite`, `baseline-browser-mapping`, `electron-to-chromium`, `es-iterator-helpers`, `function.prototype.name`, `side-channel`).

## [1.3.1] - 2026-06-22

### Added

- MCP tools to manage the Environment Inventory: `list_inventory_items` / `get_inventory_item` (read; each item carries its endoflife.date support status) and `create_inventory_item` / `update_inventory_item` / `delete_inventory_item` (write-scope gated). MCP tool count 35 → 40.
- The endoflife.date badge now shows the version's support-until date, an LTS chip, a "newer release line" hint, and a link to the product's endoflife.date page.
- The dashboard "Today" widgets now also highlight vendors/products/CVEs covered by your **SCA scans** (latest scan per target — by SBOM package or finding), floating them up with a teal tag labelled by the scan target. Both the inventory and scan tags are clickable — they open the Inventory page and the most-recent covering scan respectively.

### Changed

- Inventory items now render as compact status rows (click a row to expand its affecting CVEs) instead of cards, and the add/edit form opens from an **Add** icon button in the "Configuration management" header. Inventory edits refresh the row, its CVEs and the "Flagged CVEs" table instantly — no manual reload.
- The "Flagged CVEs" table's "Affected items" column now shows `product · version` instead of the item name.
- Documentation sync for the inventory MCP tools, the richer endoflife.date status, the compact-row UX, the auto-mapping fix, and the dashboard SCA cross-reference.
- Dependency bumps. Backend: `mcp` 1.27.2 → 1.28.0, `cryptography` 48.0.0 → 49.0.0, `google-auth` 2.53.0 → 2.55.0, `pydantic-settings` 2.14.1 → 2.14.2, `python-multipart` 0.0.30 → 0.0.32, `sse-starlette` 3.4.4 → 3.4.5, `tzlocal` 5.3.1 → 5.4.3, plus `anyio` / `certifi` / `coverage` / `grpcio` / `protobuf` / `pywin32` refreshes. Scanner: `fastapi` 0.136.3 → 0.138.0, `starlette` 1.2.1 → 1.3.1, `uvicorn` 0.48.0 → 0.49.0, `anyio` 4.13.0 → 4.14.0. Frontend: `axios` 1.16.1 → 1.17.0, `react`/`react-dom` 19.2.6 → 19.2.7, `react-router-dom` 7.15.1 → 7.17.0, `vite` 7.3.3 → 7.3.5.

### Fixed

- Editing an inventory item (e.g. a version bump) no longer wipes a manual endoflife.date product link — the auto-mapping only re-runs when the product itself changes.

## [1.3.0] - 2026-06-19

### Added

- End-of-life / support tracking for Environment Inventory items via endoflife.date: cards show active-support / security-support / end-of-life status, the cycle's latest release, and an "update available" hint. Products are auto-linked by name with a manual override (and clear) in the add/edit dialog. Configurable via `ENDOFLIFE_*` env vars and the `eolEnabled` runtime flag.
- "Flagged CVEs" table on the Inventory page listing every distinct CVE affecting any configured item, sorted by severity, each linked to its vulnerability detail page.
- Dashboard "Today" widgets now highlight configured-inventory vendors, products, and CVEs and float them to the top, with a count of how many of the day's CVEs touch your inventory.

### Changed

- The inventory add/edit form now opens in a modal dialog, and the "Your Inventory" section is renamed to "Configuration management".
- Documentation sync for the endoflife.date integration, the inventory matcher fix, and the dashboard inventory highlight.

### Fixed

- Inventory matching is now strictly fail-closed for version-less references: a bare `vendor:product:*` CPE (with no version bounds) or a broad `>=0` range string no longer matches a specific installed version. This removes false positives such as old phpBB add-on-module CVEs (CVE-2008-6301, CVE-2007-5688, CVE-2006-7168, CVE-2007-5173) being reported as affecting phpBB 3.3.17.

## [1.2.4] - 2026-06-11

### Added

- "Unaffected" / fixed-in versions column on the vulnerability detail page
- Search field to filter scan targets by name or URL on the SCA Targets tab

### Changed

- Redesigned per-target SCA overview with a metrics strip and severity bar

### Fixed

- Open SCA target pages whose URL contains encoded or unescaped characters
- Mobile dashboard "Today" loading bar no longer crowds the date arrows

## [1.2.3] - 2026-06-10

### Added

- Configurable AI batch-analysis limit, editable in System → General
- Pick vulnerabilities for AI Analyse from a saved search, not just live search

### Changed

- AI password alone authorizes AI analysis when set (no separate write password)
- App-wide toast notifications for consistent action feedback across pages
- AI analyses now return a one-shot report without follow-up questions
- Scanner tool bumps: grype 0.113.0 → 0.114.0, syft 1.45.0 → 1.45.1
- Expanded documentation site with admin, guide, integrations and SCA sections

## [1.2.2] - 2026-06-05

### Changed

- Restyle the per-target detail page to match the scan detail page: back-link inside the header,
  mobile horizontal-scroll tables, and bottom-right toast notifications instead of an inline banner.
- Unify all toast notifications onto one shared component, so success/error messages look and behave
  consistently across every page.
- Documentation sync: complete environment-variable reference on the Configuration page, grype
  SBOM-scanning behaviour, the new frontend components and the per-target history endpoint.

### Fixed

- Grype no longer times out re-cataloging large container images — it now matches against an SBOM
  that syft builds first (`grype sbom:`), with a direct-image fallback if that step fails.
- The write-password prompt is now a fully opaque, readable dialog titled "Password required".
- Page-level unlock dialogs (AI Analysis, System) no longer pop a second, spurious write-password
  prompt — the global prompt now only appears for genuine write-gate rejections.
- Container entrypoints are pinned to LF line endings so the scanner/frontend start from
  Windows/CRLF checkouts.

## [1.2.1] - 2026-06-04

### Added

- Per-target scan history is now paginated (Load more / Show all) and can page through all scans,
  not just the latest page.

### Changed

- Grype default scan timeout raised 1200 → 1800 s, and the grype vulnerability DB is pre-warmed at
  scanner startup so the first scan after a restart no longer spends its timeout budget downloading
  the DB. Persisting the DB across restarts is documented as an optional volume. If grype still
  times out on a very large target, raise `GRYPE_TIMEOUT_SECONDS` (e.g. 2400/3600) and recreate the
  scanner.
- Manage per-target write passwords from a dedicated System → Access Control tab.

## [1.2.0] - 2026-06-04

### Added

- Per-target SCA overview page at `/scans/targets/:targetId` (deep-linkable): metadata, severity
  rollup, auto-scan diagnostics, scan history, top findings, quick actions, and per-target
  write-protection controls. Target card titles now link here.
- Write protection for the REST API gated by `SYSTEM_PASSWORD`: all mutating requests
  (POST/PUT/PATCH/DELETE) require the `X-System-Password` admin header when set; reads stay open.
  Fail-open when unset.
- Per-target write passwords: assign a target its own write password (System → Target Access, or the
  target detail page) so an owner can manage that target's writes (settings, scans, findings/VEX,
  scan AI) via `X-Target-Password` without the admin password. Stored hashed (PBKDF2); the admin
  password always overrides. A 🔒 badge marks protected targets.
- AI analysis now requires the AI password (`AI_ANALYSIS_PASSWORD`) as a mandatory final layer on top
  of the write gate when configured.
- Read the Docs documentation site (`.readthedocs.yaml` + MkDocs Material under `docs/`) with a
  Documentation link in the sidebar.

### Changed

- Every scanner's subprocess timeout is now configurable via `<SCANNER>_TIMEOUT_SECONDS` (Grype
  default raised to 1200 s; DevSkim 1500, TruffleHog 300, all others 600). Hyphenated names use
  underscores (`osv-scanner` → `OSV_SCANNER_TIMEOUT_SECONDS`), and the backend → sidecar HTTP timeout
  auto-derives from these so a single scanner bump no longer requires touching
  `SCA_SCANNER_TIMEOUT_SECONDS`.

### Fixed

- Scanner provenance checks no longer flood the log with registry 404s: unresolved pnpm/npm version
  specifiers (`catalog:frontend`, `workspace:*`, …) are skipped before any lookup and dropped from
  the SBOM (the lockfile already supplies the real resolved versions), and PyPI attestations are now
  read from the package's JSON metadata instead of a malformed `pypi.org/integrity/` URL that always
  404'd.
- Grype scans on large images / repositories no longer fail at the hardcoded 600 s subprocess timeout
  (default raised to 1200 s, configurable via `GRYPE_TIMEOUT_SECONDS`).

## [1.1.3] - 2026-06-03

### Changed

- Runtime bump: backend and scanner container images now build on `python:3.14-slim` (was
  `python:3.13-slim`). The backend runtime-stage `site-packages` COPY path was updated `python3.13` →
  `python3.14` accordingly.
- Scanner tool bumps: Trivy 0.69.3 → 0.71.0, Grype 0.112.0 → 0.113.0, Syft 1.44.0 → 1.45.0, Semgrep
  1.114.0 → 1.164.0, TruffleHog 3.95.3 → 3.95.5. The obsolete `setuptools<74` pin was dropped from the
  Semgrep install — Semgrep 1.16x no longer imports `pkg_resources` and `python:3.14-slim` ships no
  setuptools.
- Dependency bumps (backend / poetry): click 8.4.0 → 8.4.1, coverage 7.14.0 → 7.14.1, grpcio 1.80.0 →
  1.81.0, idna 3.15 → 3.18, mcp 1.27.1 → 1.27.2, pyjwt 2.12.1 → 2.13.0, pytest-asyncio 1.3.0 → 1.4.0,
  python-multipart 0.0.29 → 0.0.30, rpds-py 0.30.0 → 2026.5.1, typer 0.25.1 → 0.26.7
- Dependency bumps (scanner / poetry): click 8.4.0 → 8.4.1, fastapi 0.136.1 → 0.136.3, idna 3.15 →
  3.18, starlette 1.0.0 → 1.2.1, uvicorn 0.47.0 → 0.48.0
- Dependency bumps (frontend / pnpm): axios 1.16.0 → 1.16.1, mermaid 11.14.0 → 11.15.0,
  react-router-dom 7.15.0 → 7.15.1, @types/react 19.2.14 → 19.2.15
- Documentation sync: Python 3.13 → 3.14 across README, docs/architecture.md, backend/README and
  scanner/README.

### Fixed

- Scanner /check no longer hangs on stuck git subprocesses

## [1.1.2] - 2026-05-21

### Changed

- Dependency bumps (backend / poetry): certifi 2026.4.22 → 2026.5.20, protobuf 7.34.1 → 7.35.0
- Dependency bumps (frontend / pnpm): react / react-dom 19.2.5 → 19.2.6, react-router-dom 7.14.2 →
  7.15.0, vite 7.3.2 → 7.3.3

## [1.1.1] - 2026-05-18

### Changed

- Documentation sync with the 1.1.0 feature set: README CI/CD section rewritten to describe the
  actual GitHub Actions workflows (build-images, release) and GHCR registry; architecture.md CI/CD +
  container-registry section finalized; Support page added to every frontend route / view table
  (README, frontend/README, architecture.md); DevSkim now listed in every scanner enumeration,
  Mermaid diagram, and tech-stack row (architecture.md system context + deployment diagram,
  scanner/README integration diagram); router count bumped 19 → 20 (architecture.md, backend/README,
  README) with the new `malware` / `version` routers added to the API-layer listing;
  `sca_malware_alert` listed alongside the other notification rule types in the `notification_rules`
  collection description; `enrich-mal` / `purge-malware` added to the CLI block in architecture.md
- Dependency bumps (backend / poetry): click 8.3.3 → 8.4.0, coverage 7.13.5 → 7.14.0, google-auth
  2.51.0 → 2.53.0, idna 3.13 → 3.15, markdown-it-py 4.1.0 → 4.2.0, mcp 1.27.0 → 1.27.1,
  pydantic-settings 2.14.0 → 2.14.1, python-multipart 0.0.27 → 0.0.29, requests 2.33.1 → 2.34.2,
  sse-starlette 3.4.2 → 3.4.4, urllib3 2.6.3 → 2.7.0
- Dependency bumps (scanner / poetry): click 8.3.3 → 8.4.0, idna 3.13 → 3.15, uvicorn 0.46.0 → 0.47.0
- Dependency bumps (frontend / pnpm): axios 1.15.2 → 1.16.0 (direct); transitive refreshes for
  `@babel/*`, `@iconify/utils`, and the `@rollup/rollup-*` platform binaries (4.60.2 → 4.60.3)
- Tooling pin: `packageManager` in `frontend/package.json` bumped from pnpm 10.33.0 → 10.33.4 (picked
  up automatically via Corepack in the frontend Dockerfile)

## [1.1.0] - 2026-05-17

### Added

- Continuous MAL-* watcher cross-checks new malware against existing SCA scans
- Regex search mode on the Vulnerabilities page and saved searches
- TruffleHog 3.95.3 (was 3.95.2)

### Changed

- `/check` probe now runs in parallel with scans (no more spurious skips under load)

### Fixed

- Surface real `/check` error (auth/DNS/TLS/timeout) on the target diagnostics row

## [1.0.2] - 2026-05-11

### Fixed

- Running version on Support page now reflects pyproject.toml

## [1.0.1] - 2026-05-11

### Added

- GHCR package descriptions for backend / frontend / scanner

### Changed

- Support page: Version section moved to top, Support + Star side-by-side

### Fixed

- Support page badge shows "Up to date" when all components match latest

## [1.0.0] - 2026-05-11

Initial tagged release. Establishes the baseline for the semantic versioning timeline. All prior
development history is captured in the git log; future changes will be tracked here.

### Added

- Scanner Breakdown tab on scan detail
- Per-component version check on the Support page
- Shields.io status badges for scans

### Changed

- Scanner subprocesses log via LOG_LEVEL

### Fixed

- DevSkim timeout handling
