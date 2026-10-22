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

- `OSV_INCREMENTAL_LOOKBACK_HOURS` (default `48`): incremental OSV syncs re-read `modified_id.csv` from this many hours before the cursor. Rows already processed with the same `modified` timestamp are skipped without an API call, so the overlap costs about one CSV download per ecosystem.

### Changed

### Fixed

- Malware feed / OSV sync: updates to existing advisories could be missed. OSV writes a record into its per-ecosystem export hours after the record's upstream `modified` timestamp, but the incremental sync advanced its cursor to the wall-clock time, so such rows ended up behind the cursor and were only picked up by the weekly full sync. Example: MAL-2026-2144 (litellm) gained version 1.107.0 at 22:01 UTC, but the export containing it was written hours later. The incremental sync now reads a lookback window (see Added).
- Malware feed / OSV sync: a new affected version on an existing package entry was never stored. `impactedProducts` from OSV was merged only by `(ecosystem, package)` key, so once `litellm` existed, a record update adding `1.107.0` changed nothing, not even after a full sync. New concrete versions are now merged into the existing entry; versions are never removed, and a broad `>=0` no longer overrides versions already resolved via deps.dev.
- Malware feed: a malicious package could appear twice. An OSV record that only *aliases* a MAL-* advisory (e.g. `PYSEC-2026-2` → `MAL-2026-2144`) was stored as its own document, so the feed counted 2 entries but showed 1 card. Such records now resolve to the MAL-* document, consistently in the OSV pipeline, the normalizer and the manual refresh. Existing duplicates are absorbed the next time their MAL-* record is synced.

## [1.7.1] - 2026-10-19

### Added

### Changed

- Dependency bumps (backend / poetry) for advisories published since 1.6.0: pyjwt 2.13.0 → 2.15.1 (one critical and six high advisories, fixed in 2.14.0), pymongo 4.18.0 → 4.19.0 (fixed in 4.18.2), urllib3 2.7.0 → 2.8.0, mcp 1.29.1 → 1.30.0 (fixed in 1.30.0, no major-version change needed). No other locked package changed.
- Dependency bumps (frontend / pnpm): axios 1.19.0 → 1.20.0 (seven high advisories, fixed in 1.20.0), dompurify 3.4.14 → 3.4.16, source-map-js 1.2.1 → 1.2.2, brace-expansion 5.0.9 → 5.0.12, and the `brace-expansion@1` override in `frontend/pnpm-workspace.yaml` 1.1.16 → 1.1.21. All new versions are older than the 14-day `minimumReleaseAge`.
- Documentation build: `pymdown-extensions` floor raised to `>=11.0.1` in `docs/requirements.txt` (advisory fixed in 11.0.1). The docs build with 12.3 produces the same output and warnings as before.
- Not updated: katex 0.16.47 (one low-severity advisory, fixed in 0.18.2) because mermaid 11 requires `katex ^0.16`; the fix arrives with mermaid 12, a major version.

### Fixed

- Semgrep failed on every scan with `ImportError: cannot import name '_ExtendedAttributes' from 'opentelemetry.util.types'`. The scanner Dockerfile copied only `pyproject.toml`, not `poetry.lock`, so Poetry re-resolved the scanner dependencies on each build, pulled a newer FastAPI (which requires `opentelemetry-api>=1.44`), and upgraded Semgrep's pinned `opentelemetry-api 1.37` in the shared site-packages. Semgrep now runs from its own virtualenv (`/opt/semgrep`), and the image installs the locked scanner dependencies. `httpx`, which the provenance checker imports but which previously arrived only as a Semgrep dependency, is now declared explicitly.

## [1.7.0] - 2026-10-19

### Added

- `MCP_ALLOWED_REDIRECT_HOSTS` (default `claude.ai,claude.com,localhost,127.0.0.1,::1`): CSV of hosts an MCP OAuth client may use as `redirect_uri`, checked at dynamic client registration and again at authorize. Entries match exact hosts, `*.example.com` matches subdomains, and `*` disables the check. Plain `http` is accepted only for loopback hosts, and redirect URIs with userinfo or a fragment are rejected. This stops a self-registered client from phishing tokens bound to another user's identity.
- Regression test suites for the security fixes below (`backend/tests/test_security_fixes.py`, `scanner/tests/test_argv_hardening.py`)

### Changed

- Bundled scanner toolchain updated: Grype 0.118.0 → 0.120.1, Syft 1.51.1 → 1.54.1, OSV Scanner 2.5.1 → 2.7.0, TruffleHog 3.97.4 → 3.99.2, DevSkim 1.0.59 → 1.0.100. Syft now emits CycloneDX 1.7; the backend parser does not depend on the spec version.
- DevSkim is now installed from the `Microsoft.CST.DevSkim.CLI` NuGet package, because GitHub releases after v1.0.59 publish no binaries. The scanner image extracts the framework-dependent `net10.0` build, keeps only the `linux-x64` native libraries, and verifies the package against a pinned SHA-256 (`DEVSKIM_VERSION` / `DEVSKIM_SHA256` build args). A `devskim` wrapper keeps the command line unchanged.
- The .NET runtime in the scanner image moved from .NET 8 to .NET 10 (LTS); .NET 8 reaches end of support on 2026-11-10. The runtime is copied from `mcr.microsoft.com/dotnet/runtime:10.0-noble`, since .NET 10 has no GA Debian image. Only the distro-agnostic `/usr/share/dotnet` is copied.
- `docker-compose.yml.example` now mounts a persistent `grype-db` volume for the scanner by default and sets `GRYPE_DB_CACHE_DIR=/grype-db` on the service, which overrides `.env`. The grype DB (now ~3 GB) is downloaded once instead of after every restart (measured: 80 s → 1 s on restart). It also no longer shares the `/tmp` tmpfs with scan workspaces, and a parallel download by the entrypoint prewarm and the first scan can no longer fill that tmpfs. Existing deployments should add the volume and the variable to their own `docker-compose.yml`.
- **Behavior change:** the MCP write-scope IP safelist and the auth brute-force throttle now take the client IP from a trusted proxy only. `X-Forwarded-For` is honoured only when the direct peer is listed in `TRUSTED_PROXY_IPS`, and then the right-most (proxy-appended) hop is used. Deployments that use `MCP_WRITE_IP_SAFELIST` behind a reverse proxy must set `TRUSTED_PROXY_IPS` to the proxy address, otherwise `mcp:write` is no longer granted.
- **Behavior change:** MCP OAuth authorize now requires a registered `client_id`, an exact `redirect_uri` match and a PKCE S256 `code_challenge`. Clients that register through DCR and use PKCE (Claude Desktop, `mcp-remote`) are unaffected.
- **Behavior change:** `MCP_AUTH_DISABLED` is ignored outside development-like `ENVIRONMENT` values, both when `/mcp` is mounted and in the request middleware. In production `/mcp` therefore always requires OAuth.
- Notification channel URLs are masked to `scheme://***` in the API and on the System page.
- OIDC emails that the identity provider marks `email_verified: false` are no longer matched against `MCP_ALLOWED_USERS`. Allow-listing by identity is unaffected.

### Fixed

- **Security:** `GET /notifications/channels` returned the full Apprise URLs, including embedded Slack/Discord webhook tokens, SMTP passwords and bot tokens, to any unauthenticated caller. The admin write gate only covers mutating methods, so this read was public. URLs are now redacted. Credentials configured before this fix should be rotated.
- **Security:** a spoofed left-most `X-Forwarded-For` hop granted the MCP `mcp:write` scope, even behind the shipped nginx template, and let a client rotate its brute-force lockout key.
- **Security:** MCP OAuth authorize skipped `redirect_uri` validation when `client_id` was empty or unknown, which sent auth codes to arbitrary URLs. PKCE was also optional.
- **Security:** unauthenticated search parameters (CPE, asset catalogue, scan findings, security alerts, SBOM) reached MongoDB `$regex` unescaped, which allowed catastrophic-backtracking ReDoS. All eight sinks now use an escaping, length-capped helper. The changelog unknown-source fallback regex is escaped as well, the malware-feed wildcard term is capped, and `searchTerm` / `dqlQuery` have a maximum length.
- **Security:** trivy, syft, grype and dockle now receive `--` before the scan target, so a target that starts with `-` can never be parsed as an option. Requirements pinning no longer writes through `requirements*.txt` symlinks or to files outside the cloned checkout.
- The example OpenSearch password from `.env.example` now triggers the insecure-default startup warning.
- The documentation-site changelog mirror was missing the `[1.6.0]` heading.

## [1.6.0] - 2026-09-04

### Added

### Changed

- Bundled scanner toolchain updated: Grype 0.116.0 → 0.118.0, Syft 1.49.0 → 1.51.1, OSV Scanner 2.4.0 → 2.5.1, TruffleHog 3.96.0 → 3.97.4
- Python floor raised to 3.14 in `backend/pyproject.toml` and `scanner/pyproject.toml` (`^3.13` → `^3.14`), together with ruff's `target-version` (`py313` → `py314`). The container images and CI already ran 3.14 exclusively, so this only drops an untested 3.13 compatibility claim — dependency resolution is byte-identical. Local development environments now have to be created on Python 3.14.
- Tooling pin: `packageManager` in `frontend/package.json` bumped from pnpm 10.33.4 → 11.22.0 (picked up automatically via Corepack in the frontend Dockerfile and by `pnpm/action-setup` in CI). pnpm 11 removed `onlyBuiltDependencies`, so `frontend/pnpm-workspace.yaml` now declares the equivalent `allowBuilds` map; with `strictDepBuilds` on by default an unapproved dependency install script fails the install instead of being skipped silently.
- Frontend linting moved to ESLint 10 (9.39.4 → 10.9.0). The unused `eslint-plugin-react` dependency was dropped — it was never referenced by `eslint.config.js` and was the only package blocking the upgrade. Lint results are unchanged.
- Dependency bumps (frontend / pnpm): axios 1.18.1 → 1.19.0, mermaid 11.16.0 → 11.17.0, react + react-dom 19.2.7 → 19.2.8, react-router-dom 7.18.1 → 7.18.2, typescript-eslint 8.63.0 → 8.67.0, vitest 4.1.10 → 4.1.11, globals 17.7.0 → 17.11.0, @types/react 19.2.17 → 19.2.18, @types/react-dom 19.2.3 → 19.2.4
- Dependency bumps (backend / poetry): cryptography 49.0.0 → 50.0.1, mcp 1.28.1 → 1.29.1, pymongo 4.17.0 → 4.18.0, pydantic-settings 2.14.2 → 2.15.0, google-auth 2.56.0 → 2.57.1, grpcio 1.82.1 → 1.83.1, protobuf 7.35.1 → 7.36.1, sse-starlette 3.4.6 → 3.4.10, coverage 7.15.2 → 7.16.0, certifi 2026.6.17 → 2026.7.22, plus transitive patch refreshes (annotated-doc, annotated-types, anyio, cffi, charset-normalizer, click, idna, packaging, pydantic, pygments, python-dotenv, typer, typing-inspection)
- Dependency bumps (scanner / poetry): fastapi 0.139.2 → 0.141.1, starlette 1.3.1 → 1.6.0, uvicorn 0.51.0 → 0.52.4, anyio 4.14.2 → 4.15.0, click 8.4.2 → 8.5.0, idna 3.18 → 3.19, pydantic 2.13.4 → 2.13.5 (colorama is no longer pulled in)
- Documentation sync: ESLint version in `frontend/README.md` plus a new note on pnpm's `allowBuilds` opt-in for dependency install scripts, an explicit Python 3.14 prerequisite on the local-setup instructions in `backend/README.md` and `scanner/README.md`, the Axios version in the `docs/architecture.md` tech-stack table, and the missing `[1.5.4]` section backfilled into the documentation-site changelog mirror

### Fixed

## [1.5.4] - 2026-07-24

### Added

### Changed

### Fixed

- **`affectedVersion:` matched advisories it shouldn't** — a search like `affectedVersion:7.0.1` returned WordPress advisories patched years before 7.0 existed, because a version-less wildcard CPE node (`cpe:2.3:a:wordpress:wordpress:*` with no bounds), which core advisories almost always carry, was indexed as an "all versions" range. Such bound-less wildcard nodes are now ignored, consistent with the rest of the version matching.
- **Clicking a version chip that is a range showed nothing** — chips built from an advisory's own range (`>= 7.0.0, < 7.0.2`) searched for that string literally and never matched. The chip now resolves to a concrete version inside the range and searches by coverage, so the click lands on the advisories affecting that version.

## [1.5.3] - 2026-07-24

### Added

### Changed

- Updated bundled syft and trufflehog scanner versions

### Fixed

- Query Builder field list stayed partly German in English mode

## [1.5.2] - 2026-07-24

### Added

- **Affected-version search** — the new `affectedVersion:` DQL field answers "which advisories affect the version I actually run?" by comparing against the version *ranges* an advisory declares, instead of only matching versions it names verbatim. An advisory for "WordPress 7.0.x before 7.0.2" records just the boundaries `7.0` and `7.0.2`, so searching for `7.0.1` previously found nothing despite 7.0.1 being affected; `vendorSlugs:"wordpress" AND productSlugs:"wordpress" AND affectedVersion:7.0.1` now returns it. Boundaries are exact (`< 7.0.2` excludes 7.0.2, `<= 6.8.2` includes it), and advisories with no usable version bound (`*`, `-`, `n/a`, `>=0`) never match rather than matching everything. Backed by a new nested `versionRanges` index built from curated range strings, NVD CPE bounds and concrete CPEs. **Records ingested or refreshed after this release get it automatically; run `poetry run python -m app.cli reindex-opensearch` once to backfill the existing corpus.**
- **Version chips now carry their vendor and product** — clicking a version on a result row builds a query for "this product at this version" instead of a bare version string that matched every product ever shipping that number. Concrete releases use the new range-covering match; advisory range strings that aren't a single version keep the literal term match.

### Changed

- Documentation sync for affected-version search, exact slug matching, the range-string normalisation, and the index-rebuild step in Getting Started.

### Fixed

- **DQL slug searches returned unrelated vendors and products** — `vendorSlugs:"wordpress"` also matched "Dokan WordPress Plugin", "WPMU DEV - Your All-in-One WordPress Platform" and "WordPress.com", because on indexes created before those fields were explicitly typed they were inferred as analyzed text and matched word-by-word. Hecate now inspects the live index mapping at startup and points slug / identifier clauses (`vendorSlugs`, `productSlugs`, `productVersions`, `productVersionIds`, `sourceNames`) at whichever path is exact, so existing deployments get precise matching without rebuilding the index. Wildcards (`vendorSlugs:*wordpress*`) still work and now span the whole slug; the display-name fields `vendors:` / `products:` stay word-based on purpose.
- **Inventory missed advisories whose version ranges use typographic operators** — a large share of European advisories express ranges as `4.7 ≤4.7.30`, `0 ≤2.4.7` or `n/a ≤6.8.2`. The parser read only the leading token and treated a whole-release-line range as the *exact* version `4.7`, so an inventory entry running 4.7.20 was never flagged. All of these shapes are now normalised before comparison, which also feeds the new affected-version index. A bare `n/a` is treated as "no version information" instead of an exact version.
- **Rebuilding the search index silently dropped data** — `reindex-opensearch` lost each record's impacted products, CPE configurations and CPE version tokens, because those fields could only be read back under their camelCase spelling while MongoDB stores them in snake_case. Affected-product data is now preserved across a rebuild.

## [1.5.1] - 2026-07-21

### Added

- **Reverse-proxy templates** — ready-to-adapt nginx, Caddy, and Traefik configs in `deploy/reverse-proxy/` that terminate TLS in front of Hecate and set a hardened HTTP security-header set (HSTS, a strict Content-Security-Policy, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, and the cross-origin isolation headers). Documented in Getting Started, with cross-links from Security & Access Control and Configuration.

### Changed

### Fixed

- **Dependency vulnerabilities** — upgraded packages to clear seven CVEs flagged by SCA scanning: `starlette` 0.52.1 → 1.3.1 (fixes CVE-2026-48710, CVE-2026-48817, CVE-2026-48818, CVE-2026-54282, CVE-2026-54283), which required `fastapi` 0.128.5 → 0.139.2 because older FastAPI pinned `starlette` below 1.0; `pytest` 9.0.2 → 9.0.3 (CVE-2025-71176, dev-only); and the frontend transitive `brace-expansion` 1.1.15 → 1.1.16 (CVE-2026-13149), forced to the patched build via a pnpm override.

## [1.5.0] - 2026-07-21

### Added

- **Brute-force protection & constant-time secrets** — the admin / AI / SCA-key checks are now constant-time, and the password-check endpoints (`POST /api/v1/status/system-auth`, `/status/ai-auth`) plus the write gates throttle repeated failures per client and lock out with `HTTP 429` after too many, so a weak secret can't be guessed at full request rate.
- **`CORS_ORIGINS`** setting to scope which browser origins may read the API. The `*` default serves wildcard reads *without* credentials; set explicit origin(s) (e.g. `https://hecate.example.com`) to scope cross-origin access to your own frontend.
- **Insecure-default-secret startup check** — in any non-`development` environment, Hecate logs a warning when a secret is left at a known example/placeholder value (e.g. `MONGO_PASSWORD=changeme`).
- **CI quality gate** — container images now build only after the backend (ruff + pytest), scanner (pytest), and frontend (ESLint + TypeScript type-check + Vitest + build) checks pass; a red check blocks the push to the registry.

### Changed

- **CORS** no longer pairs a wildcard origin with `Access-Control-Allow-Credentials` (a spec-violating combination). Credentials are disabled under the `*` default; set `CORS_ORIGINS` to explicit origins to re-enable them.
- Documentation sync for CORS scoping, the auth throttle / constant-time comparison, the insecure-default-secret check, scan-target validation, and the CI gate.
- Dependency bumps. Backend: `apscheduler` 3.11.2 → 3.11.3, `google-auth` 2.55.1 → 2.56.0, `grpcio` 1.81.1 → 1.82.1, `typer` 0.26.8 → 0.27.0, `typing-extensions` 4.15.0 → 4.16.0, `websockets` 16.0 → 16.1.1, `sse-starlette` 3.4.5 → 3.4.6, `coverage` 7.14.3 → 7.15.2, plus transitive refreshes (`anyio`, `cffi`, `charset-normalizer`, `pyasn1`, `rpds-py`, `tzdata`, `tzlocal`). Scanner tools: Trivy 0.71.0 → 0.72.0, Grype v0.114.0 → v0.116.0, Syft v1.45.1 → v1.48.0, TruffleHog v3.95.6 → v3.95.9; deps `fastapi` 0.138.1 → 0.139.2, `uvicorn` 0.49.0 → 0.51.0. Frontend: `axios` ^1.17.0 → ^1.18.1, `mermaid` ^11.15.0 → ^11.16.0, `react-router-dom` ^7.17.0 → ^7.18.1, `vite` ^7.3.5 → ^7.3.6; added dev tooling `typescript-eslint`, `eslint-plugin-react-hooks`, `@eslint/js`, `globals`, `vitest`.

### Fixed

- **Scanner command-injection (RCE)** — a source-repo scan target's URL flowed unvalidated into `git clone` / `git ls-remote`, so a crafted target (a `ext::…` transport-helper or a `-`-prefixed value) could execute arbitrary commands inside the scanner container. Targets are now validated (scheme allowlist; `::` and leading `-` rejected) at both the API and the scanner, git runs with a restricted `GIT_ALLOW_PROTOCOL` and an end-of-options `--` separator, and the same guards cover the image-reference path.
- **CVSS vector parsing** — modified-environmental metrics (`MAV` / `MAC` / `MPR` / `MUI` / `MS`) and CVSS v4 metrics (`attackRequirements`, `automatable`, `recovery`, `valueDensity`, `vulnerabilityResponseEffort`) were expanded from a flat abbreviation table with colliding single-letter keys, so their labels were wrong (e.g. `modifiedScope:U` showed as *UNKNOWN* instead of *UNCHANGED*, `recovery:A` as *ACTIVE* instead of *AUTOMATIC*). Each metric now maps through its own table; base and impact metrics are unchanged.
- **Query Builder** — saving a search from the DQL Query Builder failed silently; it now saves correctly.
- **Scan detail** — the SAST tab's scanner label rendered blank; it now shows the scanner name(s).

## [1.4.2] - 2026-07-01

### Added

### Changed

### Fixed

- Fixed the dashboard "Today" stats endpoint crashing with a 500 error.

## [1.4.1] - 2026-07-01

### Added

### Changed

- Deleting a scan target now removes it from the list immediately; its scans, findings, SBOM and layer-analysis data are cleaned up in the background, with a startup sweep that catches anything left over from an interrupted delete.
- The dashboard "Today" inventory highlight now uses the same precise, version-aware matcher as the Inventory page instead of a vendor/product-only check.
- The scan-target detail page now shows **Top findings** and **SBOM changes** side by side on desktop.
- Documentation sync for the NetScaler version-matching fix, the SBOM-changes lookback, background target deletion, and the precise dashboard inventory highlight.

### Fixed

- **NetScaler ADC/Gateway** inventory version matching now treats each release branch's build counter independently, fixing cross-branch false positives/negatives (e.g. a patched build on one branch no longer matches an unrelated branch's fix threshold).
- The **SBOM changes** card on the scan-target detail page now shows the most recent scan whose dependencies actually changed, walking back through scan history so a run of unchanged auto-rescans no longer hides an earlier real change.

## [1.4.0] - 2026-06-26

### Added

- **SBOM changes** card on the scan-target detail page: shows how the software bill of materials changed between the target's two most-recent completed scans — components added, version-updated (`old → new`), and removed — annotated with the latest scan's date and commit short-hash. Shows a baseline line for targets with a single completed scan. Backed by a new `GET /api/v1/scans/targets/{id}/sbom-diff` endpoint.
- **Advisory fix hint in scan findings**: the Findings tab now surfaces a vulnerability's unaffected/patched versions (from the advisory's impacted-products data) as a teal "adv" chip next to the scanner's own fix version — filling the gap when a scanner reports no fix. Computed at read time, so it always reflects the current vulnerability database.
- **"Affected in your scans" block** on the vulnerability detail page (red, mirroring the "Affected in your environment" inventory callout): lists the SCA scan targets affected by this CVE (or its aliases), each linking to the covering scan. Two kinds of match — a confirmed scan **finding** (with scanner + fix), or an **SBOM** match where the package is in the target's latest scan at an affected version but the scan predates the advisory (tagged *in SBOM · rescan to confirm*), so newly-published CVEs surface even without a re-scan.

### Changed

- Documentation sync for the SBOM-changes card, the advisory fix hint in findings, and the affected-scans block on CVE detail.
- Dependency bumps. Backend: `mcp` 1.28.0 → 1.28.1, `click` 8.4.1 → 8.4.2, `typer` 0.26.7 → 0.26.8, `google-auth` 2.55.0 → 2.55.1, `anyio` 4.14.0 → 4.14.1, `coverage` 7.14.2 → 7.14.3. Scanner: `fastapi` 0.138.0 → 0.138.1, `anyio` 4.14.0 → 4.14.1, `click` 8.4.1 → 8.4.2. Frontend: `dompurify` 3.4.8 → 3.4.10, `es-toolkit` 1.47.0 → 1.47.1, `ts-dedent` 2.2.0 → 2.3.0, plus transitive refreshes (`acorn`, `caniuse-lite`, `baseline-browser-mapping`, `electron-to-chromium`, `es-iterator-helpers`, `function.prototype.name`, `side-channel`).

### Fixed

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

### Fixed

## [1.2.2] - 2026-06-05

### Added

### Changed

- Restyle the per-target detail page to match the scan detail page: back-link inside the header, mobile horizontal-scroll tables, and bottom-right toast notifications instead of an inline banner.
- Unify all toast notifications onto one shared component, so success/error messages look and behave consistently across every page.
- Documentation sync: complete environment-variable reference on the Configuration page, grype SBOM-scanning behaviour, the new frontend components and the per-target history endpoint.

### Fixed

- Grype no longer times out re-cataloging large container images — it now matches against an SBOM that syft builds first (`grype sbom:`), with a direct-image fallback if that step fails.
- The write-password prompt is now a fully opaque, readable dialog titled "Password required".
- Page-level unlock dialogs (AI Analysis, System) no longer pop a second, spurious write-password prompt — the global prompt now only appears for genuine write-gate rejections.
- Container entrypoints are pinned to LF line endings so the scanner/frontend start from Windows/CRLF checkouts.

## [1.2.1] - 2026-06-04

### Added

- Per-target scan history is now paginated (Load more / Show all) and can page through all scans, not just the latest page.

### Changed

- Grype default scan timeout raised 1200 → 1800 s, and the grype vulnerability DB is pre-warmed at scanner startup so the first scan after a restart no longer spends its timeout budget downloading the DB. Persisting the DB across restarts is documented as an optional volume. If grype still times out on a very large target, raise `GRYPE_TIMEOUT_SECONDS` (e.g. 2400/3600) and recreate the scanner.
- Manage per-target write passwords from a dedicated System → Access Control tab.

### Fixed

## [1.2.0] - 2026-06-04

### Added

- Per-target SCA overview page at `/scans/targets/:targetId` (deep-linkable): metadata, severity rollup, auto-scan diagnostics, scan history, top findings, quick actions, and per-target write-protection controls. Target card titles now link here.
- Write protection for the REST API gated by `SYSTEM_PASSWORD`: all mutating requests (POST/PUT/PATCH/DELETE) require the `X-System-Password` admin header when set; reads stay open. Fail-open when unset.
- Per-target write passwords: assign a target its own write password (System → Target Access, or the target detail page) so an owner can manage that target's writes (settings, scans, findings/VEX, scan AI) via `X-Target-Password` without the admin password. Stored hashed (PBKDF2); the admin password always overrides. A 🔒 badge marks protected targets.
- AI analysis now requires the AI password (`AI_ANALYSIS_PASSWORD`) as a mandatory final layer on top of the write gate when configured.
- Read the Docs documentation site (`.readthedocs.yaml` + MkDocs Material under `docs/`) with a Documentation link in the sidebar.

### Changed

- Every scanner's subprocess timeout is now configurable via `<SCANNER>_TIMEOUT_SECONDS` (Grype default raised to 1200 s; DevSkim 1500, TruffleHog 300, all others 600). Hyphenated names use underscores (`osv-scanner` → `OSV_SCANNER_TIMEOUT_SECONDS`), and the backend → sidecar HTTP timeout auto-derives from these so a single scanner bump no longer requires touching `SCA_SCANNER_TIMEOUT_SECONDS`.

### Fixed

- Scanner provenance checks no longer flood the log with registry 404s: unresolved pnpm/npm version specifiers (`catalog:frontend`, `workspace:*`, …) are skipped before any lookup and dropped from the SBOM (the lockfile already supplies the real resolved versions), and PyPI attestations are now read from the package's JSON metadata instead of a malformed `pypi.org/integrity/` URL that always 404'd.
- Grype scans on large images / repositories no longer fail at the hardcoded 600 s subprocess timeout (default raised to 1200 s, configurable via `GRYPE_TIMEOUT_SECONDS`).

## [1.1.3] - 2026-06-03

### Added

### Changed
- Runtime bump: backend and scanner container images now build on `python:3.14-slim` (was `python:3.13-slim`). The backend runtime-stage `site-packages` COPY path was updated `python3.13` → `python3.14` accordingly.
- Scanner tool bumps: Trivy 0.69.3 → 0.71.0, Grype 0.112.0 → 0.113.0, Syft 1.44.0 → 1.45.0, Semgrep 1.114.0 → 1.164.0, TruffleHog 3.95.3 → 3.95.5. The obsolete `setuptools<74` pin was dropped from the Semgrep install — Semgrep 1.16x no longer imports `pkg_resources` and `python:3.14-slim` ships no setuptools.
- Dependency bumps (backend / poetry): click 8.4.0 → 8.4.1, coverage 7.14.0 → 7.14.1, grpcio 1.80.0 → 1.81.0, idna 3.15 → 3.18, mcp 1.27.1 → 1.27.2, pyjwt 2.12.1 → 2.13.0, pytest-asyncio 1.3.0 → 1.4.0, python-multipart 0.0.29 → 0.0.30, rpds-py 0.30.0 → 2026.5.1, typer 0.25.1 → 0.26.7
- Dependency bumps (scanner / poetry): click 8.4.0 → 8.4.1, fastapi 0.136.1 → 0.136.3, idna 3.15 → 3.18, starlette 1.0.0 → 1.2.1, uvicorn 0.47.0 → 0.48.0
- Dependency bumps (frontend / pnpm): axios 1.16.0 → 1.16.1, mermaid 11.14.0 → 11.15.0, react-router-dom 7.15.0 → 7.15.1, @types/react 19.2.14 → 19.2.15
- Documentation sync: Python 3.13 → 3.14 across README, docs/architecture.md, backend/README and scanner/README.

### Fixed
- Scanner /check no longer hangs on stuck git subprocesses

## [1.1.2] - 2026-05-21

### Added

### Changed
- Dependency bumps (backend / poetry): certifi 2026.4.22 → 2026.5.20, protobuf 7.34.1 → 7.35.0
- Dependency bumps (frontend / pnpm): react / react-dom 19.2.5 → 19.2.6, react-router-dom 7.14.2 → 7.15.0, vite 7.3.2 → 7.3.3

### Fixed

## [1.1.1] - 2026-05-18

### Added

### Changed
- Documentation sync with the 1.1.0 feature set: README CI/CD section rewritten to describe the actual GitHub Actions workflows (build-images, release) and GHCR registry; architecture.md CI/CD + container-registry section finalized; Support page added to every frontend route / view table (README, frontend/README, architecture.md); DevSkim now listed in every scanner enumeration, Mermaid diagram, and tech-stack row (architecture.md system context + deployment diagram, scanner/README integration diagram); router count bumped 19 → 20 (architecture.md, backend/README, README) with the new `malware` / `version` routers added to the API-layer listing; `sca_malware_alert` listed alongside the other notification rule types in the `notification_rules` collection description; `enrich-mal` / `purge-malware` added to the CLI block in architecture.md
- Dependency bumps (backend / poetry): click 8.3.3 → 8.4.0, coverage 7.13.5 → 7.14.0, google-auth 2.51.0 → 2.53.0, idna 3.13 → 3.15, markdown-it-py 4.1.0 → 4.2.0, mcp 1.27.0 → 1.27.1, pydantic-settings 2.14.0 → 2.14.1, python-multipart 0.0.27 → 0.0.29, requests 2.33.1 → 2.34.2, sse-starlette 3.4.2 → 3.4.4, urllib3 2.6.3 → 2.7.0
- Dependency bumps (scanner / poetry): click 8.3.3 → 8.4.0, idna 3.13 → 3.15, uvicorn 0.46.0 → 0.47.0
- Dependency bumps (frontend / pnpm): axios 1.15.2 → 1.16.0 (direct); transitive refreshes for `@babel/*`, `@iconify/utils`, and the `@rollup/rollup-*` platform binaries (4.60.2 → 4.60.3)
- Tooling pin: `packageManager` in `frontend/package.json` bumped from pnpm 10.33.0 → 10.33.4 (picked up automatically via Corepack in the frontend Dockerfile)

### Fixed

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

### Added

### Changed

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

Initial tagged release. Establishes the baseline for the semantic versioning timeline.
All prior development history is captured in the git log; future changes will be
tracked here.

### Added
- Scanner Breakdown tab on scan detail
- Per-component version check on the Support page
- Shields.io status badges for scans

### Changed
- Scanner subprocesses log via LOG_LEVEL

### Fixed
- DevSkim timeout handling