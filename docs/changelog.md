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

- VEX documents for Hecate's own images in [`vex/`](https://github.com/0x3e4/hecate/tree/main/vex): for every finding Trivy or Grype report in `hecate-backend`, `hecate-frontend`, `hecate-docs` and `hecate-scanner` (and the repository's lockfiles), one statement whether it affects Hecate and why, as OpenVEX (`trivy --vex`, `grype --vex`) and CycloneDX VEX (Hecate's own import). [`vex/STATUS.md`](https://github.com/0x3e4/hecate/blob/main/vex/STATUS.md) lists the current state. Most statements come from evidence collected from the image: `vex/tools/collect.sh` records the shared libraries the service's process maps and the `ldd` closure of every program it runs, so a base-image package the service never loads is `not_affected`, and runs `govulncheck -mode=binary` on the Go binaries, so a module without its vulnerable functions is `not_affected` and one with them `affected`. What evidence cannot decide is assessed by hand in `vex/assessments.toml`, with the code each statement relies on (libcurl, which git uses only for HTTP(S); the CPython CVEs against the stdlib modules the services call; Semgrep's MCP code; DevSkim's archive extraction). A loaded library whose CVEs have not been assessed stays `under_investigation`. With the documents applied, Trivy reports 123 of 186 findings for the backend and 216 of 322 for the scanner; for frontend and docs Grype's busybox finding goes away. See [VEX for Hecate's images](admin/vex.md).
- Vulnerability detail page: every link that leaves Hecate (CVE.org, NVD, CIRCL, Wazuh, EUVD, OSV, deps.dev, GHSA, references, CWE and CAPEC entries, the CVSS vector, the attack path's standards references) carries an external-link icon. They go through the new `ExternalLink` primitive, which opens a new tab with `rel="noopener noreferrer"`.

### Changed

- Scanner: skopeo 1.24.1 is built statically from source with Go 1.27.3 and fixed `go-jose`, `x/crypto`, `x/net`, `x/text` and `grpc` modules, instead of Debian's skopeo 1.18, built with Go 1.24.4, in which govulncheck found 60 vulnerable stdlib functions. That also drops gpgme, gnupg and the CNI plugins Debian's package pulled in; the image writes the default `/etc/containers/policy.json`. The curl and unzip programs are purged after the build downloads (git keeps its libcurl). Trivy: 440 → 322 findings; Grype: critical 28 → 10, all of them in Debian's libcurl, which git uses and for which Debian has no fix yet (see the VEX for why they do not apply).
- Container images: fewer known vulnerabilities, measured with Trivy 0.76.1 against the published `:latest` images. Frontend 20 → 0, docs 53 → 0, backend 196 → 186 with none left that has a fix, scanner 758 → 440 with no critical left (high 195 → 73).
  - Frontend: the runtime stage is `nginx:1.30.6-alpine` instead of `node:24-alpine` with `serve`, on the same port 4173. Every finding came from npm, corepack or `serve`'s dependencies (undici, minimatch, compression, ip-address, brace-expansion, glob), none of which a static page needs. `frontend/nginx.conf` caches the hashed `/assets/` for good, revalidates everything else and falls back to `index.html` for client-side routes. Security headers stay with the reverse proxy as before.
  - Docs and frontend run `apk upgrade` at build time, which brings curl 8.23, brotli 1.2.1 and expat 2.10 before the nginx tag is rebuilt.
  - Backend: pip is removed from the runtime image (its vendored urllib3, msgpack and setuptools were the only fixable Python findings), and `apt-get upgrade` takes Debian fixes released after the python image. The remaining findings are Debian packages without a fix.
  - Scanner: Trivy 0.76.1, Grype 0.121.1, Syft 1.56.0, Semgrep 1.183.0 (PyJWT ≥ 2.15, mcp 1.29). Dive 0.13.1, Dockle 0.4.15 and OSV Scanner 2.7.0 are built from their release tag (checked against the commit) with Go 1.27.3 and fixed `x/net`, `x/text`, `x/oauth2`, `klauspost/compress`, `xz`, `mapstructure` and `moby/sys/user` versions; Dive and Dockle have had no release since early 2025 and still shipped Go 1.24.1 / 1.22.10. Poetry now runs from a throwaway venv and leaves the image together with virtualenv and pip. What remains with a fix is waiting on upstream: an untagged `x/crypto` fix in Trivy, Grype, Syft and OSV Scanner, `docker/docker` 29 (moved to a new module path) in Dive and Dockle, the mcp and OpenTelemetry pins of Semgrep, and SharpCompress in DevSkim.
- Vulnerability detail page: a long description that arrives as one block is split into paragraphs at sentence ends (abbreviations such as `e.g.`, `Inc.` or `U.S.` and version numbers stay intact), and the text measure grows from 70 to 80 characters, so the description no longer looks cut off next to the full-width KEV panel. Blank lines and bullet lists in the source text are kept as before.

### Fixed

- VEX export: an **Affected** finding was exported with `analysis.state: "affected"`, which CycloneDX does not define, and every version status reused the analysis state. Affected is now `exploitable` (the import maps it back), and `affects[].versions[].status` is `affected`, `unaffected` or `unknown`.
- VEX import: `analysis.detail` was dropped whenever the statement also had a justification. It is now stored in the finding's VEX detail; a bulk update without a detail keeps the existing one.
- Inventory: an item of a product with many CVEs, such as WordPress, showed "No known vulnerabilities" and a CVE count of 0 although the vulnerability detail page listed it under *Affected in your environment*. The lookup cut the candidate list at 200 before checking versions, so only the oldest CVEs of the product were ever compared; the limit now counts matches. It also reads `impactedProducts` before a stale `impacted_products`, like the detail page.
- Inventory: when no CVE matches, the **DQL** button now asks with `affectedVersion:"<version>"` instead of `productVersions:"<version>"`, which only finds advisories that name the version literally and missed every range such as "4.7 through 7.1.3".

## [2.1.0] - 2026-11-04

### Added

- Inventory: **Duplicate** opens the add dialog with an item's values, including its endoflife.date link, for the next server or environment of the same product.
- Inventory: a version change can carry a note, such as a ticket, the server or the change request. It is stored in the history entry, not on the item, and can be given in the row, in the edit dialog, as `changeNote` on `PUT /api/v1/inventory/{id}`, as `note` per entry of `POST /api/v1/inventory/report`, and as `change_note` on the MCP tool `update_inventory_item`.
- `DOCS_URL` (default `https://docs.hecate.pw`): where the sidebar's Documentation link points, so an instance can link its own docs image or, with an empty value, show no link. Only `http(s)` URLs are used.
- Docs: screenshots open larger on a click, or with Enter or Space when focused; Escape, a click or the close button closes them. `assets/zoom.js` is served from the site itself, so nothing new loads from elsewhere.
- Self-hosted documentation: `docs/Dockerfile` builds the MkDocs site into an nginx image (`ghcr.io/0x3e4/hecate-docs`, compose profile `docs`, port `127.0.0.1:8001`). IBM Plex, the app's typeface, ships with the site instead of Google Fonts, and a Content-Security-Policy keeps every page on its own host. The build runs `mkdocs build --strict` in CI. `site_url` is `https://docs.hecate.pw/` and can be changed with `--build-arg DOCS_SITE_URL=...`; instant navigation needs it to match the host serving the site. Build dependencies are locked with Poetry (`docs/pyproject.toml`, `docs/poetry.lock`), for the image and for a local `mkdocs serve` alike; `docs/requirements.txt` is gone. Read the Docs is no longer used and `.readthedocs.yaml` is gone.
- SCA scans: the Scans tab filters by status (pending, running, completed, failed, cancelled).
- `SCA_SCAN_MAX_RUNTIME_SECONDS` (default `0`): how long a running scan may take before it is cancelled. `0` derives the limit per scan from the resource wait, the clone timeout and the slowest selected scanner's timeout, about 90 minutes with the defaults.

### Changed

- Docs: the site is titled "Hecate Cyber Defense - Documentation" and uses the app's colours (warm grey paper, gold accent) instead of Material's blue-grey, and a home or overview card opens its page from anywhere on the card, not only from its link.
- Inventory and the scan target page ask in a dialog before deleting an item or a target, instead of the browser's confirmation prompt.

### Fixed

- Security: a scanned repository could put the scanner's `SCANNER_AUTH` tokens into public findings. DevSkim follows symlinks, so a committed `settings.py -> /root/.git-credentials` made it report a token as a finding snippet. Repositories are now cloned with `core.symlinks=false`, and any link left in the checkout is removed before a scanner runs. The sidecar also no longer writes `~/.git-credentials` (git gets the token in memory, as it already did through `http.extraHeader`, and the anonymous retry after a rejected token is now really anonymous), and it removes `SCANNER_AUTH` from its environment at startup so scanners don't inherit it.
- Security: an SBOM import could write into a password-protected target with another target's password. The gate read `targetName` and `target_name` differently from the import, and did not see that an import without a name takes the name inside the SBOM. Both now resolve the target the same way, the upload route included, so an SBOM naming another target needs that target's password.
- Security: a scan request repeating a scanner name (`["semgrep", "semgrep", …]`) started one sidecar scan per entry, past `SCA_MAX_CONCURRENT_SCANS`, and auto-scan repeated it from the stored list. Scanner lists are de-duplicated and unknown names answer `400` (`422` from request validation). The sidecar itself now runs at most `SCANNER_MAX_CONCURRENT_SCANS` (default 20) `/scan` calls at once and runs a scanner once per call, and it refuses an uploaded archive while it doesn't fit into the free `/tmp` space left after the extractions already running.
- Security: every distinct malware-feed query stayed in an in-process cache for good, about 1 MB per page, so anonymous requests could fill the backend's memory. The cache now holds at most 256 pages and drops expired ones, and `offset` is capped at the OpenSearch result window as on `/vulnerabilities`.
- Security: a repository URL with credentials passed to the MCP tool `trigger_scan` was rejected, but stored verbatim in the publicly readable audit log. The audit log now masks the `user:token@` part of every URL in tool inputs and errors. For entries written before this fix, run `python -m app.cli scrub-audit-credentials` (`--dry-run` lists them first) and rotate every token it finds: anyone could read them until now.
- The backend kept the host's disk busy, and other services on it slowed down. Three things read the whole `vulnerabilities` collection, tens of GB on a full corpus. First, the NVD and EUVD syncs counted the records carrying their data after every run, on a field without an index. That count now comes from OpenSearch. Second, when OpenSearch failed, the statistics fell back to four MongoDB aggregations that kept running long after the request had given up. The fallback now retries OpenSearch once, then serves its last answer, and otherwise only runs index-backed counts limited to 3 s on the server. Third, every change-history entry held a full copy of the record, and each `sources` diff carried every raw upstream payload, so the history made up about 95 % of the collection. Entries now store only the changed fields, `sources` without its raw data. A re-fetch that only moves `sources[].ingested_at` no longer counts as a change. Existing entries shrink the next time their record changes, or all at once with `python -m app.cli compact-history` (`--dry-run`, `--pause` to throttle, `--start-after` to resume); run MongoDB's `compact` on the collection afterwards to give the space back. The deps.dev enrichment's history entries are capped at 25 like all others.

- Tables no longer scroll sideways on desktop widths. The dashboard's Latest findings showed a scrollbar at every width: the hidden label of the copy column stuck out of the table by one pixel, which `.visually-hidden` now takes back in with `margin: -1px`, for every place that uses it. On SCA Scans (Findings, Scans, Security Alerts, SBOM, Licenses, Scanner) long package names, versions, paths and hashes now wrap inside their cell instead of widening the table, and below 1200 px the cell padding tightens and the Findings target count gives way. The scan detail page switches its findings and SBOM tables to stacked rows whenever their columns do not fit, measured on the table rather than the window. The changelog table lets its time column wrap below 1200 px, and the SCA Scans tabs wrap to a second line instead of hiding the last ones off to the side.
- The dashboard's Today summary and the statistics page logged an OpenSearch 400 ("Text fields are not optimised for operations that require per-document field data … `vendorSlugs`") on every load when the index came from an older version that mapped the slug fields as text. Both queried the text field first and only retried on `.keyword` after the error. They now take each aggregation field's path from the live mapping, so the first request is correct. The retry also stopped adding `.keyword` to fields that are already keyword, which left those charts empty.
- Docs image: `assets/extra.css`, the fonts and the pages were cached for a day under unchanged names, so a new image kept showing the old styling. They are now revalidated on every load; only Material's hashed bundles are cached for good.
- Docs: links were blue instead of gold, because Material's own rule for the black slate palette outranked the theme's colours.
- SCA scans that were queued or running when Hecate restarted stayed `running` or `pending` for good, and their target kept showing a scan in progress. They are now cancelled at startup, and a watchdog cancels every five minutes any scan that lost its task or ran past its maximum runtime. The reason is shown as the scan's error.

## [2.0.0] - 2026-11-02

### Added

- Frontend design system: `frontend/src/tokens.css` (colour, type, spacing, motion tokens), `frontend/src/base.css`, shared primitives in `frontend/src/ui/primitives.tsx` + `primitives.css`, one stylesheet per screen in `frontend/src/screens/`, and the locked system description in `design.md`. Typeface is IBM Plex Sans, with IBM Plex Mono only for identifiers and code (self-hosted via `@fontsource`).
- `cleanAdvisoryText()` and `formatEcosystemName()` in `frontend/src/utils/advisoryText.ts`: display-only cleanup of OSV boilerplate and registry-qualified ecosystem names.
- API tokens with scopes on System → Access Control: `scan:submit` opens `POST /api/v1/scans`, `inventory:report` opens `POST /api/v1/inventory/report`. Each token has a name and an optional expiry, is sent as `X-API-Key`, is shown once and stored only as a hash, and can be revoked without touching the others. Managing tokens needs `SYSTEM_PASSWORD` and answers `403` without it. Creating and revoking appear in the audit log.
- `SCA_SCANNER_SECRET`: shared secret between the backend and the scanner sidecar, sent as `X-Scanner-Secret`. Once set, every sidecar route except `/health` needs it. It is needed as soon as anything but the backend can reach the sidecar, and on another host it also needs TLS in front. Unset, the sidecar behaves as before and logs a warning at startup.
- Dashboard: a **Needs attention** panel shows what was added to CISA KEV or named by at least two CERTs in the last seven days, and what one CERT named if it affects your inventory. Your stack comes first, each row links to the advisories behind it, and scan findings that only one CERT named fold away per product. It does not depend on the selected day. Backed by `GET /api/v1/stats/attention`.
- CERT advisory feeds: a new job, `cert_feeds_sync`, reads CERT-FR, CERT-EU, NCSC-NL, CCCS and JPCERT/CC every two hours into the `cert_advisories` collection. `CERT_FEEDS_EXTRA` adds your own feeds as `Name|URL` pairs, for example CERT.at. Start it from System → Data, `POST /api/v1/sync/trigger/cert-feeds` or `sync-cert`. An item that names no CVE has its advisory page read once, on the feed's own host. CISA's advisory feed is not included because it refuses Hecate's client; the KEV catalogue is unaffected.
- CERT page (`/cert`, sidebar group Security): what national CERTs warn about, with advisories that share a CVE merged into one topic. Rows show the worst severity, products, reporting CERTs and your stack; they fold open to every CVE and advisory. Filters cover search, CERT, severity, period and your stack. Advisories of 20 or more CVEs are listed as round-ups and not merged. Backed by `GET /api/v1/stats/cert-advisories`.
- Inventory change history: `GET /api/v1/inventory/history` and `GET /api/v1/inventory/{id}/history` record what changed, from where (web, report, MCP, restore) and who did it, also for deleted items.
- Inventory version reports: `POST /api/v1/inventory/report` lets a pipeline record the deployed version for up to 200 entries. An entry has to identify exactly one item; `ambiguous` and `not_found` change nothing and do not stop the batch, and reports never create items.
- Inventory: the latest release of a cycle from endoflife.date is offered as a one-click `Set to`. It is never applied automatically, because a version nobody deployed would clear real CVE matches.
- Asset catalog: the first 25 hits of a vendor or product search carry `vulnerabilityCount`, so look-alikes such as `wordpress` and `wordpress-foundation` can be told apart. The inventory form can search the product first and then fills in its vendor.
- New scanner settings: `HECATE_TIMEOUT_SECONDS` (default 600), `HECATE_MAX_PARSED_FILE_BYTES` (default 32 MiB) and `SOURCE_ARCHIVE_MAX_EXTRACTED_BYTES` (default 4 GiB).
- Target owners can change or remove their target's write password with the current one, from **Change password** on the target page. A target password also covers the scanner selection and importing an SBOM into an existing SBOM-import target. When only the system password can authorize a write, the UI asks for that one alone (`X-Write-Auth-Required: admin`).

### Changed

- **Full redesign of the web UI (all 18 routes).** Routes, API calls and handlers are unchanged; every screen was recomposed. Colour now carries meaning only: gold for the primary action, the current navigation item and focus; a dedicated severity scale for severity; everything else neutral. Card grids became full-width tables where items compare, each page has a single `h1`, and severity is always shown as a word as well as a colour.
- Dashboard: the page leads with what touches your inventory or SCA scans, one row per product with a count per severity, and the CVEs fold open. In the severity list only Critical opens by default, up to 12 rows; vendors and products follow as supporting lists; severity DQL links sit on the stat figures.
- Dashboard: latest findings are ten one-line rows with a link to the full list. Aliases, CWEs, versions, the assigner and the source links stay on the detail page.
- Dashboard on phones: the day arrows sit beside the title, and rows use the full width with the identifiers left and the product right.
- Dashboard: vendors and products in the CVE rows and in latest findings link to the vulnerability list filtered on them.
- Toasts have a close button and no longer cover the scroll-to-top button.
- Scrollbars: the sidebar has none, the tabs on the vulnerability page wrap on a desktop and swipe on a phone, and the remaining scrollbars are a thin thumb without arrows or track.
- Vulnerability list: rows are a dense table with a Product column (product, vendor and version each filter in one click) and start collapsed; the title column shows the cleaned advisory text, because `title` usually repeats the ID.
- Attack path graphs: Mermaid colours come from the design tokens at runtime; only CVE and impact nodes carry severity colour.
- `styles.css` shrank from about 3,800 to about 160 lines; screen rules moved to `frontend/src/screens/`.
- Copy: em dashes, glued arrows, middle-dot strings, uppercase labels and flag emoji are gone from the interface in both languages; a few labels were reworded as a result.
- Info pages: the MCP page now lists all 40 tools (it listed 30), the batch limit is described as configurable, and the pages use the full width.
- `POST /api/v1/vulnerabilities/lookup`: the local read stays public, but fetching a miss from upstream now takes `X-System-Password` when `SYSTEM_PASSWORD` is set, so an anonymous lookup with the default `autoSync` answers `401` on a miss. The identifier is limited to 128 characters of a fixed pattern (`422` otherwise).
- Manual refresh: when upstream has no data, a stored record or an ID that is not a CVE or EUVD ID now answers `skipped` instead of being replaced by a reserved placeholder.
- Scan targets: repository URLs with credentials are rejected, because the target id is that URL and target ids are public. Use `SCANNER_AUTH`; `ssh://git@host` stays valid. Existing targets with credentials in the URL will fail on their next scan. Image references naming a local source (`dir:`, `file:`, `sbom:`, `oci-dir:`, `docker-archive:` and similar) are rejected too.
- Uploaded source archives lose their `.git` directory on extraction, so a pipeline has to send `commitSha` itself.
- Scanner: symlinked manifests and manifests above `HECATE_MAX_PARSED_FILE_BYTES` are skipped. Archives are capped at 200,000 members and `SOURCE_ARCHIVE_MAX_EXTRACTED_BYTES`.
- Scanner sidecar: `entrypoint.sh` unsets `MONGO_*`, `OPENSEARCH_*`, `*PASSWORD*`, `*SECRET*`, `*API_KEY*` and `*_TOKEN` before start, keeping `TRIVY_*`, `GRYPE_*`, `SYFT_*`, `SEMGREP_*`, `SCANNER_AUTH` and `SCA_SCANNER_SECRET`. A custom variable with such a name no longer reaches the scanner.
- Failure lockout: ten wrong CI keys from one client now lock that route for 5 minutes, like every other secret check. Behind a reverse proxy set `TRUSTED_PROXY_IPS`, or all clients share one lockout; the backend logs `request.forwarded_header_from_untrusted_peer` once when it sees this.
- MCP audit log: the client IP comes from `get_security_client_ip`, so behind a proxy it shows the proxy until `TRUSTED_PROXY_IPS` is set.
- TruffleHog findings show only the last four characters of a secret of 20 or more characters, otherwise `***`. Existing findings keep the old form until the next scan.
- AI reports no longer render images, and every AI system prompt states that advisory and scan text is data.
- Limits: `POST /api/v1/cwe/bulk` and `POST /api/v1/capec/bulk` take at most 500 IDs, and the SBOM file upload is capped at `SCA_SOURCE_ARCHIVE_MAX_BYTES` (`413` above it).
- `GET /api/v1/status/scanner-health` probes `/stats` instead of `/health`, so a wrong scanner secret shows as an unreachable scanner.
- Asset catalog: vendor and product searches rank by relevance (exact name, then prefix, then word start, then substring, shorter names first) instead of alphabetically, which put WordPress itself behind 1,700 plugins.
- Dependency bumps for advisories: backend certifi 2026.10.23, dnspython 2.9.1 and pyasn1 0.6.5, scanner certifi 2026.10.23, frontend dompurify 3.4.17, follow-redirects 1.16.2, vite 7.3.7, vitest 4.1.12 and zod 4.6.7, docs mkdocs-material 9.7.7. katex stays on 0.16.47 for the reason given under 1.7.1, and minimatch on 10.2.6 because ESLint needs the 10.x line and the fix is in 11.0.1.

### Fixed

- Security: remote code execution through uploaded archives. A `.git/config` with `core.fsmonitor` in an archive ran a shell command in the scanner when Semgrep called `git ls-files`, and with the compose example the sidecar held the backend's whole `.env`. Without `SYSTEM_PASSWORD` this needed no authentication. `.git` is dropped on extraction, Git config is pinned at command scope, and secrets are removed from the sidecar environment. If a reachable instance ran without a system password, or untrusted parties held a CI key or a target password, rotate the secrets in `.env`.
- Security: anonymous writes through `POST /api/v1/vulnerabilities/lookup`. A miss synced from upstream without authentication, and an unknown ID could replace a stored record with a reserved placeholder. Lower-case CVE and EUVD IDs now find the stored record.
- Security: the attack path graph rendered package, product and target names as HTML, because Mermaid treats labels as HTML even with `htmlLabels: false`. Label text is now escaped, and directives can no longer change the render configuration.
- Security: the failure lockout did not cover target-scoped routes, the scan AI gate, the CI key or the AI read gate, so the admin password could be guessed without limit through any of them. Password hashing now also runs off the event loop.
- Security: a hostile repository could stall the scanner. A crafted `go.mod` pinned a regex and blocked `/check` and `/stats`, and a symlink to `/dev/zero` exhausted memory. The analyzer now runs as a child process that is killed at `HECATE_TIMEOUT_SECONDS`, and every file read is bounded.
- Security: a malformed lockfile such as a `composer.lock` containing `[]` switched off all later analysis, so a repository could hide from the malware detector. Each parser and detector now fails alone.
- Security: an image in an AI report could carry inventory details out on every view, through an instruction injected into advisory text. Web search during AI analysis is unchanged.
- Security: MCP dynamic client registration kept clients forever without a limit. It is now capped at 60 registrations per minute per client and 5,000 stored clients, with a 30-day idle expiry and size limits.
- Security: a non-string vulnerability ID in a VEX import reached MongoDB as an operator.
- API info page: the statement that all other endpoints are unauthenticated was out of date. It now describes the write gate (`X-System-Password`, `X-Target-Password`, `X-AI-Analysis-Password`).
- MCP info page: tool calls check the `mcp:write` scope on the token; the page claimed the source IP is re-validated at request time.
- CI/CD info page: `SCA_SCANNER_TIMEOUT_SECONDS` defaults to 2060, not 600.
- Malware feed and vulnerability pages: raw OSV markers (`_-= Per source details...`, `## Source: ...`) no longer appear in descriptions, or in the text that copy and email actions produce.
- Security: someone holding one target's write password could guess the admin password without ever being locked out, reading each answer from the response time. A request with a valid target password no longer compares the admin password, and one lockout counter now covers each secret across all routes, so a client gets ten guesses at the system password in total rather than ten per route. IPv6 clients count by their /64.
- Security: without `SYSTEM_PASSWORD` anyone could set or clear a target's write password. The first password on a target now needs the system password, and without one a target that has no password answers `403`; a target that has one can still be changed by its owner.
- AI analysis: a second analysis started after an earlier one picked up the earlier run's result, and the batch page listed it under the newly selected IDs. Each run now has a `runId` that the page waits for, and the batch result stays with the IDs it analysed. The same applied to single analyses and attack path narratives on the vulnerability page.
- Security: a scanned repository could make the scanner overwrite a file outside its checkout by placing a symlink where DevSkim writes its report, and could exhaust the sidecar's memory or keep it busy for hours through a huge `requirements.txt`. The report goes to its own directory, `requirements.txt` is read with the size and symlink checks every other manifest gets, and version pinning stops after 500 lookups or `HECATE_PIN_BUDGET_SECONDS`.
- Security: XML from CERT feeds and from scanned manifests (`pom.xml`, `*.csproj`, `packages.config`, `Directory.Packages.props`) is refused when it declares a DTD, checked by the parser itself; the earlier byte pattern missed a DTD behind a second processing instruction or in UTF-16, and rejected harmless feeds that start with a comment. Manifests are read with the same size and symlink checks as lockfiles.
- Security: links taken from data (references, scan findings, repository URLs, endoflife.date and CERT links) only open `http` and `https` URLs. Other schemes such as `search-ms:` or `file:` launch local programs when clicked.
- Security: the public search accepts at most 50 values per list filter and asks OpenSearch to stop after 10 seconds, `/stats/overview` is computed once a minute, and unknown CWE IDs are remembered and limited to ten upstream lookups per request, so one anonymous request can no longer tie up the cluster or the shared MITRE client.
- Security: with MCP enabled, `/mcp/oauth/authorize` is rate-limited per client, accepts only a well-formed S256 challenge and a bounded `state`, and caps pending sign-ins, so it can no longer be used to fill memory and the audit log.
- Scanner: `SCANNER_AUTH` git credentials are only sent to `https` repositories and are redacted in debug logs; Dive runs no longer share temporary files, which could show one image's layers in another scan; the sidecar no longer serves `/docs` and `/openapi.json` outside the secret check.
- VEX import and inventory restore ignore values of the wrong type instead of storing them, which could break later reads of a target's findings.
- Dashboard: the day summary loaded only the newest 200 CVEs, so on a busy day the severity lists fell short of the figures above them and inventory or scan matches past that point were lost. It now loads up to 2,000.
- Dashboard: the date in the heading follows the interface language.
- Dashboard: registry-qualified vendor names such as `Packagist:https://packages.drupal.org/8` are shown as `Packagist (packages.drupal.org)`.
- Inventory: a CVE or end-of-life cell could stay on its loading placeholder when the item list changed while a lookup was running.
- Dialogs: focused fields keep the visible focus ring, and the password prompt's field has an accessible name.

## [1.7.2] - 2026-10-22

### Added

- `OSV_INCREMENTAL_LOOKBACK_HOURS` (default `48`): incremental OSV syncs re-read `modified_id.csv` from this many hours before the cursor. Rows already processed with the same `modified` timestamp are skipped without an API call, so the overlap costs about one CSV download per ecosystem.

### Changed

- The frontend image is rebuilt on Node.js 24.22.1, which contains the October 2026 Node.js security release. The image uses the `node:24-alpine` tag, so no code change was needed. Its runtime only serves static files, which limits exposure to the client-side TLS, DNS and HTTP issues in that release.
- Documentation: README gains a Support section; DevSkim is now described as running on .NET 10 from the NuGet package, and the frontend as served by Node.js `serve` rather than nginx (README, `docs/architecture.md`, `scanner/README.md`, `SECURITY.md`, image description in `build-images.yml`).

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