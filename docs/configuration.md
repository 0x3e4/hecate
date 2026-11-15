# Configuration

All configuration is via environment variables. The **authoritative defaults live in
`backend/app/core/config.py`** (every Pydantic field is an env var, uppercased); scanner-side
variables are read directly by the scanner sidecar. `.env.example` ships example values that may
differ from the code defaults.

!!! warning "Fail-open by design"
    When `SYSTEM_PASSWORD` is unset the REST write gate is a no-op so existing deployments keep
    working. For any shared or internet-reachable instance, **set it** — see
    [Security & Access Control](security-access-control.md). Secrets are marked **🔑** below.

## Core / application

| Variable | Default | Description |
| --- | --- | --- |
| `API_PREFIX` | `/api/v1` | URL prefix for all REST endpoints. |
| `ENVIRONMENT` | `development` | Deployment label. Any non-development value also enables the startup check that logs a warning when a secret is left at a known example/placeholder value (e.g. `changeme`). |
| `LOG_LEVEL` | `INFO` | Python log level: `DEBUG` / `INFO` / `WARNING` / `ERROR`. |
| `TZ` | `UTC` | Container timezone; day-bucket boundaries and notification timestamps. |
| `DOMAIN` | (unset) | Public hostname label (OAuth callbacks, badge links). **Not** used for CORS — scope browser access with `CORS_ORIGINS`. |
| `CORS_ORIGINS` | `*` | Comma-separated allowed browser origins. The `*` default serves wildcard reads **without** credentials (Hecate authenticates via headers, not cookies). Set explicit origin(s) — e.g. `https://hecate.example.com` — to scope reads and re-enable credentials. |
| `SUPPORT_PAGE_ENABLED` | `true` | Show the in-app Support page. |
| `DOCS_URL` | `https://docs.hecate.pw` | Target of the sidebar's **Documentation** link: the public docs, your own docs image (`docs/Dockerfile`), or empty to hide the link. Only `http(s)` URLs are used. |
| `HECATE_GHCR_OWNER` | `0x3e4` | GHCR namespace for the three Hecate images (version-check on Support page). |
| `HECATE_BUILD_SHA` | (build-injected) | Short git SHA of the running build (set at image build). |
| `VITE_API_BASE_URL` | `/api` | Frontend API base URL, baked into the bundle at build time. |

## Access control (passwords)

These three secrets are how you lock a shared or internet-reachable instance down. They are
independent layers — set the ones you need — and each is fail-open: when unset, that gate is a no-op.
The full model, including per-target write delegation, is described in
[Security & Access Control](security-access-control.md).

| Variable | Default | Description |
| --- | --- | --- |
| `SYSTEM_PASSWORD` 🔑 | (unset) | Admin password. When set, **all REST writes** require header `X-System-Password`, and it unlocks the System page. |
| `AI_ANALYSIS_PASSWORD` 🔑 | (unset) | Required (header `X-AI-Analysis-Password`) to trigger any AI analysis — the final layer on top of the write gate. |
| `SCA_API_KEY` 🔑 | (unset) | API key (header `X-API-Key`) for the CI/CD scan-submission endpoint `POST /api/v1/scans`. API tokens from System → Access Control work as well, see [Security & Access Control](security-access-control.md#api-tokens). |
| `SCA_SCANNER_SECRET` 🔑 | (unset) | Shared secret between the backend and the scanner sidecar (header `X-Scanner-Secret`). Set the same value on both; needed once anything else can reach the sidecar. |

All secret comparisons are constant-time, and the password endpoints carry a per-client throttle:
after repeated failures from the same client the endpoint locks out (HTTP 429) for a cooldown, so a
weak secret can't be brute-forced at full request rate. See
[Security & Access Control](security-access-control.md).

## Sign-in (OIDC)

Optional sign-in through your identity provider, with admin / editor / viewer roles. Off until
`OIDC_ISSUER` and `OIDC_CLIENT_ID` are set. Full description and provider walkthroughs:
[Sign-in (OIDC) & Roles](admin/authentication.md).

| Variable | Default | Description |
| --- | --- | --- |
| `OIDC_ISSUER` | (unset) | Issuer URL; discovery is `<issuer>/.well-known/openid-configuration`. |
| `OIDC_CLIENT_ID` | (unset) | Client ID registered at the IdP. |
| `OIDC_CLIENT_SECRET` 🔑 | (unset) | Client secret; empty = public client with PKCE only. |
| `OIDC_SCOPES` | `openid profile email` | Requested scopes (add `groups` for Authelia / Pocket ID). |
| `OIDC_PROVIDER_LABEL` | `Single sign-on` | Text on the "Sign in with …" button. |
| `OIDC_ROLES_CLAIM` | `groups` | Claim with group / role names; dotted paths reach nested claims (`realm_access.roles`). |
| `OIDC_ADMIN_GROUPS` / `OIDC_EDITOR_GROUPS` / `OIDC_VIEWER_GROUPS` | (unset) | CSV of names per role. An empty viewer list makes every signed-in account a viewer. |
| `AUTH_REQUIRE_LOGIN` | `true` with OIDC | Require a session (or API key / system password) for every API read. |
| `AUTH_PUBLIC_URL` | (unset) | Browser-facing URL; redirect URI is `<url>/api/v1/auth/callback`. Set it in production. |
| `AUTH_SESSION_LIFETIME_HOURS` | `12` | Absolute session lifetime. |
| `AUTH_SESSION_IDLE_MINUTES` | `120` | Idle timeout (`0` = none). |
| `AUTH_COOKIE_NAME` | `hecate_session` | Session cookie name. |
| `OIDC_USE_USERINFO` | `true` | Fill claims the ID token lacks from the userinfo endpoint. |
| `OIDC_RP_INITIATED_LOGOUT` | `true` | Also end the IdP session on sign-out. |
| `OIDC_ALLOWED_ALGS` | `RS256,…,EdDSA` | Accepted ID-token algorithms; `none` / `HS*` are never accepted. |
| `OIDC_CLOCK_SKEW_SECONDS` | `60` | Leeway for token times. |
| `OIDC_TIMEOUT_SECONDS` | `10` | Timeout for IdP calls. |

## TLS / corporate proxy

Only relevant if your network terminates outbound TLS at a MITM proxy with a private root CA. Point
`HTTP_CA_BUNDLE` at a PEM containing just that corporate CA — Hecate merges it with the system roots
at startup, so direct egress (for example to NVD) keeps working alongside proxied traffic.

| Variable | Default | Description |
| --- | --- | --- |
| `HTTP_CA_BUNDLE` | (unset) | Path inside the backend **and** scanner containers to a PEM with your corporate/MITM root CA (merged with system CAs); trusted for all outbound HTTPS. |

!!! tip "Mount only the corporate CA"
    The mounted PEM is additive to the container's system trust store, not a replacement. It therefore
    needs to contain only your internal/MITM root — the public roots (Mozilla bundle) already ship in
    the image.

## MongoDB

| Variable | Default | Description |
| --- | --- | --- |
| `MONGO_URL` | `mongodb://mongo:27017` | Connection string. |
| `MONGO_USERNAME` | (unset) | Username (kept out of the URI). |
| `MONGO_PASSWORD` 🔑 | (unset) | Password. |
| `MONGO_TLS` | `false` | Enable TLS to MongoDB. |
| `MONGO_TLS_CERT_KEY_FILE` | (unset) | Client cert+key path for MongoDB TLS auth. |
| `MONGO_DB` | `hecate` | Database name. |

Collection names are also overridable (`MONGO_*_COLLECTION`, e.g. `MONGO_VULNERABILITIES_COLLECTION`,
`MONGO_SCANS_COLLECTION`) — defaults match the collection list in the [Architecture](architecture.md)
docs and rarely need changing.

## OpenSearch

| Variable | Default | Description |
| --- | --- | --- |
| `OPENSEARCH_URL` | `https://opensearch:9200` | Cluster URL. |
| `OPENSEARCH_USERNAME` | (unset) | Username. |
| `OPENSEARCH_PASSWORD` 🔑 | (unset) | Password. |
| `OPENSEARCH_INDEX` | `hecate-vulnerabilities` | Vulnerability full-text index name. |
| `OPENSEARCH_INDEX_TOTAL_FIELDS_LIMIT` | `2000` | Mapping field ceiling. |
| `OPENSEARCH_INDEX_MAX_RESULT_WINDOW` | `200000` | Max `from+size` for paged search. |
| `OPENSEARCH_VERIFY_CERTS` | `false` | Verify the cluster's TLS certificate. |
| `OPENSEARCH_CA_CERT` | (unset) | PEM CA bundle path for cluster verification. |
| `OPENSEARCH_JAVA_OPTS` | (unset) | JVM heap for the OpenSearch container, e.g. `-Xms2g -Xmx2g`. |

## AI providers (all optional)

Set any one provider to enable AI features; configuring several lets you pick per analysis from the
provider dropdown. As a rule of thumb: use **OpenAI** when you want reasoning plus live web search,
**Anthropic** or **Gemini** for strong general summaries, and the generic **OpenAI-compatible**
endpoint to keep everything on-premises through Ollama, vLLM, LM Studio or a gateway like OpenRouter.
The compatible provider activates only once both its base URL and model are set. See
[AI Analysis & Attack Paths](guide/ai-analysis.md) for how the features behave.

| Variable | Default | Description |
| --- | --- | --- |
| `OPENAI_API_KEY` 🔑 | (unset) | OpenAI (Responses API, reasoning + web search). |
| `OPENAI_MODEL` | `gpt-4o-mini` | OpenAI model ID. |
| `OPENAI_REASONING_EFFORT` | `medium` | `minimal` / `low` / `medium` / `high` for reasoning models. |
| `ANTHROPIC_API_KEY` 🔑 | (unset) | Anthropic Messages API. |
| `ANTHROPIC_MODEL` | `claude-3-haiku-20240307` | Anthropic model ID. |
| `GOOGLE_GEMINI_API_KEY` 🔑 | (unset) | Google Gemini. |
| `GOOGLE_GEMINI_MODEL` | `gemini-1.5-flash` | Gemini model ID. |
| `OPENAI_COMPATIBLE_BASE_URL` | (unset) | Generic OpenAI-compatible endpoint (Ollama, vLLM, OpenRouter, LocalAI, LM Studio). |
| `OPENAI_COMPATIBLE_MODEL` | (empty) | Model ID; the provider activates when base URL **and** model are set. |
| `OPENAI_COMPATIBLE_API_KEY` 🔑 | (unset) | Optional key for the compatible endpoint. |
| `OPENAI_COMPATIBLE_LABEL` | `Local / OpenAI-Compatible` | Display name in the provider dropdown. |
| `AI_MAX_OUTPUT_TOKENS` | `16000` | Hard ceiling per completion across providers. |
| `AI_RESPONSE_LANGUAGE` | `en` | Default AI response language. |
| `AI_WEB_SEARCH_ENABLED` | `true` | Enable web search where supported (OpenAI; OpenRouter `:online`). |

## MCP server (optional)

Enabling the MCP server lets AI assistants query Hecate in natural language. It is fail-closed: the
endpoint mounts only when `MCP_ENABLED=true` *and* either a full IdP OAuth configuration is present or
the dev-only `MCP_AUTH_DISABLED` bypass is set. See [MCP Server](integrations/mcp.md) for the connection
walkthrough and the in-app MCP page (`/info/mcp`) for the live OAuth metadata.

| Variable | Default | Description |
| --- | --- | --- |
| `MCP_ENABLED` | `false` | Mount the `/mcp` endpoint. |
| `MCP_OAUTH_PROVIDER` | (unset) | `github` / `microsoft` / `oidc`. |
| `MCP_OAUTH_CLIENT_ID` 🔑 | (empty) | OAuth client ID. |
| `MCP_OAUTH_CLIENT_SECRET` 🔑 | (empty) | OAuth client secret. |
| `MCP_OAUTH_ISSUER` | (empty) | OIDC discovery / Microsoft tenant URL. |
| `MCP_OAUTH_SCOPES` | (empty) | Override IdP scopes (space-separated). |
| `MCP_WRITE_IP_SAFELIST` | (empty) | CSV of IPs/CIDRs granted the `mcp:write` scope. |
| `MCP_ALLOWED_USERS` | (empty) | Optional CSV allow-list of identities/emails. |
| `MCP_ALLOWED_REDIRECT_HOSTS` | `claude.ai,claude.com,localhost,127.0.0.1,::1` | CSV of hosts an MCP OAuth client may use as `redirect_uri` (`*.example.com` for subdomains, `*` disables). Plain `http` only for loopback. |
| `MCP_RATE_LIMIT_PER_MINUTE` | `60` | Per-client request budget. |
| `MCP_MAX_RESULTS` | `50` | Max rows any tool returns. |
| `MCP_MAX_CONCURRENT_CONNECTIONS` | `20` | Concurrent connection cap. |
| `MCP_PUBLIC_URL` | (empty) | Pin the base URL in OAuth metadata behind tricky proxies. |
| `MCP_AUTH_DISABLED` | `false` | **DEV ONLY** — bypass OAuth, grant every request read+write. |

## SCA scanning

| Variable | Default | Description |
| --- | --- | --- |
| `SCA_ENABLED` | `true` | Mount the `/scans` pages and SCA endpoints. |
| `SCA_SCANNER_URL` | `http://scanner:8080` | Scanner sidecar URL. |
| `SCA_SCANNER_TIMEOUT_SECONDS` | `2060` | Floor for the backend → sidecar HTTP timeout; the actual per-call value auto-derives as `max(this, max(<SCANNER>_TIMEOUT_SECONDS) + 60)`. |
| `SCA_SOURCE_ARCHIVE_MAX_BYTES` | `52428800` | Max uploaded source archive size (50 MiB). |
| `SCA_SBOM_IMPORT_MAX_COMPONENTS` | `25000` | Most components one imported SBOM may carry (CycloneDX `components` / SPDX `packages`); a larger one is refused with 400. |
| `SCA_VEX_SOURCE_TIMEOUT_SECONDS` | `20` | Timeout for fetching one VEX source of a scan target. |
| `SCA_VEX_SOURCE_MAX_BYTES` | `10485760` | Largest VEX source document read (10 MiB). |
| `SCA_VEX_SOURCES_ALLOW_PRIVATE_HOSTS` | `false` | Let VEX source URLs point at private or internal addresses. Off, a host that resolves to one is refused. |
| `CSAF_PUBLISHER_NAME` | `Hecate` | Publisher named in exported VEX: CSAF `document.publisher.name`, OpenVEX `author`. Set it to your organisation. |
| `CSAF_PUBLISHER_NAMESPACE` | `https://hecate.invalid` | CSAF `document.publisher.namespace`, the issuer's identity (a URL of your organisation). The default marks an unconfigured instance. |
| `CSAF_PUBLISHER_CATEGORY` | `vendor` | CSAF publisher category: `vendor`, `coordinator`, `discoverer`, `other`, `translator` or `user` (anything else is written as `other`). |
| `CSAF_PUBLISHER_CONTACT` | (empty) | Optional CSAF `publisher.contact_details`, e.g. a security mailbox. |
| `SOURCE_ARCHIVE_MAX_EXTRACTED_BYTES` | `4294967296` | Max total size of an archive once extracted, checked by the scanner (4 GiB). An archive is also refused while it doesn't fit into the free `/tmp` space left after the extractions already running. |
| `SCA_AUTO_SCAN_ENABLED` | `false` | Enable the auto-scan scheduler. |
| `SCA_AUTO_SCAN_INTERVAL_MINUTES` | `1440` | How often auto-scan checks each target for changes. |
| `SCA_MAX_CONCURRENT_SCANS` | `2` | Concurrent scan slots. |
| `SCA_SCAN_MAX_RUNTIME_SECONDS` | `0` | A running scan older than this is cancelled. `0` derives the limit per scan from the resource wait, the clone timeout and the slowest selected scanner's timeout. |
| `SCA_MIN_FREE_MEMORY_MB` | `1024` | Pre-scan resource gate: min free memory. |
| `SCA_MIN_FREE_DISK_MB` | `2048` | Pre-scan resource gate: min free disk. |
| `SCA_RELEASE_INFO_ENABLED` | `true` | Look up release age, latest release and npm publisher of every registry package after a scan ([supply-chain signals](sca-scanning.md#supply-chain-signals)); also the release part of the [package check](integrations/package-check.md). |
| `SCA_FRESH_RELEASE_DAYS` | `7` | A release younger than this is a "fresh release" (cooldown). |
| `SCA_UNMAINTAINED_DAYS` | `730` | A package whose latest release is older than this is "unmaintained". |
| `SCA_PUBLISHER_CHECK_MAX_AGE_DAYS` | `365` | npm: compare the publisher only for versions at most this old. |
| `SCA_PUBLISHER_HISTORY` | `3` | npm: how many earlier versions the publisher is compared with. |
| `SCA_RELEASE_INFO_CACHE_TTL_HOURS` | `24` | Cache lifetime of release data per package version (`package_releases`; unknown packages 6 h; the latest-version answer and a version not published yet 15 min). |
| `SCA_RELEASE_INFO_MAX_COMPONENTS` | `3000` | Most components looked up per scan. |
| `SCA_RELEASE_INFO_CONCURRENCY` | `8` | Packages looked up at once (deps.dev keeps its own `DEPS_DEV_RATE_LIMIT_SECONDS`). |
| `SCA_RELEASE_INFO_TIMEOUT_SECONDS` | `900` | Time budget of the lookups after one scan. |
| `PACKAGE_CHECK_RELEASE_TIMEOUT_SECONDS` | `5` | `GET /packages/check`: longest wait for registry data; past it the verdict rests on the advisories. |
| `PACKAGE_CHECK_RATE_PER_MINUTE` | `120` | `GET /packages/check`: checks per minute per client without a session (429 beyond; `0` = no limit). |

### Scanner sidecar (scanner-side)

| Variable | Default | Description |
| --- | --- | --- |
| `<SCANNER>_TIMEOUT_SECONDS` | grype `1800`, devskim `1500`, trufflehog `300`, others `600` | Per-scanner subprocess timeout. Hyphenated names use underscores (`osv-scanner` → `OSV_SCANNER_TIMEOUT_SECONDS`). The backend's HTTP timeout auto-derives from these. For `govulncheck` it is the budget for all Go modules of a scan. |
| `GOVULNCHECK_MAX_MODULES` | `25` | Most Go modules (`go.mod` files) govulncheck analyses per repository. More make the run incomplete, and then it sets no VEX statements. |
| `GOVULNCHECK_DB` | (vuln.go.dev) | Go vulnerability database for govulncheck, e.g. a mirror for an offline site (`https://` or `file://`). |
| `GOVULNCHECK_CACHE_DIR` | (per run) | Persistent Go module cache for govulncheck; unset, modules are downloaded into a per-run directory under `/tmp` and removed afterwards. |
| `GOPROXY` | `https://proxy.golang.org` | Module proxy govulncheck's `go list` uses. The default has no `direct`, so a scanned `go.mod` cannot make the sidecar fetch from arbitrary hosts; set it (plus `GOPRIVATE` / `GONOSUMDB`) for private modules. |
| `GIT_CLONE_TIMEOUT_SECONDS` | `300` | `git clone` timeout for source-repo scans. The repo is cloned once per scan (sidecar `/prepare-source`) and shared across all scanners. The backend widens the `/prepare-source` HTTP timeout to `max(SCA_SCANNER_TIMEOUT_SECONDS, this + 60)`. |
| `SOURCE_CHECKOUT_TTL_SECONDS` | `7200` | Idle TTL after which the sidecar reaps a leaked shared checkout (crash-leak backstop; a checkout with live scanners is never reaped). |
| `SCANNER_MAX_CONCURRENT_SCANS` | `20` | How many `/scan` calls the sidecar works on at once; further calls wait. The backend sends one per scanner of `SCA_MAX_CONCURRENT_SCANS` scans, so the default never queues its own traffic. |
| `TRIVY_CACHE_DIR` | `/tmp/.trivy-cache` | Trivy DB cache dir (tmpfs by default; mount a volume to persist). |
| `GRYPE_DB_CACHE_DIR` | `/tmp/.grype-cache` | Grype DB cache dir. The bundled `docker-compose.yml.example` sets it to `/grype-db` on the persistent `grype-db` volume, so the ~3 GB DB survives restarts. Without that volume it sits on tmpfs and is re-downloaded after each restart. |
| `SEMGREP_RULES` | `p/security-audit` | Semgrep ruleset(s). |
| `SCANNER_AUTH` 🔑 | (unset) | Per-host registry/git auth: `host:token` (git PATs) or `host:user:token` (Docker Hub). Git credentials are only sent to `https://` repositories, and only in memory: the sidecar writes no `~/.git-credentials` and removes the variable from its environment at startup, so scanners don't inherit it. |
| `HECATE_MALWARE_ALLOWLIST` | (empty) | Comma-separated package names to skip during malware detection. |
| `HECATE_REGISTRY_CACHE_TTL` | `604800` | Typosquatting registry-lookup cache TTL (seconds; 7 days). |
| `HECATE_TIMEOUT_SECONDS` | `600` | Time limit of the `hecate` analyzer. It runs as its own process and is killed when the limit is reached. |
| `HECATE_MAX_PARSED_FILE_BYTES` | `33554432` | Largest manifest or lockfile the analyzer reads (32 MiB). Bigger files and symlinks are skipped. |
| `HECATE_PIN_BUDGET_SECONDS` | `120` | Time the OSV scan may spend asking PyPI for the latest version of unpinned `requirements.txt` entries, at most 500 per scan. |

## Ingestion

### Shared

| Variable | Default | Description |
| --- | --- | --- |
| `INGESTION_USER_AGENT` | `hecate-ingestion/1.0` | User-Agent on outbound ingestion calls. |
| `INGESTION_RUNNING_TIMEOUT_MINUTES` | `60` | Wall-clock budget per ingestion run (0 = none). |
| `INGESTION_BOOTSTRAP_ON_STARTUP` | `true` | One-shot sync of every empty source at startup. |
| `INGESTION_PRIORITY_VULN_DB` | `NVD` | Which source wins overlapping version fields: `NVD` or `EUVD`. |
| `VULNERABILITY_INITIAL_BACKFILL_SINCE` | (unset) | Optional ISO date as the initial incremental-sync start. |

### Per source

Each source shares the same knobs (`*_BASE_URL`, `*_TIMEOUT_SECONDS`, `*_RATE_LIMIT_SECONDS`,
`*_MAX_RETRIES`, `*_RETRY_BACKOFF_SECONDS`, `*_MAX_RECORDS_PER_RUN`). Notable ones:

| Variable | Default | Description |
| --- | --- | --- |
| `EUVD_BASE_URL` | `https://euvdservices.enisa.europa.eu/api` | ENISA EUVD API. |
| `EUVD_PAGE_SIZE` | `250` | Records per page (max 250). |
| `NVD_API_KEY` 🔑 | (unset) | NVD key (5× rate limit). |
| `NVD_PAGE_SIZE` | `2000` | Records per page; don't lower or backfill slows hugely. |
| `NVD_TIMEOUT_SECONDS` | `60` | NVD per-request timeout. |
| `KEV_FEED_URL` | CISA KEV JSON | CISA Known Exploited Vulnerabilities feed. |
| `CPE_MAX_RECORDS_PER_RUN` | `10000` | Per-run cap for the CPE catalog. |
| `CWE_BASE_URL` | `https://cwe-api.mitre.org/api/v1` | MITRE CWE API. |
| `CAPEC_XML_URL` | MITRE CAPEC XML | MITRE CAPEC download. |
| `CIRCL_BASE_URL` | `https://vulnerability.circl.lu/api` | CIRCL CVE + EPSS API. |
| `CERT_FEEDS_ENABLED` | `true` | Read the advisory feeds behind the Advisories page and the dashboard's *Needs attention* panel, including those added on System → Data. |
| `CERT_FEEDS_EXTRA` | (unset) | Feeds on top of the built-in list, as `Name\|URL` or `Name\|URL\|kind` entries separated by commas, e.g. `CERT.at\|https://www.cert.at/cert-at.de.warnings.rss_2.0.xml`. `kind` is `cert` (default), `vendor` or `community`. Any RSS, RDF or Atom feed; a built-in name replaces that entry. Feeds can also be added on System → Data. See [Advisory feeds](guide/dashboard.md#advisory-feeds). |
| `CERT_FEEDS` | CERT-FR, CERT-EU, NCSC-NL, CCCS, JPCERT/CC | Replaces the built-in list, same format. |
| `CERT_FEEDS_MAX_PAGE_FETCHES_PER_RUN` | `50` | Per feed and run: advisory pages read for items that name no CVE in the feed. Community feeds read none. |
| `CERT_FEEDS_ALLOW_PRIVATE_HOSTS` | `false` | Let feeds added on System → Data point at private, loopback or link-local addresses. Off, such a feed is refused when saved and skipped before every run. `.env` feeds are not checked. |
| `GHSA_TOKEN` 🔑 | (unset) | GitHub PAT (60 → 5000 req/h). |
| `OSV_BASE_URL` | `https://api.osv.dev/v1` | OSV.dev API. |
| `OSV_INCREMENTAL_LOOKBACK_HOURS` | `48` | Incremental OSV syncs re-read `modified_id.csv` from this many hours before the cursor, because OSV exports a record hours after its upstream `modified` timestamp. Rows already processed with the same timestamp are skipped. `0` disables. |
| `OSV_INITIAL_SYNC_CONCURRENCY` | `16` | Workers for the OSV initial sync. |
| `OSV_INITIAL_SYNC_BATCH_SIZE` | `32` | Batch size for the OSV initial sync. |
| `DEPS_DEV_BASE_URL` | `https://api.deps.dev/v3` | deps.dev API for MAL-* version enrichment. |

## Inventory enrichment (endoflife.date)

Annotates [Environment Inventory](guide/inventory.md) items with support / end-of-life status from endoflife.date. Best-effort and cached; never blocks a write.

| Variable | Default | Description |
| --- | --- | --- |
| `ENDOFLIFE_ENABLED` | `true` | Master toggle. Surfaced to the UI as the `eolEnabled` flag via `GET /config`; when off, the inventory EOL badge and the "End-of-life tracking" field are hidden. |
| `ENDOFLIFE_BASE_URL` | `https://endoflife.date/api/v1` | endoflife.date v1 API base URL. |
| `ENDOFLIFE_TIMEOUT_SECONDS` | `15` | Per-request HTTP timeout. |
| `ENDOFLIFE_RATE_LIMIT_SECONDS` | `0.5` | Minimum interval between requests. |
| `ENDOFLIFE_MAX_RETRIES` | `3` | Retry attempts on transient errors. |
| `ENDOFLIFE_RETRY_BACKOFF_SECONDS` | `2.0` | Exponential-backoff base. |
| `ENDOFLIFE_CACHE_TTL_HOURS` | `24` | Cache lifetime for the catalog + per-product lookups. |

## Scheduler

| Variable | Default | Description |
| --- | --- | --- |
| `SCHEDULER_ENABLED` | `true` | Master toggle for all periodic ingestion jobs. |
| `SCHEDULER_TIMEZONE` | `UTC` | IANA timezone for cron expressions. |
| `SCHEDULER_<SOURCE>_INTERVAL_MINUTES` | EUVD 60, NVD 10, KEV 60, CPE 1440, CIRCL/GHSA/OSV/CERT_FEEDS 120 | Incremental sync interval per source. |
| `SCHEDULER_<SOURCE>_FULL_SYNC_*` | enabled; Sun/Wed/Fri 02:00 | Weekly full-sync verification for EUVD/NVD/OSV (`*_ENABLED`, `*_CRON_HOUR`, `*_CRON_DAY_OF_WEEK`). |
| `SCHEDULER_CWE_CRON_*` / `SCHEDULER_CAPEC_CRON_*` | Mon/Tue 03:00 | Wall-clock cron for the CWE / CAPEC catalogs. |
| `SCHEDULER_CATALOG_STALE_CATCHUP_MULTIPLIER` | `1.5` | Startup stale-catalog catch-up threshold (× the interval). |

## Notifications (Apprise)

| Variable | Default | Description |
| --- | --- | --- |
| `NOTIFICATIONS_ENABLED` | `false` | Master toggle; rules/channels are inert when off. |
| `NOTIFICATIONS_APPRISE_URL` | `http://apprise:8000` | Apprise REST API base URL. |
| `NOTIFICATIONS_APPRISE_TAGS` | `all` | Default Apprise tag routing. |
| `NOTIFICATIONS_APPRISE_TIMEOUT` | `10` | Apprise request timeout (seconds). |
| `NOTIFICATIONS_WATCH_RULE_LIMIT` | `100` | Max matches a single watch-rule pass may emit. |

## Reverse proxy / real client IP

| Variable | Default | Description |
| --- | --- | --- |
| `TRUSTED_PROXY_IPS` | (unset; `.env.example`: `frontend`) | CSV of proxies whose forwarded headers the backend trusts: addresses, CIDR ranges (`172.16.0.0/12`) or host names, which are resolved every 30 s and trust exactly the addresses they point at. In Docker Compose the frontend gateway is the backend's only proxy, so `frontend` is the right value; it follows the container across restarts without trusting its neighbours (the scanner shares the network). **Required behind any proxy**: without it every client shares the proxy's address, so ten wrong passwords lock the write gates for everyone. The backend logs `request.forwarded_header_from_untrusted_peer` once when it sees this. |
| `TRUSTED_PROXY_FORWARD_HEADER` | `x-forwarded-for` | Header carrying the client-IP chain. |
| `TRUSTED_PROXY_REAL_IP_HEADER` | `x-real-ip` | Header carrying the originating client IP. |

### Frontend gateway

The frontend container serves the web app and forwards `/api`, `/mcp` and `/.well-known/oauth-*` to
the backend, so the backend publishes no port. Its settings are environment variables of the
`frontend` service (it reads no `.env`):

| Variable | Default | Description |
| --- | --- | --- |
| `TRUSTED_PROXIES` | `10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.1,::1,fc00::/7` | Addresses or CIDRs allowed to tell the gateway the client IP (`X-Forwarded-For`, right-most hop). Your reverse proxy must be among them; `none` when nothing sits in front. |
| `BACKEND_UPSTREAM` | `http://backend:8000` | The backend as the gateway reaches it. |
| `UPSTREAM_RESOLVER` | `127.0.0.11` | DNS server for the upstream name, looked up per request (Docker's embedded DNS; set your cluster DNS elsewhere). |
| `MAX_UPLOAD_MB` | `100` | Request body limit for `/api` and `/mcp` (SBOM uploads, base64 source archives, backups). Keep it above `SCA_SOURCE_ARCHIVE_MAX_BYTES` × 1.4. |

Ready-to-adapt nginx / Caddy / Traefik templates that terminate TLS, send every request to the
gateway, and set a hardened HTTP security-header set live in `deploy/reverse-proxy/`.
