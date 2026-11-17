# Environment Variables

Every setting of Hecate is an environment variable. This page lists all of them. Where they go:

- **`.env`**: read by the backend and the scanner (`env_file` in `docker-compose.yml`). Most settings
  on this page.
- **The `frontend` service** in `docker-compose.yml`: the [gateway settings](#frontend-gateway). The
  frontend reads no `.env`, so the backend's secrets stay out of it.
- **The other services** in `docker-compose.yml`: MongoDB, OpenSearch and Apprise take a few
  variables of their own, see [Bundled services](#bundled-services).
- **Build arguments**: baked into an image when you [build it yourself](#build-arguments).

The defaults below are the ones the code uses when a variable is unset; `.env.example` sometimes ships
a different example value. A change takes effect after `docker compose up -d` recreates the
container. How to install and run the stack: [Installation & Deployment](deployment.md).

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
| `HECATE_GHCR_OWNER` | `0x3e4` | GHCR namespace the Support page checks for newer `hecate-backend`, `-frontend` and `-scanner` images. |
| `HECATE_BUILD_SHA` | (from the image) | Git commit of the running backend or scanner, normally baked in as a [build argument](#build-arguments). Set it as a variable only when you run the backend outside Docker. |

## Access control (passwords)

These three secrets are how you lock a shared or internet-reachable instance down. They are
independent layers — set the ones you need — and each is fail-open: when unset, that gate is a no-op.
The full model, including per-target write delegation, is described in
[Security & Access Control](security-access-control.md).

| Variable | Default | Description |
| --- | --- | --- |
| `SYSTEM_PASSWORD` 🔑 | (unset) | Admin password (header `X-System-Password`). When set, every REST write needs it, and so do the admin reads: the System page, the audit log and API tokens. With [sign-in](admin/authentication.md), admins don't need it. |
| `AI_ANALYSIS_PASSWORD` 🔑 | (unset) | Needed (header `X-AI-Analysis-Password`) to start any AI analysis and to list past analyses on the AI analysis page, for every role. |
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

### Collection names

Each collection's name can be changed, for example to share one database between two instances.
Rarely needed; the defaults are:

| Variable | Default |
| --- | --- |
| `MONGO_VULNERABILITIES_COLLECTION` | `vulnerabilities` |
| `MONGO_CPE_COLLECTION` | `cpe_catalog` |
| `MONGO_ASSET_VENDORS_COLLECTION` | `asset_vendors` |
| `MONGO_ASSET_PRODUCTS_COLLECTION` | `asset_products` |
| `MONGO_ASSET_VERSIONS_COLLECTION` | `asset_versions` |
| `MONGO_INGESTION_STATE_COLLECTION` | `ingestion_state` |
| `MONGO_INGESTION_LOG_COLLECTION` | `ingestion_logs` |
| `MONGO_KEV_COLLECTION` | `known_exploited_vulnerabilities` |
| `MONGO_CERT_ADVISORIES_COLLECTION` | `cert_advisories` |
| `MONGO_ADVISORY_FEEDS_COLLECTION` | `advisory_feeds` |
| `MONGO_CWE_COLLECTION` | `cwe_catalog` |
| `MONGO_CAPEC_COLLECTION` | `capec_catalog` |
| `MONGO_SAVED_SEARCHES_COLLECTION` | `saved_searches` |
| `MONGO_SCAN_TARGETS_COLLECTION` | `scan_targets` |
| `MONGO_SCANS_COLLECTION` | `scans` |
| `MONGO_SCAN_FINDINGS_COLLECTION` | `scan_findings` |
| `MONGO_SCAN_SBOM_COLLECTION` | `scan_sbom_components` |
| `MONGO_SCAN_LAYERS_COLLECTION` | `scan_layer_analysis` |
| `MONGO_NOTIFICATION_RULES_COLLECTION` | `notification_rules` |
| `MONGO_NOTIFICATION_CHANNELS_COLLECTION` | `notification_channels` |
| `MONGO_NOTIFICATION_TEMPLATES_COLLECTION` | `notification_templates` |
| `MONGO_LICENSE_POLICIES_COLLECTION` | `license_policies` |
| `MONGO_ENVIRONMENT_INVENTORY_COLLECTION` | `environment_inventory` |
| `MONGO_ENVIRONMENT_INVENTORY_HISTORY_COLLECTION` | `environment_inventory_history` |
| `MONGO_MALWARE_INTEL_COLLECTION` | `malware_intel` |
| `MONGO_APP_SETTINGS_COLLECTION` | `app_settings` |
| `MONGO_API_TOKENS_COLLECTION` | `api_tokens` |
| `MONGO_VEX_RULES_COLLECTION` | `vex_rules` |
| `MONGO_PACKAGE_RELEASES_COLLECTION` | `package_releases` |
| `MONGO_AUTH_SESSIONS_COLLECTION` | `auth_sessions` |

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
| `AI_BATCH_MAX_VULNS` | `10` | Most vulnerabilities in one batch analysis. Admins can change it on System → General → AI analysis, up to 100; that value wins over this one. |

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

Set in `.env` like the rest; the scanner reads them. When a scanner's time limit is raised, the
backend waits longer for it on its own: its timeout per call is the largest of these plus 60 s, at
least `SCA_SCANNER_TIMEOUT_SECONDS`.

| Variable | Default | Description |
| --- | --- | --- |
| `TRIVY_TIMEOUT_SECONDS` | `600` | Time limit of one Trivy run. |
| `GRYPE_TIMEOUT_SECONDS` | `1800` | Grype; loading its database and matching a large image takes long. |
| `SYFT_TIMEOUT_SECONDS` | `600` | Syft, also the SBOM step before Grype on images. |
| `OSV_SCANNER_TIMEOUT_SECONDS` | `600` | OSV Scanner. |
| `DOCKLE_TIMEOUT_SECONDS` | `600` | Dockle (images). |
| `DIVE_TIMEOUT_SECONDS` | `600` | Dive (images). |
| `SEMGREP_TIMEOUT_SECONDS` | `600` | Semgrep (repositories). |
| `TRUFFLEHOG_TIMEOUT_SECONDS` | `300` | TruffleHog (repositories). |
| `DEVSKIM_TIMEOUT_SECONDS` | `1500` | DevSkim (repositories). |
| `GOVULNCHECK_TIMEOUT_SECONDS` | `600` | govulncheck: one budget for all Go modules of a scan. |
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

Most sources share the same kinds of settings:

- `*_BASE_URL`: the API address, for a mirror or proxy.
- `*_TIMEOUT_SECONDS`: timeout per request.
- `*_RATE_LIMIT_SECONDS`: least time between two requests.
- `*_MAX_RETRIES` / `*_RETRY_BACKOFF_SECONDS`: retries after timeouts, 5xx and 429; the wait doubles
  from the backoff on each try.
- `*_MAX_RECORDS_PER_RUN`: cap per sync run; empty means no cap.

| Variable | Default | Description |
| --- | --- | --- |
| `EUVD_BASE_URL` | `https://euvdservices.enisa.europa.eu/api` | ENISA EUVD API. |
| `EUVD_PAGE_SIZE` | `250` | Records per page (max 250). |
| `EUVD_TIMEOUT_SECONDS` | `30` | |
| `EUVD_RATE_LIMIT_SECONDS` | `1.0` | |
| `EUVD_MAX_RETRIES` | `3` | |
| `EUVD_RETRY_BACKOFF_SECONDS` | `5.0` | |
| `EUVD_MAX_RECORDS_PER_RUN` | (none) | |
| `NVD_BASE_URL` | `https://services.nvd.nist.gov/rest/json` | NVD CVE API. |
| `NVD_API_KEY` 🔑 | (unset) | NVD key (5× rate limit). |
| `NVD_PAGE_SIZE` | `2000` | Records per page; don't lower or backfill slows hugely. |
| `NVD_TIMEOUT_SECONDS` | `60` | NVD per-request timeout. |
| `NVD_RATE_LIMIT_SECONDS` | `6.0` | Lower it with an API key (NVD allows about 50 requests in 30 s then). |
| `NVD_MAX_RETRIES` | `5` | |
| `NVD_RETRY_BACKOFF_SECONDS` | `5.0` | |
| `NVD_MAX_RECORDS_PER_RUN` | (none) | |
| `KEV_FEED_URL` | CISA KEV JSON | CISA Known Exploited Vulnerabilities feed. |
| `CPE_BASE_URL` | `https://services.nvd.nist.gov/rest/json/cpes/2.0` | NVD CPE API. |
| `CPE_MAX_RECORDS_PER_RUN` | `10000` | Per-run cap for the CPE catalog. |
| `CWE_BASE_URL` | `https://cwe-api.mitre.org/api/v1` | MITRE CWE API. |
| `CWE_TIMEOUT_SECONDS` | `30` | |
| `CWE_RATE_LIMIT_SECONDS` | `1.0` | |
| `CAPEC_XML_URL` | MITRE CAPEC XML | MITRE CAPEC download. |
| `CAPEC_TIMEOUT_SECONDS` | `60` | |
| `CIRCL_BASE_URL` | `https://vulnerability.circl.lu/api` | CIRCL CVE + EPSS API. |
| `CIRCL_TIMEOUT_SECONDS` | `30` | |
| `CIRCL_RATE_LIMIT_SECONDS` | `1.0` | |
| `CIRCL_MAX_RETRIES` | `3` | |
| `CIRCL_RETRY_BACKOFF_SECONDS` | `3.0` | |
| `CIRCL_MAX_RECORDS_PER_RUN` | `1000` | CVEs enriched with CIRCL data (and EPSS) per run. |
| `CERT_FEEDS_ENABLED` | `true` | Read the advisory feeds behind the Advisories page and the dashboard's *Needs attention* panel, including those added on System → Data. |
| `CERT_FEEDS_EXTRA` | (unset) | Feeds on top of the built-in list, as `Name\|URL` or `Name\|URL\|kind` entries separated by commas, e.g. `CERT.at\|https://www.cert.at/cert-at.de.warnings.rss_2.0.xml`. `kind` is `cert` (default), `vendor` or `community`. Any RSS, RDF or Atom feed; a built-in name replaces that entry. Feeds can also be added on System → Data. See [Advisory feeds](guide/dashboard.md#advisory-feeds). |
| `CERT_FEEDS` | CERT-FR, CERT-EU, NCSC-NL, CCCS, JPCERT/CC | Replaces the built-in list, same format. |
| `CERT_FEEDS_MAX_PAGE_FETCHES_PER_RUN` | `50` | Per feed and run: advisory pages read for items that name no CVE in the feed. Community feeds read none. |
| `CERT_FEEDS_ALLOW_PRIVATE_HOSTS` | `false` | Let feeds added on System → Data point at private, loopback or link-local addresses. Off, such a feed is refused when saved and skipped before every run. `.env` feeds are not checked. |
| `CERT_FEEDS_TIMEOUT_SECONDS` | `30` | |
| `CERT_FEEDS_RATE_LIMIT_SECONDS` | `1.0` | |
| `CERT_FEEDS_MAX_RETRIES` | `3` | |
| `CERT_FEEDS_RETRY_BACKOFF_SECONDS` | `3.0` | |
| `GHSA_BASE_URL` | `https://api.github.com/advisories` | GitHub Advisory API. |
| `GHSA_TOKEN` 🔑 | (unset) | GitHub PAT (60 → 5000 req/h). Also raises the limit of the Support page's version check. |
| `GHSA_TIMEOUT_SECONDS` | `30` | |
| `GHSA_RATE_LIMIT_SECONDS` | `1.0` | |
| `GHSA_MAX_RETRIES` | `3` | |
| `GHSA_RETRY_BACKOFF_SECONDS` | `5.0` | |
| `GHSA_MAX_RECORDS_PER_RUN` | `5000` | |
| `OSV_BASE_URL` | `https://api.osv.dev/v1` | OSV.dev API. |
| `OSV_TIMEOUT_SECONDS` | `30` | |
| `OSV_RATE_LIMIT_SECONDS` | `0.5` | |
| `OSV_MAX_RETRIES` | `5` | |
| `OSV_RETRY_BACKOFF_SECONDS` | `5.0` | |
| `OSV_MAX_RECORDS_PER_RUN` | (none) | The run's time budget (`INGESTION_RUNNING_TIMEOUT_MINUTES`) bounds it instead. |
| `OSV_INCREMENTAL_LOOKBACK_HOURS` | `48` | Incremental OSV syncs re-read `modified_id.csv` from this many hours before the cursor, because OSV exports a record hours after its upstream `modified` timestamp. Rows already processed with the same timestamp are skipped. `0` disables. |
| `OSV_INITIAL_SYNC_CONCURRENCY` | `16` | Workers for the OSV initial sync. |
| `OSV_INITIAL_SYNC_BATCH_SIZE` | `32` | Batch size for the OSV initial sync. |
| `DEPS_DEV_BASE_URL` | `https://api.deps.dev/v3` | deps.dev API: versions of malicious packages, release data for the supply-chain signals and the package check. |
| `DEPS_DEV_TIMEOUT_SECONDS` | `15` | |
| `DEPS_DEV_RATE_LIMIT_SECONDS` | `0.1` | |
| `DEPS_DEV_MAX_RETRIES` | `3` | |
| `DEPS_DEV_RETRY_BACKOFF_SECONDS` | `2.0` | |

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
| `SCHEDULER_NVD_INTERVAL_MINUTES` | `10` | Incremental NVD sync. |
| `SCHEDULER_EUVD_INTERVAL_MINUTES` | `60` | Incremental EUVD sync. |
| `SCHEDULER_KEV_INTERVAL_MINUTES` | `60` | CISA KEV catalog. |
| `SCHEDULER_CPE_INTERVAL_MINUTES` | `1440` | CPE catalog. |
| `SCHEDULER_CIRCL_INTERVAL_MINUTES` | `120` | CIRCL enrichment and EPSS. |
| `SCHEDULER_GHSA_INTERVAL_MINUTES` | `120` | GitHub advisories. |
| `SCHEDULER_OSV_INTERVAL_MINUTES` | `120` | OSV, including malicious packages. |
| `SCHEDULER_CERT_FEEDS_INTERVAL_MINUTES` | `120` | Advisory feeds. |
| `SCHEDULER_NVD_FULL_SYNC_ENABLED` / `_CRON_DAY_OF_WEEK` / `_CRON_HOUR` | `true` / `wed` / `2` | Weekly full NVD sync that catches anything the incremental runs missed. |
| `SCHEDULER_EUVD_FULL_SYNC_ENABLED` / `_CRON_DAY_OF_WEEK` / `_CRON_HOUR` | `true` / `sun` / `2` | Weekly full EUVD sync. |
| `SCHEDULER_OSV_FULL_SYNC_ENABLED` / `_CRON_DAY_OF_WEEK` / `_CRON_HOUR` | `true` / `fri` / `2` | Weekly full OSV sync (re-reads every ecosystem export). |
| `SCHEDULER_CWE_CRON_DAY_OF_WEEK` / `_CRON_HOUR` | `mon` / `3` | Weekly CWE catalog refresh. |
| `SCHEDULER_CAPEC_CRON_DAY_OF_WEEK` / `_CRON_HOUR` | `tue` / `3` | Weekly CAPEC catalog refresh. |
| `SCHEDULER_CWE_INTERVAL_DAYS` / `SCHEDULER_CAPEC_INTERVAL_DAYS` | `7` | How old the catalog may get; the startup check below measures against it. |
| `SCHEDULER_CATALOG_STALE_CATCHUP_MULTIPLIER` | `1.5` | At startup, a CWE or CAPEC catalog older than interval × this is refreshed right away. |

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
| `TRUSTED_PROXY_IPS` | (unset; `.env.example`: `hecate-frontend`) | CSV of proxies whose forwarded headers the backend trusts: addresses, CIDR ranges (`172.16.0.0/12`) or host names, which are resolved every 30 s and trust exactly the addresses they point at. In Docker Compose the frontend gateway is the backend's only proxy, so its network alias `hecate-frontend` (set in `docker-compose.yml.example`) is the right value; it follows the container across restarts without trusting its neighbours (the scanner shares the network). Do not use the service name `frontend`: once Hecate's containers join a network other projects share (one your reverse proxy is on), it resolves to their frontend containers too, and the backend trusts every one of them. **Required behind any proxy**: without it every client shares the proxy's address, so ten wrong passwords lock the write gates for everyone. The backend logs `request.forwarded_header_from_untrusted_peer` once when it sees this. |
| `TRUSTED_PROXY_FORWARD_HEADER` | `x-forwarded-for` | Header carrying the client-IP chain. |
| `TRUSTED_PROXY_REAL_IP_HEADER` | `x-real-ip` | Header carrying the originating client IP. |

### Frontend gateway

The frontend container serves the web app and forwards `/api`, `/mcp` and `/.well-known/oauth-*` to
the backend, so the backend publishes no port. Its settings are environment variables of the
`frontend` service (it reads no `.env`):

| Variable | Default | Description |
| --- | --- | --- |
| `TRUSTED_PROXIES` | `10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.1,::1,fc00::/7` | Addresses or CIDRs allowed to tell the gateway the client IP (`X-Forwarded-For`, right-most hop). Your reverse proxy must be among them; `none` when nothing sits in front. |
| `BACKEND_UPSTREAM` | `http://backend:8000` | The backend as the gateway reaches it. `docker-compose.yml.example` sets `http://hecate-backend:8000`, the backend's network alias: on a network shared with other projects the name `backend` resolves to their backends too, and requests go to them in turn. |
| `UPSTREAM_RESOLVER` | `127.0.0.11` | DNS server for the upstream name, looked up per request (Docker's embedded DNS; set your cluster DNS elsewhere). |
| `MAX_UPLOAD_MB` | `100` | Request body limit for `/api` and `/mcp` (SBOM uploads, base64 source archives, backups). Keep it above `SCA_SOURCE_ARCHIVE_MAX_BYTES` × 1.4. |

Ready-to-adapt nginx / Caddy / Traefik templates that terminate TLS, send every request to the
gateway, and set a hardened HTTP security-header set live in `deploy/reverse-proxy/`, see
[Reverse proxy & TLS](deployment.md#reverse-proxy-tls).

## Bundled services

The compose file passes a few `.env` values on to the database and notification containers:

| Variable | Service | Set from | Description |
| --- | --- | --- | --- |
| `MONGO_INITDB_ROOT_USERNAME` / `MONGO_INITDB_ROOT_PASSWORD` | `mongo` | `MONGO_USERNAME` / `MONGO_PASSWORD` | Create the MongoDB admin user on the **first** start. Changing them later does not change the user; change it in MongoDB. |
| `OPENSEARCH_INITIAL_ADMIN_PASSWORD` | `opensearch` | `OPENSEARCH_PASSWORD` | The `admin` password on the first start. OpenSearch refuses weak ones (at least 8 characters with upper and lower case, a digit and a special character). |
| `OPENSEARCH_JAVA_OPTS` | `opensearch` | `OPENSEARCH_JAVA_OPTS` | Java heap, e.g. `-Xms2g -Xmx2g`. Give it about half the memory you allow the container. |
| `APPRISE_STATEFUL_MODE` | `apprise` | fixed `simple` | Lets Apprise keep its configuration on the `apprise-config` volume. Hecate sends its channel URLs with every message and does not depend on it. |
| `TZ` | `opensearch` | `TZ` | Timezone of the OpenSearch logs. |

## Build arguments

Only when you [build the images yourself](deployment.md#building-your-own-images):

| Argument | Image | Description |
| --- | --- | --- |
| `HECATE_BUILD_SHA` | backend, frontend, scanner | Git commit of the build (`git rev-parse HEAD`). The Support page compares it with the published images; without it the page shows *SHA unknown*. |
| `VITE_API_BASE_URL` | frontend | Where the web app sends API requests, default `/api`. Only change it when the API is served under another path. |
| `DOCS_SITE_URL` | docs | Address the documentation is served under, default `https://docs.hecate.pw/`. Links inside the site only stay on your copy when this matches it. |

The scanner's `Dockerfile` also pins the version and commit of every bundled tool (`DIVE_VERSION`,
`OSV_SCANNER_VERSION`, `GOVULNCHECK_VERSION`, …). Leave them as they are; a release updates them.
