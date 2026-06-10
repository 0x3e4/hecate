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
| `ENVIRONMENT` | `development` | Deployment label (affects logging only). |
| `LOG_LEVEL` | `INFO` | Python log level: `DEBUG` / `INFO` / `WARNING` / `ERROR`. |
| `TZ` | `UTC` | Container timezone; day-bucket boundaries and notification timestamps. |
| `DOMAIN` | (unset) | Public hostname; used in CORS, OAuth callbacks, badge links. |
| `SUPPORT_PAGE_ENABLED` | `true` | Show the in-app Support page. |
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
| `SCA_API_KEY` 🔑 | (unset) | API key (header `X-API-Key`) for the CI/CD scan-submission endpoint `POST /api/v1/scans`. |

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
| `SCA_AUTO_SCAN_ENABLED` | `false` | Enable the auto-scan scheduler. |
| `SCA_AUTO_SCAN_INTERVAL_MINUTES` | `1440` | How often auto-scan checks each target for changes. |
| `SCA_MAX_CONCURRENT_SCANS` | `2` | Concurrent scan slots. |
| `SCA_MIN_FREE_MEMORY_MB` | `1024` | Pre-scan resource gate: min free memory. |
| `SCA_MIN_FREE_DISK_MB` | `2048` | Pre-scan resource gate: min free disk. |

### Scanner sidecar (scanner-side)

| Variable | Default | Description |
| --- | --- | --- |
| `<SCANNER>_TIMEOUT_SECONDS` | grype `1800`, devskim `1500`, trufflehog `300`, others `600` | Per-scanner subprocess timeout. Hyphenated names use underscores (`osv-scanner` → `OSV_SCANNER_TIMEOUT_SECONDS`). The backend's HTTP timeout auto-derives from these. |
| `TRIVY_CACHE_DIR` | `/tmp/.trivy-cache` | Trivy DB cache dir (tmpfs by default; mount a volume to persist). |
| `GRYPE_DB_CACHE_DIR` | `/tmp/.grype-cache` | Grype DB cache dir (tmpfs by default; mount a volume to persist). |
| `SEMGREP_RULES` | `p/security-audit` | Semgrep ruleset(s). |
| `SCANNER_AUTH` 🔑 | (unset) | Per-host registry/git auth: `host:token` (git PATs) or `host:user:token` (Docker Hub). |
| `HECATE_MALWARE_ALLOWLIST` | (empty) | Comma-separated package names to skip during malware detection. |
| `HECATE_REGISTRY_CACHE_TTL` | `604800` | Typosquatting registry-lookup cache TTL (seconds; 7 days). |

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
| `GHSA_TOKEN` 🔑 | (unset) | GitHub PAT (60 → 5000 req/h). |
| `OSV_BASE_URL` | `https://api.osv.dev/v1` | OSV.dev API. |
| `OSV_INITIAL_SYNC_CONCURRENCY` | `16` | Workers for the OSV initial sync. |
| `OSV_INITIAL_SYNC_BATCH_SIZE` | `32` | Batch size for the OSV initial sync. |
| `DEPS_DEV_BASE_URL` | `https://api.deps.dev/v3` | deps.dev API for MAL-* version enrichment. |

## Scheduler

| Variable | Default | Description |
| --- | --- | --- |
| `SCHEDULER_ENABLED` | `true` | Master toggle for all periodic ingestion jobs. |
| `SCHEDULER_TIMEZONE` | `UTC` | IANA timezone for cron expressions. |
| `SCHEDULER_<SOURCE>_INTERVAL_MINUTES` | EUVD 60, NVD 10, KEV 60, CPE 1440, CIRCL/GHSA/OSV 120 | Incremental sync interval per source. |
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
| `TRUSTED_PROXY_IPS` | (unset) | CSV of proxy IPs whose forwarded headers we trust. |
| `TRUSTED_PROXY_FORWARD_HEADER` | `x-forwarded-for` | Header carrying the client-IP chain. |
| `TRUSTED_PROXY_REAL_IP_HEADER` | `x-real-ip` | Header carrying the originating client IP. |
