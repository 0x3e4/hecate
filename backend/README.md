# Hecate Backend

> FastAPI service that ingests, enriches, and exposes vulnerability information. Whole-project documentation lives in the [repository root README](../README.md).

![Python](https://img.shields.io/badge/python-3.13-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.128-009688?logo=fastapi&logoColor=white)
![Poetry](https://img.shields.io/badge/Poetry-managed-60A5FA?logo=poetry&logoColor=white)
![MongoDB](https://img.shields.io/badge/MongoDB-8-47A248?logo=mongodb&logoColor=white)
![OpenSearch](https://img.shields.io/badge/OpenSearch-3-005EB8?logo=opensearch&logoColor=white)

---

## Architecture

<details>
<summary><strong><code>app/</code> directory layout</strong> (click to expand)</summary>

```text
app/
├── api/v1/                  REST endpoints
│   ├── routes.py            Router registration (19 modules)
│   ├── vulnerabilities.py   Search · lookup · refresh · AI analysis · attack-path graph (GET/POST /vulnerabilities/{id}/attack-path)
│   ├── cwe.py               CWE queries (single + bulk)
│   ├── capec.py             CAPEC queries · CWE→CAPEC mapping
│   ├── cpe.py               CPE catalogue (entries · vendors · products)
│   ├── assets.py            Asset catalogue (vendors · products · versions)
│   ├── stats.py             Statistics aggregations
│   ├── backup.py            Streaming export / import: vulnerabilities · saved searches · environment inventory
│   ├── sync.py              Manual sync triggers
│   ├── saved_searches.py    Saved searches (CRUD)
│   ├── audit.py             Ingestion logs
│   ├── changelog.py         Recent changes (pagination, date / source filters)
│   ├── scans.py             SCA scan management — submit, targets (group filter + manual /check trigger for auto-scan diagnostics),
│   │                          target-group roll-up, history (since filter), findings (?includeDismissed), SBOM, SBOM export,
│   │                          SBOM import, compare, VEX (incl. bulk-update-by-ids and import), findings dismiss,
│   │                          license compliance, cross-CVE attack chain (GET/POST /scans/{id}/attack-chain)
│   ├── events.py            Server-Sent Events (SSE) stream
│   ├── notifications.py     Notifications (channels, rules, templates)
│   ├── license_policies.py  License-policy management (CRUD, default policy, license groups)
│   ├── inventory.py         Environment inventory (CRUD + /affected-vulnerabilities)
│   ├── malware.py           Malware intelligence (GET /malware-feed for the frontend overview)
│   ├── config.py            Public runtime config (feature flags from backend settings for the frontend)
│   └── status.py            Health check
├── mcp/                     MCP server (Model Context Protocol)
│   ├── server.py            ASGI sub-app factory (FastMCP)
│   ├── auth.py              Path-aware MCPAuthMiddleware (only /mcp + /mcp/*) · OAuth token validation · scope-based write gating;
│   │                          honours MCP_PUBLIC_URL for the WWW-Authenticate resource hint and MCP_AUTH_DISABLED as the dev bypass
│   │                          (synthetic local-dev identity with mcp:read mcp:write)
│   ├── oauth.py             OAuth 2.0 AS endpoints (metadata incl. RFC 9728 path suffix, DCR, authorize, IdP callback,
│   │                          token with PKCE) · get_dcr_client_name() for MCP attribution · _base_url() pins MCP_PUBLIC_URL when set
│   ├── oauth_providers.py   Upstream IdP abstraction (GitHub / Microsoft Entra / generic OIDC)
│   ├── security.py          Rate limiting · input sanitisation
│   ├── audit.py             Dual audit (structlog + MongoDB) for tool invocations and OAuth events
│   └── tools/               35 MCP tools (6 modules)
│       ├── vulnerabilities.py   search_vulnerabilities · get_vulnerability · prepare/save_vulnerability_ai_analysis ·
│       │                          prepare/save_vulnerabilities_ai_batch_analysis · prepare/save_attack_path_analysis ·
│       │                          refine_attack_path_analysis
│       ├── cpe.py               search_cpe
│       ├── assets.py            search_vendors · search_products
│       ├── stats.py             get_vulnerability_stats
│       ├── cwe_capec.py         get_cwe · get_capec
│       └── scans.py             get_scan_findings · get_scan_findings_by_scan · get_security_alerts · get_scan_sbom ·
│                                  get_sbom_components · get_sbom_facets · get_target_scan_history · compare_scans ·
│                                  get_layer_analysis · list_scan_targets · list_target_groups · list_scans ·
│                                  find_findings_by_cve · get_sca_scan · trigger_scan · trigger_sync ·
│                                  prepare/save_scan_ai_analysis · prepare/save_scan_attack_chain_analysis
├── core/
│   ├── config.py            Pydantic Settings (all env variables)
│   └── logging_config.py    structlog configuration
├── db/
│   ├── mongo.py             Motor (async MongoDB) connection
│   └── opensearch.py        OpenSearch connection + operations
├── models/                  MongoDB document schemas (Pydantic)
├── repositories/            Data-access layer (15 repositories)
├── schemas/                 API request / response schemas
│   ├── _utc.py              Shared `UtcDatetime` annotated type (BeforeValidator) — normalises every outgoing datetime field
│   │                          to UTC-aware so the frontend never parses it as local time
│   ├── vulnerability.py     VulnerabilityQuery (incl. advanced filters: severity, CVSS vector, EPSS, CWE, sources, time range),
│   │                          VulnerabilityDetail
│   ├── cwe.py · capec.py · cpe.py · assets.py
│   ├── ai.py                AI-analysis schemas
│   ├── backup.py · sync.py · audit.py · changelog.py
│   ├── scan.py              SCA scan API schemas (incl. ImportSbomRequest)
│   ├── vex.py               VEX API schemas (VexUpdate, VexBulkUpdate, VexBulkUpdateByIds, FindingsDismiss, VexImport)
│   ├── license_policy.py
│   ├── inventory.py
│   ├── attack_path.py       Attack-path-graph schemas (Node, Edge, Labels, Graph, Narrative, Response, Request)
│   ├── scan_attack_chain.py Cross-CVE attack-chain schemas (AttackStage literal, ChainFindingRef, ScanAttackChainStage,
│   │                          Narrative, Response, Request)
│   └── saved_search.py
├── services/                Business logic (see "Services" below)
├── utils/
│   ├── strings.py
│   └── request.py
├── main.py                  FastAPI app initialisation
└── cli.py                   CLI entrypoint (13 commands)
```
</details>

### Services

| Service | Responsibility |
| --- | --- |
| `VulnerabilityService` | Search, refresh, lookup. |
| `CWEService` | 3-tier cache (memory → MongoDB → MITRE API). |
| `CAPECService` | 3-tier cache + CWE→CAPEC mapping. |
| `CPEService` | CPE catalogue. |
| `AIService` | OpenAI / Anthropic / Gemini / OpenAI-compatible wrapper (httpx for OpenAI, Anthropic, OpenAI-compatible; google-genai SDK for Gemini). |
| `StatsService` | OpenSearch aggregations with MongoDB fallback. |
| `BackupService` | Streaming export / import for vulnerabilities (NVD / EUVD / ALL), saved searches, and environment inventory (inventory restore is upsert by `_id`). |
| `SyncService` | Sync coordination. |
| `AuditService` | Audit logging. |
| `ChangelogService` | Change tracking. |
| `SavedSearchService` | Saved searches. |
| `AssetCatalogService` | Asset catalogue from ingested data. |
| `ScanService` | SCA scan orchestration (concurrency limiting, resource gating, SBOM import, AI analysis, per-scan SBOM dedup via `unique_component_keys → sbom_component_count`, `backfill_sbom_component_count_v2` startup backfill). |
| `ScanParser` | Scanner-output parsers (Trivy, Grype, Syft, OSV, Hecate, Dockle, Dive, Semgrep, TruffleHog, SPDX SBOM, generic SARIF for DevSkim). The generic `parse_sarif()` is reusable for any future SARIF-emitting tool (CodeQL, Snyk Code, …). |
| `SbomExport` | SBOM export builder (CycloneDX 1.5, SPDX 2.3). |
| `VexService` | VEX export / import (CycloneDX VEX), VEX + dismissal carry-forward across scans. |
| `LicenseComplianceService` | License-policy evaluation, automatic evaluation after scans. |
| `InventoryService` / `inventory_matcher` | CRUD + matching with a pure-function CPE version-range matcher (self-contained version comparator). |
| `AttackPathService` | Deterministic attack-path graph builder (`entry → asset → package → CVE → CWE → CAPEC → exploit → impact → fix`); orchestrates `CAPECService`, `CWEService`, `InventoryService`; derives the label set (likelihood, exploit_maturity, reachability, privileges_required, user_interaction, business_impact) deterministically from EPSS, KEV, and CVSS vector. Optionally accepts `assumptions=` for the MCP `refine_attack_path_analysis` workflow (allow-list `reachability` / `entry_point` / `network_exposure` / `privileges_required` / `user_interaction`, 200-char cap per value). |
| `attack_chain_stages` | CWE → ATT&CK kill-chain stage map (`foothold` / `credential_access` / `priv_escalation` / `lateral_movement` / `impact`); `categorize_cve(cwes, severity)` with severity fallback. |
| `ScanAttackChainService` | Cross-CVE attack-chain builder for the scan-detail tab. Filter + dedup findings → bulk-fetch CWEs → bucket per stage → top-5 per stage by CVSS → top-2 CAPECs per stage via `CAPECService` → `AttackPathGraph` (entry → stage anchors → CVE leaves). |
| `EventBus` | In-memory async event bus for SSE. |
| `NotificationService` | Apprise notifications (incl. inventory watch-rule evaluator with optional `inventory_item_ids` filter). |

### HTTP helpers

- `services/http/rate_limiter.py` — minimum interval between requests
- `services/http/retry.py` — `request_with_retry()`: shared exponential-backoff helper (transient httpx errors, 5xx, 429 with `Retry-After`)
- `services/http/ssl.py` — `get_http_verify()`: TLS trust store (`HTTP_CA_BUNDLE` or certifi)

### Ingestion clients & pipelines

```text
services/ingestion/
├── normalizer.py           Source-agnostic normalisation
├── job_tracker.py          Job lifecycle + audit
├── manual_refresher.py     On-demand refresh — default dispatcher routes MAL-/PYSEC-/OSV-* → OSV
├── startup_cleanup.py      Zombie-job cleanup
├── deps_dev_client.py      deps.dev Package API client (api.deps.dev/v3)
├── mal_enrichment.py       deps.dev enrichment for MAL-* / GHSA-* with broad >=0 ranges
├── euvd_pipeline.py + euvd_client.py
├── nvd_pipeline.py + nvd_client.py
├── kev_pipeline.py + cisa_client.py
├── cpe_pipeline.py + cpe_client.py
├── circl_pipeline.py + circl_client.py
├── ghsa_pipeline.py + ghsa_client.py
├── osv_pipeline.py + osv_client.py
├── cwe_client.py
└── capec_client.py
```

### Scheduling

- `services/scheduling/manager.py` — APScheduler (bootstrap + periodic).
- CWE / CAPEC use `CronTrigger` (wall-clock, default Mon / Tue 03:00 UTC) instead of `IntervalTrigger`, so backend redeploys cannot reset the refresh timer.
- `_run_catalog_catchup_jobs()` runs once per backend start in parallel with the bootstrap path and dispatches an out-of-band sync if the latest successful run is older than `interval_days × SCHEDULER_CATALOG_STALE_CATCHUP_MULTIPLIER` (default `1.5`).

---

## Data model

### MongoDB collections

| Collection | Model | Description |
| --- | --- | --- |
| `vulnerabilities` | `VulnerabilityDocument` | Vulnerabilities with CVSS, EPSS, CWEs, CPEs, source raw data |
| `cwe_catalog` | `CWEEntry` | CWE weaknesses (7-day TTL cache) |
| `capec_catalog` | `CAPECEntry` | CAPEC attack patterns (7-day TTL cache) |
| `known_exploited_vulnerabilities` | `CisaKevEntry` | CISA KEV entries |
| `cpe_catalog` | — | CPE entries (vendor, product, version) |
| `asset_vendors` | — | Vendors with slug and product count |
| `asset_products` | — | Products with vendor mapping |
| `asset_versions` | — | Versions with product mapping |
| `ingestion_state` | — | Sync-job status (Running / Completed / Failed) |
| `ingestion_logs` | — | Detailed job logs with metadata |
| `saved_searches` | — | Saved queries |
| `scan_targets` | `ScanTargetDocument` | Scan targets (container images, source repos). Carries `last_check_at`, `last_check_verdict`, `last_check_current_fingerprint`, `last_check_error` for the auto-scan diagnostics shown in the Scanner tab — set by every `ScanService.check_target_changed` call (scheduler or manual `POST /v1/scans/targets/{id}/check`); never blocks a scan on error. |
| `scans` | `ScanDocument` | Scan runs with status and summary |
| `scan_findings` | `ScanFindingDocument` | Vulnerability findings from SCA scans |
| `scan_sbom_components` | `ScanSbomComponentDocument` | SBOM components from SCA scans (exportable as CycloneDX 1.5 / SPDX 2.3) |
| `scan_layer_analysis` | `ScanLayerAnalysisDocument` | Image-layer analysis from Dive scans |
| `notification_rules` | — | Notification rules (event, watch, DQL, scan, inventory) |
| `notification_channels` | — | Apprise channels (URL + tag) |
| `notification_templates` | — | Title / body templates per event type |
| `license_policies` | `LicensePolicyDocument` | License policies (allowed, denied, review-required) |
| `environment_inventory` | `InventoryItemDocument` | User-declared product / version inventory (deployment, environment, instance count) |
| `malware_intel` | `MalwareIntelDocument` | Dynamic malware-intel entries; upsert key `(source, ecosystem, package_name, version)`; merged into the `/v1/malware/malware-feed` UI (currently unused, reserved for future threat-intel pipelines) |

### OpenSearch index (`hecate-vulnerabilities`)

Full-text index with text fields for search and `.keyword` fields for aggregations. Nested `sources` path for per-source aggregations. Flat `sourceNames` keyword array for DQL source-alias search (`source:X` automatically searches both `source` and `sourceNames`).

**Configuration:** `max_result_window = 200000`, `total_fields.limit = 2000`, `OPENSEARCH_VERIFY_CERTS` (SSL certificate verification, default `false`), `OPENSEARCH_CA_CERT` (path to a CA certificate, optional).

---

## Ingestion pipelines

| Pipeline | Source | Default interval | Description |
| --- | --- | --- | --- |
| EUVD | ENISA REST API | 60 min | Vulnerabilities with change history |
| NVD | NIST REST API | 10 min | CVSS, CPE configurations |
| KEV | CISA JSON feed | 60 min | Exploitation status |
| CPE | NVD CPE 2.0 API | 1440 min (daily) | Product / version catalogue |
| CWE | MITRE REST API | 7 days | Weakness definitions |
| CAPEC | MITRE XML download | 7 days | Attack patterns |
| CIRCL | CIRCL REST API | 120 min | Additional enrichment |
| GHSA | GitHub Advisory API | 120 min | GitHub Security Advisories |
| OSV | OSV.dev GCS bucket + REST API | 120 min + weekly full sync (Fri 02:00 UTC) | OSV vulnerabilities (hybrid: CVE enrichment + MAL / PYSEC / OSV entries, 11 ecosystems; per-run cursor advancement against cap-hit data loss) |

All pipelines support both incremental and initial syncs. Weekly full syncs: EUVD Sun 02:00 UTC, NVD Wed 02:00 UTC, OSV Fri 02:00 UTC.

> [!IMPORTANT]
> Bulk pipelines wrap their `pipeline.sync(...)` calls in `opensearch_bulk_mode()` (see `app/db/opensearch.py`), switching OpenSearch writes to `refresh=false`. Initial syncs go from ~1 s/PUT (`wait_for`) down to ~5–9 ms/PUT and stop blocking concurrent manual refreshes. User-initiated writes (manual refresh, scan completion, deps.dev enrichment via manual refresh) keep `refresh=wait_for` for read-after-write consistency. **OSV initial sync** additionally dispatches records in batches (`OSV_INITIAL_SYNC_BATCH_SIZE=32`) through an `asyncio.Semaphore`-bounded `asyncio.gather` (`OSV_INITIAL_SYNC_CONCURRENCY=16`) and short-circuits unchanged records before deep-copy via the `_osv_would_change()` predicate — ~100 records/s instead of ~0.085 records/s.

> [!NOTE]
> Intervals in `.env.example` may differ from code defaults. The authoritative defaults live in `app/core/config.py`.

---

## Design patterns

### Repository pattern

- `create()` classmethod creates indexes
- `_id` = entity ID in MongoDB
- `upsert()` returns `"inserted"`, `"updated"`, or `"unchanged"`

### 3-tier cache (CWE, CAPEC)

```text
Memory dict → MongoDB collection → External API / XML
                  (7-day TTL)
```

Singleton via `@lru_cache`, lazy repository loading.

### Job tracking

```text
start(job_name) → Running in MongoDB → finish(ctx, result) → Completed + Log
```

Startup cleanup marks zombie jobs as cancelled.

### Server-Sent Events (SSE)

```text
EventBus (singleton) → publish(event) → asyncio.Queue per subscriber → SSE stream
```

Events: `job_started`, `job_completed`, `job_failed`, `new_vulnerabilities`. JobTracker, SchedulerManager, and the AI-analysis endpoints publish automatically. The frontend connects via `GET /api/v1/events`. AI analyses run asynchronously through `asyncio.create_task()` and report results over SSE (`ai_investigation_{vulnId}`, `ai_batch_investigation`, `ai_scan_analysis_{scanId}`, `attack_path_{vulnId}`).

### API schema convention

```python
field_name: str = Field(alias="fieldName", serialization_alias="fieldName")
```

snake_case in Python, camelCase on the wire.

### UTC-aware datetime serialisation

All outgoing `datetime` fields use the `UtcDatetime` alias from `app/schemas/_utc.py` (`Annotated[datetime, BeforeValidator(_coerce_utc)]`). The validator attaches `tzinfo=UTC` to every incoming naive datetime / ISO string, so the JSON output always carries a `+00:00` suffix.

> [!WARNING]
> OpenSearch `_source` reads of fields indexed as naive strings return values without a time zone. The frontend would parse them with `new Date()` as local time and shift them by the user's offset. `app/db/mongo.py` additionally opens the Motor client with `tz_aware=True` so MongoDB reads are also UTC-aware. All writes use `datetime.now(UTC)`.

---

## CLI

```sh
poetry run python -m app.cli ingest         [--since ISO] [--limit N] [--initial]
poetry run python -m app.cli sync-euvd      [--since ISO] [--initial]
poetry run python -m app.cli sync-cpe       [--limit N]   [--initial]
poetry run python -m app.cli sync-nvd       [--since ISO | --initial]
poetry run python -m app.cli sync-kev       [--initial]
poetry run python -m app.cli sync-cwe       [--initial]
poetry run python -m app.cli sync-capec     [--initial]
poetry run python -m app.cli sync-circl     [--limit N]
poetry run python -m app.cli sync-ghsa      [--limit N]   [--initial]
poetry run python -m app.cli sync-osv       [--limit N]   [--initial]
poetry run python -m app.cli enrich-mal     [--limit N]                   # deps.dev enrichment of existing MAL-* docs
poetry run python -m app.cli purge-malware  --ecosystem <eco> [--dry-run] # delete an ecosystem from malware_intel + MAL-* vulnerabilities
poetry run python -m app.cli reindex-opensearch
```

---

## Development

### Dependency management

This project uses [Poetry](https://python-poetry.org/).

#### Add a new dependency

```sh
# Edit pyproject.toml manually, then refresh the lock file:
poetry lock

# Or add it directly:
poetry add <package-name>

# Then commit both files:
git add pyproject.toml poetry.lock
git commit -m "Add <package-name> dependency"
```

#### Update dependencies

```sh
# Update everything to the latest compatible versions:
poetry update

# Or a single package:
poetry update <package-name>

# Then commit:
git add poetry.lock
git commit -m "Update dependencies"
```

#### Install dependencies locally

```sh
poetry install
```

### Tests and linting

```sh
poetry run pytest
poetry run ruff check app
```

### Docker build

Multi-stage build (builder → runtime) on top of `python:3.13-slim`. Port 8000.

```sh
docker build -t hecate-backend ./backend
docker run -p 8000:8000 --env-file .env hecate-backend
```

### Why `poetry.lock` matters

The lock file ensures:

- **Reproducible builds** — everyone uses the same dependency versions
- **Security scanning** — Trivy scans this file for vulnerabilities
- **Supply-chain safety** — pins exact versions to mitigate substitution attacks

Always commit `poetry.lock` to version control.
