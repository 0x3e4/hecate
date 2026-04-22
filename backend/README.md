# Hecate Backend

FastAPI-Service zum Erfassen, Anreichern und Bereitstellen von Schwachstelleninformationen. Die Dokumentation für das Gesamtprojekt befindet sich in der [README im Repository-Root](../README.md).

## Architektur

```
app/
├── api/v1/                  # REST-Endpunkte
│   ├── routes.py            # Router-Registrierung (18 Module)
│   ├── vulnerabilities.py   # Suche, Lookup, Refresh, AI-Analyse
│   ├── cwe.py               # CWE-Abfragen (einzeln & bulk)
│   ├── capec.py             # CAPEC-Abfragen, CWE->CAPEC Mapping
│   ├── cpe.py               # CPE-Katalog (Entries, Vendors, Products)
│   ├── assets.py            # Asset-Katalog (Vendoren, Produkte, Versionen)
│   ├── stats.py             # Statistik-Aggregationen
│   ├── backup.py            # Export/Import (Streaming): Vulnerabilities, Saved Searches, Environment Inventory
│   ├── sync.py              # Manuelle Sync-Trigger
│   ├── saved_searches.py    # Gespeicherte Suchen (CRUD)
│   ├── audit.py             # Ingestion-Logs
│   ├── changelog.py         # Letzte Änderungen (Pagination, Datum-/Source-Filter)
│   ├── scans.py             # SCA-Scan-Verwaltung (Submit, Targets inkl. Group-Filter, Target-Gruppen-Roll-up, History mit since-Filter, Findings inkl. ?includeDismissed, SBOM, SBOM-Export, SBOM-Import, Compare, VEX inkl. bulk-update-by-ids/import, Findings-Dismiss, License-Compliance)
│   ├── events.py            # Server-Sent Events (SSE) Stream
│   ├── notifications.py     # Benachrichtigungen (Channels, Regeln, Templates)
│   ├── license_policies.py  # Lizenz-Policy-Verwaltung (CRUD, Default-Policy, Lizenzgruppen)
│   ├── inventory.py         # Environment-Inventory (CRUD + /affected-vulnerabilities)
│   ├── config.py            # Public Runtime-Config (Feature-Flags aus Backend-Settings für das Frontend)
│   └── status.py            # Health Check
├── mcp/                         # MCP Server (Model Context Protocol)
│   ├── server.py                # ASGI Sub-App Factory (FastMCP)
│   ├── auth.py                  # Pfad-bewusste MCPAuthMiddleware (nur /mcp + /mcp/*), OAuth-Token-Validierung, Scope-basierte Write-Gatung
│   ├── oauth.py                 # OAuth 2.0 AS-Endpoints (Metadata inkl. RFC 9728 Path-Suffix, DCR, Authorize, IdP-Callback, Token mit PKCE); get_dcr_client_name() für MCP-Attribution
│   ├── oauth_providers.py       # Upstream-IdP-Abstraktion (GitHub / Microsoft Entra / generisches OIDC)
│   ├── security.py              # Rate-Limiting, Input-Sanitisierung
│   ├── audit.py                 # Dual Audit (structlog + MongoDB) für Tool-Invocations und OAuth-Events
│   └── tools/                   # 18 MCP-Tools (6 Module)
│       ├── vulnerabilities.py   # search_vulnerabilities, get_vulnerability, prepare_vulnerability_ai_analysis, save_vulnerability_ai_analysis, prepare_vulnerabilities_ai_batch_analysis, save_vulnerabilities_ai_batch_analysis
│       ├── cpe.py               # search_cpe
│       ├── assets.py            # search_vendors, search_products
│       ├── stats.py             # get_vulnerability_stats
│       ├── cwe_capec.py         # get_cwe, get_capec
│       └── scans.py             # get_scan_findings, get_sca_scan, trigger_scan, trigger_sync, prepare_scan_ai_analysis, save_scan_ai_analysis
├── core/
│   ├── config.py            # Pydantic Settings (alle Env-Variablen)
│   └── logging_config.py    # structlog-Konfiguration
├── db/
│   ├── mongo.py             # Motor (async MongoDB) Verbindung
│   └── opensearch.py        # OpenSearch Verbindung & Operationen
├── models/                  # MongoDB-Dokument-Schemata (Pydantic)
│   ├── vulnerability.py     # VulnerabilityDocument (Hauptschema)
│   ├── cwe.py               # CWEEntry
│   ├── capec.py             # CAPECEntry
│   ├── scan.py              # SCA-Scan-Modelle (Target, Scan, Finding, SBOM)
│   ├── license_policy.py    # LicensePolicyDocument
│   ├── inventory_item.py    # InventoryItemDocument (Environment Inventory)
│   └── kev.py               # CisaKevEntry, CisaKevCatalog
├── repositories/            # Datenzugriffsschicht (15 Repositories)
│   ├── vulnerability_repository.py
│   ├── cwe_repository.py
│   ├── capec_repository.py
│   ├── kev_repository.py
│   ├── cpe_repository.py
│   ├── asset_repository.py
│   ├── saved_search_repository.py
│   ├── ingestion_state_repository.py
│   ├── ingestion_log_repository.py
│   ├── scan_target_repository.py
│   ├── scan_repository.py
│   ├── scan_finding_repository.py
│   ├── scan_sbom_repository.py  # list_by_scan: $group {name, version} + $facet-Aggregation (deduped Total + paginierte Items); count_by_scan_consolidated für Backfill
│   ├── license_policy_repository.py
│   └── inventory_repository.py
├── schemas/                 # API Request/Response Schemata
│   ├── _utc.py              # Shared `UtcDatetime` Annotated-Type (BeforeValidator) — normalisiert alle ausgehenden datetime-Felder auf UTC-aware, damit der Frontend sie nicht als local time parst
│   ├── vulnerability.py     # VulnerabilityQuery (inkl. Advanced Filters: Severity, CVSS-Vektor, EPSS, CWE, Quellen, Zeitraum), VulnerabilityDetail
│   ├── cwe.py, capec.py, cpe.py, assets.py
│   ├── ai.py                # AI-Analyse Schemata
│   ├── backup.py, sync.py, audit.py, changelog.py
│   ├── scan.py              # SCA-Scan API-Schemata (inkl. ImportSbomRequest)
│   ├── vex.py               # VEX API-Schemata (VexUpdate, VexBulkUpdate, VexBulkUpdateByIds, FindingsDismiss, VexImport)
│   ├── license_policy.py    # License-Policy API-Schemata
│   ├── inventory.py         # Environment-Inventory API-Schemata
│   └── saved_search.py
├── services/                # Business-Logik
│   ├── vulnerability_service.py   # Suche, Refresh, Lookup
│   ├── cwe_service.py             # 3-Tier-Cache (Memory->Mongo->API)
│   ├── capec_service.py           # 3-Tier-Cache + CWE->CAPEC Mapping
│   ├── ai_service.py              # OpenAI, Anthropic, Gemini, OpenAI-Compatible Wrapper (lokale/Drittanbieter-Endpoints)
│   ├── stats_service.py           # OpenSearch-Aggregationen (Mongo-Fallback)
│   ├── backup_service.py          # Streaming Export/Import für Vulnerabilities (NVD/EUVD/ALL), Saved Searches und Environment Inventory (Inventory-Restore = Upsert per `_id`)
│   ├── sync_service.py            # Sync-Koordination
│   ├── audit_service.py           # Audit-Logging
│   ├── changelog_service.py       # Change-Tracking
│   ├── saved_search_service.py    # Gespeicherte Suchen
│   ├── cpe_service.py             # CPE-Katalog
│   ├── asset_catalog_service.py   # Asset-Katalog
│   ├── scan_service.py            # SCA-Scan-Orchestrierung (Concurrency-Limiting, Ressourcen-Gating, SBOM-Import, AI-Analyse, SBOM-Dedup per Scan via unique_component_keys → sbom_component_count, Startup-Backfill backfill_sbom_component_count_v2)
│   ├── scan_parser.py             # Scanner-Output-Parser (Trivy, Grype, Syft, OSV, SPDX-SBOM)
│   ├── sbom_export.py             # SBOM-Export-Builder (CycloneDX 1.5, SPDX 2.3)
│   ├── vex_service.py             # VEX-Export/Import (CycloneDX VEX), Carry-Forward (VEX + Dismissal)
│   ├── license_compliance_service.py  # Lizenz-Policy-Auswertung
│   ├── inventory_service.py       # Environment-Inventory CRUD + Matching (30s TTL-Cache)
│   ├── inventory_matcher.py       # CPE-Versionsbereichs-Matcher (pure functions, selbst-enthaltener Version-Comparator)
│   ├── event_bus.py               # In-Memory Async Event-Bus für SSE
│   ├── notification_service.py    # Apprise-Benachrichtigungen (inkl. inventory-Watch-Rule-Evaluator)
│   ├── http/
│   │   └── rate_limiter.py        # HTTP Rate-Limiting
│   ├── ingestion/                 # Datenpipelines
│   │   ├── euvd_pipeline.py       # EUVD (ENISA)
│   │   ├── nvd_pipeline.py        # NVD (NIST)
│   │   ├── kev_pipeline.py        # CISA KEV
│   │   ├── cpe_pipeline.py        # CPE (NVD, Mid-Run-Progress-Reporting)
│   │   ├── circl_pipeline.py      # CIRCL
│   │   ├── ghsa_pipeline.py       # GHSA (GitHub Advisory)
│   │   ├── euvd_client.py         # EUVD API-Client
│   │   ├── nvd_client.py          # NVD API-Client
│   │   ├── cisa_client.py         # KEV API-Client
│   │   ├── cpe_client.py          # CPE API-Client (Retry mit Exponential-Backoff)
│   │   ├── cwe_client.py          # CWE MITRE API-Client
│   │   ├── capec_client.py        # CAPEC XML-Parser
│   │   ├── circl_client.py        # CIRCL API-Client
│   │   ├── ghsa_client.py         # GHSA API-Client
│   │   ├── osv_client.py          # OSV.dev GCS Bucket + REST-API-Client
│   │   ├── osv_pipeline.py        # OSV (OSV.dev, Mid-Run-Progress-Reporting)
│   │   ├── normalizer.py          # Normalisierung aller Quellen
│   │   ├── job_tracker.py         # Job-Lifecycle & Audit
│   │   ├── manual_refresher.py    # On-Demand Refresh
│   │   └── startup_cleanup.py     # Zombie-Job Bereinigung
│   └── scheduling/
│       └── manager.py             # APScheduler (Bootstrap + Periodic)
├── utils/
│   ├── strings.py                 # Slugify etc.
│   └── request.py                 # IP-Extraktion
├── main.py                        # FastAPI App-Initialisierung
└── cli.py                         # CLI-Einstiegspunkt (11 Befehle)
```

## Datenmodell

### MongoDB Collections

| Collection | Modell | Beschreibung |
|-----------|--------|-------------|
| `vulnerabilities` | `VulnerabilityDocument` | Schwachstellen mit CVSS, EPSS, CWEs, CPEs, Quell-Rohdaten |
| `cwe_catalog` | `CWEEntry` | CWE-Schwächen (7-Tage TTL-Cache) |
| `capec_catalog` | `CAPECEntry` | CAPEC-Angriffsmuster (7-Tage TTL-Cache) |
| `known_exploited_vulnerabilities` | `CisaKevEntry` | CISA KEV-Einträge |
| `cpe_catalog` | — | CPE-Einträge (Vendor, Product, Version) |
| `asset_vendors` | — | Vendoren mit Slug und Produkt-Anzahl |
| `asset_products` | — | Produkte mit Vendor-Zuordnung |
| `asset_versions` | — | Versionen mit Produkt-Zuordnung |
| `ingestion_state` | — | Sync-Job-Status (Running/Completed/Failed) |
| `ingestion_logs` | — | Detaillierte Job-Logs mit Metadaten |
| `saved_searches` | — | Gespeicherte Suchanfragen |
| `scan_targets` | `ScanTargetDocument` | Scan-Ziele (Container-Images, Source-Repos) |
| `scans` | `ScanDocument` | Scan-Durchläufe mit Status und Zusammenfassung |
| `scan_findings` | `ScanFindingDocument` | Schwachstellen-Funde aus SCA-Scans |
| `scan_sbom_components` | `ScanSbomComponentDocument` | SBOM-Komponenten aus SCA-Scans (exportierbar als CycloneDX 1.5 / SPDX 2.3) |
| `scan_layer_analysis` | `ScanLayerAnalysisDocument` | Image-Schichtanalyse aus Dive-Scans |
| `notification_rules` | — | Benachrichtigungsregeln (Event, Watch, DQL, Scan, Inventory) |
| `notification_channels` | — | Apprise-Channels (URL + Tag) |
| `notification_templates` | — | Nachrichtenvorlagen (Titel/Body-Templates pro Event-Typ) |
| `license_policies` | `LicensePolicyDocument` | Lizenz-Policies (erlaubt, verboten, Review-erforderlich) |
| `environment_inventory` | `InventoryItemDocument` | Benutzerdeklariertes Produkt/Version-Inventory (Deployment, Environment, Instance-Count) |

### OpenSearch Index (`hecate-vulnerabilities`)

Volltext-Index mit Text-Feldern für Suche und `.keyword`-Feldern für Aggregationen. Nested `sources`-Pfad für Quell-Aggregationen. Flaches `sourceNames`-Keyword-Array für DQL-Source-Alias-Suche (`source:X` sucht automatisch in `source` und `sourceNames`).

**Konfiguration:** `max_result_window` = 200.000, `total_fields.limit` = 2.000, `OPENSEARCH_VERIFY_CERTS` (SSL-Zertifikatsüberprüfung, Default: false), `OPENSEARCH_CA_CERT` (Pfad zum CA-Zertifikat, optional)

## Ingestion-Pipelines

| Pipeline | Quelle | Intervall (Default) | Beschreibung |
|----------|--------|---------------------|-------------|
| EUVD | ENISA REST-API | 60 min | Schwachstellen mit Change-History |
| NVD | NIST REST-API | 10 min | CVSS, CPE-Konfigurationen |
| KEV | CISA JSON-Feed | 60 min | Exploitation-Status |
| CPE | NVD CPE 2.0 API | 1440 min (täglich) | Produkt-/Versions-Katalog |
| CWE | MITRE REST-API | 7 Tage | Schwäche-Definitionen |
| CAPEC | MITRE XML-Download | 7 Tage | Angriffsmuster |
| CIRCL | CIRCL REST-API | 120 min | Zusätzliche Anreicherung |
| GHSA | GitHub Advisory API | 120 min | GitHub Security Advisories |
| OSV | OSV.dev GCS Bucket + REST-API | 120 min | OSV-Schwachstellen (Hybrid: CVE-Enrichment + MAL/PYSEC/OSV-Einträge, 11 Ökosysteme) |

Alle Pipelines unterstützen inkrementelle und initiale Syncs. Wöchentliche Full-Syncs: EUVD Sonntag 2 Uhr UTC, NVD Mittwoch 2 Uhr UTC.

**Hinweis:** Die Intervalle in `.env.example` können von den Code-Defaults abweichen. Die autoritativen Defaults stehen in `app/core/config.py`.

## Design-Patterns

### Repository-Pattern
- `create()` Classmethod erstellt Indexes
- `_id` = Entity-ID in MongoDB
- `upsert()` gibt `"inserted"`, `"updated"` oder `"unchanged"` zurück

### 3-Tier-Cache (CWE, CAPEC)
```
Memory-Dict → MongoDB Collection → Externe API/XML
                  (7 Tage TTL)
```
Singleton via `@lru_cache`, Lazy Repository-Loading.

### Job-Tracking
```
start(job_name) → Running in MongoDB → finish(ctx, result) → Completed + Log
```
Startup-Cleanup markiert Zombie-Jobs als abgebrochen.

### Server-Sent Events (SSE)
```
EventBus (Singleton) → publish(event) → asyncio.Queue per Subscriber → SSE Stream
```
Events: `job_started`, `job_completed`, `job_failed`, `new_vulnerabilities`. JobTracker, SchedulerManager und AI-Analyse-Endpunkte publizieren automatisch. Frontend verbindet sich über `GET /api/v1/events`. AI-Analysen laufen asynchron via `asyncio.create_task()` und melden Ergebnisse über SSE (`ai_investigation_{vulnId}`, `ai_batch_investigation`).

### API-Schema-Konvention
```python
field_name: str = Field(alias="fieldName", serialization_alias="fieldName")
```
Snake-Case in Python, camelCase auf dem Wire.

### UTC-aware Datetime-Serialisierung
Alle nach außen exponierten `datetime`-Felder verwenden den `UtcDatetime`-Alias aus `app/schemas/_utc.py` (ein `Annotated[datetime, BeforeValidator(_coerce_utc)]`). Der Validator hängt an jedes eingehende naive datetime / ISO-String ein `tzinfo=UTC` an, sodass die JSON-Ausgabe immer ein `+00:00`-Suffix enthält. Hintergrund: OpenSearch `_source`-Reads von als naive String indizierten Date-Feldern liefern Werte ohne Zeitzone; der Frontend würde sie via `new Date()` als local time parsen und um den Offset des Benutzers verschoben anzeigen. Zusätzlich öffnet `app/db/mongo.py` den Motor-Client mit `tz_aware=True`, damit auch MongoDB-Reads UTC-aware zurückkommen. Alle Writes nutzen `datetime.now(UTC)`.

## CLI

```sh
poetry run python -m app.cli ingest [--since ISO] [--limit N] [--initial]
poetry run python -m app.cli sync-euvd [--since ISO] [--initial]
poetry run python -m app.cli sync-cpe [--limit N] [--initial]
poetry run python -m app.cli sync-nvd [--since ISO | --initial]
poetry run python -m app.cli sync-kev [--initial]
poetry run python -m app.cli sync-cwe [--initial]
poetry run python -m app.cli sync-capec [--initial]
poetry run python -m app.cli sync-circl [--limit N]
poetry run python -m app.cli sync-ghsa [--limit N] [--initial]
poetry run python -m app.cli sync-osv [--limit N] [--initial]
poetry run python -m app.cli reindex-opensearch
```

## Entwicklung

### Abhängigkeiten verwalten

Dieses Projekt verwendet [Poetry](https://python-poetry.org/) für die Verwaltung von Abhängigkeiten.

#### Neue Abhängigkeit hinzufügen

```bash
# pyproject.toml manuell bearbeiten und dann die Lock-Datei aktualisieren:
poetry lock

# Oder direkt mit Poetry hinzufügen:
poetry add <paket-name>

# Dann beide Dateien committen:
git add pyproject.toml poetry.lock
git commit -m "Add <paket-name> dependency"
```

#### Abhängigkeiten aktualisieren

```bash
# Alle Abhängigkeiten auf die neuesten kompatiblen Versionen aktualisieren:
poetry update

# Ein bestimmtes Paket aktualisieren:
poetry update <paket-name>

# Dann die Änderungen committen:
git add poetry.lock
git commit -m "Update dependencies"
```

#### Abhängigkeiten lokal installieren

```bash
poetry install
```

### Tests und Linting

```bash
poetry run pytest
poetry run ruff check app
```

### Docker Build

Multi-Stage Build (Builder → Runtime) basierend auf `python:3.13-slim`. Port 8000.

```bash
docker build -t hecate-backend ./backend
docker run -p 8000:8000 --env-file .env hecate-backend
```

### Warum poetry.lock wichtig ist

Die Datei `poetry.lock` stellt sicher:
- **Reproduzierbare Builds** — Alle verwenden die gleichen Abhängigkeitsversionen
- **Sicherheitsprüfung** — Trivy scannt diese Datei auf Schwachstellen
- **Supply-Chain-Sicherheit** — Fixiert exakte Versionen zur Verhinderung von Angriffen

Committe `poetry.lock` immer in die Versionsverwaltung.
