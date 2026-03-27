# Hecate Architektur

## Überblick

Hecate ist eine Schwachstellen-Management-Plattform, die Daten aus 8 externen Quellen aggregiert, normalisiert und über eine REST-API sowie ein React-Frontend bereitstellt. Ergänzend können Container-Images und Source-Repositories aktiv auf Schwachstellen gescannt werden (SCA).

### Systemkontext

- React Single-Page-Application konsumiert REST-APIs des FastAPI-Backends.
- FastAPI orchestriert Ingestion, Persistenz, KI-Aufrufe und liefert Daten an das Frontend.
- OpenSearch dient als performanter Query-Index, MongoDB hält Normalformdaten und Jobzustand.
- Externe Feeds (EUVD, NVD, CISA KEV, CPE, CWE, CAPEC, CIRCL, GHSA) sowie optionale AI-Provider (OpenAI, Anthropic, Gemini) stellen Rohdaten bereit.
- Ein Scanner-Sidecar (Trivy, Grype, Syft, OSV Scanner, Hecate Analyzer, Dockle, Dive) führt aktive SCA-Scans für Container-Images und Source-Repositories durch.

## Deployment-Topologie

```
                    +-----------+
                    |  Frontend |  React 19 / Vite / TypeScript
                    |  :4173    |  Dark-Theme SPA (serve)
                    +-----+-----+
                          | /api
                    +-----v-----+
                    |  Backend  |  FastAPI / Python 3.13 / Poetry
                    |  :8000    |  REST-API, Scheduler, Pipelines
                    +--+--+--+--+
                       |  |  |
                       |  |  +--------+
                       |  |           |
                       |  |     +-----v-----+
                       |  |     |  Scanner  |  Trivy, Grype, Syft, OSV, Hecate,
                       |  |     |  :8080    |  Dockle, Dive (FastAPI Sidecar)
                       |  |     +-----------+
                       |  |
                       |  +--+
                       |     |
                       |  +--v--------+
                       |  |  Apprise  |  Notification Gateway
                       |  |  :8000    |  Slack, Discord, E-Mail, etc.
                       |  +-----------+
                       |
              +--------+  +--------+
              |                    |
        +-----v-----+      +------v------+
        |  MongoDB   |      | OpenSearch  |
        |  :27017    |      |  :9200      |
        +------------+      +-------------+
         Persistenz          Volltext-Index
```

- Docker Compose Orchestrierung: backend, frontend, scanner, mongo, opensearch, apprise
- Container Registry: `git.nohub.lol/rk/hecate-{backend,frontend}:latest`
- CI/CD: Gitea Actions (`build.yml` Docker Build + Grype-Scan, `scan.yml` SonarQube + Trivy)

## Backend-Architektur

### API-Schicht

14 Router-Module unter `app/api/v1` kapseln funktionale Bereiche:
- `status.py` — Health Check / Liveness Probe, Scanner-Health
- `vulnerabilities.py` — Suche, Lookup, Refresh, AI-Analyse
- `cwe.py` — CWE-Abfragen (einzeln & bulk)
- `capec.py` — CAPEC-Abfragen, CWE→CAPEC Mapping
- `cpe.py` — CPE-Katalog (Entries, Vendors, Products)
- `assets.py` — Asset-Katalog (Vendoren, Produkte, Versionen)
- `stats.py` — Statistik-Aggregationen
- `backup.py` — Streaming Export/Import
- `sync.py` — Manuelle Sync-Trigger für alle 8 Datenquellen
- `saved_searches.py` — Gespeicherte Suchen (CRUD)
- `audit.py` — Ingestion-Logs
- `changelog.py` — Letzte Änderungen
- `scans.py` — SCA-Scan-Verwaltung (Submit, Targets, Findings, SBOM, SBOM-Export, Layer-Analyse)
- `notifications.py` — Benachrichtigungsstatus, Channels, Regeln, Nachrichtenvorlagen

Standardpräfix `/api/v1` (konfigurierbar) und CORS für lokale Integration. Responses basieren auf Pydantic-Schemas; Validierung auf Eingabe- und Ausgabeseite. Schema-Konvention: Snake-Case in Python, camelCase auf dem Wire (`Field(alias="fieldName", serialization_alias="fieldName")`).

### Services & Domain

Service-Klasse je Anwendungsfall:
- `VulnerabilityService` — Suche, Refresh, Lookup
- `CWEService` — 3-Tier-Cache (Memory → MongoDB → MITRE API)
- `CAPECService` — 3-Tier-Cache + CWE→CAPEC Mapping
- `CPEService` — CPE-Katalog
- `AIService` — OpenAI, Anthropic, Gemini Wrapper (httpx für OpenAI/Anthropic, google-genai SDK für Gemini)
- `StatsService` — OpenSearch-Aggregationen (Mongo-Fallback)
- `BackupService` — Streaming Export/Import
- `SyncService` — Sync-Koordination
- `AuditService` — Audit-Logging
- `ChangelogService` — Change-Tracking
- `SavedSearchService` — Gespeicherte Suchen
- `AssetCatalogService` — Asset-Katalog aus ingestierten Daten
- `ScanService` — SCA-Scan-Orchestrierung (Scanner-Sidecar, Ergebnisverarbeitung)
- `NotificationService` — Apprise-Anbindung, Regeln, Channels, Nachrichtenvorlagen mit Template-Engine

Services kapseln Datenbankzugriff (Repositories) und koordinieren OpenSearch + Mongo Operationen. Der Asset-Katalog wird aus ingestierten Daten abgeleitet (Vendor-/Produkt-/Versions-Slugs) und füttert die Filter-UI.

### Ingestion-Pipelines

| Pipeline | Quelle | Intervall (Default) | Beschreibung |
|----------|--------|---------------------|-------------|
| EUVD | ENISA REST-API | 60 min | Schwachstellen mit Change-History, inkrementell + wöchentlicher Full-Sync (So 2 Uhr UTC) |
| NVD | NIST REST-API | 10 min | CVSS, EPSS, CPE-Konfigurationen, optionaler API-Key, Full-Sync (Mi 2 Uhr UTC) |
| KEV | CISA JSON-Feed | 60 min | Exploitation-Status |
| CPE | NVD CPE 2.0 API | 1440 min (täglich) | Produkt-/Versions-Katalog |
| CWE | MITRE REST-API | 7 Tage | Schwäche-Definitionen |
| CAPEC | MITRE XML-Download | 7 Tage | Angriffsmuster |
| CIRCL | CIRCL REST-API | 120 min | Zusätzliche Anreicherung |
| GHSA | GitHub Advisory API | 120 min | GitHub Security Advisories (Hybrid: reichert CVEs an + erstellt GHSA-only-Einträge) |

- Alle Pipelines unterstützen inkrementelle und initiale Syncs.
- **EUVD Pipeline:** Liest paginiert, gleicht CVE-IDs ab, reichert mit NVD- und KEV-Daten an, pflegt Change-Historie, aktualisiert OpenSearch-Index + Mongo-Dokumente.
- **NVD Pipeline:** Aktualisiert CVSS/EPSS/Referenzen für bestehende Datensätze, optional begrenzt über `modifiedSince`.
- **CPE Pipeline:** Synchronisiert NVD-CPE-Katalog, erzeugt Vendor-/Produkt-/Versionseinträge und legt Slug-Metadaten in Mongo ab.
- **KEV Pipeline:** Hält CISA Known-Exploited-Catalog aktuell und stellt Exploitation-Metadaten für EUVD/NVD bereit.
- **CWE Pipeline:** Synchronisiert MITRE CWE-Katalog über REST-API mit 7-Tage TTL-Cache.
- **CAPEC Pipeline:** Parst MITRE CAPEC XML, erstellt Angriffsmuster-Einträge mit CWE-Zuordnung.
- **CIRCL Pipeline:** Liest zusätzliche Schwachstelleninformationen von CIRCL und reichert bestehende Datensätze an.
- **GHSA Pipeline:** Synchronisiert GitHub Security Advisories, verknüpft mit bestehenden CVEs und erstellt eigenständige GHSA-Einträge.
- **Manual Refresher:** Ermöglicht gezielte Reingestion einzelner IDs (API + CLI) und protokolliert Ergebnisse.

### Datenbeziehungen
- CVE → CWE: Aus NVD `weaknesses`-Array, gespeichert auf `VulnerabilityDocument`.
- CWE → CAPEC: Bidirektionales Mapping aus CWE-Rohdaten + CAPEC-XML.
- CAPEC-IDs werden NICHT auf `VulnerabilityDocument` gespeichert; Auflösung erfolgt zur Anzeigezeit.

### Scheduler & Job-Tracking
- `SchedulerManager` initialisiert APScheduler (AsyncIO) mit Intervallen für alle 8 Datenquellen + optionalem SCA Auto-Scan.
- Initial-Bootstrap läuft beim Start einmalig (EUVD, CPE, NVD, KEV, CWE, CAPEC, GHSA) und wird in `IngestionStateRepository` (Mongo) als abgeschlossen markiert.
- CIRCL hat keinen Bootstrap-Job, da es nur bestehende Datensätze anreichert.
- `JobTracker` aktualisiert Laufzeitstatus, setzt Overdue-Flags und persistiert Fortschritt im Audit-Log.
- Startup-Cleanup markiert Zombie-Jobs (Running-Status bei Neustart) als abgebrochen.
- Audit-Service schreibt Ereignisse in `ingestion_logs` inklusive Dauer, Ergebnis und Metadaten.
- Konfigurierbare `INGESTION_RUNNING_TIMEOUT_MINUTES` markiert Jobs als Overdue, ohne sie abzubrechen.

### Persistenz

#### MongoDB (19 Collections)

| Collection | Beschreibung |
|-----------|-------------|
| `vulnerabilities` | Schwachstellen mit CVSS, EPSS, CWEs, CPEs, Quell-Rohdaten |
| `cwe_catalog` | CWE-Schwächen (7-Tage TTL-Cache) |
| `capec_catalog` | CAPEC-Angriffsmuster (7-Tage TTL-Cache) |
| `known_exploited_vulnerabilities` | CISA KEV-Einträge |
| `cpe_catalog` | CPE-Einträge (Vendor, Product, Version) |
| `asset_vendors` | Vendoren mit Slug und Produkt-Anzahl |
| `asset_products` | Produkte mit Vendor-Zuordnung |
| `asset_versions` | Versionen mit Produkt-Zuordnung |
| `ingestion_state` | Sync-Job-Status (Running/Completed/Failed) |
| `ingestion_logs` | Detaillierte Job-Logs mit Metadaten |
| `saved_searches` | Gespeicherte Suchanfragen |
| `scan_targets` | Scan-Ziele (Container-Images, Source-Repos) |
| `scans` | Scan-Durchläufe mit Status und Zusammenfassung |
| `scan_findings` | Schwachstellen-Funde aus SCA-Scans |
| `scan_sbom_components` | SBOM-Komponenten aus SCA-Scans |
| `scan_layer_analysis` | Image-Schichtanalyse aus Dive-Scans |
| `notification_rules` | Benachrichtigungsregeln (Event, Watch, DQL) |
| `notification_channels` | Apprise-Channels (URL + Tag) |
| `notification_templates` | Nachrichtenvorlagen (Titel/Body-Templates pro Event-Typ) |

- Repositories auf Basis von Motor (async) kapseln Abfragen und Updates.
- Repository-Pattern: `create()` Classmethod erstellt Indexes, `_id` = Entity-ID, `upsert()` gibt `"inserted"` / `"updated"` / `"unchanged"` zurück.
- TTL-Indizes (z. B. `expires_at`) sichern optionales Aufräumen von Zustandsdokumenten.

#### OpenSearch
- Index `hecate-vulnerabilities` mit normalisierten Dokumenten (IDs als CVE oder EUVD-ID).
- Text-Felder für Volltext-Suche, `.keyword`-Felder für Aggregationen, nested `sources`-Pfad.
- DQL (Domain-Specific Query Language) für erweiterte Suchanfragen.
- Konfiguration: `max_result_window` = 200.000, `total_fields.limit` = 2.000.

### SCA-Scanning (Software Composition Analysis)
- **Scanner-Sidecar:** Separater Docker-Container mit 7 Scannern: Trivy, Grype, Syft, OSV Scanner, Hecate Analyzer, Dockle und Dive.
- **Scan-Ablauf:** CI/CD oder manuelle Anfrage → Backend → Scanner-Sidecar → Ergebnisse parsen → MongoDB speichern → Antwort.
- **Image-Pull:** Scanner-Tools ziehen Container-Images direkt über Registry-APIs (kein Docker-Socket). Dive nutzt Skopeo zum Image-Pull als docker-archive.
- **Registry-Auth:** Konfigurierbar über `SCANNER_AUTH` Umgebungsvariable.
- **Parser:** Trivy-JSON, Grype-JSON, CycloneDX-SBOM (Syft), OSV-JSON, Hecate-JSON, Dockle-JSON, Dive-JSON werden in einheitliche Modelle überführt.
- **Hecate Analyzer:** Eigener SBOM-Extraktor (18 Parser, 12 Ökosysteme: Docker, npm, Python, Go, Rust, Ruby, PHP, Java, .NET, Swift, Elixir, Dart, CocoaPods) + Malware-Detektor (33 Regeln, HEC-001 bis HEC-090).
- **Dockle:** CIS Docker Benchmark Linter — prüft Container-Images auf Best Practices (~21 Checkpoints). Ergebnisse als `ScanFindingDocument` mit `package_type="compliance-check"`, werden nicht in Vulnerability-Summary gezählt. Nur für Container-Images, opt-in.
- **Dive:** Docker-Image-Schichtanalyse — Effizienz, verschwendeter Speicher, Layer-Aufschlüsselung. Ergebnisse in separater `scan_layer_analysis` Collection. Nur für Container-Images, opt-in.
- **Scanner-Auswahl pro Target:** Beim Erst-Scan gewählte Scanner werden auf dem `ScanTargetDocument` gespeichert und für Auto-Scans wiederverwendet.
- **Scan-Vergleich:** Findings können zwischen zwei Scans verglichen werden (Added, Removed, Changed). "Changed" gruppiert Findings mit gleichem Paket aber unterschiedlicher Schwachstelle.
- **SBOM-Export:** CycloneDX 1.5 JSON und SPDX 2.3 JSON Export über `GET /api/v1/scans/{scan_id}/sbom/export?format=cyclonedx-json|spdx-json`. Pure-Function-Builder in `sbom_export.py` (keine externen Bibliotheken). Download mit `Content-Disposition: attachment` Header. EU Cyber Resilience Act (CRA) Compliance.
- **Deduplizierung:** Gleiche CVE + Paket-Kombination über mehrere Scanner wird zusammengeführt.
- **Auto-Scan:** Optionales periodisches Scannen registrierter Ziele mit den beim Erst-Scan gewählten Scannern (konfigurierbar über `SCA_AUTO_SCAN_INTERVAL_HOURS`).
- **Audit-Integration:** Scan-Ereignisse werden im Ingestion-Log protokolliert.

### KI & Analyse
- `AIClient` verwaltet verfügbare Provider anhand gesetzter API-Schlüssel (OpenAI, Anthropic, Google Gemini).
- **OpenAI:** Responses API (`POST /v1/responses`) mit Reasoning (`reasoning.effort`) und Web-Suche (`web_search_preview` Tool). Konfigurierbar über `OPENAI_REASONING_EFFORT` (Default: `medium`) und `OPENAI_MAX_OUTPUT_TOKENS` (Default: 16000).
- **Anthropic:** Messages API via httpx.
- **Google Gemini:** `google-genai` SDK mit optionaler Google-Suche.
- Prompt-Builder erstellt Kontexte inkl. Asset- und Historieninformationen in frei wählbarer Sprache.
- **Asynchrone Verarbeitung:** Einzel- und Batch-Analyse-Endpunkte geben sofort HTTP 202 zurück. Die eigentliche Analyse läuft als `asyncio.create_task()` im Hintergrund. Fortschritt und Ergebnis werden über SSE-Events (`job_started`, `job_completed`, `job_failed`) an das Frontend geliefert.
- Ergebnisse werden in MongoDB gespeichert und als Audit-Event protokolliert.
- Fehlerbehandlung liefert 4xx bei Konfigurationsfehlern, SSE `job_failed` bei Provider-Ausfällen.

### Benachrichtigungen (Apprise)
- `NotificationService` kommuniziert via HTTP mit der Apprise REST-API (fire-and-forget).
- **Channels:** Apprise-URLs mit Tags, gespeichert in MongoDB, konfigurierbar über System-Seite.
- **Regeln:** Event-basiert (`scan_completed`, `scan_failed`, `sync_failed`, `new_vulnerabilities`) und Watch-basiert (`saved_search`, `vendor`, `product`, `dql`).
- **Nachrichtenvorlagen:** Anpassbare Titel/Body-Templates pro Event-Typ mit `{placeholder}`-Variablen und `{#each}...{/each}`-Schleifen. Auflösung: exakter Tag-Match → `all`-Fallback → hardcodierter Default.
- **Watch-Auswertung:** Nach jeder Ingestion werden Watch-Regeln automatisch gegen neue Einträge in OpenSearch evaluiert.
- Partial Delivery (HTTP 424 von Apprise) wird als Erfolg gewertet.

### Backup & Restore
- Backup-Service exportiert JSON-Snapshots für Schwachstellen (quellenweise: EUVD/NVD/Alle), CPE-Katalog und gespeicherte Suchen.
- Streaming Export/Import mit Metadaten (Dataset, Source, Item-Count, Timestamp).
- Restore validiert Metadaten, schreibt Dokumente in Mongo + OpenSearch und gibt eine Zusammenfassung zurück (inserted/updated/skipped).
- Frontend-Systemseite nutzt diese Endpunkte für Self-Service-Backups.

### Observability
- `structlog` für strukturierte Logs, konsistent in Pipelines und Services verwendet.
- Audit-Log dient als Betriebsführer (Status, Fehlergründe, Dauer, Overdue-Hinweise).

### CLI
```
poetry run python -m app.cli ingest [--since ISO] [--limit N] [--initial]
poetry run python -m app.cli sync-euvd [--since ISO] [--initial]
poetry run python -m app.cli sync-cpe [--limit N] [--initial]
poetry run python -m app.cli sync-nvd [--since ISO | --initial]
poetry run python -m app.cli sync-kev [--initial]
poetry run python -m app.cli sync-cwe [--initial]
poetry run python -m app.cli sync-capec [--initial]
poetry run python -m app.cli sync-circl [--limit N]
poetry run python -m app.cli sync-ghsa [--limit N] [--initial]
poetry run python -m app.cli reindex-opensearch
```

## Frontend-Architektur

### Technologie-Stack
- React 19, TypeScript 5.9, Vite 7, React Router 7
- Axios (HTTP-Client, 60s Timeout), react-markdown (AI-Zusammenfassungen), react-select (Async Multi-Select), react-icons (Lucide)

### Seiten & Routing

| Route | Komponente | Beschreibung |
|-------|-----------|-------------|
| `/` | `DashboardPage` | Startseite mit Schwachstellensuche und aktuellen Einträgen |
| `/vulnerabilities` | `VulnerabilityListPage` | Paginierte Liste mit Freitext-, Vendor-, Produkt- und Version-Filtern |
| `/vulnerability/:vulnId` | `VulnerabilityDetailPage` | Detailansicht mit AI-Assessments, Referenzen, Change-History |
| `/query-builder` | `QueryBuilderPage` | Interaktiver DQL-Editor mit Field-Browser und Aggregationen |
| `/ai-analyse` | `AIAnalysePage` | Einzel- und Batch-KI-Analyse (bedingt, via `VITE_AI_FEATURES_ENABLED`) |
| `/stats` | `StatsPage` | Trenddiagramme, Top-Vendoren/-Produkte, Severity-Verteilung |
| `/audit` | `AuditLogPage` | Ingestion-Job-Protokolle mit Status und Metadaten |
| `/changelog` | `ChangelogPage` | Letzte Änderungen an Schwachstellen (erstellt/aktualisiert) |
| `/system` | `SystemPage` | Backup/Restore, Sync-Verwaltung, gespeicherte Suchen, Benachrichtigungen, Dienste-Status |
| `/scans` | `ScansPage` | SCA-Scan-Verwaltung (Ziele, Scans, manueller Scan) |
| `/scans/:scanId` | `ScanDetailPage` | Scan-Details mit Findings, SBOM (Export & Summary-Stats), Security Alerts, Best Practices (Dockle), Layer Analysis (Dive), Scan-Vergleich |

### State-Management
- Kein Redux/Zustand — basiert auf Reacts eingebauten Mechanismen:
  - **Context API:** `SavedSearchesContext` für globale gespeicherte Suchen
  - **useState:** Lokaler Komponentenstate (Loading, Error, Daten)
  - **URL-Parameter:** Filter, Pagination, Query-Modus (bookmarkbar)
  - **localStorage:** Sidebar-Zustand, Asset-Filter-Auswahl (`usePersistentState` Hook)
- Datenlademuster: `useEffect → setLoading(true) → API-Aufruf → setData/setError → setLoading(false)` mit Skeleton-Platzhaltern.

### Styling
- Custom CSS Dark-Theme in `styles.css` (~800+ Zeilen), kein CSS-Framework.
- CSS-Variablen: `#080a12` Hintergrund, `#f5f7fa` Text.
- Severity-Farben: Critical (`#ff6b6b`), High (`#ffa3a3`), Medium (`#ffcc66`), Low (`#8fffb0`).
- Responsive Design mit CSS Grid/Flexbox, mobile Sidebar als Overlay.

### Lokalisierung
- Sprache: Deutsch und Englisch (einfaches i18n via Context API mit `t(english, german)` Pattern, Browser-Spracherkennung, localStorage-Persistenz).
- Kein externes i18n-Framework (kein i18next o. ä.).
- Datumsformat: `DD.MM.YYYY HH:mm` (de-DE) bzw. `MM/DD/YYYY` (en-US).
- Zeitzone: Konfigurierbar via `VITE_TIMEZONE` (Default: `UTC`).

### Code-Splitting
- Manuelle Chunk-Aufteilung in `vite/chunk-split.ts`:
  - `react-select`, `react-icons`, `axios` jeweils als eigener Chunk
  - Restliche `node_modules` als `vendor` Chunk

## Design-Patterns

### Repository-Pattern
- `create()` Classmethod erstellt Indexes.
- `_id` = Entity-ID in MongoDB.
- `upsert()` gibt `"inserted"`, `"updated"` oder `"unchanged"` zurück.

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

### Normalizer
Alle Quellen werden über `normalizer.py` in ein einheitliches `VulnerabilityDocument`-Schema überführt. CVSS-Metriken normalisiert über v2.0, v3.0, v3.1 und v4.0.

## Datenfluss

```
Scheduler / CLI
      │
      v
Pipeline (EUVD/NVD/KEV/CPE/CWE/CAPEC/CIRCL/GHSA)
      │
      ├──> Normalizer ──> VulnerabilityDocument
      │                         │
      │                    +----+----+
      │                    │         │
      │                    v         v
      │               MongoDB   OpenSearch
      │
      └──> AssetCatalogService ──> Vendor/Produkt/Versions-Slugs
```

1. Scheduler oder CLI löst einen Ingestion-Job aus.
2. Pipeline zieht Daten von der externen Quelle, normalisiert sie (`build_document`), aktualisiert Mongo und OpenSearch.
3. AssetCatalogService leitet Vendor-/Produkt-/Versionsdaten ab und aktualisiert Slugs für Filter.
4. Frontend ruft Listen- und Detailendpunkte ab, optional startet AI-Assessments oder Backups.
5. Audit-Service protokolliert alle relevanten Aktionen, Stats-Service aggregiert Kennzahlen aus OpenSearch (Fallback Mongo).

## Externe Integrationen

| Integration | Typ | Beschreibung |
|------------|-----|-------------|
| EUVD (ENISA) | REST-API | Primäre Schwachstellendatenquelle |
| NVD (NIST) | REST-API | CVE-Detail- und CPE-Katalog-Synchronisation |
| CISA KEV | JSON-Feed | Exploitation-Metadaten |
| CPE (NVD) | REST-API | CPE 2.0 Produkt-Katalog |
| CWE (MITRE) | REST-API | Schwäche-Definitionen (`cwe-api.mitre.org`) |
| CAPEC (MITRE) | XML-Download | Angriffsmuster (`capec.mitre.org`) |
| CIRCL | REST-API | Zusätzliche Schwachstelleninformationen (`vulnerability.circl.lu`) |
| GHSA (GitHub) | REST-API | GitHub Security Advisories (`api.github.com`) |
| OpenAI | API | Optionaler KI-Provider für Zusammenfassungen und Risikohinweise |
| Anthropic | API | Optionaler KI-Provider für Zusammenfassungen und Risikohinweise |
| Google Gemini | API | Optionaler KI-Provider für Zusammenfassungen und Risikohinweise |

## Technologie-Stack

| Komponente | Technologie |
|-----------|------------|
| Backend | Python 3.13, FastAPI 0.128, Uvicorn, Poetry |
| Frontend | React 19, TypeScript 5.9, Vite 7, React Router 7 |
| Datenbank | MongoDB 8 (Motor async), OpenSearch 3 |
| Scheduling | APScheduler 3.11 |
| HTTP-Client | httpx 0.28 (async), Axios 1.13 (Frontend) |
| Logging | structlog 25 |
| KI | OpenAI, Anthropic, Google Gemini |
| Scanner-Sidecar | Trivy, Grype, Syft, OSV Scanner, Hecate Analyzer, Dockle, Dive, Skopeo, FastAPI |
| Benachrichtigungen | Apprise (caronc/apprise) |
| CI/CD | Gitea Actions, Grype, Trivy, SonarQube |
