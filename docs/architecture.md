# Hecate Architecture Overview

## Vision
- KI-gestuetzte Cyberabwehrplattform, die Schwachstellen aggregiert, anreichert und priorisiert.
- Fokus auf schnelle Sichtbarkeit fuer Security-Teams ohne initialen Authentifizierungsaufwand.
- Erweiterbarkeit fuer weitere Datenquellen, Automatisierung und Integrationen (Ticketing, Assets).

## System Context
- React Single-Page-Application konsumiert REST-APIs des FastAPI-Backends.
- FastAPI orchestriert Ingestion, Persistenz, KI-Aufrufe und liefert Daten an das Frontend.
- OpenSearch dient als performanter Query-Index, MongoDB haelt Normalformdaten und Jobzustand.
- Externe Feeds (EUVD, NVD, CISA KEV, CPE, CWE, CAPEC, CIRCL) sowie optionale AI-Provider (OpenAI, Anthropic, Gemini) stellen Rohdaten bereit.

## Backend Architecture

### API Layer
- 12 Router-Module unter `app/api/v1` kapseln funktionale Bereiche:
  - `status.py` - Health Check / Liveness Probe
  - `vulnerabilities.py` - Suche, Lookup, Refresh, AI-Analyse
  - `cwe.py` - CWE-Abfragen (einzeln & bulk)
  - `capec.py` - CAPEC-Abfragen, CWE→CAPEC Mapping
  - `cpe.py` - CPE-Katalog (Entries, Vendors, Products)
  - `assets.py` - Asset-Katalog (Vendoren, Produkte, Versionen)
  - `stats.py` - Statistik-Aggregationen
  - `backup.py` - Streaming Export/Import
  - `sync.py` - Manuelle Sync-Trigger fuer alle 7 Datenquellen
  - `saved_searches.py` - Gespeicherte Suchen (CRUD)
  - `audit.py` - Ingestion-Logs
  - `changelog.py` - Letzte Aenderungen
- Standardpraefix `/api/v1` (konfigurierbar) und CORS-Allower fuer lokale Integration.
- Responses basieren auf Pydantic-Schemas; Validierung erfolgt auf Eingabe- und Ausgabeseite.
- Schema-Konvention: Snake-Case in Python, camelCase auf dem Wire (`Field(alias="fieldName", serialization_alias="fieldName")`).

### Services & Domain
- Service-Klasse je Anwendungsfall:
  - `VulnerabilityService` - Suche, Refresh, Lookup
  - `CWEService` - 3-Tier-Cache (Memory → MongoDB → MITRE API)
  - `CAPECService` - 3-Tier-Cache + CWE→CAPEC Mapping
  - `CPEService` - CPE-Katalog
  - `AIService` - OpenAI, Anthropic, Gemini Wrapper
  - `StatsService` - OpenSearch-Aggregationen (Mongo-Fallback)
  - `BackupService` - Streaming Export/Import
  - `SyncService` - Sync-Koordination
  - `AuditService` - Audit-Logging
  - `ChangelogService` - Change-Tracking
  - `SavedSearchService` - Gespeicherte Suchen
  - `AssetCatalogService` - Asset-Katalog aus ingestierten Daten
- Services kapseln Datenbankzugriff (Repositories) und koordinieren OpenSearch + Mongo Operations.
- Asset-Katalog wird aus ingestierten Daten abgeleitet (Vendor-/Produkt-/Versions-Slugs) und fuettert Filter-UI.

### Ingestion Pipelines

| Pipeline | Quelle | Intervall (Default) | Beschreibung |
|----------|--------|---------------------|-------------|
| EUVD | ENISA REST-API | 60 min | Schwachstellen mit Change-History, inkrementell + woechentlicher Full-Sync (So 2 Uhr) |
| NVD | NIST REST-API | 10 min | CVSS, EPSS, CPE-Konfigurationen, optionaler API-Key, Full-Sync (Mi 2 Uhr) |
| KEV | CISA JSON-Feed | 60 min | Exploitation-Status |
| CPE | NVD CPE 2.0 API | 1440 min (taeglich) | Produkt-/Versions-Katalog |
| CWE | MITRE REST-API | 7 Tage | Schwaeche-Definitionen |
| CAPEC | MITRE XML-Download | 7 Tage | Angriffsmuster |
| CIRCL | CIRCL REST-API | 120 min | Zusaetzliche Anreicherung |

- Alle Pipelines unterstuetzen inkrementelle und initiale Syncs.
- **EUVD Pipeline:** Liest paginiert, gleicht CVE-IDs ab, reichert mit NVD- und KEV-Daten an, pflegt Change-Historie, aktualisiert OpenSearch-Index + Mongo-Dokumente.
- **NVD Pipeline:** Aktualisiert CVSS/EPSS/Referenzen fuer bestehende Datensaetze, optional begrenzt ueber `modifiedSince`.
- **CPE Pipeline:** Synchronisiert NVD-CPE-Katalog, erzeugt Vendor-/Produkt-/Versionseintraege und legt Slug-Metadaten in Mongo ab.
- **KEV Pipeline:** Haelt CISA Known-Exploited-Catalog aktuell und stellt Exploitation-Metadaten fuer EUVD/NVD bereit.
- **CWE Pipeline:** Synchronisiert MITRE CWE-Katalog ueber REST-API mit 7-Tage TTL-Cache.
- **CAPEC Pipeline:** Parst MITRE CAPEC XML, erstellt Angriffsmuster-Eintraege mit CWE-Zuordnung.
- **CIRCL Pipeline:** Liest zusaetzliche Schwachstelleninformationen von CIRCL und reichert bestehende Datensaetze an.
- **Manual Refresher:** Ermoeglicht gezielte Reingestion einzelner IDs (API + CLI) und protokolliert Ergebnisse.

### Data Relationships
- CVE → CWE: Aus NVD `weaknesses`-Array, gespeichert auf `VulnerabilityDocument`.
- CWE → CAPEC: Bidirektionales Mapping aus CWE-Rohdaten + CAPEC-XML.
- CAPEC-IDs werden NICHT auf `VulnerabilityDocument` gespeichert; Aufloesung erfolgt zur Anzeigezeit.

### Scheduler & Job Tracking
- `SchedulerManager` initialisiert APScheduler (AsyncIO) mit Intervallen fuer alle 7 Datenquellen.
- Initial-Bootstrap laeuft beim Start einmalig und wird in `IngestionStateRepository` (Mongo) als abgeschlossen markiert.
- `JobTracker` aktualisiert Laufzeitstatus, setzt Overdue-Flags und persistiert Fortschritt im Audit-Log.
- Startup-Cleanup markiert Zombie-Jobs (Running-Status bei Neustart) als abgebrochen.
- Audit-Service schreibt Ereignisse in `ingestion_logs` inklusive Dauer, Ergebnis und Metadaten (Client-IP, Label).
- Konfigurierbare `INGESTION_RUNNING_TIMEOUT_MINUTES` markiert Jobs als overdue, ohne sie abzubrechen.

### Persistence

#### MongoDB (11 Collections)

| Collection | Beschreibung |
|-----------|-------------|
| `vulnerabilities` | Schwachstellen mit CVSS, EPSS, CWEs, CPEs, Quell-Rohdaten |
| `cwe_catalog` | CWE-Schwaechen (7-Tage TTL-Cache) |
| `capec_catalog` | CAPEC-Angriffsmuster (7-Tage TTL-Cache) |
| `known_exploited_vulnerabilities` | CISA KEV-Eintraege |
| `cpe_catalog` | CPE-Eintraege (Vendor, Product, Version) |
| `asset_vendors` | Vendoren mit Slug und Produkt-Anzahl |
| `asset_products` | Produkte mit Vendor-Zuordnung |
| `asset_versions` | Versionen mit Produkt-Zuordnung |
| `ingestion_state` | Sync-Job-Status (Running/Completed/Failed) |
| `ingestion_logs` | Detaillierte Job-Logs mit Metadaten |
| `saved_searches` | Gespeicherte Suchanfragen |

- Repositories auf Basis von Motor (async) kapseln Abfragen und Updates.
- Repository-Pattern: `create()` Classmethod erstellt Indexes, `_id` = Entity-ID, `upsert()` gibt `"inserted"` / `"updated"` / `"unchanged"` zurueck.
- TTL-Indizes (z. B. `expires_at`) sichern optionales Aufraeumen von Zustandsdokumenten.

#### OpenSearch
- Index `hecate-vulnerabilities` mit normalisierten Dokumenten (IDs als CVE oder EUVD-ID).
- Text-Felder fuer Volltext-Suche, `.keyword`-Felder fuer Aggregationen, nested `sources`-Pfad.
- DQL (Domain-Specific Query Language) fuer erweiterte Suchanfragen.
- Konfiguration: `max_result_window` = 200.000, `total_fields.limit` = 2.000.

### AI & Analysis
- `AIClient` verwaltet verfuegbare Provider anhand gesetzter API-Schluessel (OpenAI, Anthropic, Google Gemini).
- Prompt-Builder erstellt Kontexte inkl. Asset- und Historieninformationen in frei waehlbarer Sprache.
- Einzel- und Batch-Analyse ueber API-Endpunkte.
- Ergebnisse werden in OpenSearch gespeichert und als Audit-Event protokolliert.
- Fehlerbehandlung liefert 4xx bei Konfigurationsfehlern, 5xx bei Provider-Ausfaellen.

### Backup & Restore
- Backup-Service exportiert JSON-Snapshots fuer Schwachstellen (quellenweise: EUVD/NVD/Alle), CPE-Katalog und gespeicherte Suchen.
- Streaming Export/Import mit Metadaten (Dataset, Source, Item-Count, Timestamp).
- Restore validiert Metadaten, schreibt Dokumente in Mongo + OpenSearch und gibt eine Zusammenfassung zurueck (inserted/updated/skipped).
- Frontend-Systemseite nutzt diese Endpunkte fuer Self-Service-Backups.

### Observability
- `structlog` fuer strukturierte Logs, konsistent in Pipelines und Services verwendet.
- Audit-Log dient als Betriebsfuehrer (Status, Fehlergruende, Dauer, Overdue-Hinweise).
- Konfigurierbare `INGESTION_RUNNING_TIMEOUT_MINUTES` markiert Jobs als overdue, ohne sie abzubrechen.

### CLI
```
poetry run python -m app.cli ingest [--since ISO] [--limit N] [--initial]
poetry run python -m app.cli sync-euvd [--since ISO] [--initial]
poetry run python -m app.cli sync-cpe [--limit N] [--initial]
poetry run python -m app.cli sync-nvd [--since ISO | --initial]
poetry run python -m app.cli sync-kev [--initial]
```

## Frontend Architecture

### Technology Stack
- React 19, TypeScript 5.9, Vite 7, React Router 7
- Axios (HTTP-Client, 60s Timeout), react-markdown (AI-Zusammenfassungen), react-select (Async Multi-Select), react-icons (Lucide)

### Seiten & Routing

| Route | Komponente | Beschreibung |
|-------|-----------|-------------|
| `/` | `DashboardPage` | Startseite mit Schwachstellensuche und aktuellen Eintraegen |
| `/vulnerabilities` | `VulnerabilityListPage` | Paginierte Liste mit Freitext-, Vendor-, Produkt- und Version-Filtern |
| `/vulnerability/:vulnId` | `VulnerabilityDetailPage` | Detailansicht mit AI-Assessments, Referenzen, Change-History |
| `/query-builder` | `QueryBuilderPage` | Interaktiver DQL-Editor mit Field-Browser und Aggregationen |
| `/ai-analyse` | `AIAnalysePage` | Einzel- und Batch-KI-Analyse (bedingt, via `VITE_AI_FEATURES_ENABLED`) |
| `/stats` | `StatsPage` | Trenddiagramme, Top-Vendoren/-Produkte, Severity-Verteilung |
| `/audit` | `AuditLogPage` | Ingestion-Job-Protokolle mit Status und Metadaten |
| `/changelog` | `ChangelogPage` | Letzte Aenderungen an Schwachstellen (erstellt/aktualisiert) |
| `/system` | `SystemPage` | Backup/Restore, Sync-Verwaltung, gespeicherte Suchen |

### State-Management
- Kein Redux/Zustand - basiert auf Reacts eingebauten Mechanismen:
  - **Context API:** `SavedSearchesContext` fuer globale gespeicherte Suchen
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
- Sprache: Deutsch (hardcoded, kein i18n-Framework).
- Datumsformat: `DD.MM.YYYY HH:mm` (de-DE Locale).
- Zeitzone: Konfigurierbar via `VITE_TIMEZONE` (Default: `Europe/Vienna`).

### Code-Splitting
- Manuelle Chunk-Aufteilung in `vite/chunk-split.ts`:
  - `react-select`, `react-icons`, `axios` jeweils als eigener Chunk
  - Restliche `node_modules` als `vendor` Chunk

## Design Patterns

### Repository-Pattern
- `create()` Classmethod erstellt Indexes.
- `_id` = Entity-ID in MongoDB.
- `upsert()` gibt `"inserted"`, `"updated"` oder `"unchanged"` zurueck.

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
Alle Quellen werden ueber `normalizer.py` in ein einheitliches `VulnerabilityDocument`-Schema ueberfuehrt. CVSS-Metriken normalisiert ueber v2.0, v3.0, v3.1 und v4.0.

## Data Flow Summary
1. Scheduler oder CLI loest einen Ingestion-Job aus.
2. Pipeline zieht Daten von EUVD/NVD/CISA/CPE/CWE/CAPEC/CIRCL, normalisiert sie (`build_document`), aktualisiert Mongo und OpenSearch.
3. AssetCatalogService leitet Vendor-/Produkt-/Versionsdaten ab und aktualisiert Slugs fuer Filter.
4. Frontend ruft Listen- und Detailendpunkte ab, optional startet AI-Assessments oder Backups.
5. Audit-Service protokolliert alle relevanten Aktionen, Stats-Service aggregiert Kennzahlen aus OpenSearch (Fallback Mongo).

## External Integrations

| Integration | Typ | Beschreibung |
|------------|-----|-------------|
| EUVD (ENISA) | REST-API | Primaere Schwachstellendatenquelle |
| NVD (NIST) | REST-API | CVE-Detail- und CPE-Katalog-Synchronisation |
| CISA KEV | JSON-Feed | Exploitation-Metadaten |
| CPE (NVD) | REST-API | CPE 2.0 Produkt-Katalog |
| CWE (MITRE) | REST-API | Schwaeche-Definitionen (`cwe-api.mitre.org`) |
| CAPEC (MITRE) | XML-Download | Angriffsmuster (`capec.mitre.org`) |
| CIRCL | REST-API | Zusaetzliche Schwachstelleninformationen (`vulnerability.circl.lu`) |
| OpenAI | API | Optionaler KI-Provider fuer Zusammenfassungen und Risikohinweise |
| Anthropic | API | Optionaler KI-Provider fuer Zusammenfassungen und Risikohinweise |
| Google Gemini | API | Optionaler KI-Provider fuer Zusammenfassungen und Risikohinweise |

## Deployment Topology
```
                    +-----------+
                    |  Frontend |  React 19 / Vite / TypeScript
                    |  :4173    |  Dark-Theme SPA
                    +-----+-----+
                          | /api
                    +-----v-----+
                    |  Backend  |  FastAPI / Python 3.13 / Poetry
                    |  :8000    |  REST-API, Scheduler, Pipelines
                    +--+-----+--+
                       |     |
              +--------+     +--------+
              |                       |
        +-----v-----+         +------v------+
        |  MongoDB   |         | OpenSearch  |
        |  :27017    |         |  :9200      |
        +------------+         +-------------+
         Persistenz             Volltext-Index
```

- Docker Compose Orchestrierung: backend, frontend, mongo, opensearch + externes `dmz00` Netzwerk.
- Container Registry: `git.nohub.lol/rk/hecate-{backend,frontend}:latest`.
- CI/CD: Gitea Actions (`build.yml` Docker Build + Grype-Scan, `scan.yml` SonarQube + Trivy).

## Technology Stack

| Komponente | Technologie |
|-----------|------------|
| Backend | Python 3.13, FastAPI 0.128, Uvicorn, Poetry |
| Frontend | React 19, TypeScript 5.9, Vite 7, React Router 7 |
| Datenbank | MongoDB 8 (Motor async), OpenSearch 2/3 |
| Scheduling | APScheduler 3.11 |
| HTTP-Client | httpx 0.28 (async), Axios 1.13 (Frontend) |
| Logging | structlog 25.5 |
| KI | OpenAI, Anthropic, Google Gemini |
| CI/CD | Gitea Actions, Grype, Trivy, SonarQube |
