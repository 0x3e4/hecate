# Hecate

Schwachstellen-Management-Plattform zur automatisierten Aggregation, Anreicherung und Analyse von Sicherheitslücken. Die Anwendung sammelt Daten aus 9 externen Quellen (EUVD, NVD, CISA KEV, CPE, CWE, CAPEC, CIRCL, GHSA, OSV), normalisiert sie in ein einheitliches Schema und stellt sie über eine REST-API sowie ein React-Frontend bereit. Zusätzlich können Container-Images und Source-Repositories aktiv auf Schwachstellen gescannt werden (SCA).

## Architektur

```
                    +-----------+
                    |  Frontend |  React 19 / Vite / TypeScript
                    |  :4173    |  Dark-Theme SPA
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
                       |  |     |  :8080    |  Dockle, Dive, Semgrep, TruffleHog
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

## Projektstruktur

```
.
├── backend/              # FastAPI-Service, Ingestion-Pipelines, Scheduler, CLI
│   ├── app/
│   │   ├── api/v1/       # REST-Endpunkte (16 Router-Module)
│   │   ├── core/         # Konfiguration (Pydantic Settings), Logging
│   │   ├── db/           # MongoDB (Motor) & OpenSearch Verbindungen
│   │   ├── models/       # MongoDB-Dokument-Schemata
│   │   ├── repositories/ # Datenzugriffsschicht (Repository-Pattern)
│   │   ├── schemas/      # API Request/Response Schemata
│   │   ├── services/     # Business-Logik, AI, Backup, Stats
│   │   │   ├── ingestion/    # Datenpipelines & Clients (9 Quellen)
│   │   │   ├── scheduling/   # APScheduler Job-Verwaltung
│   │   │   └── http/         # HTTP Rate-Limiting
│   │   └── utils/        # String- und Request-Hilfsfunktionen
│   ├── pyproject.toml    # Python-Abhängigkeiten (Poetry)
│   └── Dockerfile        # Multi-Stage Build (python:3.13-slim)
├── frontend/             # React SPA
│   ├── src/
│   │   ├── api/          # Axios-basierte Service-Module
│   │   ├── components/   # Wiederverwendbare UI-Komponenten
│   │   ├── views/        # Seitenkomponenten (14 Ansichten)
│   │   ├── hooks/        # Custom React Hooks
│   │   ├── ui/           # Layout-Komponenten (Sidebar, Header)
│   │   ├── utils/        # CVSS-Parsing, Datumsformatierung
│   │   ├── constants/    # DQL-Feld-Definitionen
│   │   ├── router.tsx    # React Router v7 Konfiguration
│   │   ├── types.ts      # TypeScript-Interfaces
│   │   └── styles.css    # Globales Dark-Theme CSS
│   ├── package.json      # Node-Abhängigkeiten (pnpm)
│   └── Dockerfile        # Multi-Stage Build (node:24-alpine)
├── scanner/              # Scanner-Sidecar (Trivy, Grype, Syft, OSV, Hecate, Dockle, Dive, Semgrep, TruffleHog)
│   ├── app/
│   │   ├── main.py           # FastAPI-App (POST /scan, GET /health)
│   │   ├── models.py         # Request/Response-Schemata
│   │   └── scanners.py       # Subprocess-Wrapper für Scanner-Tools
│   ├── pyproject.toml    # Python-Abhängigkeiten (Poetry)
│   └── Dockerfile        # Multi-Stage Build mit Scanner-Binaries
├── docs/                 # Architektur- und Konzeptdokumente
├── .gitea/workflows/     # CI/CD (ci.yml: Build, Hecate Scan, SonarQube)
├── actions/              # Reusable Composite Actions (hecate-scan)
├── .env.example          # Umgebungsvariablen-Vorlage
└── docker-compose.yml.example
```

## Kernfunktionen

### Datenaggregation & Automatisierung
- **9 Datenquellen:** EUVD, NVD, CISA KEV, CPE, CWE (MITRE API), CAPEC (MITRE XML), CIRCL, GHSA (GitHub Advisory), OSV (OSV.dev — GCS Bucket + REST-API, 11 Ökosysteme)
- **APScheduler** steuert periodische Syncs mit konfigurierbaren Intervallen und Bootstrap-on-Startup
- **Normalisierung:** Alle Quellen werden in ein einheitliches `VulnerabilityDocument`-Schema überführt
- **Asset-Katalog:** Vendoren, Produkte und Versionen werden aus ingestierten Daten extrahiert
- **Change-Tracking:** Änderungshistorien für Schwachstellen, vollständiger Audit-Trail
- **Server-Sent Events (SSE):** Echtzeit-Streaming von Job-Status und neuen Schwachstellen an das Frontend

### SCA-Scanning (Software Composition Analysis)
- **Scanner-Sidecar:** 9 Scanner als Docker-Container — Trivy, Grype, Syft, OSV Scanner, Hecate Analyzer, Dockle (CIS Docker Benchmarks), Dive (Image-Schichtanalyse), Semgrep (SAST), TruffleHog (Secret Detection)
- **CI/CD-Integration:** Container-Images und Source-Repos über API scannen (`POST /api/v1/scans`)
- **Manueller Scan:** Scans direkt aus dem Frontend starten (Scanner-Auswahl je Scan-Typ)
- **Auto-Scan:** Optionales automatisches Scannen registrierter Ziele mit den beim Erst-Scan gewählten Scannern (konfigurierbares Intervall via `SCA_AUTO_SCAN_INTERVAL_MINUTES`, Change-Detection über Image-Digest/Commit-SHA mit Staleness-Fallback)
- **Target-Gruppierung:** Mehrere Scan-Targets (z.B. Backend-, Frontend- und Worker-Repo desselben Produkts) lassen sich zu einer Anwendung gruppieren. Targets-Tab im Frontend rendert kollabierbare Application-Sektionen mit aggregiertem Severity-Roll-up; Inline-Editor pro Target-Card mit Vorschlägen aus existierenden Gruppen.
- **SBOM-Generierung:** CycloneDX-Format via Syft
- **SBOM-Export:** CycloneDX 1.5 JSON und SPDX 2.3 JSON Export für EU Cyber Resilience Act (CRA) Compliance
- **SBOM-Import:** Externes CycloneDX- und SPDX-SBOM-Upload (JSON oder Datei-Upload) mit automatischem Format-Erkennung und Schwachstellen-Matching gegen die Vulnerability-DB
- **VEX (Vulnerability Exploitability Exchange):** VEX-Status-Annotationen auf Findings (not_affected, affected, fixed, under_investigation) mit Justification und Detail. Expandierbarer Inline-Editor, Multi-Select-Bulk-Updates aus dem Findings-Tab, CycloneDX VEX Export/Import. Automatischer VEX Carry-Forward zwischen Scans.
- **Findings-Dismissal:** Verwerfen irrelevanter Findings als persönlicher Anzeigefilter (separat von VEX); standardmäßig ausgeblendet, "Show dismissed"-Toggle blendet sie wieder ein. Carry-Forward zwischen Scans wie bei VEX.
- **License Compliance:** Lizenz-Policy-Management mit konfigurierbaren Regeln (erlaubt, verboten, Review-erforderlich), automatische Auswertung nach jedem Scan, License-Compliance-Übersicht über alle Scans
- **Malware-Erkennung:** Hecate Analyzer mit 35 Heuristik-Regeln für Supply-Chain-Angriffe (inkl. Steganografie, plattformspezifische Payloads, SHA-256 Hash-Matching)
- **Provenance-Verifikation:** Automatische Prüfung der Paketherkunft über Registry-APIs (npm, PyPI, Go, Maven, RubyGems, Cargo, NuGet, Docker)
- **Best Practices:** Dockle prüft CIS Docker Benchmarks (nur Container-Images, opt-in)
- **Layer-Analyse:** Dive analysiert Image-Schichten auf Effizienz und Verschwendung (nur Container-Images, opt-in)
- **Deduplizierung:** Automatische Zusammenführung von Ergebnissen mehrerer Scanner
- **Audit-Trail:** Scan-Ereignisse im Ingestion-Log protokolliert

### Suche & Analyse
- **OpenSearch-Volltext** mit DQL-Unterstützung (Domain-Specific Query Language) und Relevanzsortierung; `source:`-Abfragen suchen automatisch über alle Datenquellen (inkl. `sourceNames`-Alias)
- **KI-Assessments** über OpenAI, Anthropic oder Google Gemini (einzeln oder Batch)
- **CVSS-Metriken** normalisiert über v2.0, v3.0, v3.1 und v4.0
- **CWE/CAPEC-Anreicherung** mit 3-Tier-Cache (Memory -> MongoDB -> externe Quelle, 7 Tage TTL)
- **EPSS-Scores** und KEV-Exploitation-Status

### Frontend-Ansichten
| Ansicht | Beschreibung |
|---------|-------------|
| Dashboard | Schwachstellensuche mit CVSS, EPSS, Exploitation-Status, Echtzeit-Refresh via SSE |
| Schwachstellen-Liste | Paginierte Liste mit Freitext-, Vendor-, Produkt-, Version- und erweiterten Filtern (Severity, CVSS-Vektor, EPSS, CWE, Quellen, Zeitraum) |
| Detail-Seite | Vollständige Schwachstellendetails mit AI-Assessments, Referenzen, Change-History |
| Query Builder | Interaktiver DQL-Editor mit Field-Browser und Aggregationen |
| KI-Analyse | Einzel- und Batch-Analyse über verschiedene AI-Provider |
| Statistiken | Trenddiagramme, Top-Vendoren/-Produkte, Severity-Verteilung |
| Audit Log | Ingestion-Job-Protokolle mit Status, Dauer und Metadaten |
| Changelog | Letzte Änderungen an Schwachstellen mit Pagination, Datum- und Job-Filter |
| SCA-Scans | Scan-Ziele, letzte Scans, aggregierte Findings & SBOM (Summary-Cards, Spalten-Sortierung, Provenance-Filter), manueller Scan, SBOM-Import, Lizenzen, Scanner-Monitoring |
| Scan-Detail | Findings (Multi-Select-Bulk-VEX, expandierbarer VEX-Editor, Show-Dismissed-Toggle, VEX-Import), SBOM (sortierbar, klickbare Filter, Provenance-Filter), History (Zeitbereichs-Filter, Commit-SHA-Links), Compare (bis zu 200 Scans), Security Alerts, SAST (Semgrep), Secrets (TruffleHog), Best Practices (Dockle), Layer Analysis (Dive), License Compliance, VEX-Export |
| System | Single-Card-Layout. 4 Tabs: General (Sprache, Dienste, Backup), Notifications (Kanäle, Regeln, Vorlagen), Data (Sync, Re-Sync mit Multi-ID/Wildcards/Delete-Only, Suchen), Policies (Lizenzrichtlinien) |
| CI/CD | Anleitung zur CI/CD-Integration mit Pipeline-Beispielen (GitHub Actions, GitLab CI, Shell) |
| API | Interaktive API-Dokumentation mit eingebetteter Swagger-UI und Endpunkt-Übersicht |

### Benachrichtigungen (Apprise)
- **Apprise-Integration:** Benachrichtigungen über einen Apprise-API-Service (Slack, Discord, E-Mail, Telegram, etc.)
- **Docker-Sidecar:** Lokaler Apprise-Container in `docker-compose.yml.example` enthalten
- **Externer Service:** Alternativ kann ein externer Apprise-Service via `NOTIFICATIONS_APPRISE_URL` genutzt werden
- **Ereignisse:** SCA-Scan abgeschlossen/fehlgeschlagen, Sync-Fehler, neue Schwachstellen nach Ingestion
- **Regelbasiert:** Konfigurierbare Regeln pro Ereignistyp mit individuellem Channel-Routing (Apprise-Tags)
- **Watch-Regeln:** Automatische Auswertung von Saved Searches, Vendor-/Produkt-Watches und DQL-Queries nach Ingestion
- **Scan-Regeln:** Bedingte Benachrichtigungen für SCA-Scans mit Severity-Schwellenwert (z.B. nur bei Critical/High) und Ziel-Filter (Wildcard-Pattern)
- **Nachrichtenvorlagen:** Anpassbare Titel- und Body-Templates pro Event-Typ mit Platzhaltern (`{variable}`) und Schleifen (`{#each}...{/each}`)
- **Test-Endpoint:** `POST /api/v1/notifications/test` mit optionalem Tag-Filter und Button in der System-Seite
- **Fire-and-forget:** Benachrichtigungsfehler unterbrechen nie primäre Workflows

### Betrieb
- **Backup & Restore** für Schwachstellen (EUVD/NVD/Alle) und gespeicherte Suchen
- **Gespeicherte Suchen** mit Sidebar-Integration und Audit-Trail
- **Statistiken** mit OpenSearch-Aggregationen (Mongo-Fallback bei Ausfällen)
- **Manuelle Sync-Trigger** für alle 9 Datenquellen über die API

## Schnellstart (Docker Compose)

### Voraussetzungen
- Docker + Docker Compose

### Setup

```sh
# 1. Konfiguration anlegen
cp .env.example .env
cp docker-compose.yml.example docker-compose.yml

# 2. .env anpassen (Mongo-Passwort, OpenSearch-Passwort, API-Schlüssel etc.)
nano .env

# 3. Stack starten
docker compose up --build
```

### Standard-Endpoints

| Service | URL |
|---------|-----|
| Frontend | http://localhost:4173 |
| Backend API | http://localhost:8000/api/v1 |
| Health Check | http://localhost:8000/api/v1/status/health |
| MongoDB | mongodb://localhost:27017 |
| OpenSearch | https://localhost:9200 |
| Scanner Sidecar | http://localhost:8080 |
| Apprise (Notifications) | http://localhost:8000 (intern) |

## Lokale Entwicklung

```sh
# Backend
cd backend && poetry install
uvicorn app.main:app --reload

# Frontend (in einem separaten Terminal)
cd frontend && corepack enable pnpm && pnpm install
pnpm run dev   # Dev-Server auf Port 3000, proxied /api -> Backend
```

Vite proxied `/api`-Anfragen im Dev-Modus automatisch an `http://backend:8000` (Docker) bzw. `http://localhost:8000` (lokal).

Die UI-Sprache ist Deutsch oder Englisch (automatische Browser-Erkennung, umschaltbar, kein externes i18n-Framework).

## API-Überblick

### Status
- `GET /api/v1/status/health` — Liveness Probe
- `GET /api/v1/status/scanner-health` — Scanner-Sidecar Erreichbarkeit

### Schwachstellen
- `POST /api/v1/vulnerabilities/search` — Volltextsuche mit DQL, Filtern, Pagination
- `GET /api/v1/vulnerabilities/{id}` — Einzelne Schwachstelle abrufen
- `POST /api/v1/vulnerabilities/lookup` — Lookup mit Auto-Sync
- `POST /api/v1/vulnerabilities/refresh` — Manueller Refresh einzelner IDs

### KI-Analyse (asynchron)
- `POST /api/v1/vulnerabilities/{id}/ai-investigation` — Einzelanalyse (HTTP 202, Ergebnis via SSE)
- `POST /api/v1/vulnerabilities/ai-investigation/batch` — Batch-Analyse (HTTP 202, Ergebnis via SSE)
- `GET /api/v1/vulnerabilities/ai-investigation/batch/{id}` — Batch-Ergebnis abrufen

### Kataloge
- `GET /api/v1/cwe/{id}` & `POST /api/v1/cwe/bulk` — CWE-Daten
- `GET /api/v1/capec/{id}` & `POST /api/v1/capec/from-cwes` — CAPEC-Daten
- `GET /api/v1/cpe/entries|vendors|products` — CPE-Katalog
- `GET /api/v1/assets/vendors|products|versions` — Asset-Katalog

### SCA-Scans
- `POST /api/v1/scans` — Scan einreichen (CI/CD, API-Key erforderlich)
- `POST /api/v1/scans/manual` — Manueller Scan aus dem Frontend
- `GET /api/v1/scans/targets` — Scan-Ziele auflisten
- `GET /api/v1/scans` — Scans auflisten
- `GET /api/v1/scans/{scanId}` — Scan-Details
- `GET /api/v1/scans/{scanId}/findings` — Findings eines Scans
- `GET /api/v1/scans/{scanId}/sbom` — SBOM-Komponenten eines Scans
- `GET /api/v1/scans/{scanId}/sbom/export` — SBOM-Export (CycloneDX 1.5 oder SPDX 2.3 JSON)
- `GET /api/v1/scans/{scanId}/findings/export` — Findings-Export (SonarQube External Issues)
- `GET /api/v1/scans/{scanId}/layers` — Layer-Analyse eines Scans (Dive)
- `POST /api/v1/scans/import-sbom` — Externes SBOM importieren (JSON)
- `POST /api/v1/scans/import-sbom/upload` — Externes SBOM importieren (Datei-Upload)
- `GET /api/v1/scans/{scanId}/license-compliance` — License-Compliance-Auswertung eines Scans
- `GET /api/v1/scans/license-overview` — License-Compliance-Übersicht über alle Scans

### VEX (Vulnerability Exploitability Exchange) & Findings-Dismissal
- `PUT /api/v1/scans/vex/findings/{findingId}` — VEX-Status eines Findings setzen (Status, Justification, Detail)
- `POST /api/v1/scans/vex/bulk-update` — VEX-Status für alle Findings einer Vulnerability+Target setzen
- `POST /api/v1/scans/vex/bulk-update-by-ids` — VEX-Status auf eine Liste von Finding-IDs anwenden (Multi-Select)
- `POST /api/v1/scans/findings/dismiss` — Findings als verworfen/wiederhergestellt markieren
- `POST /api/v1/scans/vex/import` — VEX-Dokument importieren (CycloneDX VEX)
- `GET /api/v1/scans/{scanId}/vex/export` — VEX-Dokument exportieren (CycloneDX VEX)
- `GET /api/v1/scans/{scanId}/findings?includeDismissed=true` — Verworfene Findings einbeziehen

### License Policies
- `GET /api/v1/license-policies` — Lizenz-Policies auflisten
- `POST /api/v1/license-policies` — Neue Policy erstellen
- `GET /api/v1/license-policies/{id}` — Policy abrufen
- `PUT /api/v1/license-policies/{id}` — Policy aktualisieren
- `DELETE /api/v1/license-policies/{id}` — Policy löschen
- `POST /api/v1/license-policies/{id}/set-default` — Policy als Standard setzen
- `GET /api/v1/license-policies/groups` — Lizenzgruppen abrufen

### Benachrichtigungen
- `GET /api/v1/notifications/status` — Benachrichtigungs-Status (Apprise erreichbar?)
- `POST /api/v1/notifications/test` — Testbenachrichtigung senden (optionaler `tag`-Parameter)
- `GET/POST /api/v1/notifications/channels` — Channels auflisten/hinzufügen
- `DELETE /api/v1/notifications/channels/{id}` — Channel entfernen
- `GET/POST /api/v1/notifications/rules` — Benachrichtigungsregeln auflisten/erstellen
- `GET/PUT/DELETE /api/v1/notifications/rules/{id}` — Regel abrufen/aktualisieren/löschen
- `GET/POST /api/v1/notifications/templates` — Nachrichtenvorlagen auflisten/erstellen
- `PUT/DELETE /api/v1/notifications/templates/{id}` — Vorlage aktualisieren/löschen

### MCP Server (Model Context Protocol)
- `POST /mcp` — MCP-Protokoll-Endpoint (Streamable HTTP, erfordert `MCP_ENABLED=true` + `MCP_API_KEY`)
- `GET /.well-known/oauth-authorization-server` — OAuth 2.0 Discovery
- `POST /mcp/oauth/register` — Dynamische Client-Registrierung (RFC 7591)
- `GET/POST /mcp/oauth/authorize` — OAuth-Autorisierung
- `POST /mcp/oauth/token` — Token-Austausch mit PKCE (S256)
- 11 Tools: `search_vulnerabilities`, `get_vulnerability`, `search_cpe`, `search_vendors`, `search_products`, `get_vulnerability_stats`, `get_cwe`, `get_capec`, `get_scan_findings`, `trigger_scan`, `trigger_sync`

### Echtzeit-Events (SSE)
- `GET /api/v1/events` — Server-Sent Events Stream (Job-Status, neue Schwachstellen, AI-Analyse-Ergebnisse)

### Verwaltung
- `GET/POST/DELETE /api/v1/saved-searches` — Gespeicherte Suchen
- `GET /api/v1/stats/overview` — Statistik-Aggregationen
- `GET /api/v1/audit/ingestion` — Audit-Log
- `GET /api/v1/changelog` — Letzte Änderungen (mit Pagination, Datum- und Source-Filter)
- `POST /api/v1/sync/trigger/{job}` — Sync-Trigger (euvd, nvd, cpe, kev, cwe, capec, circl, ghsa, osv)
- `POST /api/v1/sync/resync` — Vulnerabilities löschen und optional neu von Upstream abrufen (Multi-ID, Wildcards, Delete-Only)
- `GET/POST /api/v1/backup/...` — Export/Import

## Backend-CLI

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

## Konfiguration

Alle Parameter werden über Umgebungsvariablen gesteuert (siehe `.env.example`):

| Kategorie | Wichtige Variablen |
|-----------|-------------------|
| **Allgemein** | `ENVIRONMENT`, `API_PREFIX`, `LOG_LEVEL`, `TZ` |
| **MongoDB** | `MONGO_URL`, `MONGO_USERNAME`, `MONGO_PASSWORD`, `MONGO_DB` |
| **OpenSearch** | `OPENSEARCH_URL`, `OPENSEARCH_USERNAME`, `OPENSEARCH_PASSWORD`, `OPENSEARCH_VERIFY_CERTS`, `OPENSEARCH_CA_CERT` |
| **KI-Provider** | `OPENAI_API_KEY`, `OPENAI_MODEL`, `OPENAI_REASONING_EFFORT`, `OPENAI_MAX_OUTPUT_TOKENS`, `ANTHROPIC_API_KEY`, `GOOGLE_GEMINI_API_KEY` |
| **Datenquellen** | `EUVD_BASE_URL`, `NVD_BASE_URL`, `NVD_API_KEY`, `KEV_FEED_URL`, `GHSA_TOKEN`, `OSV_BASE_URL`, `OSV_TIMEOUT_SECONDS`, `OSV_RATE_LIMIT_SECONDS`, `OSV_MAX_RECORDS_PER_RUN` |
| **Scheduler** | `SCHEDULER_ENABLED`, `SCHEDULER_*_INTERVAL_*` |
| **Frontend** | `VITE_TIMEZONE`, `VITE_AI_FEATURES_ENABLED`, `VITE_API_BASE_URL` |
| **SCA-Scanner** | `SCA_ENABLED`, `SCA_API_KEY`, `SCA_SCANNER_URL`, `SCA_AUTO_SCAN_INTERVAL_MINUTES`, `SCA_MAX_CONCURRENT_SCANS`, `SCA_MIN_FREE_MEMORY_MB`, `SCA_MIN_FREE_DISK_MB`, `SCANNER_AUTH`, `SEMGREP_RULES`, `VITE_SCA_FEATURES_ENABLED`, `VITE_SCA_AUTO_SCAN_ENABLED` |
| **Benachrichtigungen** | `NOTIFICATIONS_ENABLED`, `NOTIFICATIONS_APPRISE_URL`, `NOTIFICATIONS_APPRISE_TAGS`, `NOTIFICATIONS_APPRISE_TIMEOUT` |
| **MCP Server** | `MCP_ENABLED`, `MCP_API_KEY`, `MCP_WRITE_API_KEY`, `MCP_RATE_LIMIT_PER_MINUTE`, `MCP_MAX_RESULTS`, `MCP_MAX_CONCURRENT_CONNECTIONS` |

## CI/CD

Gitea-Workflow `.gitea/workflows/ci.yml` + Composite Action `actions/hecate-scan/`:
- **ci.yml:** SonarQube Code-Analyse, Docker-Image Build & Push, Hecate Security Scan (Images auf `main`, Source-Repos für PRs), SonarQube Findings-Upload
- **Hecate Scan Action:** Wiederverwendbare Composite Action für GitHub/Gitea Actions — Scan-Übermittlung, Polling, Quality Gates, SonarQube-Export

## Technologie-Stack

| Komponente | Technologie |
|-----------|------------|
| Backend | Python 3.13, FastAPI 0.128, Uvicorn, Poetry |
| Frontend | React 19, TypeScript 5.9, Vite 7, React Router 7 |
| Datenbank | MongoDB 8 (Motor async), OpenSearch 3 |
| Scheduling | APScheduler 3.11 |
| HTTP-Client | httpx 0.28 (async) |
| Logging | structlog 25 |
| KI | OpenAI, Anthropic, Google Gemini (jeweils optional) |
| Scanner-Sidecar | Trivy, Grype, Syft, OSV Scanner, Hecate Analyzer, Dockle, Dive, Semgrep, TruffleHog, Skopeo, FastAPI |
| Benachrichtigungen | Apprise (caronc/apprise) |
| MCP Server | mcp SDK, OAuth 2.0 (PKCE), Streamable HTTP |
| CI/CD | Gitea Actions, Hecate Scan Action, SonarQube |

## Weiterführende Dokumentation

- [Backend-Details](backend/README.md)
- [Frontend-Details](frontend/README.md)
- [Scanner-Sidecar](scanner/README.md)
- [Architektur-Übersicht](docs/architecture.md)
