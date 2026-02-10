# Hecate

KI-basierte Cyberabwehrplattform zur automatisierten Analyse von Schwachstellen. Die Anwendung aggregiert Daten aus EUVD, NVD, CISA KEV, CIRCL, CWE und CAPEC, reichert sie mit KI-Unterstuetzung an und macht sie ueber ein React-Frontend sowie eine REST-API nutzbar.

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

## Projektstruktur

```
.
├── backend/              # FastAPI-Service, Ingestion-Pipelines, Scheduler, CLI
│   ├── app/
│   │   ├── api/v1/       # REST-Endpunkte (11 Router-Module)
│   │   ├── core/         # Konfiguration (Pydantic Settings), Logging
│   │   ├── db/           # MongoDB (Motor) & OpenSearch Verbindungen
│   │   ├── models/       # MongoDB-Dokument-Schemata
│   │   ├── repositories/ # Datenzugriffsschicht (Repository-Pattern)
│   │   ├── schemas/      # API Request/Response Schemata
│   │   ├── services/     # Business-Logik, AI, Backup, Stats
│   │   │   ├── ingestion/    # Datenpipelines & Clients (EUVD, NVD, KEV, CPE, CWE, CAPEC, CIRCL)
│   │   │   ├── scheduling/   # APScheduler Job-Verwaltung
│   │   │   └── http/         # HTTP Rate-Limiting
│   │   └── utils/        # String- und Request-Hilfsfunktionen
│   ├── pyproject.toml    # Python-Abhaengigkeiten (Poetry)
│   └── Dockerfile        # Multi-Stage Build (python:3.13-slim)
├── frontend/             # React SPA
│   ├── src/
│   │   ├── api/          # Axios-basierte Service-Module
│   │   ├── components/   # Wiederverwendbare UI-Komponenten
│   │   ├── views/        # Seitenkomponenten (9 Ansichten)
│   │   ├── hooks/        # Custom React Hooks
│   │   ├── ui/           # Layout-Komponenten (Sidebar, Header)
│   │   ├── utils/        # CVSS-Parsing, Datumsformatierung
│   │   ├── router.tsx    # React Router v7 Konfiguration
│   │   ├── types.ts      # TypeScript-Interfaces
│   │   └── styles.css    # Globales Dark-Theme CSS
│   ├── package.json      # Node-Abhaengigkeiten (npm)
│   └── Dockerfile        # Multi-Stage Build (node:24-alpine)
├── docs/                 # Architektur- und Konzeptdokumente
├── .gitea/workflows/     # CI/CD (Build, Grype-Scan, SonarQube, Trivy)
├── .env.example          # Umgebungsvariablen-Vorlage
└── docker-compose.yml.example
```

## Kernfunktionen

### Datenaggregation & Automatisierung
- **7 Datenquellen:** EUVD, NVD, CISA KEV, CPE, CWE (MITRE API), CAPEC (MITRE XML), CIRCL
- **APScheduler** steuert periodische Syncs mit konfigurierbaren Intervallen und Bootstrap-on-Startup
- **Normalisierung:** Alle Quellen werden in ein einheitliches `VulnerabilityDocument`-Schema ueberfuehrt
- **Asset-Katalog:** Vendoren, Produkte und Versionen werden aus ingestierten Daten extrahiert
- **Change-Tracking:** Aenderungshistorien fuer Schwachstellen, vollstaendiger Audit-Trail

### Suche & Analyse
- **OpenSearch-Volltext** mit DQL-Unterstuetzung (Domain-Specific Query Language) und Relevanzsortierung
- **KI-Assessments** ueber OpenAI, Anthropic oder Google Gemini (einzeln oder Batch)
- **CVSS-Metriken** normalisiert ueber v2.0, v3.0, v3.1 und v4.0
- **CWE/CAPEC-Anreicherung** mit 3-Tier-Cache (Memory -> MongoDB -> externe Quelle, 7 Tage TTL)
- **EPSS-Scores** und KEV-Exploitation-Status

### Frontend-Ansichten
| Ansicht | Beschreibung |
|---------|-------------|
| Dashboard | Schwachstellensuche mit CVSS, EPSS, Exploitation-Status |
| Schwachstellen-Liste | Paginierte Liste mit Freitext-, Vendor-, Produkt- und Version-Filtern |
| Detail-Seite | Vollstaendige Schwachstellendetails mit AI-Assessments, Referenzen, Change-History |
| Query Builder | Interaktiver DQL-Editor mit Field-Browser und Aggregationen |
| KI-Analyse | Einzel- und Batch-Analyse ueber verschiedene AI-Provider |
| Statistiken | Trenddiagramme, Top-Vendoren/-Produkte, Severity-Verteilung |
| Audit Log | Ingestion-Job-Protokolle mit Status, Dauer und Metadaten |
| Changelog | Letzte Aenderungen an Schwachstellen (erstellt/aktualisiert) |
| System | Backup/Restore, Sync-Verwaltung, gespeicherte Suchen |

### Betrieb
- **Backup & Restore** fuer Schwachstellen (EUVD/NVD/Alle) und gespeicherte Suchen
- **Gespeicherte Suchen** mit Sidebar-Integration und Audit-Trail
- **Statistiken** mit OpenSearch-Aggregationen (Mongo-Fallback bei Ausfaellen)
- **Manuelle Sync-Trigger** fuer alle 7 Datenquellen ueber die API

## Schnellstart (Docker Compose)

### Voraussetzungen
- Docker + Docker Compose

### Setup

```sh
# 1. Konfiguration anlegen
cp .env.example .env
cp docker-compose.yml.example docker-compose.yml

# 2. .env anpassen (Mongo-Passwort, OpenSearch-Passwort, API-Schluessel etc.)
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

## Lokale Entwicklung

```sh
# Backend
cd backend && poetry install
uvicorn app.main:app --reload

# Frontend (in einem separaten Terminal)
cd frontend && npm install
npm run dev   # Dev-Server auf Port 3000, proxied /api -> Backend
```

Vite proxied `/api`-Anfragen im Dev-Modus automatisch an `http://backend:8000` (Docker) bzw. `http://localhost:8000` (lokal).

## API-Ueberblick

### Status
- `GET /api/v1/status/health` - Liveness Probe

### Schwachstellen
- `POST /api/v1/vulnerabilities/search` - Volltextsuche mit DQL, Filtern, Pagination
- `GET /api/v1/vulnerabilities/{id}` - Einzelne Schwachstelle abrufen
- `POST /api/v1/vulnerabilities/lookup` - Lookup mit Auto-Sync
- `POST /api/v1/vulnerabilities/refresh` - Manueller Refresh einzelner IDs

### KI-Analyse
- `POST /api/v1/vulnerabilities/{id}/ai-investigation` - Einzelanalyse
- `POST /api/v1/vulnerabilities/ai-investigation/batch` - Batch-Analyse

### Kataloge
- `GET /api/v1/cwe/{id}` & `POST /api/v1/cwe/bulk` - CWE-Daten
- `GET /api/v1/capec/{id}` & `POST /api/v1/capec/from-cwes` - CAPEC-Daten
- `GET /api/v1/cpe/entries|vendors|products` - CPE-Katalog
- `GET /api/v1/assets/vendors|products|versions` - Asset-Katalog

### Verwaltung
- `GET/POST/DELETE /api/v1/saved-searches` - Gespeicherte Suchen
- `GET /api/v1/stats/overview` - Statistik-Aggregationen
- `GET /api/v1/audit/ingestion` - Audit-Log
- `GET /api/v1/changelog` - Letzte Aenderungen
- `POST /api/v1/sync/trigger/{job}` - Sync-Trigger (euvd, nvd, cpe, kev, cwe, capec, circl)
- `GET/POST /api/v1/backup/...` - Export/Import

## Backend-CLI

```sh
poetry run python -m app.cli ingest [--since ISO] [--limit N] [--initial]
poetry run python -m app.cli sync-euvd [--since ISO] [--initial]
poetry run python -m app.cli sync-cpe [--limit N] [--initial]
poetry run python -m app.cli sync-nvd [--since ISO | --initial]
poetry run python -m app.cli sync-kev [--initial]
```

## Konfiguration

Alle Parameter werden ueber Umgebungsvariablen gesteuert (siehe `.env.example`):

| Kategorie | Wichtige Variablen |
|-----------|-------------------|
| **Allgemein** | `ENVIRONMENT`, `API_PREFIX`, `LOG_LEVEL` |
| **MongoDB** | `MONGO_URL`, `MONGO_USERNAME`, `MONGO_PASSWORD`, `MONGO_DB` |
| **OpenSearch** | `OPENSEARCH_URL`, `OPENSEARCH_USERNAME`, `OPENSEARCH_PASSWORD` |
| **KI-Provider** | `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GOOGLE_GEMINI_API_KEY` |
| **Datenquellen** | `EUVD_BASE_URL`, `NVD_BASE_URL`, `NVD_API_KEY`, `KEV_FEED_URL` |
| **Scheduler** | `SCHEDULER_ENABLED`, `SCHEDULER_*_INTERVAL_*` |
| **Frontend** | `VITE_TIMEZONE`, `VITE_AI_FEATURES_ENABLED`, `VITE_API_BASE_URL` |

## CI/CD

Gitea-Workflows in `.gitea/workflows/`:
- **build.yml:** Docker-Image Build & Push, Grype-Vulnerability-Scan (SARIF)
- **scan.yml:** SonarQube Code-Analyse, Trivy Dependency-Scan

## Technologie-Stack

| Komponente | Technologie |
|-----------|------------|
| Backend | Python 3.13, FastAPI 0.128, Uvicorn, Poetry |
| Frontend | React 19, TypeScript 5.9, Vite 7, React Router 7 |
| Datenbank | MongoDB 8 (Motor async), OpenSearch 2/3 |
| Scheduling | APScheduler 3.11 |
| HTTP-Client | httpx 0.28 (async) |
| Logging | structlog 25.5 |
| KI | OpenAI, Anthropic, Google Gemini |
| CI/CD | Gitea Actions, Grype, Trivy, SonarQube |
