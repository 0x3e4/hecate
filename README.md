# Hecate

KI-basierte Cyberabwehrplattform zur automatisierten Analyse von Schwachstellen. Die Anwendung aggregiert EUVD-, NVD- und CPE-Daten, reichert sie mit KI-Unterstuetzung an und macht sie ueber ein React-Frontend sowie eine REST-API nutzbar.

## Aktueller Stand
- Vollstaendige Ingestion-Pipelines fuer EUVD, NVD, NVD-CPE und das CISA KEV-Feed inkl. Normalisierung nach MongoDB und OpenSearch.
- APScheduler steuert periodische Jobs, fuehrt Initial-Syncs aus und protokolliert Ablaufinformationen im Audit-Log.
- React/Vite Frontend mit Dashboard, Listen-, Detail-, Audit-, Statistik- und System-Ansichten.
- KI-Analysen koennen ueber OpenAI-, Anthropic- oder Google-Gemini-Provider ausgelöst und gespeichert werden.
- Asset-Katalog (Vendoren/Produkte/Versionen) wird aus ingestierten Daten aufgebaut und fuer Filter bereitgestellt.

## Kernfunktionen
- Schnelle Volltextsuche und DQL-Unterstuetzung auf dem OpenSearch-Index inkl. Relevanzsortierung.
- Integrierte AI-Assessments mit Persistierung im Index und Audit-Events.
- Backup- und Restore-Workflow fuer Vulnerability- und CPE-Bestaende (System-Ansicht im Frontend).
- Gespeicherte Suchen mit Audit-Trail und direkter Integration im UI.
- Statistiken zu Quellen, Severity, Trends und Assets (Fallback auf Mongo bei OpenSearch-Ausfaellen).

## Projektstruktur
```
.
├── backend/         # FastAPI Service, Ingestion-Pipelines, Scheduler, CLI (Poetry)
├── frontend/        # React SPA (Vite + TypeScript) inkl. Build- und Runtime-Dockerfiles
├── docs/            # Architektur- und Konzeptdokumente
└── docker-compose.yml
```

## Datenfluesse & Automatisierung
- EUVD-Pipeline reichert Datensaetze mit NVD-, KEV- und Asset-Informationen an und pflegt Change-Historien.
- NVD- und KEV-Syncs halten Zusatzinformationen (CVSS, Exploitation, Catalog) aktuell.
- CPE-Pipeline baut Vendor-/Produkt-/Versions-Katalog und wird fuer Filterauflagen genutzt.
- APScheduler startet periodische Jobs (konfigurierbar via `.env`) und markiert Initial-Syncs als abgeschlossen.
- Audit-Service protokolliert alle Jobs, AI-Aufrufe sowie Saved-Search-Aktionen in MongoDB.

## Schnellstart (Docker Compose)
1. Abhaengigkeiten: Docker + Docker Compose.
2. Umgebungsvariablen hinterlegen:
   ```sh
   cp backend/.env.example backend/.env
   ```
   Passe Mongo-, OpenSearch- und API-Schluessel nach Bedarf an.
3. Stack bauen und starten:
   ```sh
   docker compose up --build
   ```
4. Standard-Endpoints:
   - Frontend: http://localhost:4173
   - Backend API: http://localhost:8000/api/v1
   - MongoDB: mongodb://localhost:27017
   - OpenSearch: http://localhost:9200

## Lokale Entwicklung
- **Backend:** `cd backend && poetry install && uvicorn app.main:app --reload`
- **Backend-Tests/Lint:** `poetry run pytest` und `poetry run ruff check app`
- **Frontend:** `cd frontend && npm install && npm run dev`
- **Frontend-Lint:** `npm run lint`
- Vite proxied `/api` im Dev-Modus automatisch an `http://localhost:8000`.

## Backend-CLI
- `poetry run python -m app.cli ingest [--since ISO] [--limit N] [--initial]`
- `poetry run python -m app.cli sync-euvd [--since ISO] [--initial]`
- `poetry run python -m app.cli sync-cpe [--limit N] [--initial]`
- `poetry run python -m app.cli sync-nvd [--since ISO | --initial]`
- `poetry run python -m app.cli sync-kev [--initial]`
- CLI aktualisiert Daten, erzeugt Audit-Events und respektiert `CPE_MAX_RECORDS_PER_RUN` sowie Rate-Limits aus `.env`.

## API-Ueberblick
- `GET /api/v1/status/health` – Liveness Probe mit Environment-Info.
- `POST /api/v1/vulnerabilities/search` & `GET /api/v1/vulnerabilities` - Volltextsuche, Filterung, Pagination (Offset + Limit <= `OPENSEARCH_INDEX_MAX_RESULT_WINDOW`, Default 50.000).
- `POST /api/v1/vulnerabilities/{id}/ai-investigation` – Fuehrt KI-Analyse aus und persistiert Ergebnis.
- `POST /api/v1/vulnerabilities/refresh` – Manueller Refresh einzelner IDs.
- `GET /api/v1/cpe/vendors|products|versions` – Asset-Katalog fuer Filter und UI.
- `GET /api/v1/audit/ingestion` – Audit-Log mit Status, Dauer, Metadaten.
- `GET /api/v1/stats/overview` – Aggregationen aus OpenSearch (mit Mongo-Fallback).
- `GET/POST /api/v1/saved-searches` – Verwaltung gespeicherter Suchen.
- `GET/POST /api/v1/backup/...` – Export/Import fuer Vulnerabilities (EUVD/NVD) und CPE.

## Frontend
- Dashboard zeigt aktuelle Schwachstellen mit CVSS, EPSS, Exploitation und direkten Links (CVE, EUVD, GHSA).
- Detailseite mit AI-Assessments, Change-History, Referenzen und Asset-Bezug.
- Vulnerability-Listing mit kombinierbaren Freitext-, Vendor-, Produkt- und Version-Filtern.
- Audit-Log-Ansicht inkl. Statusfarben, Filterung nach Jobtypen und Detail-JSONs.
- Stats-Seite mit Trenddiagrammen und Top-Vendor/-Produkt-Auswertungen.
- System-Seite fuer Backups, Restore, Saved-Search-Verwaltung und Statusmeldungen.

## Konfiguration
- Backend liest Parameter aus `backend/.env` (siehe `.env.example` fuer Defaults).
- `VITE_API_BASE_URL` setzt das Frontend beim Build; Standard `/api`.
- Scheduler-Intervalle (`SCHEDULER_*`) und Bootstrapping koennen zur Laufzeit angepasst werden.
- AI-Provider koennen einzeln aktiviert werden, indem API-Schluessel gesetzt werden.
