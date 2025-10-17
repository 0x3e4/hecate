# Hecate

KI-basierte Cyberabwehrplattform zur automatisierten Analyse von Schwachstellen. Die Plattform kombiniert Daten aus EUVD/CVE/CPE-Quellen, verknuepft sie mit lokalen Asset-Profilen und liefert KI-gestuetzte Handlungsempfehlungen ueber ein Web-Frontend und eine REST-API.

## Aktueller Stand (MVP Scaffold)
- **Frontend:** React (Vite + TypeScript) Dashboard mit dynamischer EUVD-Vulnerability-Liste und API-Client.
- **Backend:** FastAPI Skeleton mit Healthcheck, EUVD/NVD-Ingestion, Such-Endpoint und Platzhalter fuer AI-Analysen.
- **Datastores:** Docker Compose Services fuer MongoDB (Konfiguration) und OpenSearch (Vuln Index).
- **AI Integration:** Struktur zum Einbinden eines OpenAI-kompatiblen Clients vorbereitet.

## Projektstruktur
```
.
├── backend/         # FastAPI Anwendung inkl. Dockerfile und Poetry-Setup
├── frontend/        # React SPA (Vite) inkl. Dockerfile
├── docs/            # Architektur- und Konzeptdokumente
└── docker-compose.yml
```

## Schnellstart
1. Stelle sicher, dass Docker und Docker Compose installiert sind.
2. Kopiere die Backend-Umgebungsvariablen:
   ```sh
   cp backend/.env.example backend/.env
   ```
   Passe Werte fuer Mongo/OpenSearch/AI an (falls noetig).
3. Baue und starte den Stack:
   ```sh
   docker compose up --build
   ```
4. Services:
   - Frontend: http://localhost:3000 (Proxy zu `serve` Port 4173)
   - Backend API: http://localhost:8000/api
   - MongoDB: mongodb://localhost:27017
   - OpenSearch: http://localhost:9200

## Schwachstellen-Ingestion
- Der Backend-CLI-Befehl zieht EUVD-Daten, reichert (falls moeglich) via NVD an und speichert Ergebnisse in MongoDB sowie OpenSearch.
  Alle wesentlichen Metadaten (Aliases, CVSS, EPSS, Vendors/Products, Exploit-Status, Assigner) werden normalisiert abgelegt.
- Beispielaufruf (im Backend-Verzeichnis):
  ```sh
  poetry run python -m app.cli ingest --since 2024-01-01T00:00:00Z
  # oder ohne Kommando, da 'ingest' Standard ist:
  poetry run python -m app.cli --since 2024-01-01T00:00:00Z
  ```
- Optionen:
  - `--since` (optional): ISO-Zeitstempel, ab dem modifizierte Schwachstellen geladen werden.
  - `--limit` (optional): Anzahl der Datensaetze begrenzen (fuer Tests).
- CPE-Katalog-Synchronisation (Vendors/Produkte fuer spaetere Filter) laesst sich manuell ausloesen:
  ```sh
  poetry run python -m app.cli sync-cpe
  # fuer Tests optional begrenzen:
  poetry run python -m app.cli sync-cpe --limit 100
  ```
- Ohne `--limit` greift `CPE_MAX_RECORDS_PER_RUN` (Default 10000) – der Sync holt in Batches weitere Datensaetze nach.
- Hinweis: `EUVD_BASE_URL` im Backend-`.env` ist standardmaessig auf `https://euvdservices.enisa.europa.eu/api` (GET `/search`) gesetzt. Wenn du einen alternativen Endpunkt oder Proxy nutzt, passe diesen Wert entsprechend an.
- Hinweis: Nach Schema-Aenderungen an den OpenSearch-Mappings kann ein Neuaufbau des Index erforderlich sein  
  (z. B. `curl -XDELETE http://localhost:9200/hecate-vulnerabilities` vor einem erneuten `ingest`-Durchlauf).
- Hinweis: Ein APScheduler startet beim Backend-Startup automatisch (konfigurierbar via `.env`). Standard: EUVD alle 60 Minuten, CPE alle 24 Stunden.
- Frontend-Builds lassen sich containerisiert erzeugen (nutzt das `dev`-Stage mit lokalem Source-Mount):
  ```sh
  docker compose run --rm --no-deps frontend-build
  ```
  Die gebaute Ausgabe liegt anschliessend in `frontend/dist/` auf dem Host.
- Passe `VITE_API_BASE_URL` (z. B. `http://backend:8000/api`) an, falls Frontend und Backend unter unterschiedlichen Hosts/Ports erreichbar sind. Der Wert wird beim Build ausgewertet.
- API-Endpunkte:
  - `POST /api/v1/vulnerabilities/search` – OpenSearch-gestuetzte Suche inkl. Metadaten.
  - `GET /api/v1/vulnerabilities/{id}` – Detailansicht eines Eintrags (CVE oder EUVD-ID).
  - API-Präfix konfigurierbar über `API_PREFIX` (Standard `/api/v1`).
  - `GET /api/v1/cpe/entries` – CPE-Katalog fuer Vendor-/Produktfilter (Frontend nutzt dies fuer dynamische Filter).
  - `GET /api/v1/cpe/vendors` & `GET /api/v1/cpe/products` – Distinct-Werte fuer Such-/Dropdowns.
  - `GET /api/v1/audit/ingestion` – Audit-Log der Ingestion-Jobs (wird im Frontend unter „Audit Log“ angezeigt).

## Lokale Entwicklung
- **Backend:** `cd backend && poetry install && uvicorn app.main:app --reload`
- **Frontend:** `cd frontend && npm install && npm run dev`
- Beide Services nutzen denselben API-Pfad `/api`, im Dev-Setup proxied Vite alle API-Calls an FastAPI.

## Nächste Schritte
1. **Datenpipelines:** Implementiere Aufgaben zum Pullen und Normalisieren von CVE/EUVD/CPE-Daten.
2. **Persistenz:** Schema und Repositories fuer MongoDB sowie OpenSearch-Mappings ausarbeiten.
3. **AI-Prompting:** Prompt-Builder und Bewertungslogik inkl. konfigurierbarer Konfidenzmodelle umsetzen.
4. **Auth-Roadmap:** Optionales Login deaktiviert lassen, spaeter lokale Nutzerverwaltung + OAuth2 hinzufuegen.
5. **Testing & QA:** Unit-/Integrationstests, Linter-Configs (Ruff, ESLint) aktiv nutzen.
6. **DevEx:** CI-Pipeline, Makefile, seed scripts, Infrastructure-as-Code fuer Produktionsdeployment.
7. **Reverse Proxy:** Externe Reverse-Proxies (z. B. Traefik/NGINX) ausserhalb dieses Repos anbinden.
8. **Ingestion Automation:** Scheduler/Worker (z. B. Celery, APScheduler) integrieren, um CLI-Aufrufe regelmaessig auszufuehren.

## Lizenz
Interne Projektbasis. Lizenzierung kann spaeter definiert werden.
