# Hecate Architecture Overview

## Vision
- KI-gestuetzte Cyberabwehrplattform, die Schwachstellen aggregiert, anreichert und priorisiert.
- Fokus auf schnelle Sichtbarkeit fuer Security-Teams ohne initialen Authentifizierungsaufwand.
- Erweiterbarkeit fuer weitere Datenquellen, Automatisierung und Integrationen (Ticketing, Assets).

## System Context
- React Single-Page-Application konsumiert REST-APIs des FastAPI-Backends.
- FastAPI orchestriert Ingestion, Persistenz, KI-Aufrufe und liefert Daten an das Frontend.
- OpenSearch dient als performanter Query-Index, MongoDB haelt Normalformdaten und Jobzustand.
- Externe Feeds (EUVD, NVD, CISA KEV) sowie optionale AI-Provider (OpenAI, Anthropic, Gemini) stellen Rohdaten bereit.

## Backend Architecture

### API Layer
- Router unter `app/api/v1` kapseln funktionale Bereiche (Status, Vulnerabilities, Saved Searches, Assets, Backup, Stats, Audit).
- Standardpraefix `/api/v1` (konfigurierbar) und CORS-Allower fuer lokale Integration.
- Responses basieren auf pydantic-Schemas; Validierung erfolgt auf Eingabe- und Ausgabeseite.

### Services & Domain
- Service-Klasse je Anwendungsfall (`VulnerabilityService`, `StatsService`, `AssetCatalogService`, `BackupService`, `AuditService`).
- Services kapseln Datenbankzugriff (Repositories) und koordinieren OpenSearch + Mongo Operations.
- Asset-Katalog wird aus ingestierten Daten abgeleitet (Vendor-/Produkt-/Versions-Slugs) und fuettert Filter-UI.

### Ingestion Pipelines
- **EUVD Pipeline:** Liest paginiert, gleicht CVE-IDs ab, reichert mit NVD- und KEV-Daten an, pflegt Change-Historie, aktualisiert OpenSearch-Index + Mongo-Dokumente.
- **NVD Pipeline:** Aktualisiert CVSS/EPSS/Referenzen fuer bestehende Datensaetze, optional begrenzt ueber `modifiedSince`.
- **CPE Pipeline:** Synchronisiert NVD-CPE-Katalog, erzeugt Vendor-/Produkt-/Versionseintraege und legt Slug-Metadaten in Mongo ab.
- **KEV Pipeline:** Haelt CISA Known-Exploited-Catalog aktuell und stellt Exploitation-Metadaten fuer EUVD/NVD bereit.
- **Manual Refresher:** Ermoeglicht gezielte Reingestion einzelner IDs (API + CLI) und protokolliert Ergebnisse.

### Scheduler & Job Tracking
- `SchedulerManager` initialisiert APScheduler (AsyncIO) mit Intervallen fuer EUVD, CPE, NVD, KEV.
- Initial-Bootstrap laeuft beim Start einmalig und wird in `IngestionStateRepository` (Mongo) als abgeschlossen markiert.
- `JobTracker` aktualisiert Laufzeitstatus, setzt Overdue-Flags und persistiert Fortschritt im Audit-Log.
- Audit-Service schreibt Ereignisse in `ingestion_logs` inklusive Dauer, Ergebnis und Metadaten (Client-IP, Label).

### Persistence
- **MongoDB:** Beinhaltet Normalform-Collections (`vulnerabilities`, `cpe_catalog`, `asset_*`, `ingestion_state`, `known_exploited_vulnerabilities`, `saved_searches`, `ingestion_logs`).
- **OpenSearch:** Index `hecate-vulnerabilities` mit normalisierten Dokumenten (IDs als CVE oder EUVD-ID). Wird fuer Such- und Filteroperationen genutzt.
- Repositories auf Basis von Motor (Mongo) und opensearch-py kapseln Abfragen und Updates.
- TTL-Indizes (z. B. `expires_at`) sichern optionales Aufraeumen von Zustandsdokumenten.

### AI & Analysis
- `AIClient` verwaltet verfuegbare Provider anhand gesetzter API-Schluessel.
- Prompt-Builder erstellt Kontexte inkl. Asset- und Historieninformationen in frei waehlbarer Sprache.
- Ergebnisse werden wieder in OpenSearch gespeichert und als Audit-Event protokolliert.
- Fehlerbehandlung liefert 4xx bei Konfigurationsfehlern, 5xx bei Provider-Ausfaellen.

### Backup & Restore
- Backup-Service exportiert JSON-Snapshots fuer Vulnerabilities (quellenweise) und CPE-Katalog mit Metadaten (Dataset, Source, Item-Count, Timestamp).
- Restore validiert Metadaten, schreibt Dokumente in Mongo + OpenSearch und gibt eine Zusammenfassung zurueck (inserted/updated/skipped).
- Frontend-Systemseite nutzt diese Endpunkte fuer Self-Service-Backups.

### Observability
- `structlog` fuer strukturierte Logs, konsistent in Pipelines und Services verwendet.
- Audit-Log dient als Betriebsfuehrer (Status, Fehlergruende, Dauer, Overdue-Hinweise).
- Konfigurierbare `INGESTION_RUNNING_TIMEOUT_MINUTES` markiert Jobs als overdues, ohne sie abzubrechen.

## Frontend Architecture
- React 19 + Vite, Router-Struktur (`router.tsx`) spannt Dashboard, Vulnerability-Liste/-Detail, Audit, Stats und System auf.
- API-Clients (Axios) in `src/api` kapseln REST-Aufrufe inkl. TypeScript-Typen.
- Zustand ueber React Hooks, sparsame globale State-Verwendung; Skeleton-Komponenten fuer Loading-States.
- Styling via CSS-Module-Ansatz (globale Styles) mit Fokus auf Kartenlayout und Dark-Theming.
- System-Ansicht stellt Backup/Restore und Saved-Search-Management bereit; Audit-Seite zeigt detaillierte Events.

## Data Flow Summary
1. Scheduler oder CLI loest einen Ingestion-Job aus.
2. Pipeline zieht Daten von EUVD/NVD/CISA, normalisiert sie (`build_document`), aktualisiert Mongo und OpenSearch.
3. AssetCatalogService leitet Vendor-/Produkt-/Versionsdaten ab und aktualisiert Slugs fuer Filter.
4. Frontend ruft Listen- und Detailendpunkte ab, optional startet AI-Assessments oder Backups.
5. Audit-Service protokolliert alle relevanten Aktionen, Stats-Service aggregiert Kennzahlen aus OpenSearch (Fallback Mongo).

## External Integrations
- **EUVD API:** Primäre Schwachstellendatenquelle (REST JSON).
- **NVD API:** CVE-Detail- und CPE-Katalog-Synchronisation.
- **CISA Known Exploited Vulnerabilities:** Erweitert Metadaten um Exploit-Kontext.
- **OpenAI / Anthropic / Google Gemini:** Optionale KI-Provider fuer Zusammenfassungen und Risikohinweise.

## Deployment Topology
```
+--------------+        +----------------+        +---------------+
| React SPA    | <----> | FastAPI Backend| <----> | MongoDB       |
| (frontend)   |        | (backend)      |        | (state store) |
| :4173        |        | :8000          |        | :27017        |
+--------------+        +----------------+        +---------------+
                               ^
                               |
                               v
                         +------------+
                         | OpenSearch |
                         | :9200      |
                         +------------+
```