# Hecate Backend

FastAPI-Service zum Erfassen, Anreichern und Bereitstellen von Schwachstelleninformationen. Die Dokumentation für das Gesamtprojekt befindet sich in der [README im Repository-Root](../README.md).

## Architektur

```
app/
├── api/v1/                  # REST-Endpunkte
│   ├── routes.py            # Router-Registrierung
│   ├── vulnerabilities.py   # Suche, Lookup, Refresh, AI-Analyse
│   ├── cwe.py               # CWE-Abfragen (einzeln & bulk)
│   ├── capec.py             # CAPEC-Abfragen, CWE->CAPEC Mapping
│   ├── cpe.py               # CPE-Katalog (Entries, Vendors, Products)
│   ├── assets.py            # Asset-Katalog (Vendoren, Produkte, Versionen)
│   ├── stats.py             # Statistik-Aggregationen
│   ├── backup.py            # Export/Import (Streaming)
│   ├── sync.py              # Manuelle Sync-Trigger
│   ├── saved_searches.py    # Gespeicherte Suchen (CRUD)
│   ├── audit.py             # Ingestion-Logs
│   ├── changelog.py         # Letzte Änderungen
│   └── status.py            # Health Check
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
│   └── kev.py               # CisaKevEntry, CisaKevCatalog
├── repositories/            # Datenzugriffsschicht
│   ├── vulnerability_repository.py
│   ├── cwe_repository.py
│   ├── capec_repository.py
│   ├── kev_repository.py
│   ├── cpe_repository.py
│   ├── asset_repository.py
│   ├── saved_search_repository.py
│   ├── ingestion_state_repository.py
│   └── ingestion_log_repository.py
├── schemas/                 # API Request/Response Schemata
│   ├── vulnerability.py     # VulnerabilityQuery, VulnerabilityDetail
│   ├── cwe.py, capec.py, cpe.py, assets.py
│   ├── ai.py                # AI-Analyse Schemata
│   ├── backup.py, sync.py, audit.py, changelog.py
│   └── saved_search.py
├── services/                # Business-Logik
│   ├── vulnerability_service.py   # Suche, Refresh, Lookup
│   ├── cwe_service.py             # 3-Tier-Cache (Memory->Mongo->API)
│   ├── capec_service.py           # 3-Tier-Cache + CWE->CAPEC Mapping
│   ├── ai_service.py              # OpenAI, Anthropic, Gemini Wrapper
│   ├── stats_service.py           # OpenSearch-Aggregationen (Mongo-Fallback)
│   ├── backup_service.py          # Streaming Export/Import
│   ├── sync_service.py            # Sync-Koordination
│   ├── audit_service.py           # Audit-Logging
│   ├── changelog_service.py       # Change-Tracking
│   ├── saved_search_service.py    # Gespeicherte Suchen
│   ├── cpe_service.py             # CPE-Katalog
│   ├── asset_catalog_service.py   # Asset-Katalog
│   ├── http/
│   │   └── rate_limiter.py        # HTTP Rate-Limiting
│   ├── ingestion/                 # Datenpipelines
│   │   ├── euvd_pipeline.py       # EUVD (ENISA)
│   │   ├── nvd_pipeline.py        # NVD (NIST)
│   │   ├── kev_pipeline.py        # CISA KEV
│   │   ├── cpe_pipeline.py        # CPE (NVD)
│   │   ├── circl_pipeline.py      # CIRCL
│   │   ├── euvd_client.py         # EUVD API-Client
│   │   ├── nvd_client.py          # NVD API-Client
│   │   ├── cisa_client.py         # KEV API-Client
│   │   ├── cpe_client.py          # CPE API-Client
│   │   ├── cwe_client.py          # CWE MITRE API-Client
│   │   ├── capec_client.py        # CAPEC XML-Parser
│   │   ├── circl_client.py        # CIRCL API-Client
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
└── cli.py                         # CLI-Einstiegspunkt
```

## Datenmodell

### MongoDB Collections

| Collection | Modell | Beschreibung |
|-----------|--------|-------------|
| `vulnerabilities` | `VulnerabilityDocument` | Schwachstellen mit CVSS, EPSS, CWEs, CPEs, Quell-Rohdaten |
| `cwe_catalog` | `CWEEntry` | CWE-Schwächen (7-Tage TTL-Cache) |
| `capec_catalog` | `CAPECEntry` | CAPEC-Angriffsmuster (7-Tage TTL-Cache) |
| `known_exploited_vulnerabilities` | `CisaKevEntry` | CISA KEV-Einträge |
| `cpe_catalog` | - | CPE-Einträge (Vendor, Product, Version) |
| `asset_vendors` | - | Vendoren mit Slug und Produkt-Anzahl |
| `asset_products` | - | Produkte mit Vendor-Zuordnung |
| `asset_versions` | - | Versionen mit Produkt-Zuordnung |
| `ingestion_state` | - | Sync-Job-Status (Running/Completed/Failed) |
| `ingestion_logs` | - | Detaillierte Job-Logs mit Metadaten |
| `saved_searches` | - | Gespeicherte Suchanfragen |

### OpenSearch Index (`hecate-vulnerabilities`)

Volltext-Index mit Text-Feldern für Suche und `.keyword`-Feldern für Aggregationen. Nested `sources`-Pfad für Quell-Aggregationen.

**Konfiguration:** `max_result_window` = 200.000, `total_fields.limit` = 2.000

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

Alle Pipelines unterstützen inkrementelle und initiale Syncs. Wöchentliche Full-Syncs (EUVD Sonntag 2 Uhr, NVD Mittwoch 2 Uhr UTC).

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

### API-Schema-Konvention
```python
field_name: str = Field(alias="fieldName", serialization_alias="fieldName")
```
Snake-Case in Python, camelCase auf dem Wire.

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
- **Reproduzierbare Builds** - Alle verwenden die gleichen Abhängigkeitsversionen
- **Sicherheitsprüfung** - Trivy scannt diese Datei auf Schwachstellen
- **Supply-Chain-Sicherheit** - Fixiert exakte Versionen zur Verhinderung von Angriffen

Committe `poetry.lock` immer in die Versionsverwaltung.
