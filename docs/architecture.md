# Hecate Architecture Overview

## Vision
- **Topic:** KI-basierte Cyberabwehr – Automatisierte Analyse von Schwachstellen zur proaktiven Verteidigung.
- **Goal:** Collect external vulnerability data, correlate it with local asset inventories, enrich it with AI-supported analysis, and expose results through a web GUI and external APIs.
- **Initial auth:** Anonymous access for MVP. Future roadmap includes local accounts and OAuth2 single sign-on.

## High-Level Components
1. **Frontend (`frontend/`):** React single-page application.
   - Provides dashboards for vulnerability lists, asset filters, enrichment summaries, and note management.
   - Talks to backend via REST (and later WebSocket for streaming AI analysis).
2. **Backend (`backend/`):** FastAPI service.
   - REST API for vulnerability ingestion, asset preferences, AI-enriched assessments, and note storage.
   - Integrates with OpenAI (or self-hosted compatible models) for context analysis.
   - CLI/worker jobs to pull CVE/CPE data from EUVD feeds and other external sources.
3. **Datastores:**
   - **MongoDB:** Configuration, assets, user preferences, note metadata, ingestion state.
   - **OpenSearch:** Indexed vulnerability documents, analysis snapshots, and AI annotations for fast querying.
4. **Workers (future):**
   - Background processing pipeline for enrichment, deduplication, risk scoring.
   - Potential use of Celery or FastAPI background tasks (defined in backlog).
5. **Infrastructure (`infra/`):**
   - Dockerfiles for each service, `docker-compose` stack for local development.
   - Environment variable templates and secrets management placeholders.

## Data Flows
1. **Ingestion:**
   - Scheduled job fetches CVE/CPE/EUVD data.
   - Normalizes payload and stores canonical record in MongoDB.
   - Indexes relevant fields (CVSS, EPSS, vendors/products, aliases, exploit flags) into OpenSearch for full-text and faceted search.
2. **Asset Filtering:**
   - Users define product/application inventory.
   - Backend filters ingested vulnerabilities by matching CPE/keywords against stored inventory.
3. **AI Analysis:**
   - Backend builds context prompts (asset details, CVE metadata, historical actions).
   - Sends prompt to AI provider (OpenAI-compatible API).
   - Stores AI response with status and confidence metrics.
4. **Frontend UX:**
   - React app fetches vulnerability list (filtered by asset profile).
   - Displays AI assessment, allows manual overrides, links to tickets, and notes.

## External Integrations
- **EUVD:** Primary CVE feed (REST/CSV).
- **NIST NVD / CVE / CPE APIs:** Supplemental data and metadata normalization.
- **OpenAI API:** AI summarization and risk classification (pluggable provider interface).
- **Ticketing Integrations (future):** Placeholders for Jira/ServiceNow webhook references stored as URLs in notes.

## Security and Auth Roadmap
- MVP: No login required; read/write open within trusted environment.
- Phase 2: Local user store with salted password hashes.
- Phase 3: OAuth2/OpenID Connect provider integration.
- Backend to enforce RBAC policies once auth is enabled.

## Observability
- Structured logging via Python `structlog`.
- Request tracing (FastAPI middleware).
- Metrics exposed via Prometheus-compatible endpoints (later milestone).

## Container Topology (Local Dev)
```
+--------------+        +----------------+        +---------------+
| React SPA    | <----> | FastAPI Backend| <----> | MongoDB       |
| (frontend)   |        | (backend)      |        | (config store)|
| :3000        |        | :8000          |        | :27017        |
+--------------+        +----------------+        +---------------+
                               ^
                               |
                               v
                         +------------+
                         | OpenSearch |
                         | :9200/9300 |
                         +------------+
```

## Next Steps
- Scaffold FastAPI service with initial endpoints and health checks.
- Scaffold React app with routing and API client boilerplate.
- Add Dockerfiles and docker-compose stack tying services together.
- Prepare seed scripts for MongoDB collections and OpenSearch index templates.
