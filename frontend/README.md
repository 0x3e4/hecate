# Hecate Frontend

React-SPA für die Visualisierung und Verwaltung von Schwachstelleninformationen. Die Dokumentation für das Gesamtprojekt befindet sich in der [README im Repository-Root](../README.md).

## Architektur

```
src/
├── api/                         # Axios-basierte Service-Module
│   ├── client.ts                # Axios-Instanz (Base-URL, 60s Timeout)
│   ├── vulnerabilities.ts       # Suche, Detail, Refresh, AI-Analyse
│   ├── cwe.ts                   # CWE einzeln & bulk
│   ├── capec.ts                 # CAPEC einzeln, bulk, CWE->CAPEC
│   ├── stats.ts                 # Statistik-Aggregationen
│   ├── audit.ts                 # Ingestion-Logs
│   ├── changelog.ts             # Letzte Änderungen (Pagination, Datum-/Source-Filter)
│   ├── sync.ts                  # Sync-Trigger & Status (inkl. OSV)
│   ├── backup.ts                # Export/Import (10 min Timeout): Vulnerabilities, Saved Searches, Environment Inventory
│   ├── assets.ts                # Vendor/Produkt/Version-Katalog
│   ├── scans.ts                 # SCA-Scan-Verwaltung (Targets, Scans, Findings, SBOM, SBOM-Export, SBOM-Import, VEX, License-Compliance)
│   ├── savedSearches.ts         # Gespeicherte Suchen (CRUD)
│   ├── notifications.ts        # Benachrichtigungen (Channels, Regeln, Templates)
│   ├── licensePolicy.ts        # Lizenz-Policy-Verwaltung (CRUD, Default, Gruppen)
│   ├── inventory.ts            # Environment-Inventory (CRUD + affected-vulnerabilities)
│   ├── attackPath.ts           # Attack Path Graph (`fetchAttackPath` mit optionalem scanId/targetId/package/version-Kontext + `triggerAttackPathNarrative` für AI-Narrative-Job)
│   └── malware.ts              # Malware-Feed-Overview (`fetchMalwareFeed` → `GET /v1/malware/malware-feed`, server-paginiert)
├── views/                       # Seitenkomponenten (16 Ansichten)
│   ├── DashboardPage.tsx        # Startseite mit Schwachstellensuche
│   ├── VulnerabilityListPage.tsx # Paginierte Liste mit Filtern (inkl. erweiterte Filter)
│   ├── VulnerabilityDetailPage.tsx # Vollständige Detailansicht mit Tabs für CWE, CAPEC, References, Affected Products, **Attack Path** (Mermaid-Graph + optionaler AI-Narrative — `useRef`-Guard für Lazy-Fetch um die Self-Cancel-Falle zu vermeiden), AI Analysis, Change History, Raw
│   ├── QueryBuilderPage.tsx     # Interaktiver DQL-Editor
│   ├── AIAnalysePage.tsx        # KI-Analyse-Historie: kombinierte Timeline aus Single-, Batch- und Scan-AI-Analysen (listScanAiAnalyses); Trigger-Form für neue Batch-Analysen
│   ├── StatsPage.tsx            # Statistik-Dashboard
│   ├── AuditLogPage.tsx         # Ingestion-Protokolle
│   ├── ChangelogPage.tsx        # Letzte Änderungen
│   ├── ScansPage.tsx            # SCA-Scan-Übersicht (Ziele, Scans, manueller Scan, SBOM-Import, Lizenzen)
│   ├── ScanDetailPage.tsx       # Scan-Details (Findings mit klickbarem Paketnamen → Detail-Expansion + VEX-Status, SBOM server-dedupliziert nach (name, version) mit "Load more"-Pager in SBOM_PAGE_SIZE=500-Schritten, History mit Zeitbereichs-Filter, AI Analysis mit Inline-Trigger-Form + Commit/Digest-Referenz je Eintrag, Compare, Security Alerts, SAST, Secrets, Best Practices, Layer Analysis, License Compliance (nur sichtbar wenn mindestens eine Policy konfiguriert ist), VEX-Export)
│   ├── CiCdInfoPage.tsx         # CI/CD-Integrations-Anleitung
│   ├── ApiInfoPage.tsx          # API-Dokumentation mit Swagger-UI
│   ├── McpInfoPage.tsx          # MCP-Server-Info
│   ├── InventoryPage.tsx        # Environment-Inventory (CRUD + betroffene CVEs pro Eintrag)
│   ├── MalwareFeedPage.tsx      # Übersicht aller MAL-aliased OSV-Records (~417k, server-paginiert 100/Page, hardgecodete Ecosystem-Slugs, Substring-Suche routet zur OpenSearch)
│   └── SystemPage.tsx           # System (Single-Card-Layout, 4 Tabs: General, Notifications, Data, Policies)
├── components/                  # Wiederverwendbare Komponenten
│   ├── AIAnalyse/
│   │   ├── BatchAnalysisDisplay.tsx   # Batch-Ergebnisanzeige (Markdown)
│   │   └── VulnerabilitySelector.tsx  # Multi-Select für Batch-Analyse
│   ├── AILoadingIndicator.tsx         # AI-Analyse Ladeindikator (Reasoning-Steps, Timer)
│   ├── AttackPathGraph.tsx            # Mermaid-Graph-Renderer für die Attack-Path-Tab. Lazy-Loading via `import("mermaid")` mit Module-Promise-Cache; CSS-Vertikal-Chain als Fallback wenn der dynamische Import fehlschlägt. Severity-basiertes Color-Mapping pro Knoten, Label-Chips für Likelihood/Exploit-Maturity/Reachability/Privileges/User-Interaction/Business-Impact, Cross-Reference-Chips zu MITRE CWE/CAPEC, Markdown-Narrative mit `stripAiSummaryFooter` + Provider/timestamp/triggeredBy-Metadata.
│   ├── ScanFindingAttackPath.tsx      # Inline-Wrapper für die Findings-Tab-Expansion auf `/scans/:scanId`. Fetched die Attack-Path mit `scanId`/`targetId`/`packageName`/`version`-Kontext, sodass der Entry-Knoten den Scan-Target-Kontext und der Package-Knoten die exakte Version aus dem Finding zeigt.
│   ├── QueryBuilder/
│   │   ├── QueryEditor.tsx      # DQL-Texteditor mit Operator-Buttons
│   │   ├── FieldBrowser.tsx     # DQL-Feld-Browser nach Kategorien
│   │   ├── FieldItem.tsx        # Einzelnes Feld mit Typ-Info
│   │   └── FieldAggregation.tsx # Feld-Wert-Aggregation (Top Values)
│   ├── AdvancedFilters.tsx       # Erweiterte Filter (Severity, CVSS-Vektor, EPSS, CWE, Quellen, Zeitraum)
│   ├── AssetFilters.tsx         # Async Multi-Select (Vendor/Produkt/Version)
│   ├── CweList.tsx              # CWE-Anzeige mit MITRE-Links
│   ├── CapecList.tsx            # CAPEC-Angriffsmuster mit Details
│   ├── CvssMetricDisplay.tsx    # CVSS-Score-Visualisierung (v2/3/4)
│   ├── ExploitationSummary.tsx  # KEV-Exploitation-Status
│   ├── ReservedBadge.tsx        # Badge für reservierte CVEs
│   ├── Skeleton.tsx             # Lade-Platzhalter
│   └── ScrollToTop.tsx          # Scroll-to-Top Button
├── hooks/
│   ├── usePersistentState.ts    # localStorage-gestützter State
│   ├── useSSE.ts                # Server-Sent Events (Singleton EventSource, Auto-Reconnect)
│   └── useSavedSearches.tsx     # Context-Provider für gespeicherte Suchen
├── ui/                          # Layout- und shared UI-Komponenten
│   ├── AppLayout.tsx            # Root-Layout (Sidebar + Header + Content)
│   ├── Header.tsx               # Top-Navigation
│   ├── Sidebar.tsx              # Seitennavigation mit gespeicherten Suchen
│   ├── TabPill.tsx              # Geteilte Pill-Tab-Button-Style (`tabPillStyle()`) + `TabBadge` (weiße Zahl-Badge neben dem Tab-Label); von Scan- und Vulnerability-Detail-Seite benutzt
│   └── TriggeredByBadge.tsx     # Kleine Pille, die den `triggeredBy`-Wert einer AI-Analyse anzeigt (z.B. `Claude - MCP`); rendert nichts wenn leer
├── utils/
│   ├── aiSummary.ts             # `stripAiSummaryFooter()` — entfernt Legacy `---\n_Added via ..._` Attribution-Footer aus gespeicherten AI-Summaries vor dem Markdown-Rendering
│   ├── cvss.ts                  # CVSS-Metrik-Parsing & Sortierung
│   ├── cvssExplanations.ts      # CVSS-Metrik-Erklärungen
│   ├── dateFormat.ts            # Zeitzonen-bewusste Formatierung (de-DE)
│   └── published.ts             # Veröffentlichungsdatum-Helper
├── constants/
│   └── dqlFields.ts             # DQL-Feld-Definitionen & Kategorien
├── i18n/
│   ├── context.tsx              # I18nProvider & useI18n Hook
│   └── language.ts              # Spracherkennung, localStorage-Persistenz
├── timezone/
│   ├── context.tsx              # TimezoneProvider & useTimezone Hook
│   └── storage.ts               # localStorage-Persistenz (Key `hecate.ui_timezone`), Browser-TZ-Fallback, `getCurrentTimezone()` Helper für Nicht-Hook-Aufrufer
├── server-config/
│   └── context.tsx              # ServerConfigProvider (fetcht `GET /api/v1/config` einmalig beim Mount) & useServerConfig Hook für Feature-Flags (aiEnabled/scaEnabled/scaAutoScanEnabled)
├── router.tsx                   # React Router v7 Routen
├── types.ts                     # TypeScript-Interfaces
├── styles.css                   # Globales Dark-Theme CSS
└── main.tsx                     # React-Einstiegspunkt
```

## Seiten & Routing

| Route | Komponente | Beschreibung |
|-------|-----------|-------------|
| `/` | `DashboardPage` | Startseite mit Schwachstellensuche, aktuellen Einträgen und Echtzeit-Refresh via SSE |
| `/vulnerabilities` | `VulnerabilityListPage` | Paginierte Liste mit Freitext-, Vendor-, Produkt-, Version- und erweiterten Filtern (Severity, CVSS-Vektor, EPSS, CWE, Quellen, Zeitraum) |
| `/vulnerability/:vulnId` | `VulnerabilityDetailPage` | Detailansicht mit Tabs (CWE / CAPEC / References / Affected Products / **Attack Path** mit Mermaid-Graph + optionalem AI-Narrative / AI Analysis / Change History / Raw), Refresh-Dropdown (inkl. OSV). Attack-Path-Tab ist lazy-fetched: das Backend liefert den deterministischen Graph immer, der AI-Narrative ist optional via "Generate scenario narrative"-Button (gegated über `aiEnabled`). |
| `/query-builder` | `QueryBuilderPage` | Interaktiver DQL-Editor mit Field-Browser und Aggregationen |
| `/ai-analyse` | `AIAnalysePage` | KI-Analyse-Historie als kombinierte Timeline aus Single-CVE-, Batch- und Scan-AI-Analysen (neueste zuerst; Scan-Einträge linken zu `/scans/{id}` und tragen einen Commit/Image-Chip); Trigger-Form für neue Batch-Analysen. Origin-Chips (`API - Single`/`MCP - Single`/`API - Batch`/`MCP - Batch`/`API - Scan`/`MCP - Scan`) unterscheiden, ob eine Analyse über die HTTP-API oder über ein MCP-`save_*`-Tool gespeichert wurde. Bedingt via `aiEnabled`. |
| `/stats` | `StatsPage` | Trenddiagramme, Top-Vendoren/-Produkte, Severity-Verteilung |
| `/audit` | `AuditLogPage` | Ingestion-Job-Protokolle mit Status und Metadaten |
| `/changelog` | `ChangelogPage` | Letzte Änderungen mit Pagination, Datum- und Job-Filter (inkl. OSV im Job-Dropdown) |
| `/inventory` | `InventoryPage` | Environment-Inventory: drei `.card`-Sektionen (Intro+Chips-Summary, Add/Edit-Form, Items-Grid). Vendor/Product via `AsyncSelect<Option, false>` (gleicher Look wie AdvancedFilters). Deployment als Chip-Button-Gruppe, Environment als freies Textfeld mit `<datalist>`-Vorschlägen (prod/staging/dev/test/dr + bereits verwendete Werte). Item-Karten als `.vuln-card` mit Severity-Border gefärbt nach der höchsten betroffenen CVE, expandierbare "Show CVEs"-Liste per Eintrag. |
| `/system` | `SystemPage` | Single-Card-Layout mit Header. 4 Tabs: General (Sprache, Dienste, Backup), Notifications (Kanäle, Regeln inkl. `inventory`-Typ mit optionalem Item-Filter via nativem Multi-Select, Vorlagen inkl. `inventory_match`), Data (Sync-Status, Re-Sync mit Multi-ID/Wildcards/Delete-Only, Suchen), Policies (Lizenzrichtlinien) |
| `/scans` | `ScansPage` | SCA-Scan-Verwaltung (Targets, Scans, Findings mit Links-Spalte + expandierbarer Detail-Row, SBOM mit dynamischem Type-Filter aus Facets + Summary-Cards + Sortierung + Provenance-Filter, Security Alerts mit Category-Filter, Licenses, Scanner). Findings- und SBOM-Zeilen zeigen eine Links-Spalte mit deps.dev, Snyk, Registry, socket.dev, bundlephobia (npm-only), npmgraph (npm-only). Targets-Tab gruppiert Karten in **kollabierbare Application-Sektionen** mit Severity-Roll-up (Collapse-Zustand persistiert via `usePersistentState('hecate.scan.groupCollapsed')`). Target-Cards: Action-Reihe unten gepinnt (flex-column), inline editierbare **App/Group**-Zeile mit `<datalist>`-Vorschlägen aus existierenden Gruppen; SBOM-Import-Targets ohne Auto-Scan-, Rescan-, Scanner-Edit- und Group-Edit-Affordances. **Scanner-Tab**: Live-Memory- und Disk-Charts plus eine `AutoScanDiagnosticsTable`, die für jedes Auto-Scan-Target die letzte `/check`-Probe zeigt (Timestamp, aktueller vs. gespeicherter Fingerprint, Verdict-Pill mit Tooltip, Fehler). Verdict-Pills sind klickbare Buttons, die `POST /v1/scans/targets/{id}/check` triggern und die Tabelle in-place mit dem Resultat aktualisieren — primärer Debug-Werkzeug, wenn ein Target nicht automatisch gescannt wird. |
| `/scans/:scanId` | `ScanDetailPage` | Scan-Details mit Findings (VEX-Multi-Select-Toolbar mit Bulk-Apply/Dismiss/Restore, Show-Dismissed-Toggle, Inline-VEX-Editor als expandierbare Zeile mit Status/Justification/Detail, VEX-Import-Button, Links-Spalte mit 6 Pills), SBOM (sortierbare Spalten, klickbare Summary-Cards zum Filtern, Provenance-Filter, Links-Spalte), History (Zeitbereichs-Filter 7d/30d/90d/All, Commit-SHA-Links), Compare (bis zu 200 Scans), Security Alerts, SAST, Secrets, Best Practices, Layer Analysis, License Compliance, VEX-Export |
| `/malware-feed` | `MalwareFeedPage` | Übersicht aller MAL-aliased OSV-Records (~417k) für die Sidebar-Gruppe **Security** (Geschwister von SCA Scans). `/blocklist` ist Legacy-Redirect. Card-Grid mit Search-Input, Ecosystem-Dropdown (hardgecodete Slug-Liste — ohne sie würden nur npm/pypi auftauchen, da das die newest-modified-Records sind), und Server-Pagination (`offset`/`limit`, 100/Page). Substring-Suche und ID-Lookups (MAL-/GHSA-/CVE-Pattern) routen Backend-seitig zur OpenSearch (~50–100ms); unfilterte und ecosystem-gefilterte Pages laufen aus MongoDB via compound `(vendors, modified -1)`-Index (~30ms cold mit warmem Count-Cache). |
| `/info/cicd` | `CiCdInfoPage` | CI/CD-Integrations-Anleitung (Pipeline-Beispiele, Scanner-Referenz, Quality Gates) |
| `/info/api` | `ApiInfoPage` | API-Dokumentation mit eingebetteter Swagger-UI und Endpunkt-Übersicht |
| `/info/mcp` | `McpInfoPage` | MCP-Server-Info (IdP-Setup GitHub/Microsoft/OIDC, Claude-Desktop-Anleitung, Tools inkl. `prepare_*`/`save_*`-Paare und `get_sca_scan`, Beispiel-Prompts, Konfiguration) |

Die Info-Seiten liegen bewusst unter `/info/*`, damit ihre Pfade nicht mit den Backend-Präfixen `/api*` bzw. `/mcp*` kollidieren, wenn ein Reverse-Proxy diese Präfixe präfix-basiert ans Backend weiterleitet. Die alten Pfade `/cicd`, `/api-docs` und `/mcp-info` existieren weiterhin als client-seitige React-Router-Redirects (`<Navigate replace>`), damit bestehende Bookmarks funktionieren — sie greifen allerdings nur, sobald der SPA-Entry geladen wurde. Hard-Refresh auf den alten Pfaden kann je nach Proxy-Regel weiterhin fehlschlagen.

Feature-Sichtbarkeit (KI-Analyse, SCA-Scans, CI/CD, API, MCP) wird zur Laufzeit über `GET /api/v1/config` vom Backend bestimmt und in `ServerConfigProvider` ([src/server-config/context.tsx](src/server-config/context.tsx)) bereitgestellt. Das Backend leitet die Flags aus den eigenen Settings ab (AI = mindestens ein Provider-Key gesetzt, SCA = `sca_enabled`, Auto-Scan = `sca_auto_scan_enabled`). Kein Image-Rebuild nötig wenn man diese ändert — nur Backend neu starten.

## State-Management

Kein Redux/Zustand — basiert auf Reacts eingebauten Mechanismen:

| Methode | Verwendung |
|---------|-----------|
| **Context API** | `SavedSearchesContext` — globale gespeicherte Suchen |
| **SSE (useSSE)** | Echtzeit-Job-Events via Singleton EventSource (Dashboard, VulnerabilityList, System, AI-Analyse) |
| **useState** | Lokaler Komponentenstate (Loading, Error, Daten) |
| **URL-Parameter** | Filter, Pagination, Query-Modus (bookmarkbar) |
| **localStorage** | Sidebar-Zustand, Asset-Filter-Auswahl (`usePersistentState`) |

### Datenlademuster

```
useEffect → setLoading(true) → API-Aufruf → setData/setError → setLoading(false)
```

Skeleton-Platzhalter während des Ladens.

## Styling

- **Custom CSS** in `styles.css` (~800+ Zeilen), kein CSS-Framework
- **Dark Theme** mit CSS-Variablen (`#080a12` Hintergrund, `#f5f7fa` Text)
- **Severity-Farben:** Critical (`#ff6b6b`), High (`#ffa3a3`), Medium (`#ffcc66`), Low (`#8fffb0`)
- **Responsive Design** mit CSS Grid/Flexbox, mobile Sidebar als Overlay
- Einige Komponenten verwenden inline `style`-Props für dynamische Werte

## Lokalisierung

- **Sprache:** Deutsch und Englisch (einfaches i18n via Context API mit `t(english, german)` Pattern)
- **Spracherkennung:** Automatisch über Browser-Sprache, umschaltbar, gespeichert in localStorage
- **Kein externes i18n-Framework** (kein i18next o. ä.)
- **Datumsformat:** `DD.MM.YYYY HH:mm` (de-DE) bzw. `MM/DD/YYYY` (en-US)
- **Zeitzone:** Benutzer-Einstellung auf der System-Seite (`/system` → General → Timezone); persistiert in `localStorage` (`hecate.ui_timezone`), Standard ist die Browser-Zeitzone. Siehe `src/timezone/`. `formatDate()` in [utils/dateFormat.ts](src/utils/dateFormat.ts) liest den aktuellen Wert pro Aufruf via `getCurrentTimezone()`; [ui/AppLayout.tsx](src/ui/AppLayout.tsx) keyt den React-Router-`<Outlet>` auf den Timezone-Wert, sodass bei Änderungen die gesamte aktive Seite neu gerendert wird und alle Datumsangaben den neuen Wert übernehmen. Das Backend serialisiert alle Datetime-Felder UTC-aware (`+00:00`-Suffix), damit `new Date()` im Browser sie korrekt parst — siehe `backend/app/schemas/_utc.py`.

## Konfiguration

Build-Zeit-Variablen (gebacken in `dist/` beim `pnpm run build`):

| Variable | Default | Beschreibung |
|----------|---------|-------------|
| `VITE_API_BASE_URL` | `/api` | API-Basis-Pfad (wird vor dem ersten Backend-Call gebraucht, deshalb nicht runtime-konfigurierbar) |

Alle anderen Feature-Flags kommen zur Laufzeit vom Backend über `GET /api/v1/config`:
- **KI-Features**: aktiv wenn mindestens ein AI-Provider konfiguriert ist (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GOOGLE_GEMINI_API_KEY` oder `OPENAI_COMPATIBLE_BASE_URL` + `OPENAI_COMPATIBLE_MODEL` für Ollama/vLLM/OpenRouter/LocalAI/LM Studio)
- **SCA-Features**: `SCA_ENABLED` (Backend)
- **Auto-Scan-Toggle**: `SCA_AUTO_SCAN_ENABLED` (Backend)

Share-URLs werden aus `globalThis.location.origin` abgeleitet — kein `VITE_DOMAIN` mehr.

## Entwicklung

### Abhängigkeiten verwalten

Dieses Projekt verwendet [pnpm](https://pnpm.io/) für die Verwaltung von Abhängigkeiten. pnpm wird über [Corepack](https://nodejs.org/api/corepack.html) verwaltet (Version in `package.json` gepinnt).

**Supply-Chain-Schutz:** `minimumReleaseAge: 20160` in `pnpm-workspace.yaml` blockiert Pakete, die weniger als 14 Tage alt sind.

#### Neue Abhängigkeit hinzufügen

```bash
# Abhängigkeit hinzufügen:
pnpm add <paket-name>

# Entwicklungs-Abhängigkeit:
pnpm add -D <paket-name>

# Dann beide Dateien committen:
git add package.json pnpm-lock.yaml
git commit -m "Add <paket-name> dependency"
```

#### Abhängigkeiten aktualisieren

```bash
# Alle Abhängigkeiten aktualisieren:
pnpm update

# Ein bestimmtes Paket aktualisieren:
pnpm update <paket-name>

# Dann committen:
git add pnpm-lock.yaml
git commit -m "Update dependencies"
```

#### Entwicklungsserver starten

```bash
corepack enable pnpm && pnpm install && pnpm run dev
```

Dev-Server läuft auf Port 3000, proxied `/api` automatisch an `http://backend:8000`.

### Linting

```bash
pnpm run lint
```

### Docker Build

Multi-Stage Build (dev → build → runtime) basierend auf `node:24-alpine`. Nutzt `serve` für statische Auslieferung auf Port 4173.

```bash
docker build -t hecate-frontend ./frontend
docker run -p 4173:4173 hecate-frontend
```

### Code-Splitting

Manuelle Chunk-Aufteilung in `vite/chunk-split.ts`:
- `react-select` → eigener Chunk
- `react-icons` → eigener Chunk
- `axios` → eigener Chunk
- `mermaid` + alle exklusiven Sub-Deps (`@mermaid-js`, `cytoscape*`, `d3`/`d3-*`, `dagre`/`dagre-d3-es`, `katex`, `khroma`, `roughjs`, `langium`, `vscode-*`, `lodash-es`, `dayjs`, …) → `manualChunks` returnt `undefined`, sodass Rollup die `import("mermaid")` als async-Chunk auslagert. **Nicht** als `return 'mermaid'` markieren — das erzeugt einen `mermaid → vendor → mermaid`-Zirkel (z. B. `lodash-es` shared zwischen dagre-d3-es und vendor-Code) und Rollup preloadet mermaid dann beim Initial-Page-Load.
- Restliche `node_modules` → `vendor` Chunk

### Warum package-lock.json wichtig ist

Die Datei `package-lock.json` stellt sicher:
- **Reproduzierbare Builds** — Alle verwenden die gleichen Abhängigkeitsversionen
- **Sicherheitsprüfung** — Trivy scannt diese Datei auf Schwachstellen
- **Supply-Chain-Sicherheit** — Fixiert exakte Versionen zur Verhinderung von Angriffen

Committe `package-lock.json` immer in die Versionsverwaltung.

## Technologie-Stack

| Technologie | Version | Zweck |
|------------|---------|-------|
| React | 19 | UI-Bibliothek |
| TypeScript | 5.9 | Typsicherheit |
| Vite | 7 | Build-Tool & Dev-Server |
| React Router | 7 | Client-seitiges Routing |
| Axios | 1.13 | HTTP-Client |
| react-markdown | 10 | Markdown-Rendering (AI-Zusammenfassungen) |
| react-icons | 5.5 | Icon-Bibliothek (Lucide) |
| react-select | 5.10 | Async Multi-Select Dropdowns |
| mermaid | 11.14 | Lazy-loaded für die Attack-Path-Tab; Rollup splittet sie automatisch in einen async-Chunk (siehe Code-Splitting unten) |
