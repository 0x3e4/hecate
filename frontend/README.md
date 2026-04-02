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
│   ├── backup.ts                # Export/Import (10 min Timeout)
│   ├── assets.ts                # Vendor/Produkt/Version-Katalog
│   ├── scans.ts                 # SCA-Scan-Verwaltung (Targets, Scans, Findings, SBOM, SBOM-Export)
│   ├── savedSearches.ts         # Gespeicherte Suchen (CRUD)
│   └── notifications.ts        # Benachrichtigungen (Channels, Regeln, Templates)
├── views/                       # Seitenkomponenten (11 Ansichten)
│   ├── DashboardPage.tsx        # Startseite mit Schwachstellensuche
│   ├── VulnerabilityListPage.tsx # Paginierte Liste mit Filtern
│   ├── VulnerabilityDetailPage.tsx # Vollständige Detailansicht
│   ├── QueryBuilderPage.tsx     # Interaktiver DQL-Editor
│   ├── AIAnalysePage.tsx        # KI-Analyse (einzeln & Batch)
│   ├── StatsPage.tsx            # Statistik-Dashboard
│   ├── AuditLogPage.tsx         # Ingestion-Protokolle
│   ├── ChangelogPage.tsx        # Letzte Änderungen
│   ├── ScansPage.tsx            # SCA-Scan-Übersicht (Ziele, Scans, manueller Scan)
│   ├── ScanDetailPage.tsx       # Scan-Details (Findings, SBOM mit Export & Stats, Security Alerts, Best Practices, Layer Analysis)
│   └── SystemPage.tsx           # Backup, Restore, Sync-Verwaltung
├── components/                  # Wiederverwendbare Komponenten
│   ├── AIAnalyse/
│   │   ├── BatchAnalysisDisplay.tsx   # Batch-Ergebnisanzeige (Markdown)
│   │   └── VulnerabilitySelector.tsx  # Multi-Select für Batch-Analyse
│   ├── AILoadingIndicator.tsx         # AI-Analyse Ladeindikator (Reasoning-Steps, Timer)
│   ├── QueryBuilder/
│   │   ├── QueryEditor.tsx      # DQL-Texteditor mit Operator-Buttons
│   │   ├── FieldBrowser.tsx     # DQL-Feld-Browser nach Kategorien
│   │   ├── FieldItem.tsx        # Einzelnes Feld mit Typ-Info
│   │   └── FieldAggregation.tsx # Feld-Wert-Aggregation (Top Values)
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
├── ui/                          # Layout-Komponenten
│   ├── AppLayout.tsx            # Root-Layout (Sidebar + Header + Content)
│   ├── Header.tsx               # Top-Navigation
│   └── Sidebar.tsx              # Seitennavigation mit gespeicherten Suchen
├── utils/
│   ├── cvss.ts                  # CVSS-Metrik-Parsing & Sortierung
│   ├── cvssExplanations.ts      # CVSS-Metrik-Erklärungen
│   ├── dateFormat.ts            # Zeitzonen-bewusste Formatierung (de-DE)
│   └── published.ts             # Veröffentlichungsdatum-Helper
├── constants/
│   └── dqlFields.ts             # DQL-Feld-Definitionen & Kategorien
├── i18n/
│   ├── context.tsx              # I18nProvider & useI18n Hook
│   └── language.ts              # Spracherkennung, localStorage-Persistenz
├── config.ts                    # Umgebungs-Konfiguration (Vite Env)
├── router.tsx                   # React Router v7 Routen
├── types.ts                     # TypeScript-Interfaces
├── styles.css                   # Globales Dark-Theme CSS
└── main.tsx                     # React-Einstiegspunkt
```

## Seiten & Routing

| Route | Komponente | Beschreibung |
|-------|-----------|-------------|
| `/` | `DashboardPage` | Startseite mit Schwachstellensuche, aktuellen Einträgen und Echtzeit-Refresh via SSE |
| `/vulnerabilities` | `VulnerabilityListPage` | Paginierte Liste mit Freitext-, Vendor-, Produkt- und Version-Filtern |
| `/vulnerability/:vulnId` | `VulnerabilityDetailPage` | Detailansicht mit AI-Assessments, Referenzen, Change-History, Refresh-Dropdown (inkl. OSV) |
| `/query-builder` | `QueryBuilderPage` | Interaktiver DQL-Editor mit Field-Browser und Aggregationen |
| `/ai-analyse` | `AIAnalysePage` | Einzel- und Batch-KI-Analyse (bedingt, via Feature-Flag) |
| `/stats` | `StatsPage` | Trenddiagramme, Top-Vendoren/-Produkte, Severity-Verteilung |
| `/audit` | `AuditLogPage` | Ingestion-Job-Protokolle mit Status und Metadaten |
| `/changelog` | `ChangelogPage` | Letzte Änderungen mit Pagination, Datum- und Job-Filter (inkl. OSV im Job-Dropdown) |
| `/system` | `SystemPage` | Backup/Restore, Sync-Verwaltung (inkl. OSV-Trigger), gespeicherte Suchen |
| `/scans` | `ScansPage` | SCA-Scan-Verwaltung (Ziele, Scans, manueller Scan) |
| `/scans/:scanId` | `ScanDetailPage` | Scan-Details mit Findings, SBOM (Export & Summary-Stats), Security Alerts, Best Practices, Layer Analysis, Scan-Vergleich |

Die KI-Analyse-Seite wird nur angezeigt wenn `VITE_AI_FEATURES_ENABLED=true`.
Die SCA-Scans-Seite wird nur angezeigt wenn `VITE_SCA_FEATURES_ENABLED=true`.

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
- **Zeitzone:** Konfigurierbar via `VITE_TIMEZONE` (Default: `UTC`)

## Konfiguration

Umgebungsvariablen (in `.env` oder Build-Zeit via Vite):

| Variable | Default | Beschreibung |
|----------|---------|-------------|
| `VITE_API_BASE_URL` | `/api` | API-Basis-Pfad |
| `VITE_TIMEZONE` | `UTC` | Zeitzone für Datumsanzeige |
| `VITE_AI_FEATURES_ENABLED` | `true` | KI-Analyse aktivieren/deaktivieren |
| `VITE_DOMAIN` | `hecate.pw` | Domain für Share-URLs |
| `VITE_SCA_FEATURES_ENABLED` | `true` | SCA-Scans aktivieren/deaktivieren |
| `VITE_SCA_AUTO_SCAN_ENABLED` | `false` | Auto-Scan-Toggle in der UI anzeigen (Backend: `SCA_AUTO_SCAN_INTERVAL_MINUTES` für Intervall) |

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
