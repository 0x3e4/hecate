# Hecate Frontend

> React SPA for visualising and managing vulnerability information. Whole-project documentation lives in the [repository root README](../README.md).

![React](https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=black)
![TypeScript](https://img.shields.io/badge/TypeScript-5.9-3178C6?logo=typescript&logoColor=white)
![Vite](https://img.shields.io/badge/Vite-7-646CFF?logo=vite&logoColor=white)
![pnpm](https://img.shields.io/badge/pnpm-managed-F69220?logo=pnpm&logoColor=white)

---

## Architecture

<details>
<summary><strong><code>src/</code> directory layout</strong> (click to expand)</summary>

```text
src/
├── api/                         Axios-based service modules
│   ├── client.ts                Axios instance (base URL, 60 s timeout)
│   ├── vulnerabilities.ts       Search · detail · refresh · AI analysis
│   ├── cwe.ts                   CWE single + bulk
│   ├── capec.ts                 CAPEC single, bulk, CWE→CAPEC
│   ├── stats.ts                 Statistics aggregations
│   ├── audit.ts                 Ingestion logs
│   ├── changelog.ts             Recent changes (pagination, date / source filters)
│   ├── sync.ts                  Sync triggers + status (incl. OSV)
│   ├── backup.ts                Export / import (10 min timeout): vulnerabilities · saved searches · environment inventory
│   ├── assets.ts                Vendor / product / version catalogue
│   ├── scans.ts                 SCA scan management — targets, scans, findings, SBOM, SBOM export, SBOM import,
│   │                              VEX, license compliance, cross-CVE attack chain (`fetchScanAttackChain` +
│   │                              `triggerScanAttackChainNarrative`)
│   ├── savedSearches.ts         Saved searches (CRUD)
│   ├── notifications.ts         Notifications (channels, rules, templates)
│   ├── licensePolicy.ts         License-policy management (CRUD, default, groups)
│   ├── inventory.ts             Environment inventory (CRUD + affected-vulnerabilities)
│   ├── attackPath.ts            Attack-path graph (`fetchAttackPath` with optional scanId / targetId / package /
│   │                              version context + `triggerAttackPathNarrative` for the AI narrative job)
│   └── malware.ts               Malware-feed overview (`fetchMalwareFeed` → GET /v1/malware/malware-feed,
│                                  server-paginated)
├── views/                       Page components (16 views)
│   ├── DashboardPage.tsx        Home page with vulnerability search
│   ├── VulnerabilityListPage.tsx
│   │                            Paginated list with filters (incl. advanced filters)
│   ├── VulnerabilityDetailPage.tsx
│   │                            Full detail view with tabs for CWE, CAPEC, references, affected products,
│   │                              **Attack Path** (Mermaid graph + optional AI narrative — `useRef` guard
│   │                              for lazy fetch to avoid the self-cancel trap), AI analysis,
│   │                              change history, raw
│   ├── QueryBuilderPage.tsx     Interactive DQL editor
│   ├── AIAnalysePage.tsx        AI-analysis history: combined timeline of single, batch, and scan analyses
│   │                              (`listScanAiAnalyses`); trigger form for new batch analyses
│   ├── StatsPage.tsx            Statistics dashboard
│   ├── AuditLogPage.tsx         Ingestion logs
│   ├── ChangelogPage.tsx        Recent changes
│   ├── ScansPage.tsx            SCA scan overview (targets, scans, manual scan, SBOM import, licenses)
│   ├── ScanDetailPage.tsx       Scan details (findings with clickable package name → detail expansion +
│   │                              VEX status, **Attack Chain** cross-CVE chain as a top-level tab between
│   │                              findings and SBOM, server-deduped SBOM by `(name, version)` with
│   │                              "Load more" pager in `SBOM_PAGE_SIZE=500` steps, history with
│   │                              time-range filter, AI analysis with inline trigger form +
│   │                              commit / digest reference per entry, compare, security alerts, SAST,
│   │                              secrets, best practices, layer analysis, license compliance (only
│   │                              visible when at least one policy is configured), VEX export)
│   ├── CiCdInfoPage.tsx         CI/CD integration guide
│   ├── ApiInfoPage.tsx          API documentation with Swagger UI
│   ├── McpInfoPage.tsx          MCP server info
│   ├── InventoryPage.tsx        Environment inventory (CRUD + affected CVEs per item)
│   ├── MalwareFeedPage.tsx      Overview of all MAL-aliased OSV records (~417 k, server-paginated 100/page,
│   │                              hard-coded ecosystem slugs, substring search routed to OpenSearch)
│   └── SystemPage.tsx           System (single-card layout, 4 tabs: General, Notifications, Data, Policies)
├── components/                  Reusable components
│   ├── AIAnalyse/
│   │   ├── BatchAnalysisDisplay.tsx   Batch result display (Markdown)
│   │   └── VulnerabilitySelector.tsx  Multi-select for batch analysis
│   ├── AILoadingIndicator.tsx         AI-analysis loading indicator (reasoning steps, timer)
│   ├── AttackPathGraph.tsx            Mermaid graph renderer for the Attack Path tab. Lazy-loading via
│   │                                    `import("mermaid")` with module-promise cache; CSS vertical-chain
│   │                                    fallback when the dynamic import fails. Severity-based colour
│   │                                    mapping per node, label chips for likelihood / exploit-maturity /
│   │                                    reachability / privileges / user-interaction / business-impact,
│   │                                    cross-reference chips for MITRE CWE/CAPEC, Markdown narrative
│   │                                    with `stripAiSummaryFooter` + provider/timestamp/triggeredBy
│   │                                    metadata.
│   ├── ScanFindingAttackPath.tsx      Inline wrapper for the findings-tab expansion on `/scans/:scanId`.
│   │                                    Fetches the attack path with `scanId`/`targetId`/`packageName`/
│   │                                    `version` context so the entry node shows the scan-target context
│   │                                    and the package node shows the exact version from the finding.
│   ├── ScanAttackChainView.tsx        Top-level tab component for the cross-CVE attack chain on
│   │                                    `/scans/:scanId`. Lazy-fetches `fetchScanAttackChain(scanId)`,
│   │                                    renders a stage-pill bar (Foothold / Credential Access /
│   │                                    Privilege Escalation / Lateral Movement / Impact with severity
│   │                                    tone mapping) above the reused `<AttackPathGraphView>` Mermaid
│   │                                    renderer. Trigger panel calls `triggerScanAttackChainNarrative`
│   │                                    with `ai_analysis_password` from localStorage; afterwards polls
│   │                                    `fetchScan` until `attackChain` / `attackChains[]` is filled
│   │                                    (max 30 tries, 4 s interval, same pattern as scan AI analysis).
│   ├── QueryBuilder/
│   │   ├── QueryEditor.tsx      DQL text editor with operator buttons
│   │   ├── FieldBrowser.tsx     DQL field browser by category
│   │   ├── FieldItem.tsx        Single field with type info
│   │   └── FieldAggregation.tsx Field-value aggregation (top values)
│   ├── AdvancedFilters.tsx      Advanced filters (severity, CVSS vector, EPSS, CWE, sources, time range)
│   ├── AssetFilters.tsx         Async multi-select (vendor / product / version)
│   ├── CweList.tsx              CWE display with MITRE links
│   ├── CapecList.tsx            CAPEC attack patterns with details
│   ├── CvssMetricDisplay.tsx    CVSS-score visualisation (v2 / v3 / v4)
│   ├── ExploitationSummary.tsx  KEV exploitation status
│   ├── ReservedBadge.tsx        Badge for reserved CVEs
│   ├── Skeleton.tsx             Loading placeholder
│   └── ScrollToTop.tsx          Scroll-to-top button
├── hooks/
│   ├── usePersistentState.ts    localStorage-backed state
│   ├── useSSE.ts                Server-Sent Events (singleton EventSource, auto-reconnect)
│   └── useSavedSearches.tsx     Context provider for saved searches
├── ui/                          Layout + shared UI components
│   ├── AppLayout.tsx            Root layout (sidebar + header + content)
│   ├── Header.tsx               Top navigation
│   ├── Sidebar.tsx              Side navigation with saved searches
│   ├── TabPill.tsx              Shared pill-tab button style (`tabPillStyle()`) + `TabBadge`
│   │                              (white number badge next to the tab label); used by both the scan-detail
│   │                              and vulnerability-detail pages
│   └── TriggeredByBadge.tsx     Small pill that shows the `triggeredBy` value of an AI analysis
│                                  (e.g. `Claude - MCP`); renders nothing when empty
├── utils/
│   ├── aiSummary.ts             `stripAiSummaryFooter()` — removes legacy `---\n_Added via …_` attribution
│   │                              footers from stored AI summaries before Markdown rendering
│   ├── cvss.ts                  CVSS metric parsing + sorting
│   ├── cvssExplanations.ts      CVSS metric explanations
│   ├── dateFormat.ts            Timezone-aware formatting (de-DE)
│   └── published.ts             Publication-date helper
├── constants/
│   └── dqlFields.ts             DQL field definitions + categories
├── i18n/
│   ├── context.tsx              I18nProvider + useI18n hook
│   └── language.ts              Language detection, localStorage persistence
├── timezone/
│   ├── context.tsx              TimezoneProvider + useTimezone hook
│   └── storage.ts               localStorage persistence (key `hecate.ui_timezone`), browser-TZ fallback,
│                                  `getCurrentTimezone()` helper for non-hook callers
├── server-config/
│   └── context.tsx              ServerConfigProvider (fetches `GET /api/v1/config` once on mount) +
│                                  useServerConfig hook for feature flags (aiEnabled / scaEnabled /
│                                  scaAutoScanEnabled)
├── router.tsx                   React Router v7 routes
├── types.ts                     TypeScript interfaces
├── styles.css                   Global dark-theme CSS
└── main.tsx                     React entrypoint
```
</details>

---

## Pages & routing

| Route | Component | Description |
| --- | --- | --- |
| `/` | `DashboardPage` | Home page with vulnerability search, recent entries, real-time refresh via SSE |
| `/vulnerabilities` | `VulnerabilityListPage` | Paginated list with full-text, vendor, product, version filters and an advanced filter set (severity, CVSS vector, EPSS, CWE, sources, time range) |
| `/vulnerability/:vulnId` | `VulnerabilityDetailPage` | Detail view with tabs (CWE / CAPEC / references / affected products / **Attack Path** with Mermaid graph + optional AI narrative / AI analysis / change history / raw), refresh dropdown (incl. OSV). The Attack Path tab is lazy-fetched: the backend always serves the deterministic graph; the AI narrative is optional via the *Generate scenario narrative* button (gated by `aiEnabled`). |
| `/query-builder` | `QueryBuilderPage` | Interactive DQL editor with field browser and aggregations |
| `/ai-analyse` | `AIAnalysePage` | AI-analysis history as a combined timeline of single-CVE, batch, and scan analyses (newest first; scan entries link to `/scans/{id}` and carry a commit / image chip); trigger form for new batch analyses. Origin chips (`API - Single` / `MCP - Single` / `API - Batch` / `MCP - Batch` / `API - Scan` / `MCP - Scan`) tell whether an analysis was stored through the HTTP API or via an MCP `save_*` tool. Conditional on `aiEnabled`. |
| `/stats` | `StatsPage` | Trend charts, top vendors / products, severity distribution |
| `/audit` | `AuditLogPage` | Ingestion-job logs with status and metadata |
| `/changelog` | `ChangelogPage` | Recent changes with pagination, date and job filters (incl. OSV in the job dropdown) |
| `/inventory` | `InventoryPage` | Environment inventory: three `.card` sections (intro + chips summary, add / edit form, items grid). Vendor / Product via `AsyncSelect<Option, false>` (same look as AdvancedFilters). Deployment as a chip-button group, environment as a free text field with `<datalist>` suggestions (prod / staging / dev / test / dr + previously used values). Item cards as `.vuln-card` with severity border coloured by the highest affected CVE, expandable *Show CVEs* list per entry. |
| `/system` | `SystemPage` | Single-card layout with header. 4 tabs: General (language, services, backup), Notifications (channels, rules incl. `inventory` type with optional item filter via native multi-select, templates incl. `inventory_match`), Data (sync status, re-sync with multi-ID / wildcards / delete-only, searches), Policies (license policies) |
| `/scans` | `ScansPage` | SCA scan management (Targets, Scans, Findings with links column + expandable detail row, SBOM with dynamic type filter from facets + summary cards + sorting + provenance filter, Security Alerts with category filter, Licenses, Scanner). Findings and SBOM rows show a links column with deps.dev, Snyk, Registry, socket.dev, bundlephobia (npm-only), npmgraph (npm-only). The Targets tab groups cards into **collapsible application sections** with severity roll-up (collapse state persisted via `usePersistentState('hecate.scan.groupCollapsed')`). Target cards: action row pinned bottom (flex column), inline-editable **App / Group** row with `<datalist>` suggestions from existing groups; SBOM-import targets without auto-scan, rescan, scanner-edit, and group-edit affordances. **Scanner tab**: live memory and disk charts plus an `AutoScanDiagnosticsTable` showing the latest `/check` probe per auto-scan target (timestamp, current vs. stored fingerprint, verdict pill with tooltip, error). Verdict pills are clickable buttons that trigger `POST /v1/scans/targets/{id}/check` and update the row in place — primary debug tool when a target is not auto-scanning. |
| `/scans/:scanId` | `ScanDetailPage` | Scan details with Findings (VEX multi-select toolbar with bulk apply / dismiss / restore, Show Dismissed toggle, inline VEX editor as an expandable row with status / justification / detail, VEX import button, links column with 6 pills, **Show attack path** per-finding expansion), **Attack Chain** (cross-CVE chain as a top-level tab between Findings and SBOM — stage-pill bar + Mermaid graph + optional AI narrative; purple accent), SBOM (sortable columns, clickable summary cards for filtering, provenance filter, links column), History (time-range filter 7d / 30d / 90d / All, commit-SHA links), Compare (up to 200 scans), Security Alerts, SAST, Secrets, Best Practices, Layer Analysis, License Compliance, VEX export |
| `/malware-feed` | `MalwareFeedPage` | Overview of all MAL-aliased OSV records (~417 k) for the **Security** sidebar group (sibling of SCA Scans). `/blocklist` is a legacy redirect. Card grid with search input, ecosystem dropdown (hard-coded slug list — without it, only npm / pypi would show, since those are the newest-modified records), and server pagination (`offset` / `limit`, 100/page). Substring search and ID lookups (MAL- / GHSA- / CVE patterns) are routed to OpenSearch on the backend (~50–100 ms); unfiltered and ecosystem-filtered pages run from MongoDB via the compound `(vendors, modified -1)` index (~30 ms cold with a warm count cache). |
| `/info/cicd` | `CiCdInfoPage` | CI/CD integration guide (pipeline examples, scanner reference, quality gates) |
| `/info/api` | `ApiInfoPage` | API documentation with embedded Swagger UI and endpoint overview |
| `/info/mcp` | `McpInfoPage` | MCP server info (IdP setup GitHub / Microsoft / OIDC, Claude Desktop guide, tools incl. `prepare_*` / `save_*` pairs and `get_sca_scan`, example prompts, configuration) |

> [!NOTE]
> Info pages live under `/info/*` so their paths cannot collide with the backend prefixes `/api*` and `/mcp*` when a reverse proxy forwards those by prefix. The legacy paths `/cicd`, `/api-docs`, and `/mcp-info` still exist as client-side React Router redirects (`<Navigate replace>`) for bookmark compatibility — but they only kick in once the SPA entry has loaded. A hard refresh on the legacy paths can still fail depending on the proxy rule.

Feature visibility (AI analysis, SCA scans, CI/CD, API, MCP) is determined at runtime via `GET /api/v1/config` and provided by `ServerConfigProvider` ([src/server-config/context.tsx](src/server-config/context.tsx)). The backend derives the flags from its own settings (AI = at least one provider key set, SCA = `sca_enabled`, auto-scan = `sca_auto_scan_enabled`). No image rebuild is required to change them — restart the backend.

---

## State management

No Redux / Zustand — built on React's own primitives:

| Mechanism | Usage |
| --- | --- |
| **Context API** | `SavedSearchesContext` — global saved searches |
| **SSE (`useSSE`)** | Real-time job events via singleton EventSource (Dashboard, VulnerabilityList, System, AI Analyse) |
| **`useState`** | Local component state (loading, error, data) |
| **URL parameters** | Filters, pagination, query mode (bookmarkable) |
| **localStorage** | Sidebar state, asset filter selection (`usePersistentState`) |

### Data-loading pattern

```text
useEffect → setLoading(true) → API call → setData / setError → setLoading(false)
```

Skeleton placeholders during loading.

---

## Styling

- **Custom CSS** in `styles.css` (~800+ lines), no CSS framework
- **Dark theme** with CSS variables (`#080a12` background, `#f5f7fa` text)
- **Severity colours** — Critical `#ff6b6b` · High `#ffa3a3` · Medium `#ffcc66` · Low `#8fffb0`
- **Responsive design** with CSS Grid / Flexbox; mobile sidebar as overlay
- A few components use inline `style` props for dynamic values

---

## Localisation

- **Languages:** German + English (simple i18n via Context API with the `t(english, german)` pattern)
- **Detection:** automatic from browser language, switchable, persisted in `localStorage`
- **No external i18n framework** (no i18next or similar)
- **Date format:** `DD.MM.YYYY HH:mm` (de-DE) / `MM/DD/YYYY` (en-US)
- **Timezone:** user setting on the System page (`/system` → General → Timezone); persisted in `localStorage` (`hecate.ui_timezone`); default is the browser timezone. Implementation in `src/timezone/`. `formatDate()` in [utils/dateFormat.ts](src/utils/dateFormat.ts) reads the current value per call via `getCurrentTimezone()`; [ui/AppLayout.tsx](src/ui/AppLayout.tsx) keys the React Router `<Outlet>` on the timezone value, so changes re-render the entire active page and every date formatter picks up the new value. The backend serialises every datetime field UTC-aware (`+00:00` suffix) so `new Date()` parses it correctly in the browser — see `backend/app/schemas/_utc.py`.

---

## Configuration

Build-time variables (baked into `dist/` at `pnpm run build`):

| Variable | Default | Description |
| --- | --- | --- |
| `VITE_API_BASE_URL` | `/api` | API base path (needed before the first backend call, hence not runtime-configurable) |

All other feature flags come from the backend at runtime through `GET /api/v1/config`:

- **AI features** — active when at least one AI provider is configured (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GOOGLE_GEMINI_API_KEY`, or `OPENAI_COMPATIBLE_BASE_URL` + `OPENAI_COMPATIBLE_MODEL` for Ollama / vLLM / OpenRouter / LocalAI / LM Studio)
- **SCA features** — `SCA_ENABLED` (backend)
- **Auto-scan toggle** — `SCA_AUTO_SCAN_ENABLED` (backend)

Share URLs are derived from `globalThis.location.origin` — no `VITE_DOMAIN` any more.

---

## Development

### Dependency management

This project uses [pnpm](https://pnpm.io/), managed via [Corepack](https://nodejs.org/api/corepack.html) (version pinned in `package.json`).

> [!IMPORTANT]
> Supply-chain protection: `minimumReleaseAge: 20160` in `pnpm-workspace.yaml` blocks packages younger than 14 days.

#### Add a new dependency

```sh
pnpm add <package-name>
pnpm add -D <package-name>     # dev-only

git add package.json pnpm-lock.yaml
git commit -m "Add <package-name> dependency"
```

#### Update dependencies

```sh
pnpm update                    # everything
pnpm update <package-name>     # a single package

git add pnpm-lock.yaml
git commit -m "Update dependencies"
```

#### Run the dev server

```sh
corepack enable pnpm && pnpm install && pnpm run dev
```

Dev server runs on port 3000 and proxies `/api` to `http://backend:8000` automatically.

### Linting

```sh
pnpm run lint
```

### Docker build

Multi-stage build (`dev → build → runtime`) on top of `node:24-alpine`. Static assets are served by `serve` on port 4173.

```sh
docker build -t hecate-frontend ./frontend
docker run -p 4173:4173 hecate-frontend
```

### Code splitting

Manual chunk split in `vite/chunk-split.ts`:

- `react-select` → own chunk
- `react-icons` → own chunk
- `axios` → own chunk
- `mermaid` + every exclusive sub-dependency (`@mermaid-js`, `cytoscape*`, `d3` / `d3-*`, `dagre` / `dagre-d3-es`, `katex`, `khroma`, `roughjs`, `langium`, `vscode-*`, `lodash-es`, `dayjs`, …) → `manualChunks` returns `undefined` so Rollup pulls the `import("mermaid")` into an async chunk.

> [!WARNING]
> Do **not** mark them as `return 'mermaid'`. That creates a `mermaid → vendor → mermaid` cycle (e.g. `lodash-es` is shared between `dagre-d3-es` and vendor code) and Rollup then preloads mermaid on the initial page load.

- All remaining `node_modules` → `vendor` chunk

### Why `pnpm-lock.yaml` matters

The lock file ensures:

- **Reproducible builds** — everyone uses the same dependency versions
- **Security scanning** — Trivy scans this file for vulnerabilities
- **Supply-chain safety** — pins exact versions to mitigate substitution attacks

Always commit `pnpm-lock.yaml` to version control.

---

## Tech stack

| Technology | Version | Purpose |
| --- | --- | --- |
| React | 19 | UI library |
| TypeScript | 5.9 | Type safety |
| Vite | 7 | Build tool + dev server |
| React Router | 7 | Client-side routing |
| Axios | 1.13 | HTTP client |
| react-markdown | 10 | Markdown rendering (AI summaries) |
| react-icons | 5.5 | Icon library (Lucide) |
| react-select | 5.10 | Async multi-select dropdowns |
| mermaid | 11.14 | Lazy-loaded for the Attack Path tab; Rollup splits it into an async chunk automatically (see *Code splitting* above) |
