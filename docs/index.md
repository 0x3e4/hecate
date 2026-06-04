# Hecate

Hecate is a self-hosted **vulnerability management and software-composition-analysis (SCA)**
platform. It aggregates vulnerability intelligence from nine upstream feeds, indexes it for
fast search, scans your container images and source repositories, and surfaces what actually
affects the products you run.

## What it does

- **Vulnerability aggregation** — EUVD, NVD, CISA KEV, CPE, CWE, CAPEC, CIRCL, GHSA and OSV are
  normalised into one schema and indexed in OpenSearch for keyword, DQL and regex search.
- **SCA scanning** — ten scanners (Trivy, Grype, Syft, osv-scanner, the in-house Hecate
  analyzer, Dockle, Dive, Semgrep, TruffleHog, DevSkim) run in a hardened sidecar against
  container images and repositories, producing findings, SBOMs, secrets, SAST and malware
  indicators.
- **Malware watch** — a continuous OSV `MAL-*` watcher retroactively flags packages that turned
  malicious after your last scan.
- **Environment inventory** — declare what you run and Hecate tells you which CVEs touch it.
- **AI analysis** — optional per-CVE / per-scan triage and attack-path narratives via OpenAI,
  Anthropic, Gemini, or any OpenAI-compatible endpoint.
- **MCP server** — query everything in natural language from Claude Desktop, Cursor, or VS Code.

## Where to start

- New here? Read **[Getting Started](getting-started.md)**.
- Standing up a live instance? See **[Configuration](configuration.md)** and especially
  **[Security & Access Control](security-access-control.md)** — by default the REST write
  surface is open, and you almost certainly want to lock it down.
- Scanning images/repos? See **[SCA Scanning](sca-scanning.md)**.
- Want the internals? See **[Architecture](architecture.md)**.

!!! note "Documentation status"
    This site is built from the repository with MkDocs Material and published on Read the Docs.
    The canonical, always-current reference for contributors remains `CLAUDE.md` and the
    component `README.md` files in the repository.
