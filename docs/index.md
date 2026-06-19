# Hecate

Hecate is a self-hosted **vulnerability management and software-composition-analysis (SCA)**
platform. It pulls vulnerability intelligence from nine upstream feeds, normalises everything into
one schema, indexes it for fast search, scans your container images and source repositories, and
then tells you what actually affects the products you run — in the web UI, over a REST API, and
through an MCP server you can talk to from Claude Desktop.

![Hecate dashboard](img/hecate-dash.png)

## What it does

Hecate sits between the raw vulnerability world and your environment. On the **intake** side it
continuously ingests EUVD, NVD, CISA KEV, CPE, CWE, CAPEC, CIRCL, GHSA and OSV, reconciles
duplicates across sources, and keeps a change history. On the **output** side it scans your software
with ten scanners, matches findings against your declared inventory, and surfaces the handful of
issues that genuinely matter — enriched with EPSS, known-exploited status, attack paths, and
optional AI triage.

<div class="grid cards" markdown>

-   :material-magnify: **Vulnerability intelligence**

    Nine feeds normalised into one searchable index with keyword, DQL and regex modes, saved
    searches, and a visual query builder. → [Vulnerabilities](guide/vulnerabilities.md)

-   :material-shield-search: **SCA scanning**

    Ten scanners in a hardened sidecar produce findings, SBOMs, secrets, SAST results and malware
    indicators for images and repos. → [SCA Scanning](sca-scanning.md)

-   :material-bug-outline: **Malware watch**

    A continuous OSV `MAL-*` watcher retroactively flags packages that turned malicious *after* your
    last scan. → [Malware Detection & Feed](sca/malware.md)

-   :material-clipboard-list-outline: **Environment inventory**

    Declare what you run and Hecate tells you which CVEs touch it (down to the version) and its end-of-life status.
    → [Environment Inventory](guide/inventory.md)

-   :material-robot-outline: **AI analysis**

    Optional per-CVE / per-scan triage and attack-path narratives via OpenAI, Anthropic, Gemini, or
    any OpenAI-compatible endpoint. → [AI Analysis & Attack Paths](guide/ai-analysis.md)

-   :material-connection: **MCP server**

    Query everything in natural language from Claude Desktop, Cursor, or VS Code.
    → [MCP Server](integrations/mcp.md)

</div>

## Where to start

<div class="grid cards" markdown>

-   :material-rocket-launch-outline: **New here?**

    Stand up the Docker Compose stack in a few minutes. → [Getting Started](getting-started.md)

-   :material-book-open-variant: **Learn the UI**

    A guided tour of every page and what you can do on it. → [User Guide](guide/overview.md)

-   :material-lock-outline: **Going live?**

    By default the REST write surface is open — lock it down before exposing the instance.
    → [Security & Access Control](security-access-control.md)

-   :material-cog-outline: **Tuning a deployment?**

    Every environment variable, grouped and explained. → [Configuration](configuration.md)

</div>

!!! note "Documentation status"
    This site is built from the repository with MkDocs Material and published on Read the Docs.
    For contributor-level detail, see the component `README.md` files in the repository
    (`backend/`, `frontend/`, `scanner/`).
