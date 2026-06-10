# User Guide

This guide walks through Hecate the way you actually use it — page by page, with what each screen is
for and what you can do there. If you have just brought the stack up, start with
[Getting Started](../getting-started.md); if you want the engineering internals instead, jump to the
[Architecture](../architecture.md) reference.

## How Hecate works

Everything in Hecate flows in one direction: **intelligence comes in, your software is measured
against it, and what matters comes out.**

On the intake side, nine feeds (EUVD, NVD, CISA KEV, CPE, CWE, CAPEC, CIRCL, GHSA and OSV) are pulled
on a schedule and folded into a single normalised record per vulnerability. Hecate reconciles the
same CVE arriving from several sources, keeps a change history, and indexes the result in OpenSearch
so search stays fast even across hundreds of thousands of records.

On the measurement side, the scanner sidecar inspects your container images and source repositories,
and an environment inventory you maintain by hand records the products and versions you run. Findings
and inventory entries are matched back against the vulnerability index, then ranked by the signals
that predict real risk — CVSS, EPSS exploit probability, CISA known-exploited status, and whether a
package has been flagged malicious.

What comes out is the part you act on: a prioritised list of what affects you, attack-path and
attack-chain visualisations that explain *how* a weakness could be abused, optional AI triage, SBOM
and VEX exports for compliance, and notifications that reach you on Slack, email, or any Apprise
channel.

```text
   Feeds ──► Normalise & index ──►  Search / Inventory match / SCA scan  ──► Act
 (9 sources)   (MongoDB + OpenSearch)        (rank by EPSS / KEV / malware)   (alerts, exports, AI)
```

## The navigation, at a glance

The sidebar groups pages by what you are trying to do. Each card below links to the part of this
guide that covers it.

<div class="grid cards" markdown>

-   :material-view-dashboard-outline: **Dashboard**

    The day's newly published CVEs, a quick ID lookup, and a live feed.
    → [Dashboard](dashboard.md)

-   :material-magnify: **Vulnerabilities**

    Search and filter the whole index, then drill into a single CVE's detail tabs.
    → [Vulnerabilities](vulnerabilities.md)

-   :material-code-braces: **Search & Query Builder**

    Keyword, DQL and regex modes, the visual field browser, and saved searches.
    → [Search & Query Builder](search.md)

-   :material-clipboard-list-outline: **Environment Inventory**

    Declare what you run; see exactly which CVEs touch each entry.
    → [Environment Inventory](inventory.md)

-   :material-robot-outline: **AI Analysis**

    Single and batch CVE triage, scan triage, and attack-path narratives.
    → [AI Analysis & Attack Paths](ai-analysis.md)

-   :material-chart-line: **Statistics & Changelog**

    Trends across the index and a feed of what changed in each ingestion.
    → [Statistics & Changelog](statistics.md)

-   :material-shield-search: **SCA Scanning**

    Register targets, run scans, and read findings, SBOMs, secrets and SAST.
    → [SCA Scanning](../sca-scanning.md)

-   :material-bug-outline: **Malware**

    The supply-chain malware detector and the `MAL-*` feed overview.
    → [Malware Detection & Feed](../sca/malware.md)

-   :material-connection: **Integrations**

    MCP, CI/CD scan submission, the REST API, and notifications.
    → [MCP Server](../integrations/mcp.md)

-   :material-cog-outline: **Administration**

    System settings, access control, and the audit log.
    → [System Settings](../admin/system.md)

</div>

## A few conventions

A handful of things are true everywhere, so they are worth knowing once.

**Reading is always free; writing can be gated.** Browsing, searching and viewing scans never needs a
password. Mutating actions can be protected by a shared admin password (and, optionally, per-target
or AI passwords). If a write is blocked, the UI prompts you for the right password and retries — see
[Security & Access Control](../security-access-control.md).

**The UI updates live.** Long-running jobs (ingestion, scans, AI analysis) stream their progress over
Server-Sent Events, so lists and detail pages refresh themselves as work completes — you rarely need
to reload.

**Language, timezone and date format follow your settings.** Hecate speaks English and German, and
every timestamp is rendered in the timezone you pick on the System page. Set both under
**System → General**.
