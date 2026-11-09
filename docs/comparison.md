# How Hecate compares

Status: November 2026. Corrections welcome – [open an issue](https://github.com/0x3e4/hecate/issues)
if something is outdated.

This page compares Hecate with four self-hosted open-source tools and two SaaS products, row by row,
with a source for every cell. Values for the other products come only from their official
documentation, website or GitHub repositories, read on 2026-11-09. Hecate's values were checked
against its own code, not against its README. `?` means the official sources do not settle it.

The tools do not all solve the same problem. Dependency-Track manages the components of your SBOMs,
DefectDojo collects findings from other scanners, OpenCVE and Vulnerability-Lookup are vulnerability
databases with alerting, Snyk and Aikido are commercial developer-security platforms. Hecate sits
between them: an advisory database with search, plus its own scanners. Where another product is
clearly further along — maturity, community, policy engine, integrations, commercial support — the
table says so.

## Overview

| | Hecate | Dependency-Track | OpenCVE (Community Edition) | DefectDojo (open source) | Vulnerability-Lookup | Snyk | Aikido |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **1. Operating model** | Self-hosted (Docker Compose) | Self-hosted (Compose, Helm) | Self-hosted; separate SaaS (OpenCVE Cloud) | Self-hosted; Pro also SaaS or on-prem | Self-hosted, plus public instances (CIRCL, GCVE) | SaaS; single-tenant private cloud on Enterprise | SaaS; local scanner, on-prem appliance |
| **2. License** | MIT | Apache-2.0 | BUSL-1.1, Apache-2.0 from 2030-08-14 | BSD-3-Clause | AGPL-3.0 | Proprietary; CLI, Broker and MCP server Apache-2.0 | Proprietary; Zen and Safe Chain AGPL or commercial |
| **3. Searchable advisory database** | Yes: keyword, DQL and regex over CVE, GHSA, OSV, MAL and EUVD records | Mirrors NVD, GHSA, OSV; look up a vulnerability and its affected projects | Yes, CVE IDs only, with a query language | No, holds imported findings only | Yes, full-text and REST API | Yes, security.snyk.io | Yes, Aikido Intel (browse by ecosystem) |
| **4. Data sources** | EUVD, NVD, CISA KEV, GHSA, OSV, CIRCL (EPSS), CPE, CWE, CAPEC, plus CERT, vendor and community feeds | NVD, GHSA, OSV, analyzers (OSS Index, Snyk, Trivy, VulnDB); EUVD only as EU KEV flag | MITRE, NVD, CISA Vulnrichment/KEV, Red Hat, EPSS; EUVD not in docs | Reports from 360+ tool parsers; EUVD not in docs | NVD, CVE list, GHSA, OSV feeds, CSAF from 50+ providers, national databases; EUVD only as KEV catalog | NVD and other databases plus own research; EUVD not mentioned | Aikido Intel, NVD, GHSA, distribution trackers; EUVD not listed |
| **5. Version-range search** | `affectedVersion:7.0.1` finds advisories whose ranges cover it | Ranges matched internally; user search by version not in docs | No (vendor/product only) | No | Not documented | Per-version package pages | Not documented (ranges shown per advisory) |
| **6. SCA scanning of images and repos** | Trivy, Grype, Syft, OSV-Scanner, Semgrep, TruffleHog, DevSkim, Dockle, Dive, Hecate Analyzer, in a sidecar | No, ingests SBOMs | No | No, imports scanner results | No | Yes (Open Source, Container) | Yes (repos, images) |
| **7. SBOM import / export** | Import CycloneDX and SPDX (JSON); export CycloneDX 1.5, SPDX 2.3 | Import CycloneDX; export CycloneDX (BOM, VDR, VEX) | None | Import CycloneDX, SPDX; export Pro only | None documented | CycloneDX 1.4–1.6, SPDX 2.3; Enterprise only | Import CycloneDX, SPDX (API); export CSV, SPDX, CycloneDX |
| **8. VEX** | CycloneDX VEX import/export; CycloneDX VEX and OpenVEX sources applied after every scan; carried forward between scans | CycloneDX VEX import/export, VDR export | None | OpenVEX import; export Pro only | Reads vendor CSAF VEX (Red Hat, Microsoft, SUSE) | ? | CycloneDX export with VEX analysis |
| **9. Supply-chain malware** | 35 heuristic rules, OSV MAL-* feed, watcher that re-checks existing SBOMs | No feed; component integrity check | Not documented | Not documented | OpenSSF Malicious Packages data | Malicious packages in the database (CWE-506) | Malware scanning (Pro and up), Safe Chain, Intel feed |
| **10. AI features** | Optional, off by default; local via Ollama, vLLM, LM Studio or cloud providers | None | Optional report summaries, local OpenAI-compatible models; more in Cloud | None (AI is Pro only) | Optional ML-Gateway, local models | DeepCode AI, Agent Fix; no local models documented | AutoFix, AutoTriage and more; local models only on the Aikido Machine |
| **11. Works fully without AI** | Yes | Yes | Yes | Yes | Yes (ML-Gateway is a separate service) | ? | Partly; ? |
| **12. MCP server** | Built in, 40 tools, OAuth | None official | None | Separate official repo; built in on Pro | VulnMCP (separate repo in the project's organisation) | Yes, in the CLI (local) | Yes, `@aikidosec/mcp` |
| **13. Notifications / integrations** | Apprise (Slack, Teams, email, Signal, webhooks, …), REST API, CI submission with API tokens; no ticketing | Email, Slack, Teams, Jira, Kafka, Mattermost, Webex, webhooks; DefectDojo, Fortify SSC, Kenna | Email, Slack, webhooks | Email, Slack, Teams, webhooks; Jira and GitHub Issues with two-way sync | Email/webhook watchlists, RSS, MISP, API | SCM, CI, IDE, Jira, Slack, webhooks (beta) | Slack, Teams, webhooks, 14 task trackers, CI, SIEM (by plan) |
| **14. Project started** | 2025 | 2013 | 2020 | 2015 | 2022 | 2015 | 2022 |
| **15. Policy engine** | License policies (SPDX allow/deny); severity gate in the CI step | CEL policies for components and vulnerabilities, build-breaking gates | ? | ? | ? | ? | ? |
| **16. Commercial support** | None | None found | OpenCVE Cloud plans | DefectDojo Pro | ? | Paid plans | Paid plans, SLA tiers |

Project start is the first commit or repository creation for the open-source projects and the
founding year for Snyk and Aikido.

## Where the others are ahead

- **Maturity and community.** Dependency-Track (OWASP, since 2013), DefectDojo (since 2015) and
  OpenCVE (since 2020) have long release histories and many contributors. Hecate is a young solo
  project.
- **Policy engine.** Dependency-Track evaluates component and vulnerability policies written in CEL
  and can break builds on them. Hecate has license policies and a severity gate in the CI step only.
- **Integrations and workflow.** DefectDojo imports results from 360+ tools and syncs Jira and GitHub
  Issues both ways. Snyk and Aikido integrate with SCMs, CI systems, IDEs and ticketing tools and open
  fix pull requests. Hecate has no ticketing integration.
- **Breadth of sources.** Vulnerability-Lookup reads national databases (China, Japan, Russia,
  France), CSAF from more than 50 providers and many OSV feeds.
- **Commercial backing.** Snyk, Aikido, DefectDojo Pro and OpenCVE Cloud come with paid support.
  Hecate has none.

## Sources

### Hecate

Checked against the code at commit `9cbc5c1` plus the 2.2.1 changes.

- **Row 1:** [`docker-compose.yml.example`](https://github.com/0x3e4/hecate/blob/main/docker-compose.yml.example)
- **Row 2:** [`LICENSE`](https://github.com/0x3e4/hecate/blob/main/LICENSE)
- **Row 3:** [`vulnerability_service.py`](https://github.com/0x3e4/hecate/blob/main/backend/app/services/vulnerability_service.py) (keyword, DQL, regex search)
- **Row 4:** [`services/ingestion/`](https://github.com/0x3e4/hecate/tree/main/backend/app/services/ingestion) (EUVD, NVD, KEV, GHSA, OSV, CIRCL, CPE pipelines; CWE and CAPEC services; advisory feeds)
- **Row 5:** [`version_ranges.py`](https://github.com/0x3e4/hecate/blob/main/backend/app/services/version_ranges.py), [`inventory_matcher.py`](https://github.com/0x3e4/hecate/blob/main/backend/app/services/inventory_matcher.py)
- **Row 6:** [`scanner/app/main.py`](https://github.com/0x3e4/hecate/blob/main/scanner/app/main.py) (`VALID_SCANNERS`)
- **Row 7:** [`sbom_export.py`](https://github.com/0x3e4/hecate/blob/main/backend/app/services/sbom_export.py), [`scan_parser.py`](https://github.com/0x3e4/hecate/blob/main/backend/app/services/scan_parser.py)
- **Row 8:** [`vex_service.py`](https://github.com/0x3e4/hecate/blob/main/backend/app/services/vex_service.py), [`vex_source_service.py`](https://github.com/0x3e4/hecate/blob/main/backend/app/services/vex_source_service.py)
- **Row 9:** [`malware_detector/rules.py`](https://github.com/0x3e4/hecate/blob/main/scanner/app/malware_detector/rules.py), [`sca_malware_watch_service.py`](https://github.com/0x3e4/hecate/blob/main/backend/app/services/sca_malware_watch_service.py)
- **Row 10:** [`ai_service.py`](https://github.com/0x3e4/hecate/blob/main/backend/app/services/ai_service.py), [`api/v1/config.py`](https://github.com/0x3e4/hecate/blob/main/backend/app/api/v1/config.py) (`aiEnabled` only with a configured provider)
- **Row 11:** [`Sidebar.tsx`](https://github.com/0x3e4/hecate/blob/main/frontend/src/ui/Sidebar.tsx), [`VulnerabilityDetailPage.tsx`](https://github.com/0x3e4/hecate/blob/main/frontend/src/views/VulnerabilityDetailPage.tsx) (AI views hidden without a provider)
- **Row 12:** [`backend/app/mcp/`](https://github.com/0x3e4/hecate/tree/main/backend/app/mcp)
- **Row 13:** [`notification_service.py`](https://github.com/0x3e4/hecate/blob/main/backend/app/services/notification_service.py), [CI/CD guide](integrations/cicd.md)
- **Row 14:** Git history (first commit 2025-10-16, tag 1.0.0 2026-05-11); [GitHub API](https://api.github.com/repos/0x3e4/hecate)
- **Row 15:** [`license_compliance_service.py`](https://github.com/0x3e4/hecate/blob/main/backend/app/services/license_compliance_service.py), [CI/CD guide](integrations/cicd.md#using-results-as-a-quality-gate)

### Dependency-Track

Version 5 is the current line (5.2.1, 2026-10-25); version 4 is in maintenance until December 2026.

- **Row 1:** <https://dependencytrack.org/>, <https://dependencytrack.github.io/docs/next/concepts/changes-in-v5/>
- **Row 2:** <https://api.github.com/repos/DependencyTrack/dependency-track>
- **Row 3:** <https://dependencytrack.github.io/docs/next/concepts/about-vulnerability-data-sources/>, <https://docs.dependencytrack.org/usage/impact-analysis/>
- **Row 4:** <https://dependencytrack.github.io/docs/next/reference/analyzers/>, <https://dependencytrack.github.io/docs/next/concepts/about-kev-data-sources/>
- **Row 5:** <https://dependencytrack.github.io/docs/next/reference/datasources/private-vulnerability-repository/>
- **Row 6:** <https://dependencytrack.github.io/docs/next/guides/user/uploading-boms/>
- **Row 7:** <https://dependencytrack.github.io/docs/next/reference/file-formats/>
- **Row 8:** <https://dependencytrack.github.io/docs/next/reference/vex-and-vdr/>
- **Row 9:** <https://dependencytrack.github.io/docs/next/concepts/component-integrity-verification/>
- **Rows 10–11:** <https://dependencytrack.github.io/docs/next/>, <https://github.com/DependencyTrack/dependency-track/releases/tag/5.2.0> (no AI documented)
- **Row 12:** <https://github.com/orgs/DependencyTrack/repositories> (no MCP repository)
- **Row 13:** <https://dependencytrack.github.io/docs/next/reference/notifications/publishers/>
- **Row 14:** <https://api.github.com/repos/DependencyTrack/dependency-track>
- **Row 15:** <https://dependencytrack.github.io/docs/next/concepts/changes-in-v5/>
- **Row 16:** <https://dependencytrack.org/> (no paid offering found)

### OpenCVE (Community Edition)

Release 3.1.0. Features of OpenCVE Cloud are named as such.

- **Row 1:** <https://github.com/opencve/opencve>, <https://www.opencve.io/pricing>
- **Row 2:** <https://github.com/opencve/opencve/blob/master/LICENSE>
- **Row 3:** <https://docs.opencve.io/guides/advanced_search/>, <https://docs.opencve.io/concepts/kb/>
- **Row 4:** <https://docs.opencve.io/concepts/kb/>
- **Row 5:** <https://docs.opencve.io/guides/advanced_search/>
- **Rows 6–9:** <https://docs.opencve.io/> (no scanning, SBOM, VEX or malware features documented)
- **Rows 10–11:** <https://docs.opencve.io/guides/report_summaries/>
- **Row 12:** <https://github.com/opencve/opencve/blob/master/CHANGELOG.md> (REST API, no MCP)
- **Row 13:** <https://docs.opencve.io/concepts/notifications/>
- **Row 14:** <https://api.github.com/repos/opencve/opencve>, <https://github.com/opencve/opencve/blob/master/CHANGELOG.md>
- **Row 16:** <https://www.opencve.io/pricing>

### DefectDojo (open source)

The comparison of editions at <https://docs.defectdojo.com/get_started/about/defectdojo_versions/>
covers most rows. The docs give "360+ built-in parsers" for the open-source edition there and
"500+ security tools" on other pages.

- **Row 1:** <https://docs.defectdojo.com/get_started/about/defectdojo_versions/>
- **Row 2:** <https://api.github.com/repos/DefectDojo/django-DefectDojo>
- **Rows 3–5:** <https://docs.defectdojo.com/get_started/about/about_defectdojo/>, <https://docs.defectdojo.com/supported_tools/>
- **Row 6:** <https://docs.defectdojo.com/supported_tools/>
- **Row 7:** <https://docs.defectdojo.com/supported_tools/parsers/file/cyclonedx/>, <https://docs.defectdojo.com/supported_tools/parsers/file/spdx/>
- **Row 8:** <https://docs.defectdojo.com/supported_tools/parsers/file/openvex/>, <https://docs.defectdojo.com/asset_modelling/locations/pro__exporting_sboms_and_vex/>
- **Rows 10–11:** <https://docs.defectdojo.com/get_started/about/defectdojo_versions/>
- **Row 12:** <https://github.com/DefectDojo/defectdojo-mcp>, <https://docs.defectdojo.com/metrics_reports/ai/mcp_server_pro/>
- **Row 13:** <https://docs.defectdojo.com/admin/notifications/about_notifications/>
- **Row 14:** <https://api.github.com/repos/DefectDojo/django-DefectDojo>
- **Row 16:** <https://docs.defectdojo.com/get_started/about/defectdojo_versions/>

### Vulnerability-Lookup

- **Row 1:** <https://github.com/vulnerability-lookup/vulnerability-lookup>
- **Row 2:** <https://api.github.com/repos/vulnerability-lookup/vulnerability-lookup>
- **Row 3:** <https://github.com/vulnerability-lookup/vulnerability-lookup/blob/main/docs/api.md>
- **Row 4:** <https://www.vulnerability-lookup.org/sources>, <https://github.com/vulnerability-lookup/vulnerability-lookup/blob/main/CHANGELOG.md>
- **Row 5:** <https://vulnerability.circl.lu/api/swagger.json>
- **Rows 6–7:** <https://www.vulnerability-lookup.org/documentation/> (no scanning or SBOM documented)
- **Row 8:** <https://github.com/vulnerability-lookup/vulnerability-lookup/blob/main/docs/api.md>
- **Row 9:** <https://github.com/vulnerability-lookup/vulnerability-lookup> (OpenSSF Malicious Packages feeder)
- **Rows 10–11:** <https://github.com/vulnerability-lookup/vulnerability-lookup/blob/main/docs/architecture.md>, <https://github.com/vulnerability-lookup/ML-Gateway>
- **Row 12:** <https://github.com/vulnerability-lookup/VulnMCP>
- **Row 13:** <https://github.com/vulnerability-lookup/vulnerability-lookup/blob/main/docs/notification.md>
- **Row 14:** <https://api.github.com/repos/vulnerability-lookup/vulnerability-lookup>

### Snyk

- **Row 1:** <https://snyk.io/platform/deployment-options/>
- **Row 2:** <https://github.com/snyk/cli>, <https://github.com/snyk/broker>, <https://github.com/snyk/studio-mcp>
- **Rows 3–4:** <https://security.snyk.io/>, <https://docs.snyk.io/scan-with-snyk/snyk-open-source/manage-vulnerabilities/snyk-vulnerability-database>
- **Row 5:** <https://security.snyk.io/package/npm/lodash/4.17.20>
- **Row 6:** <https://docs.snyk.io/scan-with-snyk/snyk-open-source>, <https://docs.snyk.io/developer-tools/snyk-cli/commands/container-test>
- **Row 7:** <https://docs.snyk.io/developer-tools/snyk-cli/commands/sbom>, <https://docs.snyk.io/developer-tools/snyk-cli/commands/sbom-test>
- **Row 9:** <https://docs.snyk.io/scan-fix-and-prevent/fix/prioritize-issues-for-fixing/malicious-packages>
- **Row 10:** <https://snyk.io/platform/deepcode-ai/>, <https://docs.snyk.io/scan-with-snyk/snyk-code/manage-code-vulnerabilities/fix-code-vulnerabilities-automatically>
- **Row 12:** <https://docs.snyk.io/integrations/developer-guardrails-for-agentic-workflows/snyk-mcp-installation-configuration-and-startup>
- **Row 13:** <https://docs.snyk.io/integrations>, <https://snyk.io/plans/>
- **Row 14:** <https://snyk.io/about/>
- **Row 16:** <https://snyk.io/plans/>

### Aikido

- **Row 1:** <https://www.aikido.dev/code/local-scanner>, <https://www.aikido.dev/attack/aikido-machine>
- **Row 2:** <https://github.com/AikidoSec/safe-chain/blob/main/LICENSE>, <https://github.com/AikidoSec/firewall-node/blob/main/LICENSE>
- **Row 3:** <https://intel.aikido.dev>
- **Row 4:** <https://help.aikido.dev/code-scanning/scanning-practices/external-vulnerability-databases-used-in-our-sca-engine>
- **Row 5:** <https://intel.aikido.dev/cve/AIKIDO-2026-303617>
- **Row 6:** <https://help.aikido.dev/container-image-scanning/container-image-scanning-overview>
- **Rows 7–8:** <https://help.aikido.dev/compliance-and-reporting/licenses-and-sbom-overview/sbom>
- **Row 9:** <https://help.aikido.dev/code-scanning/scanning-practices/malware-detection-in-open-source-dependencies>, <https://github.com/AikidoSec/safe-chain>
- **Rows 10–11:** <https://help.aikido.dev/ai-and-dev-tools/how-aikido-uses-ai>, <https://help.aikido.dev/aikido-agent/secrets-autotriage>
- **Row 12:** <https://help.aikido.dev/ai-and-dev-tools/aikido-mcp>
- **Row 13:** <https://help.aikido.dev/getting-started/chat-and-alerts>
- **Row 14:** <https://www.aikido.dev/company/about>
- **Row 16:** <https://www.aikido.dev/pricing>
