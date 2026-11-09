# Reddit launch post (draft)

Not part of the documentation site: `docs/` is the MkDocs source, so this draft lives here.

## Before posting

- Subreddits: r/blueteamsec, r/devsecops, r/cybersecurity. r/netsec only with a technical write-up,
  not as a tool announcement.
- Read each subreddit's self-promotion rules first (some require a ratio of other contributions,
  a flair, or a weekly thread).
- No calls for upvotes, no cross-posting to all subreddits on the same day.
- Post only after the 2.2.1 release is live on the demo: the README badge and the demo's own repo
  scan showed image packages from `vex/*.cdx.json` as repository findings until the OSV-Scanner fix.
- Every claim below is checked against the code; re-check if features change before posting.

## Title

Hecate – open-source, self-hosted vulnerability management (NVD/EUVD/OSV/GHSA/KEV, SCA, SBOM/VEX, malware feed)

## Text

I've been building Hecate, an MIT-licensed vulnerability management platform you can run yourself.

What it does without any AI:

- Aggregates 9 vulnerability data sources (NVD, EUVD, CISA KEV, GHSA, OSV, CIRCL, CPE, CWE, CAPEC) plus CERT and vendor advisory feeds into one searchable catalogue
- Version-range search: `affectedVersion:7.0.1` finds advisories that cover it in a range, not just literal mentions
- Scans container images and repos with Trivy, Grype, Syft, OSV-Scanner, Semgrep, TruffleHog and more in a hardened sidecar
- SBOM export/import (CycloneDX/SPDX), VEX with carry-forward between scans, license policies
- Supply-chain malware detection: heuristics based on real incidents plus a watcher that flags OSV MAL-* advisories against your existing SBOMs retroactively
- Deterministic attack-path graph per CVE (CWE → CAPEC → exploit → fix) and an ATT&CK kill chain per scan
- Inventory matching, notifications via Apprise (Slack, Teams, mail, Signal…)

AI is optional and off by default. If you want it, it works with local models (Ollama, vLLM) or cloud providers and only adds narrative/triage on top. There's also an MCP server if you want to query it from an assistant.

It's a solo project, so I'm mainly looking for feedback from people doing vuln management day to day: what's missing, what's wrong, what would stop you from using it.

Repo: https://github.com/0x3e4/hecate
Demo: https://hecate.pw
