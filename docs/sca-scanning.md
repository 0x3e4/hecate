# SCA Scanning

Software Composition Analysis (SCA) is the active half of Hecate. Where the vulnerability index tells
you what exists in the world, SCA tells you what is in *your* software: it scans your container images
and source repositories with ten tools running in a hardened sidecar, then consolidates everything
into one picture — dependency vulnerabilities, a software bill of materials, exposed secrets, static
analysis findings, container best-practice issues, and malicious-package indicators.

![SCA Scans](img/hecate-sca.png)

This page covers the building blocks: targets, the scanners, auto-scanning and status badges. Once a
scan has run, see [Reading Scan Results](sca/scan-results.md) for how to interpret every tab, and the
dedicated pages for the [Attack Chain](sca/attack-chain.md), [malware detection](sca/malware.md) and
[license compliance](sca/licenses.md).

## Targets

A **target** is a scannable entity identified by a path-like id — a container image reference such as
`ghcr.io/org/app`, or a source-repository URL. Register one on **SCA Scans → Targets**, or simply run
a scan and the target is created for you. Related targets (say the backend repo, the frontend repo and
the worker image of one product) can be grouped into a single **application**, and the Targets tab then
shows each group as a collapsible section with a combined severity roll-up.

Every target also has its own deep-linkable overview page at `/scans/targets/<id>`, reachable by
clicking a target card's title. It gathers the target's metadata, latest severity rollup, auto-scan
diagnostics, full scan history, top findings and quick actions (rescan, run a check, delete) in one
place — and because the URL is stable you can bookmark or share a link straight to it. When a target
is write-protected it shows a 🔒 badge; the password itself is managed from
**System → Access Control** (see [Security & Access Control](security-access-control.md)).

## Scanners

Ten scanners run inside the sidecar. Trivy, Grype and OSV Scanner find dependency vulnerabilities; Syft
builds the SBOM; the in-house Hecate Analyzer adds its own SBOM extractor, malware detection and
provenance checks; and the remaining four cover specialised, opt-in surfaces. Each target remembers the
scanners chosen at its first scan and reuses them for later auto-scans.

| Scanner | Purpose |
| --- | --- |
| trivy, grype, osv-scanner | Vulnerability detection |
| syft | SBOM generation |
| hecate | In-house SBOM extractor + malware detector + provenance |
| dockle | CIS Docker Benchmark, container images (Best Practices tab) |
| dive | Image-layer analysis, container images (Layer Analysis tab) |
| semgrep | SAST for source repositories |
| devskim | Microsoft SAST, strong .NET coverage (shares the SAST tab) |
| trufflehog | Secret scanning for source repositories |

The image-only scanners (Dockle, Dive) and the repo-only scanners (Semgrep, DevSkim, TruffleHog) only
produce output for the matching target type. Container images are pulled directly through registry
APIs — no Docker socket is mounted — and Dive uses Skopeo to fetch the image as an archive. Registry
and git credentials are supplied through the `SCANNER_AUTH` environment variable.

For source-repo targets the repository is cloned **once per scan** and the working tree is shared
across all scanners (rather than cloned once per scanner), so a scan no longer fires several
concurrent `git clone` of the same repo that could contend for bandwidth and trip the clone timeout.
The clone budget is `GIT_CLONE_TIMEOUT_SECONDS` (default 300 s); a clone failure surfaces as a single
clean error and marks the scan failed.

## Auto-scan

With `SCA_AUTO_SCAN_ENABLED=true`, the scheduler periodically probes each `autoScan` target through the
sidecar `/check` endpoint, comparing the current image digest or commit SHA against the stored
fingerprint, and only launches a full scan when something actually changed. Every probe writes its
outcome back onto the target — the last check time, the verdict, the current fingerprint, and the
underlying error string if the probe failed — and the **Scanner** tab surfaces all of this in a
per-target diagnostics table. The verdict pill is clickable, so you can re-probe a single target on
demand without waiting for the next cycle.

## Status badges

Hecate publishes shields.io-compatible badge endpoints that need no authentication. One renders the
severity summary for a specific scan; the other auto-resolves to a target's latest completed scan, so a
README badge always tracks the newest run. Wrap the shields.io image in a link to the target's detail
page to make the badge clickable:

```markdown
[![findings](https://img.shields.io/endpoint?url=https%3A%2F%2F<host>%2Fapi%2Fv1%2Fscans%2Ftargets%2F<id>%2Fshield)](https://<host>/scans/targets/<id>)
```

`<id>` is the path-encoded target id (for example `https%3A%2F%2Fgithub.com%2Forg%2Frepo`), encoded
once more inside the shields.io `?url=` parameter. The target detail page's **Copy badge** button
produces exactly this linked markdown for you.

## Grype performance on container images

For container-image targets, Grype matches against an **SBOM that Syft builds first**
(`grype sbom:<file>`) rather than re-pulling and re-cataloging the image itself. Image cataloging is the
slow, sometimes pathological step — feeding Grype a ready SBOM leaves only the fast vulnerability
matching, which keeps it from blowing past `GRYPE_TIMEOUT_SECONDS` on large images. If the SBOM step
fails for any reason, Grype falls back to scanning the image directly, so a scan never regresses to "no
Grype results". The Grype database is pre-warmed at scanner startup; for very large targets you can
still raise `GRYPE_TIMEOUT_SECONDS` and recreate the scanner.

## SBOM, VEX & licenses

Each scan produces a software bill of materials you can export as **CycloneDX 1.5** or **SPDX 2.3**, and
you can import an external SBOM to match its components against the vulnerability database without
running a scanner. Findings can be annotated with **VEX** status (`not_affected`, `affected`, `fixed`,
`under_investigation`) and dismissed when irrelevant — both carry forward automatically onto matching
findings on the next rescan, and VEX exports and imports as CycloneDX VEX. **License compliance** checks
every component's licenses against your policy after each scan. These workflows are covered in depth in
[Reading Scan Results](sca/scan-results.md) and [License Compliance](sca/licenses.md).

## CI/CD submission

Pipelines submit scans to `POST /api/v1/scans` with the `X-API-Key` header (`SCA_API_KEY`). This
endpoint is deliberately independent of the System password gate so CI does not need the admin
password. See [CI/CD](integrations/cicd.md) for pipeline examples and badge embedding.
