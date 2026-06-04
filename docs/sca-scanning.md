# SCA Scanning

Hecate scans **container images** and **source repositories** with ten scanners running in a
hardened sidecar, then consolidates the output into findings, SBOMs, secrets, SAST results,
malware indicators and license compliance.

![Scan findings](img/hecate-scan-find.png)

## Targets

A **target** is a scannable entity identified by a path-like id (e.g. `ghcr.io/org/app` or a repo
URL). Register one on **SCA Scans → Targets**, or it is created automatically on first scan.
Targets can be grouped into applications.

### Per-target overview page

Each target has its own deep-linkable page at `/scans/targets/<id>` (the target card title links
to it). It shows:

- target metadata (type, group, registry/repo, scanners, auto-scan state)
- the latest severity rollup and a link to the latest scan
- last auto-scan `/check` diagnostics
- scan history, top findings, and quick actions (rescan, run check, delete)
- **Write protection** — set or clear the target's own write password (admin), with a 🔒 badge
  when protected. See [Security & Access Control](security-access-control.md).

Because the URL is stable, you can bookmark or share a link straight to a specific target.

## Scanners

| Scanner | Purpose |
| --- | --- |
| trivy, grype, osv-scanner | Vulnerability detection |
| syft | SBOM generation |
| hecate | In-house SBOM extractor + malware detector |
| dockle | CIS Docker Benchmark (images) |
| dive | Image-layer analysis (images) |
| semgrep | SAST (repos) |
| trufflehog | Secret scanning (repos) |
| devskim | SAST |

## Auto-scan

When `SCA_AUTO_SCAN_ENABLED=true`, the scheduler periodically probes each `autoScan` target via the
sidecar `/check` endpoint (image digest / commit SHA) and only re-scans when the fingerprint
changed. The **Scanner** tab shows a per-target diagnostics table with the last verdict; the
verdict pill is clickable to re-probe on demand.

## Status badges

Public, no-auth shields.io endpoints render a severity badge for a scan or a target's latest scan.
Wrap the shields.io image in a link to the target's detail page so the badge is clickable:

```markdown
[![findings](https://img.shields.io/endpoint?url=https%3A%2F%2F<host>%2Fapi%2Fv1%2Fscans%2Ftargets%2F<id>%2Fshield)](https://<host>/scans/targets/<id>)
```

`<id>` is the path-encoded target id (e.g. `https%3A%2F%2Fgithub.com%2Forg%2Frepo`); it is encoded
once more inside the shields.io `?url=` parameter. The target detail page's **Copy badge** button
copies exactly this linked markdown for you.

## SBOM, VEX & licenses

- **SBOM** export in CycloneDX 1.5 and SPDX 2.3; external SBOM import is supported.
- **VEX** annotations (`not_affected` / `affected` / `fixed` / `under_investigation`) and dismissals
  carry forward across rescans and export/import as CycloneDX VEX.
- **License compliance** evaluates SBOM component licenses against your policies after every scan.

## CI/CD submission

Pipelines submit scans to `POST /api/v1/scans` with the `X-API-Key` header (`SCA_API_KEY`). This
endpoint is independent of the System password gate. See the in-app **CI/CD** info page
(`/info/cicd`) for pipeline examples.
