# DefectDojo

If your team keeps its findings in [DefectDojo](https://defectdojo.com/), Hecate hands each scan over
as one file: a CycloneDX BOM that lists the scan's components **and** its vulnerabilities. DefectDojo
reads it with its built-in **CycloneDX Scan** parser, so nothing has to be installed on either side.
Tested with DefectDojo 3.5.300.

## What the file carries

Download it from the scan's **SBOM** tab with **CycloneDX + vulnerabilities**, or from the API:

```bash
curl -o shop.cdx.json \
  "https://hecate.pw/api/v1/scans/<scanId>/sbom/export?format=cyclonedx-json&vulnerabilities=true"
```

It is the ordinary CycloneDX 1.5 SBOM, with a `vulnerabilities` array added. Each entry is one
vulnerability in one package version, merged across the scanners that reported it, and DefectDojo turns
it into one finding:

| In the file | In DefectDojo |
| --- | --- |
| `affects` → the component's `bom-ref` | Component name and version, title `<package>:<version> \| <CVE>` |
| `ratings`: the worst severity a scanner gave, with its CVSS score and vector | Severity; CVSS 3.x vectors land in the CVSS field |
| `cwes` from Hecate's record of the vulnerability | CWE |
| `description`, `advisories` (the scanner's links) | Description and references |
| `recommendation` ("Upgrade openssl to 3.0.2.") | Mitigation |
| `analysis` from the [VEX status](../sca/scan-results.md#vex-status) | `not_affected` / `fixed` → mitigated, inactive; `under_investigation` / `affected` → active |

A finding nobody has assessed yet carries no `analysis` and stays active. Left out of the file:
dismissed findings, and SAST, secret and compliance findings, which have no vulnerability id.

Use this file rather than the VEX exports. DefectDojo also reads CycloneDX VEX, OpenVEX and CSAF, but
these formats state a status, not a finding: every finding arrives as *Medium* or *Info*, and from
OpenVEX without its package.

## Importing a scan

In DefectDojo, open the engagement, choose **Import Scan Results**, set the scan type to
**CycloneDX Scan** and upload the file. Do not force **Active** on (in the API: leave out `active`);
forced on, it makes every finding active, including those your VEX statuses mark as not affected.

Over the API, `reimport-scan` updates the same test on every run instead of adding a new one, which is
what a pipeline wants:

```bash
curl -X POST "https://dojo.example.com/api/v2/reimport-scan/" \
  -H "Authorization: Token $DOJO_TOKEN" \
  -F scan_type="CycloneDX Scan" \
  -F product_type_name="Hecate" -F product_name="shop" -F engagement_name="Hecate" \
  -F test_title="ghcr.io/acme/shop" -F auto_create_context=true \
  -F file=@shop.cdx.json
```

## In a pipeline

After a [CI scan](cicd.md) has finished (`GET /api/v1/scans/<scanId>` reports `completed`), download
the file and reimport it as above. Statuses Hecate sets after the scan, from
[VEX sources](../sca/scan-results.md#vex-sources), VEX rules or by hand, reach DefectDojo with the next
export.

Exporting the scan of a [host or Kubernetes node](../sca/hosts.md) works the same way, so systems that
push their SBOMs to Hecate end up in DefectDojo too.
