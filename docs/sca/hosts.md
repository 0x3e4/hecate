# Hosts, Nodes and Other Systems

Hecate scans container images and repositories itself. Everything else you run (servers, VMs,
workstations, Kubernetes nodes, appliances) it doesn't reach, but it can still know about it, in one
of two ways:

| The system | How it gets into Hecate |
| --- | --- |
| Something an SBOM tool can read: Linux servers and VMs, Kubernetes nodes, running containers, application directories on any OS | It pushes an **SBOM** of what is installed (this page) |
| Something no SBOM tool lists: Windows or macOS programs, firewalls, routers, storage, hypervisors, OT devices, a product you only know by name and version | An entry in the [**environment inventory**](../guide/inventory.md): vendor, product, version, matched against the advisories' version ranges |

Both end up in the same places: a vulnerability's page names the systems it affects, internet-facing
ones first, and the dashboard counts them. One overview of everything you run, without an agent to
install.

## What you get

- **One target per system.** Each system is an SBOM-import target, named after it (the host name, the
  node, the workload). Every push is a new scan in its history.
- **Distribution-aware matching.** A Debian, Ubuntu, RHEL or Alpine package carries the distribution's
  own version (`nginx 1.22.1-9+deb12u2`), often with security fixes backported into an old upstream
  number. Hecate hands the SBOM to Grype in the scanner, which knows the distributions' advisories, and
  takes its answer for those packages. Language packages (npm, PyPI, Maven, …) are matched by Grype and
  Hecate's own database together.
- **Kind and exposure.** Mark a target as a host (a server, VM or workstation, whatever its OS),
  Kubernetes node, container or other, and as internet-facing or internal. A vulnerability's **Affected in your scans** block lists internet-facing systems first
  with an *Internet-facing* chip, so "where does the nginx with the RCE run, and is it exposed" is one
  page.
- **Statuses that stay.** VEX statuses and dismissals set on a system's findings carry over to its next
  push, as they do from scan to scan.

## 1. Create a token

On **System → Access Control → API tokens**, create a token with the scope **Import SBOMs (hosts,
nodes)** (`sbom:import`). It opens the two SBOM import endpoints and nothing else: it creates new
SBOM-import targets and writes existing ones, and is refused for repository and image targets. Give
each fleet or tool its own token, so one can be revoked alone.

## 2. Produce the SBOM on the system

Any tool that writes CycloneDX or SPDX JSON works: an SBOM generator, a software-distribution or
asset-management system that can export one, or a security tool that already produces them. On a Linux
system, Syft or Trivy over the root filesystem is the simplest; both name the operating system, which
the distribution matching needs.

=== "Syft"

    ```bash
    syft scan dir:/ \
      --exclude './proc/**' --exclude './sys/**' --exclude './dev/**' --exclude './run/**' \
      -o cyclonedx-json=/var/tmp/sbom.cdx.json
    ```

=== "Trivy"

    ```bash
    trivy rootfs --format cyclonedx --output /var/tmp/sbom.cdx.json /
    ```

## 3. Push it

```bash
curl -fsS -X POST \
  -H "X-API-Key: $HECATE_TOKEN" \
  -F "file=@/var/tmp/sbom.cdx.json" \
  "https://hecate.example.com/api/v1/scans/import-sbom/upload?targetName=$(hostname -f)&kind=host&exposure=internet"
```

- `targetName` picks the target; keep it stable (the FQDN) so every push lands in the same history.
- `kind` is `host`, `kubernetes-node`, `container` or `other`; `exposure` is `internet` or `internal`.
  Both are optional and only set when given, so a cron job doesn't have to repeat them, and a value
  changed on the target page stays until a push sends another one.
- The JSON endpoint `POST /api/v1/scans/import-sbom` takes the same as fields: `sbom`, `targetName`,
  `kind`, `exposure`.

The request waits until the SBOM is matched: a few seconds, longer on the first push after a scanner
restart, while Grype loads its database. Spread the schedule (a random delay) when hundreds of hosts
push at once.

### Cron

```bash
# /etc/cron.d/hecate-sbom: daily, at a random minute per host
17 3 * * * root sleep $((RANDOM % 1800)); /usr/local/bin/hecate-sbom.sh
```

with `hecate-sbom.sh` holding the two commands above and the token in a root-only file.

### Ansible

```yaml
- name: SBOM of the host
  ansible.builtin.command: >
    syft scan dir:/ --exclude './proc/**' --exclude './sys/**' --exclude './dev/**' --exclude './run/**'
    -o cyclonedx-json=/var/tmp/sbom.cdx.json
  changed_when: false

- name: Push it to Hecate
  ansible.builtin.command: >
    curl -fsS -X POST -H "X-API-Key: {{ hecate_token }}"
    -F file=@/var/tmp/sbom.cdx.json
    "{{ hecate_url }}/api/v1/scans/import-sbom/upload?targetName={{ inventory_hostname }}&kind=host&exposure={{ 'internet' if public_ip | default(false) else 'internal' }}"
  changed_when: false
  no_log: true
```

The exposure comes from your inventory (`public_ip` here), so it is set where you already know it.

## Scanner reports

If a system or a pipeline already runs Trivy, Grype or OSV-Scanner, push its JSON report instead of an
SBOM, to the same endpoints with the same token. Hecate recognises the format on its own (or take
`format=trivy-json`, `grype-json` or `osv-scanner-json`).

A CycloneDX file that lists vulnerabilities next to its components counts as a report too: Trivy's
`--format cyclonedx --scanners vuln`, Grype's `-o cyclonedx-json`, or the
[CycloneDX + vulnerabilities export](../integrations/defectdojo.md) of another Hecate. Its `analysis`
blocks come along as VEX statuses, so a file moved between two instances keeps what was assessed.
A CycloneDX VEX document (vulnerabilities without components) is not a report; it goes to the VEX
import of a scan.

=== "Trivy"

    ```bash
    trivy rootfs --format json --list-all-pkgs --output /var/tmp/report.json /
    ```

=== "Grype"

    ```bash
    grype dir:/ -o json --file /var/tmp/report.json
    ```

=== "OSV-Scanner"

    ```bash
    osv-scanner scan source --format json --all-packages -r /srv/app > /var/tmp/report.json
    ```

The report is that scanner's answer: its findings are stored as it reported them, no second scanner
runs over them, and they get what a scan's findings get (the CVE behind a GHSA id, severity from
Hecate's database, VEX sources and rules, statuses carried over). The scan names the scanner, so its
findings sit next to those of Hecate's own Trivy or Grype runs.

The system's SBOM is what the report lists. Trivy lists every package with `--list-all-pkgs`; Grype
lists only the vulnerable ones, OSV-Scanner too without `--all-packages`. An advisory published later
is matched against that SBOM (*Affected in your scans*, the malware watch), so a full list catches more;
where a scanner cannot give one, push an SBOM as well, to a target of its own.

Trivy and Grype name what they scanned; an OSV-Scanner report does not, so give it a `targetName`.

## Windows, macOS and other operating systems

Syft and Trivy also run on Windows and macOS (`syft scan dir:C:\ …`, `syft scan dir:/Applications …`),
but there they find what package managers and language ecosystems leave behind (npm, PyPI, NuGet, Go and
Java dependencies, some binaries), not the programs installed through the operating system's own
installer. Push those SBOMs the same way, with `kind=host`: they cover the application stacks on the
machine. For the installed programs themselves (Windows Server roles, Exchange, a desktop application)
add an [inventory](../guide/inventory.md) entry with the version; if your software-distribution or
asset-management tool can export a CycloneDX or SPDX file of its installed software, that file can be
pushed as the system's SBOM instead.

## Appliances and devices

Firewalls, routers, storage systems, hypervisors and OT devices have no package list to read. Add them
to the [inventory](../guide/inventory.md) with their version; Hecate matches them against the vendors'
advisories, flags them on the vulnerability page and in notifications, and shows their end-of-life
status. A deployment pipeline can keep the versions current through the version report
(`POST /api/v1/inventory/report`, token scope `inventory:report`).

## Kubernetes nodes and running containers

The same import serves them: push the SBOM of each node with `kind=kubernetes-node`, and of each
running workload with `kind=container`. A tool that already produces these SBOMs, such as NeuVector,
only needs a small job that posts each CycloneDX or SPDX file it exports. Container *images* you build
or pull are better scanned as image targets (**New scan**), which also runs the image-only checks.

## Where it shows

- The **vulnerability page**: *Affected in your scans* names the system, its kind and *Internet-facing*,
  exposed systems first.
- The **target page** of each system: findings, SBOM, history, and the **System** card to set or
  change kind and exposure.
- The **dashboard** and **Advisories** count these systems like any other scanned target.

## Settings

| Variable | Default | |
| --- | --- | --- |
| `SCA_SBOM_IMPORT_SCANNERS` | `grype` | Scanners that also match an imported SBOM: `grype`, `trivy`, or both (`grype,trivy`). Empty leaves only Hecate's own name match, which reads distribution packages less exactly. |
| `SCA_SBOM_IMPORT_MAX_COMPONENTS` | `25000` | Largest SBOM accepted. |

Without the scanner sidecar (`SCA_ENABLED=false` or unreachable), an import still works, matched by
Hecate's own data only.
