# VEX for Hecate's images

Hecate's container images contain vulnerable packages, like nearly every image does. A scanner
lists every one of them. These documents state which of them matter for Hecate and which do
not, and why, so you don't have to triage the same 300 findings yourself. They are VEX
(Vulnerability Exploitability eXchange) documents, the format Hecate itself imports and exports
for your scans.

The current state per image is in **[STATUS.md](STATUS.md)**.

## Files

| Image | OpenVEX (Trivy, Grype) | CycloneDX VEX (Hecate import) | Evidence |
| --- | --- | --- | --- |
| `ghcr.io/0x3e4/hecate-backend` | [hecate-backend.openvex.json](hecate-backend.openvex.json) | [hecate-backend.cdx.json](hecate-backend.cdx.json) | [evidence/hecate-backend.json](evidence/hecate-backend.json) |
| `ghcr.io/0x3e4/hecate-frontend` | [hecate-frontend.openvex.json](hecate-frontend.openvex.json) | [hecate-frontend.cdx.json](hecate-frontend.cdx.json) | [evidence/hecate-frontend.json](evidence/hecate-frontend.json) |
| `ghcr.io/0x3e4/hecate-docs` | [hecate-docs.openvex.json](hecate-docs.openvex.json) | [hecate-docs.cdx.json](hecate-docs.cdx.json) | [evidence/hecate-docs.json](evidence/hecate-docs.json) |
| `ghcr.io/0x3e4/hecate-scanner` | [hecate-scanner.openvex.json](hecate-scanner.openvex.json) | [hecate-scanner.cdx.json](hecate-scanner.cdx.json) | [evidence/hecate-scanner.json](evidence/hecate-scanner.json) |
| Repository (`frontend/pnpm-lock.yaml`, …) | [hecate-source.openvex.json](hecate-source.openvex.json) | [hecate-source.cdx.json](hecate-source.cdx.json) | |

Every finding that Trivy or Grype report for an image gets exactly one status:

- **`not_affected`** with a justification and a sentence on why.
- **`affected`**: the vulnerable code is there and can be reached. The statement says what an
  attacker would get and when the fix arrives.
- **`under_investigation`**: not decided yet. Nothing is declared harmless without a reason, so
  this is the honest default for a library the service does load.
- **`fixed`**: the installed version already has the fix; the scanner's version range is too
  broad.

## Using them

**Trivy**

```sh
curl -fsSLO https://raw.githubusercontent.com/0x3e4/hecate/main/vex/hecate-backend.openvex.json
trivy image --vex hecate-backend.openvex.json --show-suppressed ghcr.io/0x3e4/hecate-backend:latest
```

**Grype**

```sh
grype --vex hecate-backend.openvex.json ghcr.io/0x3e4/hecate-backend:latest
```

Both match a statement by the image (`pkg:oci/hecate-backend?repository_url=ghcr.io/0x3e4/hecate-backend`)
and the package purl with its exact version. Scan the image under its `ghcr.io/0x3e4/…` name: a
local tag such as `hecate-backend:dev` does not match. A package that changed version since the
documents were generated shows up again, which is the point: the statement was about the old
version.

**Hecate**

On the scan target of the image, open the latest scan, then **Findings → Import VEX** and choose
the `.cdx.json` file. Hecate applies the state, justification and reasoning to every finding of
that vulnerability on the target, and carries them forward to later scans.

## How the statements come about

Most statements are derived, not written by hand, from evidence that
[tools/collect.sh](tools/collect.sh) collects from the image:

1. **Runtime evidence for OS packages.** Inside the image, the service's Python process imports
   its entire package tree, and the shared objects it then maps are recorded
   (`/proc/self/maps`). The same goes for the `ldd` closure of every program the service runs
   (git, skopeo, dotnet, semgrep-core, nginx, the entrypoint shell). A Debian or Alpine package
   that is in neither, by name or through its source package, is
   **`not_affected` / `vulnerable_code_not_in_execute_path`**. One that is in them stays
   **`under_investigation`** until someone has assessed its CVEs.
2. **govulncheck for Go binaries.** `govulncheck -mode=binary` checks whether the vulnerable
   functions of an advisory are compiled into the binary. If they are, the finding is
   **`affected`**. A module that is present without them is
   **`not_affected` / `vulnerable_code_not_present`**. If the Go vulnerability database does not
   know the advisory, the finding stays `under_investigation`.
3. **Hand-written assessments** in [assessments.toml](assessments.toml) come first. They cover
   what evidence alone cannot decide, such as libcurl in the scanner, which git uses for HTTPS
   only, or the CPython CVEs measured against the stdlib modules the services call. Each one
   names the code it relies on and the date it was checked.

[tools/generate.py](tools/generate.py) writes the documents and [STATUS.md](STATUS.md) from
that.

## Limits

- **"In use" is not "exploitable".** `under_investigation` for glibc means the backend loads
  glibc, not that the CVE can be triggered. Those statements are open work, not a verdict.
- **govulncheck shows that vulnerable code is present, not that it is called.** For binaries
  Hecate does not build itself (Trivy, Grype, Syft) the call graph is unknown, so `affected`
  there means "the code is in the binary".
- **TruffleHog cannot be inspected.** Its release binary has a format that govulncheck, Trivy
  and Grype cannot read. That it has no findings means nothing is visible, not that it is
  clean.
- **Statements are about the image, not about your deployment.** If you change the defaults in
  a way a statement relies on (for example by routing the scanner through an authenticating
  proxy), the statement says so where it matters.

## Updating

After an image changes (new base image, bumped tool, new dependency):

```sh
vex/tools/collect.sh backend      # or frontend, docs, scanner, source; a local build as 2nd arg
python vex/tools/generate.py      # all five, plus STATUS.md
git diff vex/
```

`collect.sh` needs only Docker: Trivy, Grype and govulncheck run from pinned images. Review the
diff before you commit it. A new `under_investigation` row needs an assessment or an accepted
open item. When the code a hand-written statement relies on changes, check that statement
again. `generate.py` raises the document version only when a statement changes.
