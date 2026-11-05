# VEX for Hecate's images

Scan a Hecate image and you get a few hundred findings, most of them in packages of the Debian
or Alpine base image. Hecate publishes a VEX document for each of its images that says, for
every one of those findings, whether it matters for Hecate and why. Use them to separate the
findings that need attention in your deployment from the base-image background.

The documents live in the repository under
[`vex/`](https://github.com/0x3e4/hecate/tree/main/vex), together with an overview of the current
state ([`STATUS.md`](https://github.com/0x3e4/hecate/blob/main/vex/STATUS.md)) and the evidence the
statements rest on.

| Image | OpenVEX (Trivy, Grype) | CycloneDX VEX (Hecate) |
| --- | --- | --- |
| `ghcr.io/0x3e4/hecate-backend` | `vex/hecate-backend.openvex.json` | `vex/hecate-backend.cdx.json` |
| `ghcr.io/0x3e4/hecate-frontend` | `vex/hecate-frontend.openvex.json` | `vex/hecate-frontend.cdx.json` |
| `ghcr.io/0x3e4/hecate-docs` | `vex/hecate-docs.openvex.json` | `vex/hecate-docs.cdx.json` |
| `ghcr.io/0x3e4/hecate-scanner` | `vex/hecate-scanner.openvex.json` | `vex/hecate-scanner.cdx.json` |

## What a status means

- **Not affected**: the vulnerable code is not in the image, or the service never runs it. The
  statement says which of the two and how that was established.
- **Affected**: the vulnerable code is there. The statement says what an attacker would get and
  when the fix arrives.
- **Under investigation**: not decided yet, for example a library the service does load whose
  CVEs nobody has assessed one by one. Nothing is declared harmless without a reason.
- **Fixed**: the installed version already contains the fix; the scanner's version range is too
  broad.

## Apply them

=== "Trivy"

    ```sh
    curl -fsSLO https://raw.githubusercontent.com/0x3e4/hecate/main/vex/hecate-scanner.openvex.json
    trivy image --vex hecate-scanner.openvex.json --show-suppressed ghcr.io/0x3e4/hecate-scanner:latest
    ```

=== "Grype"

    ```sh
    grype --vex hecate-scanner.openvex.json ghcr.io/0x3e4/hecate-scanner:latest
    ```

=== "Hecate"

    Add the image as a scan target. On the target page, **VEX sources → Add source** takes the
    raw URL of the matching document, for example
    `https://raw.githubusercontent.com/0x3e4/hecate/main/vex/hecate-backend.openvex.json`.
    Hecate applies it right away and again after every scan, so a new release of the documents
    reaches your findings without anything to do; a status you set yourself stays. See
    [VEX sources](../sca/scan-results.md#vex-sources). A one-off import of the `.cdx.json` file
    through **Findings → Import VEX** works too.

Trivy and Grype match a statement by the image name and the exact package version: scan the
image under its `ghcr.io/0x3e4/…` name (a local tag does not match), and expect a package that
changed since the documents were generated to show up again until they catch up. Hecate matches
by vulnerability and package name, so it applies a statement to a newer version of the package
too.

## How the statements are made

Most statements come from evidence collected from the image itself rather than from judgement:

- **OS packages**: the service's process is started inside the image, and every shared library
  it maps and every library of every program it runs is recorded. A package that never appears
  there is *not affected*.
- **Go binaries** (Trivy, Grype, Syft, Dive, Dockle, OSV Scanner, skopeo in the scanner):
  `govulncheck` checks whether the vulnerable functions of an advisory are compiled in.
- **Everything else** is assessed by hand against Hecate's code: for example, libcurl in the
  scanner is used only by git, and only for HTTP(S). Each assessment names the code it relies
  on and the date it was checked.

The repository's [`vex/README.md`](https://github.com/0x3e4/hecate/blob/main/vex/README.md)
describes the tooling, its limits and how to regenerate the documents after an image changes.
