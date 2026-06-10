# License Compliance

A vulnerability scan tells you whether a dependency is *dangerous*. A license check tells you whether
it is *legally usable*. Pulling a strong-copyleft library into a closed-source product, or shipping a
package whose license your organisation has decided to forbid, is the kind of problem that surfaces
late, costs a lot, and never shows up in a CVE feed. License compliance in Hecate closes that gap by
reading the SPDX license declared on every SBOM component and measuring it against a policy you
control.

You define a policy once — which licenses are allowed, which are denied, and what to do with anything
you did not list — and Hecate evaluates it automatically after every scan. Components whose licenses
violate the policy are flagged, the rest pass quietly, and the result is available both per-scan and
aggregated across all of your targets. Nothing is enforced or blocked; the goal is visibility, so you
can decide what to do about a `GPL-3.0-only` dependency before it reaches production.

![Hecate per-scan License Compliance tab showing a policy summary banner and a table of violating components](../img/hecate-scan-licenses.png)

## How a license is evaluated

Every component in an SBOM carries one or more SPDX license identifiers — `MIT`, `Apache-2.0`,
`GPL-3.0-only`, and so on. Some components declare a compound expression such as `MIT OR Apache-2.0`
or `(MIT AND BSD-3-Clause)`. Hecate splits those expressions into their individual *atoms* and
evaluates each atom on its own, so a component offered under "MIT or Apache-2.0" is judged on both
licenses rather than treated as one opaque string. This is also why a component's row can show several
coloured license chips at once.

Each license atom is matched against your policy and resolves to one of four outcomes:

| Status | Meaning |
| --- | --- |
| **Allowed** | The license appears on the policy's allowed list. The component passes. |
| **Denied** | The license appears on the policy's denied list. The component is a violation. |
| **Warned** | The license is unlisted and the policy's default action is *Warn* — flagged for review, not a hard violation. |
| **Unknown** | The component declares no resolvable license, or the license cannot be classified. |

When a single component declares multiple licenses with mixed outcomes, the component takes the most
severe status among them — a denied atom makes the whole component a denied violation, regardless of
any allowed atoms alongside it.

## Defining a policy

Policies are created and managed on the System page, under **System → Policies → License Policies**.
The intro on that tab states the contract plainly: the *default* policy is applied automatically after
every scan. See [System Settings](../admin/system.md) for the rest of what lives on that page.

To create one, choose **Create Policy** and fill in the form:

- **Name** and an optional **Description**, so you can tell several policies apart.
- **Allowed Licenses** — a comma-separated list of SPDX IDs you permit (for example
  `MIT, Apache-2.0, BSD-3-Clause, ISC`).
- **Denied Licenses** — the SPDX IDs you forbid (for example `GPL-3.0-only, AGPL-3.0-only`).
- **Default Action (for unlisted licenses)** — what happens to any license that is on neither list:
  **Allow**, **Warn**, or **Deny**.
- **Set as default policy** — make this the policy evaluated automatically after scans. Only one
  policy can be the default at a time.

You rarely have to type long SPDX lists by hand. Hecate ships built-in license *groups* and exposes
them as one-click fill buttons next to the relevant fields. Beneath **Allowed Licenses** a *Fill:
Permissive* button drops in the common permissive licenses; beneath **Denied Licenses**, *Fill:
Copyleft* and *Fill: All Copyleft* populate the strong-copyleft set (and, for the latter, the
weak-copyleft set as well). Treat these as a starting point and edit the list to taste.

!!! tip
    The **Default Action** is the most important field to get right. Setting it to *Warn* gives you a
    soft signal on every license you have not explicitly classified yet — a good default while you are
    still building out your allowed/denied lists. Switch it to *Deny* once your lists are mature and
    you want unlisted licenses treated as violations.

Each saved policy is listed with its name, an indicator if it is the current **Default**, and a one-line
summary of how many licenses it allows, how many it denies, and its default action. From the list you
can **Set Default**, **Edit**, or **Delete** any policy. Setting a new default takes effect on the next
scan; existing scans keep the result they were evaluated under.

## Where results show up

Compliance results appear in two places, depending on whether you want the picture for one scan or
across everything you run.

### The per-scan License Compliance tab

On a scan's detail page (`/scans/:scanId`), a **Licenses** tab evaluates that scan's SBOM against the
default policy. The tab only appears when the scan produced SBOM components *and* at least one license
policy is configured — without a policy there is nothing to measure against, so Hecate hides the tab
rather than show an empty one.

At the top, a summary banner names the policy that was applied and breaks the result into counts of
**allowed**, **denied**, **warned**, and **unknown** components. Below it, a violations table lists
every component that did not cleanly pass, with its name, version, the evaluated license chips
(coloured by their individual status), and the component's overall status. When everything is clean,
the table is replaced by a green confirmation that all components comply with the policy. If no policy
has been configured at all, the tab points you to the System page to create a default one.

### The aggregated Licenses tab on the Scans page

For the bird's-eye view, the **Licenses** tab on the main Scans page (`/scans`) rolls every license up
across the latest scan of every target. Instead of components-per-scan, it answers the inverse
question: for each license, *which components use it and how many*. Each row shows the SPDX license
ID, a **Components** count, and a **Used By** column listing the first several `name@version`
components that declare it (with a "+N more" indicator when there are more). A search box at the top
filters the list by license ID. This view is about understanding your overall license exposure — it
does not pass judgement against a policy the way the per-scan tab does.

!!! note
    License data only exists once a scan has generated an SBOM. If the aggregated tab is empty, run a
    scan that includes SBOM generation first — see [Scan Results](scan-results.md) for how findings,
    SBOMs and the other scan tabs fit together.
