# Attack Chain

The **Attack Chain** is a top-level tab on a scan's detail page (`/scans/:scanId`), sitting between
**Findings** and **SBOM**. Where the per-CVE [Attack Path](../guide/ai-analysis.md) explains how one
vulnerability could be abused on its own, the Attack Chain takes a step back and asks a bigger
question: if an attacker had *all* of this scan's findings to work with, how would they string them
together into a single intrusion?

To answer that, Hecate reads every CVE-typed finding in the scan, sorts each one into a kill-chain
stage based on its weakness type (CWE), and lays the result out as one continuous story — from the
first foothold through to final impact. The structural graph is built deterministically from data
Hecate already holds (CWEs, CAPEC attack patterns, severity), so the same scan always produces the
same chain. On top of that you can optionally generate an AI-written narrative that walks through the
scenario in prose.

![The cross-CVE Attack Chain tab on a scan detail page, showing stage pills above a Mermaid graph](../img/hecate-scan-attackchain.png)

!!! note "Plausible, not proof"
    The chain shows a *plausible* path an attacker could take given the findings present — it is not
    evidence that the path is reachable or exploitable in your specific deployment. Treat it as a way
    to reason about combined risk, not as a confirmed exploit route.

## What it adds over the per-CVE Attack Path

The per-CVE Attack Path is single-vulnerability and narrow: it diagrams one CVE's route from entry
point to impact and stays focused on that weakness. It is the right tool when you are investigating a
specific advisory.

The Attack Chain is scan-wide and additive. It looks at the whole population of findings together and
chains *multiple* vulnerabilities into one multi-stage narrative — an attacker rarely relies on a
single bug, and a low-severity information-disclosure flaw plus a privilege-escalation flaw plus a
remote-code-execution flaw can together be far more serious than any of them read in isolation. The
chain is the view that surfaces that compounding effect for a target.

## The five kill-chain stages

Hecate buckets each finding into one of five stages drawn from the ATT&CK kill chain. The stages are
ordered the way an intrusion typically unfolds, left to right:

| Stage | What it represents |
| --- | --- |
| **Foothold** | The initial way in — injection, deserialisation, request forgery, and similar entry-point weaknesses. |
| **Credential Access** | Harvesting secrets, tokens, or credentials once inside. |
| **Privilege Escalation** | Gaining higher permissions than the initial access granted. |
| **Lateral Movement** | Spreading to other systems, sessions, or services. |
| **Impact** | The payoff — memory corruption, data loss, denial of service, and other terminal effects. |

Each finding is assigned to a stage by its CWEs. Hecate walks a finding's weakness list in order (the
primary CWE first) and uses the first one that maps to a stage. When none of the CWEs map cleanly, it
falls back to the finding's severity so the finding is never silently dropped — a critical or high
finding lands in **Impact**, a medium in **Privilege Escalation**, and so on. The same logic runs
every time, so the chain is reproducible.

## Reading the stage pills and graph

At the top of the tab is a short summary line — how many stages the chain spans and how many CVEs were
chained from the scan — followed by a row of **stage pills**. Each pill names a stage and carries a
count badge showing how many findings fell into that stage. The pills are colour-toned by stage so the
riskier ends of the chain stand out: Impact is rendered in red, Foothold and Privilege Escalation in
amber, Credential Access and Lateral Movement in blue. Clicking a pill toggles it active (a second
click clears it); only stages that actually contain findings appear.

Below the pills is the graph itself, rendered with the same Mermaid visualisation the per-CVE Attack
Path uses. It flows from an entry node through a node per stage and into the individual CVE nodes that
populate each stage, so you can trace how the findings line up across the kill chain at a glance. The
graph is interactive — you can pan and zoom to follow a longer chain.

The chain renders whenever the scan has at least one CVE-typed finding. If a scan has none — for
example a scan that produced only secrets or compliance findings — the tab shows a short hint
(*"This scan has no CVE-typed findings — nothing to chain yet."*) instead of an empty graph.

## The optional AI narrative

The graph is the deterministic backbone; the narrative is the optional layer on top. Below the graph,
when AI is enabled on your instance and at least one provider is configured, you can pick a provider,
add any extra context in the input field, and generate a written scenario that walks an attacker
through the chain stage by stage. Hecate feeds the model only the CVE and CAPEC identifiers that
actually appear in the chain, so the narrative stays grounded in the findings rather than inventing
new ones.

Generation runs in the background. After you trigger it, the tab polls the scan and surfaces the
narrative automatically once it is ready — you do not need to reload. Because narrative generation is
a write action, it is gated by the AI password when one is configured; if the password is missing or
wrong, Hecate tells you so rather than failing silently.

!!! tip "Generating narratives from an MCP client"
    The same chain can be analysed from an MCP client (Claude Desktop, Cursor, and similar) without an
    AI key on the server: the client fetches Hecate's prepared prompts and the deterministic chain,
    generates the narrative with its own model, and writes it back. See the
    [MCP Server](../integrations/mcp.md) integration for the `prepare` / `save` tool pattern.

## Related pages

- [Scan Results](scan-results.md) — the full set of scan-detail tabs the Attack Chain lives among.
- [AI Analysis & Attack Paths](../guide/ai-analysis.md) — the per-CVE Attack Path and AI triage.
- [SCA Scanning](../sca-scanning.md) — registering targets and running the scans that produce chains.
