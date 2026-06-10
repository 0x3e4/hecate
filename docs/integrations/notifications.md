# Notifications

Notifications are how Hecate reaches you when something matters — a critical CVE that touches a product
you run, a scan that just failed, or a package in one of your images that has retroactively been flagged
malicious. Rather than building its own integrations for every messaging service, Hecate delegates
delivery to [Apprise](https://github.com/caronc/apprise), which speaks to 90+ destinations (Slack,
Discord, email, Signal, Microsoft Teams, generic webhooks, and many more) from a single URL syntax.

You wire notifications up in three steps, all on the **System → Notifications** tab: point Hecate at an
Apprise service and add a *channel* (one Apprise URL, optionally tagged), define *rules* that decide which
events or vulnerability matches fire, and — optionally — customise the *message templates* that shape what
each notification says. The same tab also surfaces the live Apprise connection status and a one-click test
button so you can confirm delivery before you depend on it.

![System page Notifications tab — channels, rules and message templates](../img/hecate-system-notifications.png)

## Enabling Apprise

Notifications are off by default. The backend reaches Apprise over HTTP, so it needs a running Apprise
service and the feature flag turned on. The bundled `docker-compose` already includes an `apprise`
sidecar; you only have to set the environment variables and restart the backend:

```env
NOTIFICATIONS_ENABLED=true
NOTIFICATIONS_APPRISE_URL=http://apprise:8000
```

If you prefer an Apprise instance you already operate, point `NOTIFICATIONS_APPRISE_URL` at it
(for example `https://apprise.example.com`) instead of the sidecar. Two more variables fine-tune routing
and resilience: `NOTIFICATIONS_APPRISE_TAGS` (default `all`) and `NOTIFICATIONS_APPRISE_TIMEOUT` (default
`10` seconds). Notifications are fire-and-forget — a delivery failure is logged but never aborts the work
that triggered it (an ingestion run, a scan, or a sync).

Once the backend is up, open **System → Notifications**. The **General** tab shows a *Services* row for
Apprise with a coloured status pill — *Connected*, *Unreachable*, or *Disabled* — so you can tell at a
glance whether Hecate can talk to the service.

!!! note
    `NOTIFICATIONS_ENABLED=true` only switches the feature on. You still configure *where* notifications go
    (channels) and *when* they fire (rules) through the web UI — none of that lives in environment
    variables.

## Adding a channel

A channel is a single Apprise destination URL plus an optional **tag**. Click **+ Add Channel**, paste the
Apprise URL, and pick a tag. The URL follows Apprise's own syntax — for example
`slack://TokenA/TokenB/TokenC` for Slack or `mailto://user:pass@gmail.com` for email; the
[Apprise wiki](https://github.com/caronc/apprise/wiki) documents the format for every supported service.

The tag is what connects a channel to a rule. When a rule fires, Hecate dispatches to every channel whose
tag matches the rule's Apprise tag, so a tag like `email`, `slack`, or `signal` lets you route different
kinds of alerts to different places. Leave it as `all` if you just want one catch-all destination. Each
configured channel is listed with its URL, tag pill, and a **Remove** button, and channels are stored in
Hecate's database, not in environment variables, so adding or removing one takes effect immediately.

!!! tip
    Use the **Test** button in the Apprise *Services* row on the **General** tab to send a sample
    notification. Type a tag into the small box next to it to test one specific channel, or leave it blank
    to test the default tag. The result toast tells you whether delivery succeeded.

## Creating rules

Rules decide what triggers a notification and which tag it routes to. Click **+ Add Rule**, give it a name,
choose a **Type**, set the **Apprise Tag** (which must match a channel tag you configured above), and toggle
**Enabled**. The form then shows only the fields relevant to the type you picked. Every rule you create is
listed in a table showing its type, a one-line summary of its parameters, the tag, an *Active* / *Disabled*
status pill you can click to toggle, when it last fired, and **Edit** / **Delete** actions.

There are eight rule types. The first — *System Event* — reacts to things Hecate does; the rest watch the
vulnerability index or your scans for new matches.

| Rule type | Fires when… |
| --- | --- |
| **System Event** | One of the selected system events occurs: `scan_completed`, `scan_failed`, `sync_failed`, or `new_vulnerabilities`. |
| **Saved Search** | A newly published vulnerability matches one of your [saved searches](../guide/search.md). |
| **Vendor** | A new vulnerability is published for a specific vendor (by vendor slug, e.g. `microsoft`). |
| **Product** | A new vulnerability is published for a specific product (by product slug, e.g. `windows_10`). |
| **DQL Query** | A new vulnerability matches an arbitrary DQL query (e.g. `severity:critical AND vendors:microsoft`). |
| **SCA Scan** | An SCA scan completes with findings, optionally only at or above a severity threshold and/or for a chosen target. |
| **Inventory** | A newly published CVE touches an entry in your [environment inventory](../guide/inventory.md), optionally scoped to specific items. |
| **SCA Malware Alert** | The [continuous MAL-\* watcher](../sca/malware.md) retroactively flags a package in a previously completed scan as malicious. |

### System-event rules

A *System Event* rule is the simplest: tick the event types you care about — `scan_completed`,
`scan_failed`, `sync_failed`, `new_vulnerabilities` — and Hecate notifies your tag whenever one of them
happens. This is the right type for operational alerts that aren't tied to a particular vulnerability,
such as "tell me whenever a scan fails."

### Watch rules (saved search, vendor, product, DQL, inventory)

The *Saved Search*, *Vendor*, *Product*, *DQL Query*, and *Inventory* types are collectively *watch rules*.
They each describe a slice of the vulnerability index, and Hecate re-evaluates them after every ingestion
that brought in new entries. A *Saved Search* rule reuses a search you have already saved on the
Vulnerabilities page; *Vendor* and *Product* rules take a slug; a *DQL Query* rule takes any DQL expression;
and an *Inventory* rule watches the products and versions you have declared in your environment inventory.

Inventory rules accept an optional multi-select of inventory items. Leave it empty to watch every entry in
your inventory (global scope), or hold Ctrl/Cmd to pick specific items so the rule fires only when one of
those is affected. If you have not added any inventory items yet, the rule still saves and runs globally —
it simply starts matching once you populate the [Inventory page](../guide/inventory.md).

Watch rules match on the vulnerability's **published** date, which means a CVE that NVD or EUVD publishes
*today* will fire even if Hecate has known about it locally for a while under a reserved placeholder. That
is usually what you want: you are alerted the moment a vulnerability becomes real, not when it was first
seen as an empty shell.

### Scan and malware rules

*SCA Scan* and *SCA Malware Alert* rules share the same two optional filters: a **Severity Threshold**
(notify only when a finding at that severity or above exists — *Critical*, *High or above*, *Medium or
above*, *Low or above*, or *Any*) and a **Target** filter that limits the rule to a single scan target.
Leave both empty to be notified about every scan or every malware hit.

A *SCA Scan* rule is evaluated after each scan completes. An *SCA Malware Alert* rule is different in timing:
it fires when Hecate's background watcher cross-checks freshly ingested `MAL-*` advisories against the SBOM
of your most recent completed scans and finds that a package you already shipped has been flagged malicious
*after the fact*. It only fires for genuinely new findings — a re-run that re-discovers the same hit stays
silent. See [Malware Detection & Feed](../sca/malware.md) for how that watcher works.

### The anti-storm bootstrap

The first time a watch rule (or any rule that scans for new matches) is evaluated, it does **not** send
anything. Instead it silently records the current time as its watermark and notifies only on matches that
arrive *afterwards*. This is deliberate: without it, creating a rule — or simply restarting the backend —
would dump every historical match into your channel at once. Watch rules are evaluated after each ingestion
that produced new entries, plus a one-shot pass about 30 seconds after the backend starts to cover the gap
before the first scheduled run.

!!! warning
    Because the first evaluation establishes the watermark and stays quiet, you will not receive a flood of
    back-dated alerts when you add a rule. If you want to confirm a rule's wiring, use the **Test** button to
    exercise the channel, then wait for the next genuinely new match to validate the rule end to end.

## Customising message templates

By default Hecate ships a sensible message for every event, so you can run notifications without touching
templates at all. When you want to control the wording — a custom title, a different layout, or a per-channel
variant — open the **Message Templates** section and click **+ Add Template**. Pick the **Event Type**, set a
**Tag**, and edit the **Title Template** and **Body Template**.

Templates are plain text with two constructs. A `{placeholder}` is replaced by the matching value, and a
`{#each list}...{/each}` block iterates over a list — for example over the top findings of a scan or the
vulnerabilities that matched a watch rule. The available placeholders and loop blocks differ per event type,
and the editor lists them live beneath the body field as you change the event, so you always see exactly what
you can reference. The default template for the selected event is pre-filled when you start a new template,
giving you a working example to adapt.

The **Tag** decides which rules a template applies to. Resolution is layered: Hecate first looks for a
template whose tag exactly matches the rule's Apprise tag, then falls back to a template tagged `all`, and
finally to the built-in default if neither exists. So a template tagged `slack` overrides messages sent to
your Slack channel, while a template tagged `all` becomes your global default for that event. Templates are
keyed by **event** — the seven event keys are `new_vulnerabilities`, `scan_completed`, `scan_failed`,
`sync_failed`, `watch_rule_match`, `inventory_match`, and `sca_malware_alert` — and several rule types feed
the same event key (every watch rule renders through `watch_rule_match`, for instance).

Each saved template appears in a table with its event, tag, a preview of the title and body, and **Edit** /
**Delete** controls. Timestamps inside messages are rendered in the timezone the backend container is
configured with, so the dates in a notification stay consistent with its header.

## Where this fits

Notifications live alongside the rest of Hecate's administration on the System page. For the full tour of the
System tabs — General, Access Control, Data, and Policies — see [System Settings](../admin/system.md). The
rule types lean on features documented elsewhere: saved-search rules build on the
[Search & Query Builder](../guide/search.md), inventory rules on the
[Environment Inventory](../guide/inventory.md), and malware-alert rules on
[Malware Detection & Feed](../sca/malware.md).
