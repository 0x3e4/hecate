# Advisories

The **Advisories** page (`/advisories`, sidebar group **Security**; the old `/cert` address forwards there) shows in one list what CERTs, vendors and the community are warning about. Hecate reads their feeds, and advisories that share a CVE are merged into one topic, so the same flaw reported by three CERTs is one row and not three.

Where the dashboard's [Needs attention](dashboard.md#needs-attention) panel answers *what should I look at now*, this page is the full picture behind it.

![The Advisories page with the topic list, filters and a row folded open](../img/hecate-cert.png)

## Kinds of source

Every feed has a kind, and the kind decides how much its word counts:

| Kind | For example | What it does |
| --- | --- | --- |
| **CERT** | CERT-FR, NCSC-NL, JPCERT/CC | Counts as an independent voice. Two of them naming a CVE within a week put it under *Needs attention*. |
| **Vendor** | Cloudflare, Microsoft, a product's security blog | Counts exactly like a CERT. |
| **Community** | Mastodon accounts, personal blogs | Shown next to the topics as context. Never makes a CVE trend, never merges two topics, never costs a page request. |

The kind is read when the page loads, so moving a feed to another kind on **System → Data** also applies to what it has already delivered.

## Topics

A topic is every CERT or vendor advisory connected through a shared CVE. If one CERT names two CVEs of a flaw and another names only the second, both end up in the same topic.

Community posts are held to stricter rules, because one post often mentions several unrelated flaws:

- A post joins every topic whose CVE it names, but does not add its other CVEs to that topic and does not connect the topics with each other.
- Posts that touch no topic are grouped among themselves, so three accounts posting about the same new CVE form one topic.
- A post naming more than three CVEs is a list rather than a topic and goes to the [round-ups](#round-ups).

Each row shows:

- the worst severity among its CVEs
- the affected products and the first CVE IDs, taken from Hecate's own data because the feeds' titles come in several languages
- the CERTs and vendors that reported it by name, and the number of community posts about it
- an **Exploited** tag if any of its CVEs is known to be exploited, and the date of the newest advisory
- the same inventory and scan tags as on the dashboard

Click a row to fold it open. It lists every CVE with its severity, product, CVSS and EPSS, marks recent KEV listings, and links to each advisory in its original language; vendor and community sources carry their kind next to the name. A CVE a feed named before Hecate ingested it reads *Not in Hecate yet*. A Mastodon post has no title of its own, so its row shows the beginning of its text.

Topics that touch your stack come first, then those most CERTs and vendors agree on, then those with the most community posts, then by severity and date. "Your stack" here means confirmed: an inventory match from the [version-aware matcher](inventory.md#how-matching-works) or a finding in your latest scans. A package that only shares a product's name shows a tag but does not move the row up.

## Filters

The checkboxes above the filters choose which kinds are shown, each with its number of topics. CERT and Vendor are on by default; switch on **Community** to see the posts as well. The page remembers the choice.

Search covers products, vendors, CVE IDs and advisory titles. You can also narrow the list to one source, one severity or **Only my stack**, and pick the last 7, 30 or 90 days.

Feeds only offer their latest entries, so history builds up from the day Hecate starts reading them. A 90-day view fills in over time.

## Round-ups

An advisory that names 20 or more CVEs, such as a Linux distribution's kernel batch or a browser release, and a community post that names more than three, are listed under **Round-ups** and not merged. Otherwise a single shared CVE would tie unrelated topics together. Each entry links to the advisory, shows its size, and tells you how many of its CVEs are findings in your latest scans.

## Where the data comes from

The built-in feeds, how to add your own and which CERTs are left out are described under [Advisory feeds](dashboard.md#advisory-feeds). Advisories that name no CVE, in the feed or on their page, cannot be matched to anything and do not appear here.

The same data is available from `GET /api/v1/stats/cert-advisories?days=30&tz=Europe/Vienna`.
