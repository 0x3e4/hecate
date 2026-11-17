# Permissions

With [sign-in](authentication.md) on, every person gets one of three roles from your identity
provider: **admin**, **editor** or **viewer**. Each role can do everything the role below it can.
This page says what that means in the web app. The [gate-by-gate table](authentication.md#gate-by-gate)
lists the same rules per API route, including what works without a session.

## At a glance

| | Viewer | Editor | Admin |
| --- | :---: | :---: | :---: |
| Read vulnerabilities, scans, SBOMs, findings, inventory, advisories, statistics | ✓ | ✓ | ✓ |
| Export SBOMs, VEX documents, findings and evidence bundles | ✓ | ✓ | ✓ |
| Check a package before installing it | ✓ | ✓ | ✓ |
| Start scans, add scan targets, import SBOMs | – | ✓ | ✓ |
| Change a target: scanners, auto-scan, group, VEX sources | – | ✓ | ✓ |
| Set VEX statuses, dismiss findings, import VEX, mark releases | – | ✓ | ✓ |
| Edit the inventory and saved searches | – | ✓ | ✓ |
| Fetch a vulnerability from its sources again | – | ✓ | ✓ |
| Start AI analyses | – | ✓ | ✓ |
| Delete targets and scans | – | – | ✓ |
| Give a target its first write password, or reset one without knowing it | – | – | ✓ |
| Open the System page: settings, notifications, feeds, policies, backups, syncs | – | – | ✓ |
| Create and revoke API tokens | – | – | ✓ |
| Read the audit log | – | – | ✓ |

## Viewer

A viewer reads. Every page except **System** and **Audit** opens, with everything on it: the
dashboard, vulnerability details and their AI analyses, scans with findings, SBOM, VEX statuses and
attack chains, the inventory with its matches, the advisories page and the statistics. When an AI
password is set, the AI analysis page asks for it before it lists past analyses. Downloads work too: SBOMs (CycloneDX, SPDX), VEX exports, findings as CSV or JSON, evidence bundles.

Buttons that change something answer with a short notice that the editor role is needed, never with
a password prompt.

## Editor

An editor does the day-to-day work on scans and the inventory:

- **Scans**: add targets, start and cancel scans, run the change check, import SBOMs, change a
  target's scanners, auto-scan, application group and VEX sources. This holds for every target, also
  those protected by a target password.
- **Triage**: set and clear VEX statuses (one finding, several, or a whole CVE on a target), dismiss
  and restore findings, import CycloneDX VEX or OpenVEX, mark a scan as a release.
- **Inventory**: add, change, duplicate and delete entries, record new versions.
- **Searches**: save, change and delete saved searches.
- **Vulnerabilities**: fetch an entry from its sources again, and look up an ID Hecate doesn't have
  yet.
- **AI analyses** of a CVE, a batch, an attack path, a scan or an attack chain. When an AI password is
  set, the editor needs it as well.

What an editor can't do: delete targets or scans (the history behind them would go), give a target
its first password, change VEX rules or license policies, or open the System and Audit pages.

## Admin

An admin can do everything an editor can, and also:

- delete targets and scans,
- give targets their first write password, and change or remove one without knowing it,
- the whole **System** page: app settings, notification channels, rules and templates,
  advisory feeds, license policies, VEX rules, backups and restores, sync triggers and re-syncs,
- create and revoke **API tokens**,
- read the **Audit** log.

A signed-in admin opens System and Audit straight away; the system password dialog does not appear.
AI analyses still ask for the AI password when one is set, also for admins.

## Accounts without a role

An account that is in none of the configured groups can't sign in: the sign-in screen says it has no
role in Hecate. When `OIDC_VIEWER_GROUPS` is empty, every account your identity provider signs in is at
least a viewer. Which groups map to which role is set in
[Configuration](authentication.md#configuration).

## Passwords next to roles

The shared passwords keep working with sign-in on. A viewer who knows a target's write password can
change that target, and someone who holds the system password can do what an admin can. The role is
checked first; a password the person typed into a prompt or unlocked on the System page counts after
it. Whoever knows a target's current password can also change or remove it, whatever their role. See [Passwords and sign-in together](authentication.md#passwords-and-sign-in-together).

Everything a person changes lands in the [audit log](audit.md) with their name.
