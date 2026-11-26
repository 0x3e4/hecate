# Preferences & Profile

Your personal settings open in a small panel next to whatever opened it:

- **Without sign-in**, or signed out: **Preferences** at the bottom of the sidebar.
- **Signed in** ([OIDC](../admin/authentication.md)): your name at the bottom of the sidebar. The panel
  then starts with your name, e-mail and role and ends with **Sign out**; there is no separate
  *Preferences* entry. Signed out, it ends with **Sign in to keep these on your account**.

Escape, a click outside or a second click on the same entry closes it. Nobody needs admin rights for
any of this: it changes only what you see.

| Setting | What it does |
| --- | --- |
| **Language** | English or German. Defaults to your browser's language. |
| **Time zone** | The zone every date and time is shown in, and where the dashboard's day starts. Empty means your browser's zone, shown as the placeholder; type or pick any IANA zone (for example `Europe/Vienna`), clear the field to go back. |
| **Dashboard: only my stack** | Narrows the [dashboard](dashboard.md#only-my-stack) to the CVEs that hit what you run. |

## Where they are kept

- **Without sign-in**, or while you are signed out, the settings stay in this browser. Another
  browser or a cleared browser starts from the defaults.
- **Signed in**, they are saved to your account as well and follow you to every browser. The first
  time you sign in, the account takes over what this browser had, so nothing on screen changes. After
  that, signing in on another browser applies the account's settings there. The panel says which of
  the two applies.

The account copy is keyed by your identity provider and subject (the `sub` claim), so renaming
yourself at the IdP keeps your settings. Each change is a `PUT /api/v1/auth/me/preferences` and shows
up in the [audit log](../admin/audit.md) like every other write, with you as the actor. The same values
can be read with `GET /api/v1/auth/me/preferences`; both need a signed-in session.

Instance-wide settings, such as the AI batch limit, stay on the admin-only
[System](../admin/system.md) page.
