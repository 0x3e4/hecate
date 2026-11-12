# Design: Hecate

The locked system. Every Hallmark run reads this first and all screens share it. Change it on purpose; the file is the rule.

## System
- Genre: modern-minimal
- Shape of the first page: app screen
- Theme: brand (the gold is sampled from `frontend/public/logo.png`, `#c9ad66`)
- Axes: dark/grotesk-sans/warm · posture: restrained
- Scope: dark only for 2.0; a light theme would add a second token block, never literals

## Tokens
`frontend/src/tokens.css` is the source of truth. Never write a colour or a `font-family` past it.
```css
:root {
  --color-paper: oklch(15.5% 0.009 85);  --color-paper-2: oklch(19% 0.01 85);  --color-paper-3: oklch(23% 0.011 85);
  --color-ink: oklch(93% 0.01 85);  --color-ink-2: oklch(81% 0.012 85);  --color-muted: oklch(68% 0.014 85);
  --color-rule: oklch(30% 0.012 85);  --color-rule-strong: oklch(42% 0.013 85);  --color-field-edge: oklch(54% 0.014 85);
  --color-accent: oklch(75.7% 0.096 88.5);  --color-accent-ink: oklch(19% 0.02 85);  --color-focus: oklch(82% 0.13 90);
  --sev-critical: oklch(69% 0.19 25);  --sev-high: oklch(75% 0.15 55);  --sev-medium: oklch(85% 0.14 102);  --sev-low: oklch(74% 0.08 235);
  --font-body: "IBM Plex Sans";  --font-outlier: "IBM Plex Mono";
  --radius-card: 6px;  --radius-control: 4px;  --control-height: 36px;
}
```
The spacing scale, the type scale, the easings and the durations are the scaffold's and live in `tokens.css`.

## Colour has one job each
- Gold (`--color-accent`): the active nav item, the primary action, the focus ring, the current tab. Nothing else.
- Severity (`--sev-*`): severity, and only severity. A tool, a source or a link never borrows these colours.
- `--color-success` and `--color-error`: an outcome (scan finished, request failed).
- `--color-info`: state that is neither of the above. Everything else is neutral.
- A severity is never colour alone: the word or its letter stays next to it.

## Type
- IBM Plex Sans 400 and 600, self-hosted through `@fontsource`, so an on-prem instance loads nothing from a third party.
- IBM Plex Mono 400 only for what is code or an identifier: CVE and GHSA IDs, versions, hashes, paths, commands.
- Labels, table heads, chips and nav links: the body face a step smaller, sentence case, untracked. Figures that compare use tabular numerals.

## Surfaces
- Ladder: whitespace, then a hairline, then a tinted well, then a card. Never a card in a card.
- A table is not a card. Tables run full width with horizontal rules only.
- `.card` is for content that is independently interactive or of a different kind, not for every block on a page.

## Controls
- Primary: gold fill, `--color-accent-ink` text, 36px, one per screen.
- Secondary: outline in `--color-rule-strong`, same radius and height.
- Fields: `--color-field-edge`, focus ring as an `outline`, never a border change.
- Tabs: underline in gold on the current tab, the count as a muted tabular figure.

## Motion
- Character: still. `--dur-micro` and `--dur-short` for state only, `transform` and `opacity` for movement, no reveal on load, no pulsing.
- Two exceptions, both for waiting: a skeleton carries one slow sheen, and a spinner turns. Reduced motion stops both (global rule in `base.css`).

## Loading
One family, shared by every screen. Components in `components/Skeleton.tsx` and `ui/primitives.tsx`, CSS in `styles.css`.
- **First load of a region with a known shape**: a skeleton inside `LoadingRegion` (`role="status"`, one screen-reader label, appears only after `--loading-delay` so a fast answer flashes nothing). Build it from `SkeletonBlock`, `SkeletonText`, `SkeletonRows`; a screen keeps its own layout class through `className`. Table rows that cannot sit in a `div` take `.loading-appear` and the table `aria-busy`.
- **A panel, tab, dialog or list whose shape is not worth a skeleton**: `LoadingState` (spinner + one muted line), `inline` inside running text.
- **Fetching again while content is shown**: keep the content, add `.is-refreshing` and `aria-busy="true"` on its container. Never swap loaded content back to a skeleton, never refetch with no sign at all.
- **A button doing its work**: `disabled`, `aria-busy`, and `<BusyLabel busy>` — a spinner in front of the unchanged label. Never replace the label with `...`, `Saving…` or another verb; a `busyLabel` only where the wait is long and the state is the news (an AI analysis running).
- **A long job**: its own status (AI: `AILoadingIndicator`; scans and syncs: their status word). The sidebar dot marks a running scan or AI job in `--color-info`; its state comes from the server, SSE only makes it ask again.
- A spinner is `Spinner`, nothing else: no screen-specific rings, no icon swapped for an hourglass.

## Exports
`frontend/src/tokens.css` in this project.

## Where it lives
- `frontend/src/tokens.css`: every colour, size, space and duration. No literal past this file.
- `frontend/src/styles.css`: shell and primitives. `frontend/src/ui/primitives.tsx` + `primitives.css`: shared components (`PageHeader`, `Section`, `IconButton`, `SeverityTag`, `EmptyState`, `ErrorState`, `Stat`, `ExternalLink`). A link that leaves Hecate goes through `ExternalLink`: new tab, `noopener noreferrer`, trailing external-link icon.
- `frontend/src/screens/<name>.css`: one file per screen, classes prefixed with the screen name.
- Missing values: severity reads Unknown, scores read n/a. Headings are in sentence case.
