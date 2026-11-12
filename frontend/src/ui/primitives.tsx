import type { AnchorHTMLAttributes, ButtonHTMLAttributes, ReactNode } from "react";
import {
  LuExternalLink,
  LuHourglass,
  LuLock,
  LuRefreshCw,
  LuSearchX,
  LuServerCrash,
  LuTriangleAlert,
  LuWifiOff,
} from "react-icons/lu";

import { useI18n } from "../i18n/context";
import { describeError, errorHint, type ErrorKind } from "../utils/apiError";

/** Shared building blocks of the 2.0 design system. See design.md at the repo root. */

const SEVERITY_LEVELS = ["critical", "high", "medium", "low"] as const;

/** Normalises any severity string to the level that owns a `--sev-*` token. */
export const severityLevel = (severity: string | null | undefined): string => {
  const value = (severity ?? "").toLowerCase();
  return (SEVERITY_LEVELS as readonly string[]).includes(value) ? value : "none";
};

/** The colour token for a severity. Severity colours mean severity and nothing else. */
export const severityVar = (severity: string | null | undefined): string =>
  `var(--sev-${severityLevel(severity)})`;

/** A severity as a word in its colour, so it never relies on colour alone. */
export const SeverityTag = ({ severity, children }: { severity: string | null | undefined; children?: ReactNode }) => (
  <span className={`sev-tag sev-${severityLevel(severity)}`}>{children ?? (severity || "unknown")}</span>
);

/** One h1 per screen, its one-line purpose and the screen's actions. */
export const PageHeader = ({
  title,
  description,
  actions,
}: {
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
}) => (
  <header className="page-header">
    <div className="page-header-text">
      <h1>{title}</h1>
      {description ? <p className="page-header-description">{description}</p> : null}
    </div>
    {actions ? <div className="page-header-actions">{actions}</div> : null}
  </header>
);

/** A titled block separated by whitespace and a hairline, not by a card. */
export const Section = ({
  title,
  actions,
  children,
  className,
}: {
  title?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) => (
  <section className={`ui-section${className ? ` ${className}` : ""}`}>
    {title || actions ? (
      <div className="ui-section-head">
        {title ? <h2>{title}</h2> : null}
        {actions ? <div className="ui-section-actions">{actions}</div> : null}
      </div>
    ) : null}
    {children}
  </section>
);

/** An icon-only control. `label` is required so it is never unnamed for assistive tech. */
export const IconButton = ({
  label,
  children,
  type = "button",
  className,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { label: string }) => (
  <button type={type} aria-label={label} title={label} className={`icon-button${className ? ` ${className}` : ""}`} {...rest}>
    {children}
  </button>
);

/**
 * A small ring in the current text colour, for work in place: a busy button,
 * a panel loading on demand. Decorative; the text next to it carries the meaning.
 */
export const Spinner = ({ className }: { className?: string }) => (
  <span className={`spinner${className ? ` ${className}` : ""}`} aria-hidden="true" />
);

/**
 * "Loading …" for a panel or tab whose shape is not worth a skeleton: a
 * spinner and one muted line, announced once. Appears after a short delay so
 * a fast answer never flashes it.
 */
export const LoadingState = ({ label, inline = false }: { label?: ReactNode; inline?: boolean }) => {
  const { t } = useI18n();
  return (
    <div className={`loading-state${inline ? " loading-state--inline" : ""}`} role="status" aria-live="polite">
      <Spinner />
      <span>{label ?? t("Loading…", "Wird geladen…")}</span>
    </div>
  );
};

/**
 * The content of a button that can be busy: while `busy`, a spinner sits in
 * front of the label (or of `busyLabel`). The caller keeps `disabled` and sets
 * `aria-busy` on the button itself.
 */
export const BusyLabel = ({ busy, busyLabel, children }: { busy: boolean; busyLabel?: ReactNode; children: ReactNode }) => (
  <>
    {busy ? <Spinner /> : null}
    {busy && busyLabel ? busyLabel : children}
  </>
);

/** What is empty, why it matters and the one action that fills it. */
export const EmptyState = ({ title, children, action }: { title: ReactNode; children?: ReactNode; action?: ReactNode }) => (
  <div className="state-block">
    <p className="state-block-title">{title}</p>
    {children ? <p className="state-block-text">{children}</p> : null}
    {action}
  </div>
);

const ERROR_ICONS: Record<ErrorKind, ReactNode> = {
  offline: <LuWifiOff />,
  timeout: <LuHourglass />,
  not_found: <LuSearchX />,
  forbidden: <LuLock />,
  rate_limited: <LuHourglass />,
  server: <LuServerCrash />,
  unknown: <LuTriangleAlert />,
};

/**
 * What broke and what to do about it. Pass the caught `error` and the state
 * names the cause (offline, server error, not found, refused, …) and keeps the
 * request and status under "Technical details"; pass `onRetry` for a
 * "Try again" button.
 */
export const ErrorState = ({
  title,
  children,
  action,
  error,
  onRetry,
  icon,
}: {
  title: ReactNode;
  children?: ReactNode;
  action?: ReactNode;
  error?: unknown;
  onRetry?: () => void;
  icon?: ReactNode;
}) => {
  const { t } = useI18n();
  const described = error === undefined || error === null ? null : describeError(error);
  const technical = described
    ? [described.request, described.status ? `HTTP ${described.status}` : null, described.detail, described.message]
        .filter((line): line is string => Boolean(line))
        .filter((line, index, all) => all.indexOf(line) === index)
    : [];
  return (
    <div className="state-block state-block--error" role="alert">
      <span className="state-block-icon" aria-hidden="true">
        {icon ?? ERROR_ICONS[described?.kind ?? "unknown"]}
      </span>
      <div className="state-block-body">
        <p className="state-block-title">{title}</p>
        {children ? <p className="state-block-text">{children}</p> : null}
        {described ? <p className="state-block-text">{errorHint(described, t)}</p> : null}
        {onRetry || action ? (
          <div className="state-block-actions">
            {onRetry ? (
              <button type="button" className="btn-secondary" onClick={onRetry}>
                <LuRefreshCw aria-hidden="true" />
                {t("Try again", "Erneut versuchen")}
              </button>
            ) : null}
            {action}
          </div>
        ) : null}
        {technical.length ? (
          <details className="state-block-details">
            <summary>{t("Technical details", "Technische Details")}</summary>
            <pre className="mono">{technical.join("\n")}</pre>
          </details>
        ) : null}
      </div>
    </div>
  );
};

/** A figure and its label. Pairs inside a `.stat-row` part with hairlines. */
export const Stat = ({ label, value, tone }: { label: ReactNode; value: ReactNode; tone?: string }) => (
  <div className="stat">
    <dt>{label}</dt>
    <dd className={tone ? `sev-${tone}` : undefined}>{value}</dd>
  </div>
);

/** A link that leaves Hecate: opens in a new tab and says so with a trailing icon. */
export const ExternalLink = ({
  children,
  className,
  ...rest
}: Omit<AnchorHTMLAttributes<HTMLAnchorElement>, "target" | "rel">) => (
  <a target="_blank" rel="noopener noreferrer" className={`external-link${className ? ` ${className}` : ""}`} {...rest}>
    {children}
    <LuExternalLink className="external-link-icon" aria-hidden="true" />
  </a>
);
