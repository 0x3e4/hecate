import type { ButtonHTMLAttributes, ReactNode } from "react";

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

/** What is empty, why it matters and the one action that fills it. */
export const EmptyState = ({ title, children, action }: { title: ReactNode; children?: ReactNode; action?: ReactNode }) => (
  <div className="state-block">
    <p className="state-block-title">{title}</p>
    {children ? <p className="state-block-text">{children}</p> : null}
    {action}
  </div>
);

/** What broke and what to do about it. */
export const ErrorState = ({ title, children, action }: { title: ReactNode; children?: ReactNode; action?: ReactNode }) => (
  <div className="state-block state-block--error" role="alert">
    <p className="state-block-title">{title}</p>
    {children ? <p className="state-block-text">{children}</p> : null}
    {action}
  </div>
);

/** A figure and its label. Pairs inside a `.stat-row` part with hairlines. */
export const Stat = ({ label, value, tone }: { label: ReactNode; value: ReactNode; tone?: string }) => (
  <div className="stat">
    <dt>{label}</dt>
    <dd className={tone ? `sev-${tone}` : undefined}>{value}</dd>
  </div>
);
