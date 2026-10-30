import type { ReactNode } from "react";
import { AiMarkdown } from "../AiMarkdown";

/** Reports open with their own `#` headings. Mapped down so the screen keeps one h1 and a stepped outline. */
const REPORT_HEADINGS = { h1: "h4", h2: "h4", h3: "h5", h4: "h6", h5: "h6", h6: "h6" } as const;

/** The rendered body of an AI report, at a readable measure. */
export const ReportMarkdown = ({ children }: { children: string }) => (
  <div className="ai-analyse-prose">
    <AiMarkdown components={REPORT_HEADINGS}>{children}</AiMarkdown>
  </div>
);

/** Plain label and value pairs for a report: provider, language, tokens. */
export const ReportMeta = ({ rows }: { rows: { label: string; value: ReactNode }[] }) => (
  <dl className="ai-analyse-meta">
    {rows.map(({ label, value }) => (
      <div key={label} className="ai-analyse-meta-row">
        <dt>{label}</dt>
        <dd>{value}</dd>
      </div>
    ))}
  </dl>
);
