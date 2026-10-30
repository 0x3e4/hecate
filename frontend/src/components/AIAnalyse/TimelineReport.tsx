import type { ReactNode } from "react";
import { useI18n } from "../../i18n/context";
import { formatDateTime } from "../../utils/dateFormat";
import { ReportMarkdown, ReportMeta } from "./ReportParts";

interface TimelineReportProps {
  date?: string | null;
  kind: string;
  provider?: string | null;
  triggeredBy?: string | null;
  language?: string | null;
  tokenUsage?: { inputTokens: number; outputTokens: number } | null;
  heading: ReactNode;
  details?: ReactNode;
  summary: string;
}

/** One entry of the AI analysis timeline: what ran, when and by whom, then the report itself. */
export const TimelineReport = ({
  date,
  kind,
  provider,
  triggeredBy,
  language,
  tokenUsage,
  heading,
  details,
  summary,
}: TimelineReportProps) => {
  const { t, locale } = useI18n();

  const rows: { label: string; value: ReactNode }[] = [];
  if (provider) rows.push({ label: t("Provider", "Provider"), value: provider });
  // Web UI runs carry no trigger; everything with one came in through MCP.
  rows.push({ label: t("Triggered by", "Ausgelöst von"), value: (triggeredBy || "").trim() || "API" });
  if (language) rows.push({ label: t("Language", "Sprache"), value: language.toUpperCase() });
  if (tokenUsage) {
    rows.push({
      label: t("Tokens", "Tokens"),
      value: `${tokenUsage.inputTokens.toLocaleString(locale)} in / ${tokenUsage.outputTokens.toLocaleString(locale)} out`,
    });
  }

  return (
    <li className="ai-analyse-report">
      <div className="ai-analyse-report-rail">
        {date && (
          <time className="ai-analyse-report-date" dateTime={date}>
            {formatDateTime(date)}
          </time>
        )}
        <p className="ai-analyse-report-kind">{kind}</p>
        <ReportMeta rows={rows} />
      </div>
      <div className="ai-analyse-report-main">
        <h3 className="ai-analyse-report-title">{heading}</h3>
        {details}
        {summary ? (
          <ReportMarkdown>{summary}</ReportMarkdown>
        ) : (
          <p className="muted">{t("No summary available.", "Keine Zusammenfassung verfügbar.")}</p>
        )}
      </div>
    </li>
  );
};
