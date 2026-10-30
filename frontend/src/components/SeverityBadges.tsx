import type { ScanSummary } from "../types";

/**
 * Shared severity-rollup badges (C/H/M/L), used on the Scans page, the
 * per-target detail page, and scan history. Keeps the look identical everywhere.
 */
export const SeverityBadges = ({
  summary,
  style,
}: {
  summary: ScanSummary | null | undefined;
  style?: React.CSSProperties;
}) => {
  if (!summary || summary.total === 0) {
    return <span className="severity-rollup severity-rollup--none" style={style}>0</span>;
  }
  const badges: { label: string; count: number; level: string }[] = [
    { label: "C", count: summary.critical, level: "critical" },
    { label: "H", count: summary.high, level: "high" },
    { label: "M", count: summary.medium, level: "medium" },
    { label: "L", count: summary.low, level: "low" },
  ];
  return (
    <span className="severity-rollup" style={style}>
      {badges
        .filter((b) => b.count > 0)
        .map((b) => (
          <span key={b.label} className={`sev-${b.level}`}>
            {b.label} {b.count}
          </span>
        ))}
    </span>
  );
};
