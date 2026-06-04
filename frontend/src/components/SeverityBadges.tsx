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
    return <span style={{ fontSize: "0.8125rem", color: "rgba(255,255,255,0.4)", ...style }}>—</span>;
  }
  const badges: { label: string; count: number; color: string }[] = [
    { label: "C", count: summary.critical, color: "#ff6b6b" },
    { label: "H", count: summary.high, color: "#ff922b" },
    { label: "M", count: summary.medium, color: "#fcc419" },
    { label: "L", count: summary.low, color: "#69db7c" },
  ];
  return (
    <div style={{ display: "flex", gap: "0.375rem", flexWrap: "wrap", ...style }}>
      {badges
        .filter((b) => b.count > 0)
        .map((b) => (
          <span
            key={b.label}
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: "0.25rem",
              padding: "0.125rem 0.5rem",
              borderRadius: "4px",
              fontSize: "0.75rem",
              fontWeight: 600,
              background: `${b.color}20`,
              color: b.color,
            }}
          >
            {b.label}: {b.count}
          </span>
        ))}
    </div>
  );
};
