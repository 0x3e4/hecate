import React, { useEffect, useMemo, useRef, useState, type ReactNode } from "react";

import {
  CatalogSample,
  StatsResponse,
  TermsBucket,
  TimelinePoint,
  fetchStatsOverview,
} from "../api/stats";
import { SkeletonBlock } from "../components/Skeleton";
import { useI18n } from "../i18n/context";
import { getCurrentTimezone } from "../timezone/storage";
import { EmptyState, ErrorState, PageHeader, Section, SeverityTag, Stat, severityVar } from "../ui/primitives";
import "../screens/stats.css";

export const StatsPage = () => {
  const { t } = useI18n();
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [errorCause, setErrorCause] = useState<unknown>(null);
  const [retryKey, setRetryKey] = useState(0);
  const showSkeleton = loading && !stats;

  useEffect(() => {
    document.title = t("Hecate Cyber Defense - Statistics", "Hecate Cyber Defense - Statistiken");

    return () => {
      document.title = "Hecate Cyber Defense";
    };
  }, [t]);

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      setError(null);
      try {
        const response = await fetchStatsOverview();
        setStats(response);
      } catch (err) {
        console.error("Failed to load stats", err);
        setErrorCause(err);
        setError(t("Could not load statistics.", "Statistiken konnten nicht geladen werden."));
      } finally {
        setLoading(false);
      }
    };

    load();
  }, [t, retryKey]);

  return (
    <div className="page stats-page">
      <PageHeader
        title={t("Statistics", "Statistiken")}
        description={t(
          "Overview of ingested vulnerabilities, sources, and the derived asset database.",
          "Überblick über ingestierte Schwachstellen, Quellen und die abgeleitete Asset-Datenbank."
        )}
      />

      {showSkeleton && <StatsSkeleton />}
      {error && <ErrorState title={error} error={errorCause} onRetry={() => setRetryKey((k) => k + 1)} />}

      {!showSkeleton && stats && (
        <>
          <section className="stats-lead">
            <SummaryGrid stats={stats} />
            <ChartBlock title={t("Severity", "Schweregrade")}>
              <SeverityChart data={stats.vulnerabilities.severities} />
            </ChartBlock>
          </section>

          <Section title={t("Publication trend (last 30 days)", "Veröffentlichungstrend (letzte 30 Tage)")}>
            <TimelineChart data={stats.vulnerabilities.timeline} />
          </Section>

          <Section title={t("Historical overview of published vulnerabilities", "Historischer Überblick von veröffentlichten Schwachstellen")}>
            <TimelineSummaryChart data={stats.vulnerabilities.timelineSummary} />
          </Section>

          <Section>
            <div className="stats-columns stats-columns--3">
              <ChartBlock title={t("EPSS Score", "EPSS-Score")}>
                <EpssChart data={stats.vulnerabilities.epssRanges} />
              </ChartBlock>
              <ChartBlock title="Top 5 CWEs">
                <CweChart data={stats.vulnerabilities.topCwes} />
              </ChartBlock>
              <ChartBlock title={t("Source", "Quelle")}>
                <SourcesChart data={stats.vulnerabilities.sources} />
              </ChartBlock>
            </div>
          </Section>

          <Section>
            <div className="stats-columns stats-columns--2">
              <ChartBlock title={t("Most named vendors", "Meistgenannte Hersteller")}>
                <TopList data={stats.vulnerabilities.topVendors} emptyMessage={t("No vendors.", "Keine Vendors.")} limit={8} />
              </ChartBlock>
              <ChartBlock title={t("Most named products", "Meistgenannte Produkte")}>
                <TopList data={stats.vulnerabilities.topProducts} emptyMessage={t("No products.", "Keine Produkte.")} limit={8} />
              </ChartBlock>
              <ChartBlock title={t("Top reference domains", "Top-Referenzdomains")}>
                <TopList data={stats.vulnerabilities.referenceDomains} emptyMessage={t("No references.", "Keine Referenzen.")} limit={10} />
              </ChartBlock>
              <ChartBlock title={t("Top assigners", "Top-Assigners")}>
                <TopList data={stats.vulnerabilities.topAssigners} emptyMessage={t("No assigners.", "Keine Assigner.")} limit={10} />
              </ChartBlock>
            </div>
          </Section>

          <AssetSection assets={stats.assets} />
        </>
      )}
    </div>
  );
};

const SkeletonBars = ({ rows }: { rows: number }) => (
  <div className="stats-skeleton-bars">
    {Array.from({ length: rows }).map((_, index) => (
      <SkeletonBlock key={index} height="1rem" radius={2} />
    ))}
  </div>
);

const StatsSkeleton = () => (
  <div aria-hidden="true">
    <div className="stats-lead">
      <div className="stats-summary">
        <div className="stats-skeleton-figure">
          <SkeletonBlock height="0.8rem" width="45%" radius={4} />
          <SkeletonBlock height="2.3rem" width="70%" radius={4} />
        </div>
        <div className="stats-skeleton-figure">
          <SkeletonBlock height="0.8rem" width="45%" radius={4} />
          <SkeletonBlock height="1.8rem" width="60%" radius={4} />
        </div>
      </div>
      <div className="stats-block">
        <SkeletonBlock height="1rem" width="30%" radius={4} />
        <SkeletonBars rows={5} />
      </div>
    </div>

    <div className="ui-section stats-block">
      <SkeletonBlock height="1rem" width="35%" radius={4} />
      <SkeletonBlock height="240px" radius={4} />
    </div>

    <div className="ui-section stats-columns stats-columns--3">
      {Array.from({ length: 3 }).map((_, index) => (
        <div key={index} className="stats-block">
          <SkeletonBlock height="1rem" width="40%" radius={4} />
          <SkeletonBars rows={5} />
        </div>
      ))}
    </div>
  </div>
);

const SummaryGrid = ({ stats }: { stats: StatsResponse }) => {
  const { t, locale } = useI18n();
  return (
    <div className="stats-summary">
      <dl className="stats-hero">
        <Stat label={t("Exploited (KEV)", "Ausgenutzt (KEV)")} value={stats.vulnerabilities.exploitedCount.toLocaleString(locale)} />
        <Stat label={t("Vulnerabilities", "Schwachstellen")} value={stats.vulnerabilities.total.toLocaleString(locale)} />
      </dl>
      <dl className="stat-row stats-catalog-figures">
        <Stat label={t("Vendors", "Hersteller")} value={stats.assets.vendorTotal.toLocaleString(locale)} />
        <Stat label={t("Products", "Produkte")} value={stats.assets.productTotal.toLocaleString(locale)} />
        <Stat label={t("Versions", "Versionen")} value={stats.assets.versionTotal.toLocaleString(locale)} />
      </dl>
    </div>
  );
};

const ChartBlock = ({ title, children }: { title: string; children: ReactNode }) => (
  <div className="stats-block">
    <h2>{title}</h2>
    {children}
  </div>
);

interface BarItem {
  key: string;
  label: ReactNode;
  value: number;
  /** Runtime token for the mark. Set only when the colour carries meaning; otherwise the bar stays neutral ink. */
  color?: string;
  title?: string;
}

/** Sorted horizontal bars: label, zero-based bar, direct value. No legend, no axis. */
const BarList = ({ items, variant }: { items: BarItem[]; variant?: "severity" | "ranking" }) => {
  const { locale } = useI18n();
  const maxValue = Math.max(...items.map((item) => item.value), 1);

  return (
    <ul className={`stats-bars${variant ? ` stats-bars--${variant}` : ""}`}>
      {items.map((item) => (
        <li key={item.key} className="stats-bar-row">
          <span className="stats-bar-label" title={item.title}>
            {item.label}
          </span>
          <span className="stats-bar-track" aria-hidden="true">
            {item.value > 0 && (
              <span
                className="stats-bar-fill"
                style={{ width: `${(item.value / maxValue) * 100}%`, background: item.color }}
              />
            )}
          </span>
          <span className="stats-bar-value">{item.value.toLocaleString(locale)}</span>
        </li>
      ))}
    </ul>
  );
};

const severityLabels: Record<string, [string, string]> = {
  CRITICAL: ["Critical", "Kritisch"],
  HIGH: ["High", "Hoch"],
  MEDIUM: ["Medium", "Mittel"],
  LOW: ["Low", "Niedrig"],
  UNKNOWN: ["Unknown", "Unbekannt"],
};

const SeverityChart = ({ data }: { data: TermsBucket[] }) => {
  const { t } = useI18n();
  const normalized = useMemo(() => {
    if (!data.length) {
      return [];
    }
    const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
    const merged: Record<string, number> = {};
    for (const bucket of data) {
      let key = bucket.key ? bucket.key.toUpperCase() : "UNKNOWN";
      if (key === "NONE") key = "UNKNOWN";
      merged[key] = (merged[key] || 0) + bucket.doc_count;
    }
    const mapped = Object.entries(merged).map(([key, doc_count]) => ({ key, doc_count }));
    const weight = (value: string) => {
      const index = order.indexOf(value);
      return index === -1 ? order.length : index;
    };
    mapped.sort((a, b) => weight(a.key) - weight(b.key));
    return mapped;
  }, [data]);

  if (normalized.length === 0) {
    return <EmptyState title={t("No severity information.", "Keine Severity-Angaben.")} />;
  }

  return (
    <BarList
      variant="severity"
      items={normalized.map((item) => ({
        key: item.key,
        label: <SeverityTag severity={item.key}>{severityLabels[item.key] ? t(severityLabels[item.key][0], severityLabels[item.key][1]) : item.key}</SeverityTag>,
        value: item.doc_count,
        color: severityVar(item.key),
      }))}
    />
  );
};

const SourcesChart = ({ data }: { data: TermsBucket[] }) => {
  const { t } = useI18n();
  const items = useMemo(() => data.filter((item) => item.doc_count > 0).slice(0, 6), [data]);

  if (items.length === 0) {
    return <EmptyState title={t("No sources recorded.", "Keine Quellen erfasst.")} />;
  }

  return (
    <BarList
      items={items.map((item) => ({
        key: item.key,
        label: item.key || "n/a",
        value: item.doc_count,
        title: item.key,
      }))}
    />
  );
};

const CweChart = ({ data }: { data: TermsBucket[] }) => {
  const { t } = useI18n();
  const items = useMemo(
    () =>
      data
        .filter((item) => item.doc_count > 0 && !["NVD-CWE-noinfo", "NVD-CWE-Other"].includes(item.key))
        .slice(0, 5),
    [data]
  );

  if (items.length === 0) {
    return <EmptyState title={t("No CWEs recorded.", "Keine CWEs erfasst.")} />;
  }

  return (
    <BarList
      items={items.map((item) => ({
        key: item.key,
        label: <span className="mono">{item.key || "n/a"}</span>,
        value: item.doc_count,
        title: item.key,
      }))}
    />
  );
};

const epssLabels: Record<string, string> = {
  "0.0-0.1": "0-10",
  "0.1-0.3": "10-30",
  "0.3-0.5": "30-50",
  "0.5-0.7": "50-70",
  "0.7-1.0": "70-100",
};

const EpssChart = ({ data }: { data: TermsBucket[] }) => {
  const { t } = useI18n();
  if (!data.length) {
    return <EmptyState title={t("No EPSS data.", "Keine EPSS-Daten.")} />;
  }

  // Highest exploitation probability first: that band is the one an analyst reads for.
  return (
    <BarList
      items={[...data].reverse().map((item) => ({
        key: item.key,
        label: epssLabels[item.key] ?? item.key,
        value: item.doc_count,
      }))}
    />
  );
};

const useContainerWidth = (ref: React.RefObject<HTMLElement | null>, fallback = 600) => {
  const [width, setWidth] = useState(fallback);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;

    const observer = new ResizeObserver((entries) => {
      for (const entry of entries) {
        const w = entry.contentRect.width;
        if (w > 0) setWidth(w);
      }
    });
    observer.observe(el);
    return () => observer.disconnect();
  }, [ref]);

  return width;
};

const TimelineChart = ({ data }: { data: TimelinePoint[] }) => {
  const { t, locale } = useI18n();
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null);
  const [tooltipPosition, setTooltipPosition] = useState<{ x: number; y: number } | null>(null);
  const containerWidth = useContainerWidth(containerRef);

  if (!data.length) {
    return <EmptyState title={t("No timeline data yet.", "Noch keine Zeitreihendaten.")} />;
  }

  const baseWidth = containerWidth;
  const height = 240;
  const isMobile = containerWidth < 500;
  const padding = { top: 12, bottom: 48, left: isMobile ? 44 : 56, right: isMobile ? 16 : 24 };
  const chartWidth = baseWidth - padding.left - padding.right;
  const chartHeight = height - padding.top - padding.bottom;

  const maxValue = Math.max(...data.map((point) => point.count), 1);
  const step = data.length > 1 ? chartWidth / (data.length - 1) : 0;

  const chartPoints = data.map((point, index) => {
    const x = padding.left + (data.length > 1 ? index * step : chartWidth / 2);
    const y = padding.top + chartHeight - (point.count / maxValue) * chartHeight;
    return { ...point, x, y };
  });

  // Create smooth bezier curve path
  const createSmoothPath = () => {
    if (chartPoints.length < 2) return "";

    let path = `M ${chartPoints[0].x},${chartPoints[0].y}`;

    for (let i = 0; i < chartPoints.length - 1; i++) {
      const curr = chartPoints[i];
      const next = chartPoints[i + 1];
      const midX = (curr.x + next.x) / 2;

      path += ` C ${midX},${curr.y} ${midX},${next.y} ${next.x},${next.y}`;
    }

    return path;
  };

  const linePath = createSmoothPath();

  const hoveredPoint = hoveredIndex != null ? chartPoints[hoveredIndex] : null;

  // Format timestamp to readable date
  const formatDateTime = (timestamp: number) => {
    const date = new Date(timestamp);
    const day = date.toLocaleDateString(locale, { weekday: "short", day: "numeric", month: "short", year: "numeric", timeZone: getCurrentTimezone() });
    return { day };
  };

  const updateTooltipPosition = (index: number, e: React.MouseEvent) => {
    setHoveredIndex(index);
    const container = containerRef.current;
    if (!container) {
      setTooltipPosition(null);
      return;
    }
    const rect = container.getBoundingClientRect();
    setTooltipPosition({
      x: e.clientX - rect.left,
      y: e.clientY - rect.top,
    });
  };

  const clearHover = () => {
    setHoveredIndex(null);
    setTooltipPosition(null);
  };

  // Generate time axis labels
  const getTimeLabels = () => {
    if (data.length === 0) return [];

    const maxLabels = isMobile ? 4 : 8;
    const labelCount = Math.min(maxLabels, data.length);
    const labelStep = Math.max(1, Math.floor(data.length / labelCount));
    const labels: { index: number; x: number; date: Date }[] = [];

    for (let i = 0; i < data.length; i += labelStep) {
      const point = data[i];
      if (point.timestamp) {
        labels.push({ index: i, x: chartPoints[i].x, date: new Date(point.timestamp) });
      }
    }

    return labels;
  };

  const timeLabels = getTimeLabels();
  const hitWidth = step || chartWidth;

  return (
    <div ref={containerRef} className="stats-chart" onMouseLeave={clearHover}>
      <svg
        role="img"
        aria-label={t("Publication trend (last 30 days)", "Veröffentlichungstrend (letzte 30 Tage)")}
        width={baseWidth}
        height={height}
        viewBox={`0 0 ${baseWidth} ${height}`}
      >
        {/* Grid lines, the baseline first */}
        {[0, 0.5, 1].map((ratio) => (
          <line
            key={ratio}
            className="stats-grid-line"
            x1={padding.left}
            y1={padding.top + chartHeight * (1 - ratio)}
            x2={baseWidth - padding.right}
            y2={padding.top + chartHeight * (1 - ratio)}
          />
        ))}

        <path className="stats-line" d={linePath} />

        {/* Hover indicator */}
        {hoveredPoint && (
          <>
            <line
              className="stats-hover-line"
              x1={hoveredPoint.x}
              y1={padding.top}
              x2={hoveredPoint.x}
              y2={height - padding.bottom}
            />
            <circle className="stats-hover-point" cx={hoveredPoint.x} cy={hoveredPoint.y} r={4} />
          </>
        )}

        {/* Hit targets, one per day */}
        {chartPoints.map((point, index) => (
          <rect
            key={`${point.key}-${index}`}
            className="stats-hit"
            x={point.x - hitWidth / 2}
            y={padding.top}
            width={hitWidth}
            height={chartHeight}
            onMouseEnter={(e) => updateTooltipPosition(index, e)}
            onMouseMove={(e) => updateTooltipPosition(index, e)}
          />
        ))}

        {/* Time axis labels */}
        {timeLabels.map(({ x, date }, i) => {
          const dayLabel = date.toLocaleDateString(locale, { day: "numeric", month: "short", timeZone: getCurrentTimezone() });
          const yearLabel = date.getFullYear().toString();
          const yearChanged = i === 0 || timeLabels[i - 1].date.getFullYear().toString() !== yearLabel;

          return (
            <g key={`label-${i}`}>
              <text className="stats-axis-text" x={x} y={height - padding.bottom + 18} textAnchor="middle">
                {dayLabel}
              </text>
              {yearChanged && (
                <text className="stats-axis-text" x={x} y={height - padding.bottom + 34} textAnchor="middle">
                  {yearLabel}
                </text>
              )}
            </g>
          );
        })}

        {/* Y-axis labels */}
        {[0, 0.5, 1].map((ratio) => (
          <text
            key={ratio}
            className="stats-axis-text"
            x={padding.left - 8}
            y={padding.top + chartHeight * (1 - ratio) + 4}
            textAnchor="end"
          >
            {Math.round(maxValue * ratio).toLocaleString(locale)}
          </text>
        ))}
      </svg>

      {/* Tooltip */}
      {hoveredPoint && tooltipPosition && (
        <div className="stats-tooltip" style={{ left: tooltipPosition.x, top: tooltipPosition.y }}>
          <div className="stats-tooltip-value">
            {hoveredPoint.count.toLocaleString(locale)} {t("Vulnerabilities", "Schwachstellen")}
          </div>
          {hoveredPoint.timestamp && <div className="stats-tooltip-meta">{formatDateTime(hoveredPoint.timestamp).day}</div>}
        </div>
      )}
    </div>
  );
};

interface CumulativePoint extends TimelinePoint {
  cumulative: number;
  x: number;
  y: number;
}

const TimelineSummaryChart = ({ data }: { data: TimelinePoint[] }) => {
  const { t, locale } = useI18n();
  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null);
  const [tooltipPos, setTooltipPos] = useState<{ x: number; y: number } | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const containerWidth = useContainerWidth(containerRef);

  // Calculate cumulative totals
  const cumulativeData = useMemo(() => {
    let runningTotal = 0;
    return data.map((point) => {
      runningTotal += point.count;
      return { ...point, cumulative: runningTotal };
    });
  }, [data]);

  if (!data.length) {
    return <EmptyState title={t("No timeline data yet.", "Noch keine Zeitreihendaten.")} />;
  }

  const width = containerWidth;
  const height = 240;
  const isMobile = containerWidth < 500;
  const padding = { top: 12, bottom: 32, left: isMobile ? 60 : 68, right: isMobile ? 16 : 24 };
  const chartWidth = width - padding.left - padding.right;
  const chartHeight = height - padding.top - padding.bottom;

  const maxValue = cumulativeData[cumulativeData.length - 1]?.cumulative || 1;

  const chartPoints: CumulativePoint[] = cumulativeData.map((point: TimelinePoint & { cumulative: number }, index: number) => {
    const x = padding.left + (cumulativeData.length > 1 ? (index / (cumulativeData.length - 1)) * chartWidth : chartWidth / 2);
    const y = padding.top + chartHeight - (point.cumulative / maxValue) * chartHeight;
    return { ...point, x, y };
  });

  // Create smooth path
  const createPath = () => {
    if (chartPoints.length < 2) return "";
    let path = `M ${chartPoints[0].x},${chartPoints[0].y}`;
    for (let i = 1; i < chartPoints.length; i++) {
      path += ` L ${chartPoints[i].x},${chartPoints[i].y}`;
    }
    return path;
  };

  const linePath = createPath();

  const firstPoint = cumulativeData[0];
  const lastPoint = cumulativeData[cumulativeData.length - 1];
  const formatMonth = (timestamp: number) => {
    const date = new Date(timestamp);
    return date.toLocaleDateString(locale, { month: "short", year: "numeric", timeZone: getCurrentTimezone() });
  };

  const hoveredPoint = hoveredIndex !== null ? chartPoints[hoveredIndex] : null;

  const handleMouseMove = (e: React.MouseEvent<SVGSVGElement>) => {
    const container = containerRef.current;
    if (!container) return;

    const rect = container.getBoundingClientRect();
    const mouseX = e.clientX - rect.left;
    const relativeX = (mouseX / rect.width) * width;

    // Find closest point
    let closestIndex = 0;
    let closestDist = Infinity;
    chartPoints.forEach((point: CumulativePoint, index: number) => {
      const dist = Math.abs(point.x - relativeX);
      if (dist < closestDist) {
        closestDist = dist;
        closestIndex = index;
      }
    });

    setHoveredIndex(closestIndex);
    setTooltipPos({ x: mouseX, y: e.clientY - rect.top });
  };

  return (
    <div ref={containerRef} className="stats-chart">
      <svg
        role="img"
        aria-label={t("Historical overview of published vulnerabilities", "Historischer Überblick von veröffentlichten Schwachstellen")}
        width={width}
        height={height}
        viewBox={`0 0 ${width} ${height}`}
        onMouseMove={handleMouseMove}
        onMouseLeave={() => { setHoveredIndex(null); setTooltipPos(null); }}
      >
        {/* Grid lines, the baseline first */}
        {[0, 0.5, 1].map((ratio) => (
          <line
            key={ratio}
            className="stats-grid-line"
            x1={padding.left}
            y1={padding.top + chartHeight * (1 - ratio)}
            x2={width - padding.right}
            y2={padding.top + chartHeight * (1 - ratio)}
          />
        ))}

        <path className="stats-line" d={linePath} />

        {/* Hover indicator */}
        {hoveredPoint && (
          <>
            <line
              className="stats-hover-line"
              x1={hoveredPoint.x}
              y1={padding.top}
              x2={hoveredPoint.x}
              y2={height - padding.bottom}
            />
            <circle className="stats-hover-point" cx={hoveredPoint.x} cy={hoveredPoint.y} r={4} />
          </>
        )}

        {/* Y-axis labels */}
        {[0, 0.5, 1].map((ratio) => (
          <text
            key={ratio}
            className="stats-axis-text"
            x={padding.left - 8}
            y={padding.top + chartHeight * (1 - ratio) + 4}
            textAnchor="end"
          >
            {Math.round(maxValue * ratio).toLocaleString(locale)}
          </text>
        ))}

        {/* Start and end labels */}
        <text className="stats-axis-text" x={padding.left} y={height - 8} textAnchor="start">
          {firstPoint.timestamp ? formatMonth(firstPoint.timestamp) : firstPoint.key}
        </text>
        <text className="stats-axis-text" x={width - padding.right} y={height - 8} textAnchor="end">
          {lastPoint.timestamp ? formatMonth(lastPoint.timestamp) : lastPoint.key}
        </text>
      </svg>

      {/* Tooltip */}
      {hoveredPoint && tooltipPos && (
        <div className="stats-tooltip" style={{ left: tooltipPos.x, top: tooltipPos.y }}>
          <div className="stats-tooltip-value">
            {hoveredPoint.cumulative.toLocaleString(locale)} {t("total", "gesamt")}
          </div>
          <div className="stats-tooltip-meta">
            +{hoveredPoint.count.toLocaleString(locale)} {t("this month", "diesen Monat")}
          </div>
          <div className="stats-tooltip-meta">
            {hoveredPoint.timestamp ? formatMonth(hoveredPoint.timestamp) : hoveredPoint.key}
          </div>
        </div>
      )}
    </div>
  );
};

const TopList = ({ data, emptyMessage, limit = 6 }: { data: TermsBucket[]; emptyMessage: string; limit?: number }) => {
  const items = useMemo(
    () =>
      data
        .filter((item) => {
          if (!item.key || typeof item.key !== "string") {
            return false;
          }
          const normalized = item.key.trim().toLowerCase();
          return item.doc_count > 0 && normalized !== "n/a" && normalized !== "na" && normalized !== "*** n/a ***";
        })
        .slice(0, limit),
    [data, limit]
  );

  if (items.length === 0) {
    return <EmptyState title={emptyMessage} />;
  }

  return (
    <BarList
      variant="ranking"
      items={items.map((item) => ({
        key: item.key,
        label: item.key || "n/a",
        value: item.doc_count,
        title: item.key,
      }))}
    />
  );
};

const AssetSection = ({
  assets,
}: {
  assets: StatsResponse["assets"];
}) => {
  const { t } = useI18n();
  return (
    <Section>
      <div className="stats-columns stats-columns--2">
        <ChartBlock title={t("Asset vendors", "Asset-Hersteller")}>
          <CatalogSampleList items={assets.sampleVendors} emptyMessage={t("No vendors available.", "Keine Vendors verfügbar.")} />
        </ChartBlock>
        <ChartBlock title={t("Asset products", "Asset-Produkte")}>
          <CatalogSampleList items={assets.sampleProducts} emptyMessage={t("No products available.", "Keine Produkte verfügbar.")} />
        </ChartBlock>
      </div>
    </Section>
  );
};

const truncateList = (values: string[], maxLength: number): string => {
  const joined = values.join(", ");
  return joined.length > maxLength ? `${joined.slice(0, maxLength - 1)}…` : joined;
};

const CatalogSampleList = ({ items, emptyMessage }: { items: CatalogSample[]; emptyMessage: string }) => {
  const { t } = useI18n();
  if (!items.length) {
    return <EmptyState title={emptyMessage} />;
  }

  return (
    <ul className="stats-sample-list">
      {items.map((item) => (
        <li key={item.slug}>
          <strong>{item.name}</strong>
          {item.aliases.length > 0 ? (
            <span className="stats-sample-aliases">{truncateList(item.aliases, 60)}</span>
          ) : (
            <span className="stats-sample-aliases">{t("No additional aliases.", "Keine zusätzlichen Aliase.")}</span>
          )}
        </li>
      ))}
    </ul>
  );
};
