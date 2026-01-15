import React, { useEffect, useMemo, useRef, useState, type ReactNode } from "react";

import {
  CatalogSample,
  StatsResponse,
  TermsBucket,
  TimelinePoint,
  fetchStatsOverview,
} from "../api/stats";
import { SkeletonBlock } from "../components/Skeleton";

export const StatsPage = () => {
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const showSkeleton = loading && !stats;

  useEffect(() => {
    document.title = "Hecate Cyber Defense - Statistiken";

    return () => {
      document.title = "Hecate Cyber Defense";
    };
  }, []);

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      setError(null);
      try {
        const response = await fetchStatsOverview();
        setStats(response);
      } catch (err) {
        console.error("Failed to load stats", err);
        setError("Statistiken konnten nicht geladen werden.");
      } finally {
        setLoading(false);
      }
    };

    load();
  }, []);

  return (
    <div className="page">
      <section className="card">
        <h2>Statistiken</h2>
        <p className="muted">
          Überblick über ingestierte Schwachstellen, Quellen und die abgeleitete Asset-Datenbank.
        </p>

        {showSkeleton && <StatsSkeleton />}
        {error && <p className="muted">{error}</p>}

        {!showSkeleton && stats && (
          <>
            <div style={{ display: "grid", gap: "1.5rem" }}>
              <SummaryGrid stats={stats} />
              
              <div style={{ display: "grid", gap: "1.5rem" }}>
                <div style={{ display: "grid", gap: "1.25rem", gridTemplateColumns: "repeat(auto-fit, minmax(min(100%, 520px), 1fr))" }}>
                  <ChartCard title="Quelle">
                    <SourcesChart data={stats.vulnerabilities.sources} />
                  </ChartCard>
                  <ChartCard title="Schweregrade">
                    <SeverityChart data={stats.vulnerabilities.severities} />
                  </ChartCard>
                </div>

                <div style={{ display: "grid", gap: "1.25rem", gridTemplateColumns: "repeat(auto-fit, minmax(min(100%, 520px), 1fr))" }}>
                  <ChartCard title="Top 5 CWEs">
                    <CweChart data={stats.vulnerabilities.topCwes} />
                  </ChartCard>
                  <ChartCard title="EPSS Score">
                    <EpssChart data={stats.vulnerabilities.epssRanges} />
                  </ChartCard>
                </div>

                <ChartCard title="Veröffentlichungstrend (letzte 30 Tage)">
                  <TimelineChart data={stats.vulnerabilities.timeline} />
                </ChartCard>

                <ChartCard title="Historischer Überblick von veröffentlichten Schwachstellen">
                  <TimelineSummaryChart data={stats.vulnerabilities.timelineSummary} />
                </ChartCard>

                <div style={{ display: "grid", gap: "1.25rem", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))" }}>
                  <ChartCard title="Most named Vendors">
                    <TopList data={stats.vulnerabilities.topVendors} emptyMessage="Keine Vendors." limit={8} />
                  </ChartCard>
                  <ChartCard title="Most named Products">
                    <TopList data={stats.vulnerabilities.topProducts} emptyMessage="Keine Produkte." limit={8} />
                  </ChartCard>
                </div>

                <div style={{ display: "grid", gap: "1.25rem", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))" }}>
                  <ChartCard title="Top Reference Domains">
                    <TopList data={stats.vulnerabilities.referenceDomains} emptyMessage="Keine Referenzen." limit={10} />
                  </ChartCard>
                  <ChartCard title="Top Assigners">
                    <TopList data={stats.vulnerabilities.topAssigners} emptyMessage="Keine Assigner." limit={10} />
                  </ChartCard>
                </div>
              </div>

              <AssetSection assets={stats.assets} />
            </div>
          </>
        )}
      </section>
    </div>
  );
};

const StatsSkeleton = () => (
  <div style={{ display: "grid", gap: "1.5rem" }}>
    <div
      style={{
        display: "grid",
        gap: "1rem",
        gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
      }}
    >
      {Array.from({ length: 4 }).map((_, index) => (
        <div
          key={index}
          style={{
            background: "rgba(255,255,255,0.04)",
            borderRadius: "12px",
            padding: "1rem 1.25rem",
            border: "1px solid rgba(255,255,255,0.05)",
            display: "grid",
            gap: "0.85rem",
          }}
        >
          <SkeletonBlock height="0.8rem" width="45%" />
          <SkeletonBlock height="2.3rem" width="70%" />
        </div>
      ))}
    </div>

    <div style={{ display: "grid", gap: "1.5rem" }}>
      <div style={{ display: "grid", gap: "1.25rem", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))" }}>
        {Array.from({ length: 2 }).map((_, index) => (
          <div
            key={index}
            style={{
              background: "rgba(255,255,255,0.03)",
              borderRadius: "12px",
              padding: "1.25rem",
              border: "1px solid rgba(255,255,255,0.06)",
              display: "grid",
              gap: "1rem",
            }}
          >
            <SkeletonBlock height="1rem" width="40%" />
            <SkeletonBlock height="160px" />
          </div>
        ))}
      </div>

      <div
        style={{
          background: "rgba(255,255,255,0.03)",
          borderRadius: "12px",
          padding: "1.25rem",
          border: "1px solid rgba(255,255,255,0.06)",
          display: "grid",
          gap: "1rem",
        }}
      >
        <SkeletonBlock height="1rem" width="45%" />
        <SkeletonBlock height="200px" />
      </div>

      <div style={{ display: "grid", gap: "1.25rem", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))" }}>
        {Array.from({ length: 2 }).map((_, index) => (
          <div
            key={index}
            style={{
              background: "rgba(255,255,255,0.03)",
              borderRadius: "12px",
              padding: "1.25rem",
              border: "1px solid rgba(255,255,255,0.06)",
              display: "grid",
              gap: "0.85rem",
            }}
          >
            <SkeletonBlock height="1rem" width="50%" />
            <SkeletonBlock height="110px" />
          </div>
        ))}
      </div>

      <div
        style={{
          background: "rgba(255,255,255,0.03)",
          borderRadius: "12px",
          padding: "1.25rem",
          border: "1px solid rgba(255,255,255,0.06)",
          display: "grid",
          gap: "1.25rem",
        }}
      >
        <SkeletonBlock height="1rem" width="35%" />
        <div style={{ display: "grid", gap: "0.75rem", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))" }}>
          {Array.from({ length: 4 }).map((_, index) => (
            <SkeletonBlock key={index} height="64px" />
          ))}
        </div>
      </div>
    </div>
  </div>
);

const SummaryGrid = ({ stats }: { stats: StatsResponse }) => (
  <div
    style={{
      display: "grid",
      gap: "1rem",
      gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))",
    }}
  >
    <StatCard label="Vulnerabilities" value={stats.vulnerabilities.total} accent="#5c84ff" />
    <StatCard label="Exploited (KEV)" value={stats.vulnerabilities.exploitedCount} accent="#ff6b6b" />
    <StatCard label="Vendors" value={stats.assets.vendorTotal} accent="#66d9e8" />
    <StatCard label="Products" value={stats.assets.productTotal} accent="#ffd43b" />
    <StatCard label="Versions" value={stats.assets.versionTotal} accent="#a855f7" />
  </div>
);

const StatCard = ({ label, value, accent }: { label: string; value: number; accent: string }) => (
  <div
    style={{
      background: "rgba(255,255,255,0.04)",
      borderRadius: "12px",
      padding: "1rem 1.25rem",
      border: `1px solid ${accent}30`,
      boxShadow: "0 0 0 1px rgba(255,255,255,0.04) inset",
    }}
  >
    <span className="muted" style={{ fontSize: "0.85rem" }}>
      {label}
    </span>
    <div style={{ fontSize: "1.8rem", fontWeight: 600, marginTop: "0.25rem", color: accent }}>
      {value.toLocaleString()}
    </div>
  </div>
);

const ChartCard = ({ title, children }: { title: string; children: ReactNode }) => (
  <div
    style={{
      background: "rgba(255,255,255,0.03)",
      borderRadius: "12px",
      padding: "1.25rem",
      border: "1px solid rgba(255,255,255,0.06)",
    }}
  >
    <h3 style={{ marginBottom: "0.75rem" }}>{title}</h3>
    {children}
  </div>
);

const severityColors: Record<string, string> = {
  CRITICAL: "#ff6b6b",
  HIGH: "#ff922b",
  MEDIUM: "#fcc419",
  LOW: "#69db7c",
  UNKNOWN: "#748ffc",
};

const severityLabels: Record<string, string> = {
  CRITICAL: "Critical",
  HIGH: "High",
  MEDIUM: "Medium",
  LOW: "Low",
  UNKNOWN: "Unknown",
};

const SeverityChart = ({ data }: { data: TermsBucket[] }) => {
  const normalized = useMemo(() => {
    if (!data.length) {
      return [];
    }
    const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
    const mapped = data.map((bucket) => ({
      key: bucket.key ? bucket.key.toUpperCase() : "UNKNOWN",
      doc_count: bucket.doc_count,
    }));
    const weight = (value: string) => {
      const index = order.indexOf(value);
      return index === -1 ? order.length : index;
    };
    mapped.sort((a, b) => weight(a.key) - weight(b.key));
    return mapped;
  }, [data]);

  if (normalized.length === 0) {
    return <p className="muted">Keine Severity-Angaben.</p>;
  }

  const maxValue = Math.max(...normalized.map((item) => item.doc_count));
  const baseHeight = 20;
  const scaleHeight = 120;

  return (
    <div style={{ display: "flex", gap: "0.75rem", alignItems: "flex-end", minHeight: `${baseHeight + scaleHeight + 20}px` }}>
      {normalized.map((item) => {
        const barHeight = maxValue === 0 ? baseHeight : baseHeight + (item.doc_count / maxValue) * scaleHeight;
        const color = severityColors[item.key] ?? severityColors.UNKNOWN;
        const label = severityLabels[item.key] ?? item.key;
        return (
          <div key={item.key} style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", gap: "0.5rem" }}>
            <div
              style={{
                width: "100%",
                height: `${barHeight}px`,
                background: `linear-gradient(180deg, ${color}, ${color}99)`,
                borderRadius: "6px 6px 0 0",
                boxShadow: `0 0 12px ${color}40`,
                transition: "height 0.3s ease",
              }}
              title={`${label}: ${item.doc_count.toLocaleString()}`}
            />
            <div style={{ textAlign: "center", fontSize: "0.75rem", lineHeight: 1.3 }}>
              <strong>{item.doc_count.toLocaleString()}</strong>
              <div className="muted" style={{ fontSize: "0.7rem", color }}>{label}</div>
            </div>
          </div>
        );
      })}
    </div>
  );
};

const sourceColors = [
  "#5c84ff",  // Blue
  "#66d9e8",  // Cyan
  "#a855f7",  // Purple
  "#f472b6",  // Pink
  "#fbbf24",  // Amber
  "#34d399",  // Emerald
];

const SourcesChart = ({ data }: { data: TermsBucket[] }) => {
  const items = useMemo(() => data.filter((item) => item.doc_count > 0).slice(0, 6), [data]);

  if (items.length === 0) {
    return <p className="muted">Keine Quellen erfasst.</p>;
  }

  const maxValue = Math.max(...items.map((item) => item.doc_count));
  const baseHeight = 20;
  const scaleHeight = 120;

  return (
    <div style={{ display: "flex", gap: "1rem", alignItems: "flex-end", minHeight: `${baseHeight + scaleHeight + 20}px` }}>
      {items.map((item, index) => {
        const barHeight = maxValue === 0 ? baseHeight : baseHeight + (item.doc_count / maxValue) * scaleHeight;
        const color = sourceColors[index % sourceColors.length];

        return (
          <div key={item.key} style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", gap: "0.5rem" }}>
            <div
              style={{
                width: "100%",
                height: `${barHeight}px`,
                background: `linear-gradient(180deg, ${color}, ${color}88)`,
                borderRadius: "6px 6px 0 0",
                boxShadow: `0 0 16px ${color}30`,
                transition: "height 0.3s ease",
              }}
              title={`${item.key}: ${item.doc_count.toLocaleString()}`}
            />
            <div style={{ textAlign: "center", fontSize: "0.75rem", lineHeight: 1.3 }}>
              <strong>{item.doc_count.toLocaleString()}</strong>
              <div style={{ fontSize: "0.7rem", color, opacity: 0.9 }}>
                {item.key.length > 14 ? `${item.key.slice(0, 12)}…` : item.key || "–"}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
};

const cweColors = [
  "#f472b6",  // Pink
  "#a855f7",  // Purple
  "#818cf8",  // Indigo
  "#38bdf8",  // Sky
  "#2dd4bf",  // Teal
];

const CweChart = ({ data }: { data: TermsBucket[] }) => {
  const items = useMemo(() => data.filter((item) => item.doc_count > 0).slice(0, 5), [data]);

  if (items.length === 0) {
    return <p className="muted">Keine CWEs erfasst.</p>;
  }

  const maxValue = Math.max(...items.map((item) => item.doc_count));
  const baseHeight = 20;
  const scaleHeight = 120;

  return (
    <div style={{ display: "flex", gap: "0.75rem", alignItems: "flex-end", minHeight: `${baseHeight + scaleHeight + 20}px` }}>
      {items.map((item, index) => {
        const barHeight = maxValue === 0 ? baseHeight : baseHeight + (item.doc_count / maxValue) * scaleHeight;
        const color = cweColors[index % cweColors.length];

        return (
          <div key={item.key} style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", gap: "0.5rem" }}>
            <div
              style={{
                width: "100%",
                height: `${barHeight}px`,
                background: `linear-gradient(180deg, ${color}, ${color}99)`,
                borderRadius: "6px 6px 0 0",
                boxShadow: `0 0 12px ${color}40`,
                transition: "height 0.3s ease",
              }}
              title={`${item.key}: ${item.doc_count.toLocaleString()}`}
            />
            <div style={{ textAlign: "center", fontSize: "0.75rem", lineHeight: 1.3 }}>
              <strong>{item.doc_count.toLocaleString()}</strong>
              <div style={{ fontSize: "0.7rem", color, opacity: 0.9 }}>
                {item.key.length > 12 ? `${item.key.slice(0, 10)}…` : item.key || "–"}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
};

const epssColors: Record<string, string> = {
  "0.0-0.1": "#69db7c",   // Green - Low risk
  "0.1-0.3": "#a9e34b",   // Light green
  "0.3-0.5": "#fcc419",   // Yellow - Medium risk
  "0.5-0.7": "#ff922b",   // Orange - High risk
  "0.7-1.0": "#ff6b6b",   // Red - Critical risk
};

const epssLabels: Record<string, string> = {
  "0.0-0.1": "0-10",
  "0.1-0.3": "10-30",
  "0.3-0.5": "30-50",
  "0.5-0.7": "50-70",
  "0.7-1.0": "70-100",
};

const EpssChart = ({ data }: { data: TermsBucket[] }) => {
  if (!data.length) {
    return <p className="muted">Keine EPSS-Daten.</p>;
  }

  const maxValue = Math.max(...data.map((item) => item.doc_count), 1);
  const baseHeight = 20;
  const scaleHeight = 120;

  return (
    <div style={{ display: "flex", gap: "0.75rem", alignItems: "flex-end", minHeight: `${baseHeight + scaleHeight + 20}px` }}>
      {data.map((item) => {
        const barHeight = maxValue === 0 ? baseHeight : baseHeight + (item.doc_count / maxValue) * scaleHeight;
        const color = epssColors[item.key] ?? "#5c84ff";
        const label = epssLabels[item.key] ?? item.key;

        return (
          <div key={item.key} style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", gap: "0.5rem" }}>
            <div
              style={{
                width: "100%",
                height: `${barHeight}px`,
                background: `linear-gradient(180deg, ${color}, ${color}99)`,
                borderRadius: "6px 6px 0 0",
                boxShadow: `0 0 12px ${color}40`,
                transition: "height 0.3s ease",
              }}
              title={`${label}: ${item.doc_count.toLocaleString()}`}
            />
            <div style={{ textAlign: "center", fontSize: "0.75rem", lineHeight: 1.3 }}>
              <strong>{item.doc_count.toLocaleString()}</strong>
              <div className="muted" style={{ fontSize: "0.7rem", color }}>
                {label}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
};

const TimelineChart = ({ data }: { data: TimelinePoint[] }) => {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null);
  const [tooltipPosition, setTooltipPosition] = useState<{ x: number; y: number } | null>(null);
  const [isAnimated, setIsAnimated] = useState(false);

  // Trigger animation on mount
  useEffect(() => {
    const timer = setTimeout(() => setIsAnimated(true), 100);
    return () => clearTimeout(timer);
  }, []);

  if (!data.length) {
    return <p className="muted">Noch keine Zeitreihendaten.</p>;
  }

  const baseWidth = 1200;
  const height = 180;
  const padding = { top: 20, bottom: 45, left: 50, right: 20 };
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
  const areaPath = linePath + ` L ${chartPoints[chartPoints.length - 1].x},${height - padding.bottom} L ${chartPoints[0].x},${height - padding.bottom} Z`;

  // Calculate total path length for animation
  const pathLength = chartPoints.length * step * 1.5;

  const hoveredPoint = hoveredIndex != null ? chartPoints[hoveredIndex] : null;

  // Format timestamp to readable date
  const formatDateTime = (timestamp: number) => {
    const date = new Date(timestamp);
    const day = date.toLocaleDateString("de-DE", { weekday: "short", day: "numeric", month: "short", year: "numeric" });
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

    const labelCount = Math.min(8, data.length);
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

  return (
    <div
      ref={containerRef}
      style={{
        position: "relative",
        cursor: "crosshair",
      }}
      onMouseLeave={clearHover}
    >
      <svg
        width="100%"
        height={height}
        viewBox={`0 0 ${baseWidth} ${height}`}
        preserveAspectRatio="none"
      >
        <defs>
          {/* Animated gradient */}
          <linearGradient id="lineGradient" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#5c84ff">
              <animate attributeName="stop-color" values="#5c84ff;#66d9e8;#a855f7;#5c84ff" dur="4s" repeatCount="indefinite" />
            </stop>
            <stop offset="50%" stopColor="#66d9e8">
              <animate attributeName="stop-color" values="#66d9e8;#a855f7;#5c84ff;#66d9e8" dur="4s" repeatCount="indefinite" />
            </stop>
            <stop offset="100%" stopColor="#a855f7">
              <animate attributeName="stop-color" values="#a855f7;#5c84ff;#66d9e8;#a855f7" dur="4s" repeatCount="indefinite" />
            </stop>
          </linearGradient>

          {/* Area gradient */}
          <linearGradient id="areaGradient" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="rgba(92, 132, 255, 0.3)">
              <animate attributeName="stop-color" values="rgba(92,132,255,0.3);rgba(102,217,232,0.3);rgba(168,85,247,0.3);rgba(92,132,255,0.3)" dur="4s" repeatCount="indefinite" />
            </stop>
            <stop offset="100%" stopColor="rgba(92, 132, 255, 0)" />
          </linearGradient>

          {/* Glow filter */}
          <filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="3" result="coloredBlur" />
            <feMerge>
              <feMergeNode in="coloredBlur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>

          {/* Point glow */}
          <filter id="pointGlow" x="-100%" y="-100%" width="300%" height="300%">
            <feGaussianBlur stdDeviation="4" result="coloredBlur" />
            <feMerge>
              <feMergeNode in="coloredBlur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        {/* Grid lines */}
        {[0.25, 0.5, 0.75, 1].map((ratio) => (
          <line
            key={ratio}
            x1={padding.left}
            y1={padding.top + chartHeight * (1 - ratio)}
            x2={baseWidth - padding.right}
            y2={padding.top + chartHeight * (1 - ratio)}
            stroke="rgba(255,255,255,0.06)"
            strokeDasharray="4 4"
          />
        ))}

        {/* Animated area fill */}
        <path
          d={areaPath}
          fill="url(#areaGradient)"
          style={{
            opacity: isAnimated ? 1 : 0,
            transition: "opacity 0.8s ease",
          }}
        />

        {/* Main line with animation */}
        <path
          d={linePath}
          fill="none"
          stroke="url(#lineGradient)"
          strokeWidth={3}
          strokeLinecap="round"
          strokeLinejoin="round"
          filter="url(#glow)"
          style={{
            strokeDasharray: pathLength,
            strokeDashoffset: isAnimated ? 0 : pathLength,
            transition: "stroke-dashoffset 1.5s ease-out",
          }}
        />

        {/* Data points */}
        {chartPoints.map((point, index) => {
          const isActive = hoveredIndex === index;
          const hasData = point.count > 0;

          return (
            <g key={`${point.key}-${index}`}>
              {/* Pulse animation for points with data */}
              {hasData && (
                <circle
                  cx={point.x}
                  cy={point.y}
                  r={isActive ? 12 : 8}
                  fill="none"
                  stroke="rgba(92, 132, 255, 0.4)"
                  strokeWidth={1}
                  style={{
                    opacity: isAnimated ? 1 : 0,
                    transition: "opacity 0.5s ease",
                  }}
                >
                  <animate
                    attributeName="r"
                    values={isActive ? "8;16;8" : "6;12;6"}
                    dur="2s"
                    repeatCount="indefinite"
                  />
                  <animate
                    attributeName="opacity"
                    values="0.6;0;0.6"
                    dur="2s"
                    repeatCount="indefinite"
                  />
                </circle>
              )}

              {/* Main point */}
              <circle
                cx={point.x}
                cy={point.y}
                r={isActive ? 7 : hasData ? 5 : 3}
                fill={isActive ? "#fff" : hasData ? "#5c84ff" : "rgba(92, 132, 255, 0.3)"}
                stroke={isActive ? "#5c84ff" : "transparent"}
                strokeWidth={isActive ? 3 : 0}
                filter={isActive ? "url(#pointGlow)" : undefined}
                style={{
                  cursor: "pointer",
                  opacity: isAnimated ? 1 : 0,
                  transition: "all 0.2s ease, opacity 0.5s ease",
                  transitionDelay: `${index * 10}ms`,
                }}
                onMouseEnter={(e) => updateTooltipPosition(index, e)}
                onMouseMove={(e) => updateTooltipPosition(index, e)}
              />
            </g>
          );
        })}

        {/* Time axis labels */}
        {timeLabels.map(({ x, date }, i) => {
          const dayLabel = date.toLocaleDateString("de-DE", { day: "numeric", month: "short" });
          const yearLabel = date.getFullYear().toString();

          return (
            <g key={`label-${i}`}>
              <text
                x={x}
                y={height - padding.bottom + 18}
                textAnchor="middle"
                fill="rgba(255,255,255,0.5)"
                fontSize="10"
              >
                {dayLabel}
              </text>
              <text
                x={x}
                y={height - padding.bottom + 32}
                textAnchor="middle"
                fill="rgba(255,255,255,0.35)"
                fontSize="9"
              >
                {yearLabel}
              </text>
            </g>
          );
        })}

        {/* Y-axis labels */}
        {[0, 0.5, 1].map((ratio) => (
          <text
            key={ratio}
            x={padding.left - 5}
            y={padding.top + chartHeight * (1 - ratio) + 4}
            textAnchor="end"
            fill="rgba(255,255,255,0.4)"
            fontSize="10"
          >
            {Math.round(maxValue * ratio).toLocaleString()}
          </text>
        ))}
      </svg>

      {/* Tooltip */}
      {hoveredPoint && tooltipPosition && (
        <div
          style={{
            position: "absolute",
            left: `${tooltipPosition.x}px`,
            top: `${tooltipPosition.y}px`,
            transform: "translate(-50%, calc(-100% - 16px))",
            background: "linear-gradient(135deg, rgba(18, 21, 38, 0.95), rgba(30, 35, 60, 0.95))",
            color: "#fff",
            padding: "0.65rem 0.85rem",
            borderRadius: "10px",
            fontSize: "0.8rem",
            boxShadow: "0 12px 28px rgba(0,0,0,0.35), 0 0 0 1px rgba(92, 132, 255, 0.2)",
            pointerEvents: "none",
            whiteSpace: "nowrap",
            zIndex: 100,
            backdropFilter: "blur(8px)",
          }}
        >
          <div style={{
            fontSize: "1.1rem",
            fontWeight: 700,
            background: "linear-gradient(90deg, #5c84ff, #66d9e8)",
            WebkitBackgroundClip: "text",
            WebkitTextFillColor: "transparent",
            marginBottom: "0.25rem",
          }}>
            {hoveredPoint.count.toLocaleString()} Vulnerabilities
          </div>
          {hoveredPoint.timestamp && (() => {
            const { day } = formatDateTime(hoveredPoint.timestamp);
            return (
              <div style={{ color: "#adb5bd", fontSize: "0.75rem" }}>
                {day}
              </div>
            );
          })()}
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
  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null);
  const [tooltipPos, setTooltipPos] = useState<{ x: number; y: number } | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);

  // Calculate cumulative totals
  const cumulativeData = useMemo(() => {
    let runningTotal = 0;
    return data.map((point) => {
      runningTotal += point.count;
      return { ...point, cumulative: runningTotal };
    });
  }, [data]);

  if (!data.length) {
    return <p className="muted">Noch keine Zeitreihendaten.</p>;
  }

  const width = 1200;
  const height = 220;
  const padding = { top: 25, bottom: 40, left: 60, right: 20 };
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
  const areaPath = linePath + ` L ${chartPoints[chartPoints.length - 1].x},${height - padding.bottom} L ${chartPoints[0].x},${height - padding.bottom} Z`;

  const firstPoint = cumulativeData[0];
  const lastPoint = cumulativeData[cumulativeData.length - 1];
  const formatMonth = (timestamp: number) => {
    const date = new Date(timestamp);
    return date.toLocaleDateString("de-DE", { month: "short", year: "numeric" });
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
    <div ref={containerRef} style={{ position: "relative" }}>
      <svg
        width="100%"
        height={height}
        viewBox={`0 0 ${width} ${height}`}
        preserveAspectRatio="none"
        onMouseMove={handleMouseMove}
        onMouseLeave={() => { setHoveredIndex(null); setTooltipPos(null); }}
        style={{ cursor: "crosshair" }}
      >
        <defs>
          <linearGradient id="summaryAreaGradient" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="rgba(102, 217, 232, 0.3)" />
            <stop offset="100%" stopColor="rgba(102, 217, 232, 0)" />
          </linearGradient>
        </defs>

        <path d={areaPath} fill="url(#summaryAreaGradient)" />
        <path
          d={linePath}
          fill="none"
          stroke="#66d9e8"
          strokeWidth={2}
          strokeLinecap="round"
          strokeLinejoin="round"
        />

        {/* Hover indicator line */}
        {hoveredPoint && (
          <line
            x1={hoveredPoint.x}
            y1={padding.top}
            x2={hoveredPoint.x}
            y2={height - padding.bottom}
            stroke="rgba(102, 217, 232, 0.5)"
            strokeWidth={1}
            strokeDasharray="4 4"
          />
        )}

        {/* Hover point */}
        {hoveredPoint && (
          <circle
            cx={hoveredPoint.x}
            cy={hoveredPoint.y}
            r={5}
            fill="#66d9e8"
            stroke="#fff"
            strokeWidth={2}
          />
        )}

        {/* Y-axis labels */}
        <text x={padding.left - 8} y={padding.top + 4} textAnchor="end" fill="rgba(255,255,255,0.4)" fontSize="9">
          {maxValue.toLocaleString()}
        </text>
        <text x={padding.left - 8} y={height - padding.bottom} textAnchor="end" fill="rgba(255,255,255,0.4)" fontSize="9">
          0
        </text>

        {/* Start and end labels */}
        <text x={padding.left} y={height - 8} textAnchor="start" fill="rgba(255,255,255,0.5)" fontSize="10">
          {firstPoint.timestamp ? formatMonth(firstPoint.timestamp) : firstPoint.key}
        </text>
        <text x={width - padding.right} y={height - 8} textAnchor="end" fill="rgba(255,255,255,0.5)" fontSize="10">
          {lastPoint.timestamp ? formatMonth(lastPoint.timestamp) : lastPoint.key}
        </text>
      </svg>

      {/* Tooltip */}
      {hoveredPoint && tooltipPos && (
        <div
          style={{
            position: "absolute",
            left: tooltipPos.x,
            top: tooltipPos.y,
            transform: "translate(-50%, calc(-100% - 12px))",
            background: "rgba(18, 21, 38, 0.95)",
            padding: "0.5rem 0.75rem",
            borderRadius: "8px",
            fontSize: "0.75rem",
            boxShadow: "0 8px 20px rgba(0,0,0,0.3)",
            pointerEvents: "none",
            whiteSpace: "nowrap",
            zIndex: 100,
          }}
        >
          <div style={{ color: "#66d9e8", fontWeight: 600, fontSize: "0.9rem" }}>
            {hoveredPoint.cumulative.toLocaleString()} total
          </div>
          <div style={{ color: "#adb5bd", fontSize: "0.7rem" }}>
            +{hoveredPoint.count.toLocaleString()} this month
          </div>
          <div style={{ color: "#868e96", fontSize: "0.65rem", marginTop: "0.2rem" }}>
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
          return item.doc_count > 0 && normalized !== "n/a" && normalized !== "na";
        })
        .slice(0, limit),
    [data, limit]
  );

  if (items.length === 0) {
    return <p className="muted">{emptyMessage}</p>;
  }

  const maxValue = Math.max(...items.map((item) => item.doc_count));

  return (
    <ul style={{ display: "grid", gap: "0.6rem", padding: 0, margin: 0, listStyle: "none" }}>
      {items.map((item) => {
        const ratio = maxValue === 0 ? 0 : item.doc_count / maxValue;
        return (
          <li key={item.key}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.25rem" }}>
              <span>{item.key || "–"}</span>
              <span className="muted" style={{ fontSize: "0.75rem" }}>
                {item.doc_count.toLocaleString()}
              </span>
            </div>
            <div
              style={{
                background: "rgba(255,255,255,0.08)",
                borderRadius: "6px",
                overflow: "hidden",
                height: "6px",
              }}
            >
              <div
                style={{
                  width: `${Math.max(ratio * 100, 4)}%`,
                  height: "100%",
                  background: "linear-gradient(90deg, #5c84ff, #66d9e8)",
                }}
              />
            </div>
          </li>
        );
      })}
    </ul>
  );
};

const AssetSection = ({
  assets,
}: {
  assets: StatsResponse["assets"];
}) => (
  <div
    style={{
      display: "grid",
      gap: "1.25rem",
      gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))",
    }}
  >
    <ChartCard title="Asset Vendors">
      <CatalogSampleList items={assets.sampleVendors} emptyMessage="Keine Vendors verfügbar." />
    </ChartCard>
    <ChartCard title="Asset Produkte">
      <CatalogSampleList items={assets.sampleProducts} emptyMessage="Keine Produkte verfügbar." />
    </ChartCard>
  </div>
);

const truncateList = (values: string[], maxLength: number): string => {
  const joined = values.join(", ");
  return joined.length > maxLength ? `${joined.slice(0, maxLength - 1)}…` : joined;
};

const CatalogSampleList = ({ items, emptyMessage }: { items: CatalogSample[]; emptyMessage: string }) => {
  if (!items.length) {
    return <p className="muted">{emptyMessage}</p>;
  }

  return (
    <ul style={{ listStyle: "none", padding: 0, margin: 0, display: "grid", gap: "0.75rem" }}>
      {items.map((item) => (
        <li key={item.slug} style={{ display: "grid", gap: "0.2rem" }}>
          <strong>{item.name}</strong>
          {item.aliases.length > 0 ? (
            <span className="muted" style={{ fontSize: "0.75rem" }}>
              {truncateList(item.aliases, 60)}
            </span>
          ) : (
            <span className="muted" style={{ fontSize: "0.75rem" }}>Keine zusätzlichen Aliase.</span>
          )}
        </li>
      ))}
    </ul>
  );
};
