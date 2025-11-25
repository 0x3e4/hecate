import { useEffect, useMemo, useRef, useState, type CSSProperties, type ReactNode } from "react";

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
            <div style={{ display: grid; gap: "1.5rem" }}>
              <SummaryGrid stats={stats} />
              
              <div style={{ display: "grid", gap: "1.5rem" }}>
                <div style={{ display: "grid", gap: "1.25rem", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))" }}>
                  <ChartCard title="Quelle">
                    <BarChart data={stats.vulnerabilities.sources} emptyMessage="Keine Quellen erfasst." maxBars={6} />
                  </ChartCard>
                  <ChartCard title="Schweregrade">
                    <SeverityChart data={stats.vulnerabilities.severities} />
                  </ChartCard>
                </div>

                <ChartCard title="Veröffentlichungstrend (letzte Monate)">
                  <TimelineChart data={stats.vulnerabilities.timeline} />
                </ChartCard>

                <div style={{ display: "grid", gap: "1.25rem", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))" }}>
                  <ChartCard title="Meistgenannte Vendors">
                    <TopList data={stats.vulnerabilities.topVendors} emptyMessage="Keine Vendors." limit={8} />
                  </ChartCard>
                  <ChartCard title="Meistgenannte Produkte">
                    <TopList data={stats.vulnerabilities.topProducts} emptyMessage="Keine Produkte." limit={8} />
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
  <>
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
  </>
);

const SummaryGrid = ({ stats }: { stats: StatsResponse }) => (
  <div
    style={{
      display: "grid",
      gap: "1rem",
      gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
    }}
  >
    <StatCard label="Vulnerabilities" value={stats.vulnerabilities.total} accent="#5c84ff" />
    <StatCard label="Vendors" value={stats.assets.vendorTotal} accent="#66d9e8" />
    <StatCard label="Produkte" value={stats.assets.productTotal} accent="#ffd43b" />
    <StatCard label="Versionen" value={stats.assets.versionTotal} accent="#ff6b6b" />
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

const BarChart = ({
  data,
  maxBars = 5,
  emptyMessage = "Keine Daten.",
  color = "#5c84ff",
}: {
  data: TermsBucket[];
  maxBars?: number;
  emptyMessage?: string;
  color?: string;
}) => {
  const items = useMemo(() => data.filter((item) => item.doc_count > 0).slice(0, maxBars), [data, maxBars]);

  if (items.length === 0) {
    return <p className="muted">{emptyMessage}</p>;
  }

  const maxValue = Math.max(...items.map((item) => item.doc_count));
  const baseHeight = 20;
  const scaleHeight = 120;

  return (
    <div style={{ display: "flex", gap: "1rem", alignItems: "flex-end", minHeight: `${baseHeight + scaleHeight + 20}px` }}>
      {items.map((item) => {
        const barHeight = maxValue === 0 ? baseHeight : baseHeight + (item.doc_count / maxValue) * scaleHeight;
        return (
          <div key={item.key} style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", gap: "0.5rem" }}>
            <div
              style={{
                width: "100%",
                height: `${barHeight}px`,
                background: color,
                borderRadius: "6px 6px 0 0",
                transition: "height 0.3s ease",
              }}
              title={`${item.key}: ${item.doc_count.toLocaleString()}`}
            />
            <div style={{ textAlign: "center", fontSize: "0.75rem", lineHeight: 1.3 }}>
              <strong>{item.doc_count.toLocaleString()}</strong>
              <div className="muted" style={{ fontSize: "0.7rem" }}>
                {item.key.length > 14 ? `${item.key.slice(0, 12)}…` : item.key || "–"}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
};

const severityColors: Record<string, string> = {
  CRITICAL: "#ff6b6b",
  HIGH: "#ff922b",
  MEDIUM: "#fcc419",
  LOW: "#69db7c",
  UNKNOWN: "#748ffc",
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
        return (
          <div key={item.key} style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", gap: "0.5rem" }}>
            <div
              style={{
                width: "100%",
                height: `${barHeight}px`,
                background: color,
                borderRadius: "6px 6px 0 0",
              }}
              title={`${item.key}: ${item.doc_count.toLocaleString()}`}
            />
            <div style={{ textAlign: "center", fontSize: "0.75rem", lineHeight: 1.3 }}>
              <strong>{item.doc_count.toLocaleString()}</strong>
              <div className="muted" style={{ fontSize: "0.7rem" }}>{item.key}</div>
            </div>
          </div>
        );
      })}
    </div>
  );
};

const TimelineChart = ({ data }: { data: TimelinePoint[] }) => {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null);
  const [tooltipPosition, setTooltipPosition] = useState<{ x: number; y: number } | null>(null);
  const [scale, setScale] = useState<{ x: number; y: number }>({ x: 1, y: 1 });

  if (!data.length) {
    return <p className="muted">Noch keine Zeitreihendaten.</p>;
  }

  const width = Math.max(280, data.length * 40);
  const height = 160;
  const maxValue = Math.max(...data.map((point) => point.count));
  const step = data.length > 1 ? width / (data.length - 1) : 0;

  const chartPoints = data.map((point, index) => {
    const x = data.length > 1 ? index * step : width / 2;
    const y = maxValue === 0 ? height - 20 : height - 20 - (point.count / maxValue) * (height - 40);
    return { ...point, x, y };
  });

  const pathPoints = chartPoints.map((point) => `${point.x.toFixed(2)},${point.y.toFixed(2)}`);
  const areaPoints = ["0," + height, ...pathPoints, `${width},${height}`].join(" ");

  const hoveredPoint = hoveredIndex != null ? chartPoints[hoveredIndex] : null;

  useEffect(() => {
    const svg = svgRef.current;
    if (!svg) {
      return;
    }

    const computeScale = () => {
      const rect = svg.getBoundingClientRect();
      if (!rect.width || !rect.height) {
        setScale({ x: 1, y: 1 });
        return;
      }
      setScale({
        x: rect.width / width,
        y: rect.height / height,
      });
    };

    computeScale();

    let resizeObserver: ResizeObserver | null = null;
    if (typeof ResizeObserver !== "undefined") {
      resizeObserver = new ResizeObserver(() => computeScale());
      resizeObserver.observe(svg);
    } else if (typeof window !== "undefined") {
      window.addEventListener("resize", computeScale);
    }

    return () => {
      if (resizeObserver) {
        resizeObserver.disconnect();
      } else if (typeof window !== "undefined") {
        window.removeEventListener("resize", computeScale);
      }
    };
  }, [width, height]);

  const updateTooltipPosition = (index: number) => {
    setHoveredIndex(index);
    const svg = svgRef.current;
    if (!svg) {
      setTooltipPosition(null);
      return;
    }
    const rect = svg.getBoundingClientRect();
    const ratioX = rect.width / width;
    const ratioY = rect.height / height;
    const point = chartPoints[index];
    setTooltipPosition({
      x: point.x * ratioX,
      y: point.y * ratioY,
    });
  };

  const clearHover = () => {
    setHoveredIndex(null);
    setTooltipPosition(null);
  };

  return (
    <div style={{ display: "grid", gap: "0.75rem", position: "relative" }}>
      <svg
        ref={svgRef}
        width="100%"
        height={height}
        viewBox={`0 0 ${width} ${height}`}
        preserveAspectRatio="none"
        onMouseLeave={clearHover}
      >
        <polygon points={areaPoints} fill="rgba(92,132,255,0.15)" />
        <polyline points={pathPoints.join(" ")} fill="none" stroke="#5c84ff" strokeWidth={3} strokeLinecap="round" />
        {chartPoints.map((point, index) => {
          const isActive = hoveredIndex === index;
          const baseRadius = isActive ? 6 : 4;
          const safeScaleX = scale.x || 1;
          const safeScaleY = scale.y || 1;
          const avgScale = (safeScaleX + safeScaleY) / 2 || 1;
          const rx = baseRadius / safeScaleX;
          const ry = baseRadius / safeScaleY;
          const strokeWidth = (isActive ? 2.4 : 1.4) / avgScale;
          const fill = isActive ? "#7a97ff" : "#5c84ff";

          return (
            <g key={point.key}>
              <ellipse
                cx={point.x}
                cy={point.y}
                rx={rx}
                ry={ry}
                fill={fill}
                stroke="rgba(90, 132, 255, 0.45)"
                strokeWidth={strokeWidth}
                style={{
                  cursor: "pointer",
                  transition: "fill 0.15s ease, stroke-width 0.15s ease",
                  filter: isActive ? "drop-shadow(0 4px 8px rgba(92,132,255,0.35))" : "none",
                }}
                onMouseEnter={() => updateTooltipPosition(index)}
                onMouseMove={() => updateTooltipPosition(index)}
                onFocus={() => updateTooltipPosition(index)}
                onBlur={clearHover}
                tabIndex={0}
              >
                <title>{`${point.key}: ${point.count.toLocaleString()}`}</title>
              </ellipse>
            </g>
          );
        })}
      </svg>
      {hoveredPoint && tooltipPosition && (
        <div
          style={{
            position: "absolute",
            left: `${tooltipPosition.x}px`,
            top: `${tooltipPosition.y}px`,
            transform: "translate(-50%, calc(-100% - 12px))",
            background: "rgba(18, 21, 38, 0.92)",
            color: "#fff",
            padding: "0.45rem 0.6rem",
            borderRadius: "6px",
            fontSize: "0.75rem",
            boxShadow: "0 8px 16px rgba(0,0,0,0.28)",
            pointerEvents: "none",
            whiteSpace: "nowrap",
          }}
        >
          <strong style={{ display: "block" }}>{hoveredPoint.count.toLocaleString()}</strong>
          <span style={{ color: "#adb5bd" }}>{hoveredPoint.key}</span>
        </div>
      )}
      <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.75rem" }}>
        {data.map((point) => (
          <span key={point.key} className="muted" style={{ minWidth: "40px", textAlign: "center" }}>
            {point.key}
          </span>
        ))}
      </div>
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
