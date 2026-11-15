import React, { useCallback, useEffect, useId, useMemo, useRef, useState, type ReactNode } from "react";
import axios from "axios";
import { LuZoomOut } from "react-icons/lu";
import { Link } from "react-router-dom";

import { fetchProducts, fetchVendors } from "../api/assets";
import { StatsResponse, TermsBucket, fetchStatsOverview, fetchTimeline } from "../api/stats";
import { LoadingRegion, SkeletonBlock, SkeletonRows } from "../components/Skeleton";
import { useI18n, type TranslateFn } from "../i18n/context";
import { getCurrentTimezone } from "../timezone/storage";
import type { CatalogProduct, CatalogVendor } from "../types";
import { EmptyState, ErrorState, LoadingState, PageHeader, Section, SeverityTag, Stat, severityVar } from "../ui/primitives";
import { formatShare, shareOf, sumValues } from "../utils/barShare";
import { distinctAliases } from "../utils/catalog";
import { catalogQueryHref } from "../utils/catalogQuery";
import { formatDate } from "../utils/dateFormat";
import {
  TimelineCache,
  planNavigation,
  quickRange,
  rangeKey,
  safeZone,
  windowToRange,
  type QuickRange,
  type TimelineBucket,
  type TimelineInterval,
  type TimelineRange,
  type TimelineSeries,
} from "../utils/timelineRange";
import {
  fullWindow,
  indexToPixel,
  isFullWindow,
  pixelToIndex,
  selectionToWindow,
  tickIndices,
  type ZoomWindow,
} from "../utils/timeZoom";
import "../screens/stats.css";

export const StatsPage = () => {
  const { t, locale } = useI18n();
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [errorCause, setErrorCause] = useState<unknown>(null);
  const [retryKey, setRetryKey] = useState(0);
  // Both timelines start with the overview, not after it: three requests in parallel.
  const trend = useTimeline(TREND_RANGES, "30d");
  const history = useTimeline(HISTORY_RANGES, "all");
  const showSkeleton = loading && !stats;
  const totalText = stats ? stats.vulnerabilities.total.toLocaleString(locale) : "";

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
        <div className={loading ? "is-refreshing" : undefined} aria-busy={loading || undefined}>
          <section className="stats-lead">
            <SummaryGrid stats={stats} />
            <ChartBlock title={t("Severity", "Schweregrade")}>
              <SeverityChart data={stats.vulnerabilities.severities} />
            </ChartBlock>
          </section>

          <Section title={t("Publication trend", "Veröffentlichungstrend")}>
            <TimelineChart timeline={trend} />
          </Section>

          <Section title={t("Historical overview of published vulnerabilities", "Historischer Überblick von veröffentlichten Schwachstellen")}>
            <TimelineSummaryChart timeline={history} />
          </Section>

          <Section>
            <div className="stats-columns stats-columns--3">
              <ChartBlock title={t("EPSS Score", "EPSS-Score")}>
                <EpssChart data={stats.vulnerabilities.epssRanges} />
              </ChartBlock>
              <ChartBlock title="Top 5 CWEs">
                <CweChart data={stats.vulnerabilities.topCwes} total={stats.vulnerabilities.total} />
              </ChartBlock>
              <ChartBlock title={t("Source", "Quelle")}>
                <SourcesChart data={stats.vulnerabilities.sources} total={stats.vulnerabilities.total} />
              </ChartBlock>
            </div>
          </Section>

          <Section>
            <div className="stats-columns stats-columns--2">
              <ChartBlock title={t("Most named vendors", "Meistgenannte Hersteller")}>
                <TopList
                  data={stats.vulnerabilities.topVendors}
                  emptyMessage={t("No vendors.", "Keine Vendors.")}
                  limit={8}
                  basis={{
                    kind: "corpus",
                    total: stats.vulnerabilities.total,
                    note: t(
                      `Share of all ${totalText} vulnerabilities; one can name several vendors.`,
                      `Anteil an allen ${totalText} Schwachstellen; eine kann mehrere Hersteller nennen.`
                    ),
                  }}
                />
              </ChartBlock>
              <ChartBlock title={t("Most named products", "Meistgenannte Produkte")}>
                <TopList
                  data={stats.vulnerabilities.topProducts}
                  emptyMessage={t("No products.", "Keine Produkte.")}
                  limit={8}
                  basis={{
                    kind: "corpus",
                    total: stats.vulnerabilities.total,
                    note: t(
                      `Share of all ${totalText} vulnerabilities; one can name several products.`,
                      `Anteil an allen ${totalText} Schwachstellen; eine kann mehrere Produkte nennen.`
                    ),
                  }}
                />
              </ChartBlock>
              <ChartBlock title={t("Top reference domains", "Top-Referenzdomains")}>
                {/* Domain counts add up references, several per vulnerability: share of the listed domains only. */}
                <TopList
                  data={stats.vulnerabilities.referenceDomains}
                  emptyMessage={t("No references.", "Keine Referenzen.")}
                  limit={10}
                  basis={{ kind: "shown" }}
                />
              </ChartBlock>
              <ChartBlock title={t("Top assigners", "Top-Assigners")}>
                <TopList
                  data={stats.vulnerabilities.topAssigners}
                  emptyMessage={t("No assigners.", "Keine Assigner.")}
                  limit={10}
                  basis={{
                    kind: "corpus",
                    total: stats.vulnerabilities.total,
                    note: t(`Share of all ${totalText} vulnerabilities.`, `Anteil an allen ${totalText} Schwachstellen.`),
                  }}
                />
              </ChartBlock>
            </div>
          </Section>

          <AssetSection assets={stats.assets} total={stats.vulnerabilities.total} />
        </div>
      )}
    </div>
  );
};

const StatsSkeleton = () => {
  const { t } = useI18n();
  return (
    <LoadingRegion label={t("Loading statistics", "Statistiken werden geladen")}>
      <div>
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
            <SkeletonRows rows={5} height="1rem" />
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
              <SkeletonRows rows={5} height="1rem" />
            </div>
          ))}
        </div>
      </div>
    </LoadingRegion>
  );
};

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
  /** A second, muted line under the label (catalogue owner, breadth, aliases). */
  meta?: ReactNode[];
}

/**
 * What a chart's percentages are a share of. Each chart picks its own total
 * (see the callers) and says so in `note`, which is shown under the bars:
 * a share is only honest when the reader knows its denominator.
 */
interface ShareBasis {
  total: number;
  note: string;
}

/**
 * Sorted horizontal bars: label, zero-based bar, direct value, share of the basis total.
 * Hovering a row lifts its bar and shows share + count over it; the same figures are
 * printed in the row, so the overlay never holds anything a keyboard user can't read.
 */
const BarList = ({ items, variant, basis }: { items: BarItem[]; variant?: "severity" | "ranking"; basis?: ShareBasis | null }) => {
  const { t, locale } = useI18n();
  const maxValue = Math.max(...items.map((item) => item.value), 1);
  const total = basis?.total ?? 0;

  return (
    <>
      <ul className={`stats-bars${variant ? ` stats-bars--${variant}` : ""}`}>
        {items.map((item) => {
          const share = basis ? shareOf(item.value, total) : null;
          const shareText = formatShare(share, locale);
          return (
            <li key={item.key} className={`stats-bar-row${item.meta ? " stats-bar-row--meta" : ""}`}>
              {item.meta ? (
                <span className="stats-bar-label stats-bar-label--stacked">
                  <span className="stats-bar-name" title={item.title}>
                    {item.label}
                  </span>
                  <span className="stats-bar-meta">
                    {item.meta.map((part, index) => (
                      <React.Fragment key={index}>
                        {index > 0 && <span aria-hidden="true"> · </span>}
                        {part}
                      </React.Fragment>
                    ))}
                  </span>
                </span>
              ) : (
                <span className="stats-bar-label" title={item.title}>
                  {item.label}
                </span>
              )}
              <span className="stats-bar-track" aria-hidden="true">
                {item.value > 0 && (
                  <span
                    className="stats-bar-fill"
                    style={{ width: `${(item.value / maxValue) * 100}%`, background: item.color }}
                  />
                )}
                {share != null && (
                  <span className="stats-bar-tip">
                    <strong>{shareText}</strong>{" "}
                    <span>
                      {item.value.toLocaleString(locale)} {t("of", "von")} {total.toLocaleString(locale)}
                    </span>
                  </span>
                )}
              </span>
              <span className="stats-bar-value">{item.value.toLocaleString(locale)}</span>
              <span className="stats-bar-share">{shareText}</span>
            </li>
          );
        })}
      </ul>
      {basis && total > 0 && <p className="stats-bars-basis">{basis.note}</p>}
    </>
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
  const { t, locale } = useI18n();
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

  // Every vulnerability has exactly one severity (missing ones count as Unknown),
  // so the buckets partition the corpus and their sum is the total.
  const total = sumValues(normalized.map((item) => item.doc_count));
  const n = total.toLocaleString(locale);

  return (
    <BarList
      variant="severity"
      basis={{ total, note: t(`Share of all ${n} vulnerabilities.`, `Anteil an allen ${n} Schwachstellen.`) }}
      items={normalized.map((item) => ({
        key: item.key,
        label: <SeverityTag severity={item.key}>{severityLabels[item.key] ? t(severityLabels[item.key][0], severityLabels[item.key][1]) : item.key}</SeverityTag>,
        value: item.doc_count,
        color: severityVar(item.key),
      }))}
    />
  );
};

/**
 * Sources, CWEs, vendors, products and assigners are counted per vulnerability, but one
 * vulnerability can carry several of them, so their shares are taken of the whole corpus
 * (`stats.vulnerabilities.total`) and do not add up to 100 %. The note says so.
 */
const corpusBasis = (total: number, note: string): ShareBasis | null => (total > 0 ? { total, note } : null);

const SourcesChart = ({ data, total }: { data: TermsBucket[]; total: number }) => {
  const { t, locale } = useI18n();
  const items = useMemo(() => data.filter((item) => item.doc_count > 0).slice(0, 6), [data]);

  if (items.length === 0) {
    return <EmptyState title={t("No sources recorded.", "Keine Quellen erfasst.")} />;
  }

  const n = total.toLocaleString(locale);
  return (
    <BarList
      basis={corpusBasis(
        total,
        t(
          `Share of all ${n} vulnerabilities; one can come from several sources.`,
          `Anteil an allen ${n} Schwachstellen; eine kann aus mehreren Quellen stammen.`
        )
      )}
      items={items.map((item) => ({
        key: item.key,
        label: item.key || "n/a",
        value: item.doc_count,
        title: item.key,
      }))}
    />
  );
};

const CweChart = ({ data, total }: { data: TermsBucket[]; total: number }) => {
  const { t, locale } = useI18n();
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

  const n = total.toLocaleString(locale);
  return (
    <BarList
      basis={corpusBasis(
        total,
        t(
          `Share of all ${n} vulnerabilities; one can name several CWEs.`,
          `Anteil an allen ${n} Schwachstellen; eine kann mehrere CWEs nennen.`
        )
      )}
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
  const { t, locale } = useI18n();
  if (!data.length) {
    return <EmptyState title={t("No EPSS data.", "Keine EPSS-Daten.")} />;
  }

  // The bands partition the vulnerabilities that have an EPSS score, so the share
  // is of that population, not of the whole corpus.
  const total = sumValues(data.map((item) => item.doc_count));
  const n = total.toLocaleString(locale);

  // Highest exploitation probability first: that band is the one an analyst reads for.
  return (
    <BarList
      basis={{
        total,
        note: t(`Share of the ${n} vulnerabilities with an EPSS score.`, `Anteil an den ${n} Schwachstellen mit EPSS-Score.`),
      }}
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

const CHART_HEIGHT = 240;
const MIN_ZOOM_POINTS = 2;
/** Horizontal travel before a press becomes a selection; below it the press is a tap (tooltip). */
const DRAG_THRESHOLD_PX = 6;

/** Bucket start as a short date ("16.10.2026") or month ("Oct 2026"), in the zone the buckets were counted in. */
const formatBucket = (timestamp: number, interval: TimelineInterval, tz: string, locale: string) =>
  interval === "month"
    ? new Date(timestamp).toLocaleDateString(locale, { month: "short", year: "numeric", timeZone: tz })
    : formatDate(timestamp, { includeTime: false, timezone: tz });

/** One bucket for a tooltip or a screen reader: "Mon, 3 Nov 2026", "Week of 3 Nov 2026", "Nov 2026". */
const describeBucket = (timestamp: number, interval: TimelineInterval, tz: string, locale: string, t: TranslateFn) => {
  if (interval === "month") return formatBucket(timestamp, interval, tz, locale);
  const date = new Date(timestamp).toLocaleDateString(locale, {
    weekday: interval === "day" ? "short" : undefined,
    day: "numeric",
    month: "short",
    year: "numeric",
    timeZone: tz,
  });
  return interval === "week" ? t(`Week of ${date}`, `Woche ab ${date}`) : date;
};

const granularityLabel = (interval: TimelineInterval, t: TranslateFn) =>
  interval === "day" ? t("Daily", "Täglich") : interval === "week" ? t("Weekly", "Wöchentlich") : t("Monthly", "Monatlich");

/** "+12 this week": what one bucket added. */
const perBucketLabel = (interval: TimelineInterval, t: TranslateFn) =>
  interval === "day" ? t("on this day", "an diesem Tag") : interval === "week" ? t("this week", "in dieser Woche") : t("this month", "in diesem Monat");

interface ChartPreset {
  key: string;
  label: string;
}

interface TimeSeriesChartProps<T extends TimelineBucket> {
  data: T[];
  value: (point: T) => number;
  title: string;
  interval: TimelineInterval;
  /** Zone the buckets were counted in; labels use it so a day reads as the day it counts. */
  tz: string;
  curve: "smooth" | "linear";
  presets: ChartPreset[];
  activePreset: string | null;
  onPreset: (key: string) => void;
  /** Showing something other than the chart's base range (Reset is offered). */
  zoomed: boolean;
  /** A dragged window, in indices of `data`. */
  onZoom: (win: ZoomWindow) => void;
  onReset: () => void;
  /** Finer data for the shown range is loading: the slice stays up, dimmed. */
  busy: boolean;
  /** Bottom of the y-axis (the total before the window for a cumulative chart). */
  baseline: number;
  renderTooltip: (point: T) => ReactNode;
  /** The same reading as one sentence, announced when the crosshair moves by keyboard. */
  describePoint: (point: T) => string;
}

/**
 * Line chart over a time series that zooms to a dragged window.
 *
 * One Pointer Events path serves mouse, pen and touch: a press captures the pointer,
 * horizontal travel past DRAG_THRESHOLD_PX turns it into a selection band, release hands
 * the points inside the band (timeZoom.selectionToWindow, at least two) to `onZoom`, which
 * fetches that time range again at a finer interval (see useTimeline). `touch-action:
 * pan-y` on the plot leaves vertical page scroll to the browser, which then cancels the
 * gesture. A tap or a short wobble keeps the crosshair tooltip. Escape, double-click and the
 * Reset button go back to the base range. Focused, ←/→/Home/End move the crosshair.
 */
function TimeSeriesChart<T extends TimelineBucket>({
  data,
  value,
  title,
  interval,
  tz,
  curve,
  presets,
  activePreset,
  onPreset,
  zoomed,
  onZoom,
  onReset,
  busy,
  baseline,
  renderTooltip,
  describePoint,
}: TimeSeriesChartProps<T>) {
  const { t, locale } = useI18n();
  const containerRef = useRef<HTMLDivElement | null>(null);
  const width = useContainerWidth(containerRef);
  const hintId = useId();
  const [hovered, setHovered] = useState<number | null>(null);
  const [band, setBand] = useState<{ from: number; to: number } | null>(null);
  const [announcement, setAnnouncement] = useState("");
  const gesture = useRef<{ id: number; startX: number; dragging: boolean } | null>(null);

  const length = data.length;
  const win = fullWindow(length);

  const isMobile = width < 500;
  const padding =
    interval === "month"
      ? { top: 12, bottom: 32, left: isMobile ? 60 : 68, right: isMobile ? 16 : 24 }
      : { top: 12, bottom: 48, left: isMobile ? 52 : 64, right: isMobile ? 16 : 24 };
  const plot = { left: padding.left, width: Math.max(1, width - padding.left - padding.right) };
  const plotHeight = CHART_HEIGHT - padding.top - padding.bottom;
  const plotRight = plot.left + plot.width;
  const plotBottom = padding.top + plotHeight;

  const yMin = baseline;
  const yMax = Math.max(yMin + 1, ...data.map(value));
  const yOf = (v: number) => plotBottom - ((v - yMin) / (yMax - yMin)) * plotHeight;

  const points = data.map((point, index) => ({ index, point, x: indexToPixel(index, plot, win), y: yOf(value(point)) }));

  let linePath = "";
  if (points.length >= 2) {
    linePath = `M ${points[0].x},${points[0].y}`;
    for (let i = 1; i < points.length; i += 1) {
      const prev = points[i - 1];
      const curr = points[i];
      if (curve === "smooth") {
        const midX = (prev.x + curr.x) / 2;
        linePath += ` C ${midX},${prev.y} ${midX},${curr.y} ${curr.x},${curr.y}`;
      } else {
        linePath += ` L ${curr.x},${curr.y}`;
      }
    }
  }

  // A new series can be shorter than the last one; an index past its end shows nothing.
  const hoverIndex = hovered != null && hovered < length ? hovered : null;
  const hoverPoint = hoverIndex != null ? points[hoverIndex] : null;

  const ticks = length ? tickIndices(win, interval === "month" ? (isMobile ? 3 : 6) : isMobile ? 4 : 8) : [];

  const rangeText = length
    ? `${formatBucket(data[0].timestamp, interval, tz, locale)} – ${formatBucket(data[length - 1].timestamp, interval, tz, locale)}`
    : "";

  const zoomTo = (next: ZoomWindow) => {
    setHovered(null);
    if (!isFullWindow(next, length)) onZoom(next);
  };

  const resetZoom = (refocus = false) => {
    setHovered(null);
    onReset();
    // The Reset button disappears with the zoom; hand focus to the chart instead of the page.
    if (refocus) containerRef.current?.focus();
  };

  const localX = (event: React.PointerEvent<SVGSVGElement>) => {
    const rect = event.currentTarget.getBoundingClientRect();
    return ((event.clientX - rect.left) / (rect.width || 1)) * width;
  };

  const handlePointerDown = (event: React.PointerEvent<SVGSVGElement>) => {
    if (event.pointerType === "mouse" && event.button !== 0) return;
    const x = localX(event);
    gesture.current = { id: event.pointerId, startX: x, dragging: false };
    try {
      event.currentTarget.setPointerCapture(event.pointerId);
    } catch {
      // Capture is a convenience (drag past the edge); the gesture works without it.
    }
    setHovered(pixelToIndex(x, plot, win));
  };

  const handlePointerMove = (event: React.PointerEvent<SVGSVGElement>) => {
    const x = localX(event);
    const active = gesture.current;
    if (active && active.id === event.pointerId) {
      if (!active.dragging && Math.abs(x - active.startX) >= DRAG_THRESHOLD_PX) active.dragging = true;
      if (active.dragging) {
        setBand({ from: active.startX, to: x });
        setHovered(null);
        return;
      }
    }
    setHovered(pixelToIndex(x, plot, win));
  };

  const handlePointerUp = (event: React.PointerEvent<SVGSVGElement>) => {
    const active = gesture.current;
    gesture.current = null;
    if (!active || active.id !== event.pointerId || !active.dragging) return;
    setBand(null);
    const next = selectionToWindow(active.startX, localX(event), plot, win, MIN_ZOOM_POINTS);
    if (next) zoomTo(next);
  };

  const handlePointerCancel = () => {
    // The browser took the gesture over (a vertical page scroll): drop band and tooltip.
    gesture.current = null;
    setBand(null);
    setHovered(null);
  };

  const handlePointerLeave = (event: React.PointerEvent<SVGSVGElement>) => {
    // A finger "leaves" on lift; keep the tapped reading until the next touch or blur.
    if (!gesture.current && event.pointerType !== "touch") setHovered(null);
  };

  const moveCrosshair = (index: number) => {
    setHovered(index);
    setAnnouncement(describePoint(data[index]));
  };

  const handleKeyDown = (event: React.KeyboardEvent<HTMLDivElement>) => {
    if (event.key === "Escape") {
      if (zoomed) {
        event.preventDefault();
        resetZoom();
      }
      return;
    }
    let next: number | null = null;
    if (event.key === "ArrowLeft") next = hoverIndex == null ? win.end : Math.max(win.start, hoverIndex - 1);
    else if (event.key === "ArrowRight") next = hoverIndex == null ? win.end : Math.min(win.end, hoverIndex + 1);
    else if (event.key === "Home") next = win.start;
    else if (event.key === "End") next = win.end;
    if (next == null) return;
    event.preventDefault();
    moveCrosshair(next);
  };

  const handleFocus = (event: React.FocusEvent<HTMLDivElement>) => {
    if (event.target !== event.currentTarget) return;
    let keyboard: boolean;
    try {
      keyboard = event.currentTarget.matches(":focus-visible");
    } catch {
      keyboard = false;
    }
    // A click focuses too; only keyboard focus places the crosshair on the latest point.
    if (keyboard && hoverIndex == null) moveCrosshair(win.end);
  };

  const tooltipStyle: React.CSSProperties | undefined = hoverPoint
    ? {
        left: hoverPoint.x,
        top: hoverPoint.y,
        // Keep the tooltip inside the chart at both edges and below a point near the top.
        transform: `translate(${
          hoverPoint.x < width * 0.25 ? "-12px" : hoverPoint.x > width * 0.75 ? "calc(-100% + 12px)" : "-50%"
        }, ${hoverPoint.y < 64 ? "var(--space-md)" : "calc(-100% - var(--space-md))"})`,
      }
    : undefined;

  const bandLeft = band ? Math.max(plot.left, Math.min(band.from, band.to)) : 0;
  const bandRight = band ? Math.min(plotRight, Math.max(band.from, band.to)) : 0;
  const yearOf = (timestamp: number) => new Date(timestamp).toLocaleDateString(locale, { year: "numeric", timeZone: tz });

  return (
    <div className="stats-timechart">
      <div className="stats-zoom-bar">
        <p className="stats-zoom-range" aria-live="polite">
          <span className="visually-hidden">{t("Showing", "Angezeigt:")} </span>
          <span className="stats-zoom-granularity">{granularityLabel(interval, t)}</span>
          {rangeText && <span aria-hidden="true"> · </span>}
          {rangeText}
        </p>
        {!zoomed && length > 1 && (
          <p id={hintId} className="stats-zoom-hint">
            {t("Drag sideways across the chart to zoom in.", "Zum Vergrößern seitlich über das Diagramm ziehen.")}
          </p>
        )}
        <div className="stats-zoom-controls">
          <div className="stats-zoom-presets" role="group" aria-label={t("Time range", "Zeitraum")}>
            {presets.map((preset) => (
              <button
                key={preset.key}
                type="button"
                className="stats-zoom-preset"
                aria-pressed={activePreset === preset.key}
                onClick={() => {
                  setHovered(null);
                  onPreset(preset.key);
                }}
              >
                {preset.label}
              </button>
            ))}
          </div>
          {zoomed && (
            <button type="button" className="btn-secondary stats-zoom-reset" onClick={() => resetZoom(true)}>
              <LuZoomOut aria-hidden="true" />
              {t("Reset zoom", "Zoom zurücksetzen")}
            </button>
          )}
        </div>
      </div>

      {length === 0 ? (
        <EmptyState title={t("No timeline data yet.", "Noch keine Zeitreihendaten.")} />
      ) : (
        <div
          ref={containerRef}
          className={`stats-chart${busy ? " is-refreshing" : ""}`}
          role="group"
          tabIndex={0}
          aria-label={title}
          aria-busy={busy || undefined}
          aria-describedby={zoomed || length < 2 ? undefined : hintId}
          onKeyDown={handleKeyDown}
          onFocus={handleFocus}
          onBlur={() => setHovered(null)}
          onDoubleClick={() => zoomed && resetZoom()}
        >
          <svg
            role="img"
            aria-label={`${title}: ${granularityLabel(interval, t)}, ${rangeText}`}
            width={width}
            height={CHART_HEIGHT}
            viewBox={`0 0 ${width} ${CHART_HEIGHT}`}
            onPointerDown={handlePointerDown}
            onPointerMove={handlePointerMove}
            onPointerUp={handlePointerUp}
            onPointerCancel={handlePointerCancel}
            onPointerLeave={handlePointerLeave}
          >
            {/* Grid lines, the baseline first */}
            {[0, 0.5, 1].map((ratio) => (
              <line
                key={ratio}
                className="stats-grid-line"
                x1={plot.left}
                y1={padding.top + plotHeight * (1 - ratio)}
                x2={plotRight}
                y2={padding.top + plotHeight * (1 - ratio)}
              />
            ))}

            <path className="stats-line" d={linePath} />

            {hoverPoint && (
              <>
                <line className="stats-hover-line" x1={hoverPoint.x} y1={padding.top} x2={hoverPoint.x} y2={plotBottom} />
                <circle className="stats-hover-point" cx={hoverPoint.x} cy={hoverPoint.y} r={4} />
              </>
            )}

            {band && bandRight > bandLeft && (
              <rect
                className="stats-zoom-band"
                aria-hidden="true"
                x={bandLeft}
                y={padding.top}
                width={bandRight - bandLeft}
                height={plotHeight}
              />
            )}

            {/* Time axis: evenly spread ticks; the outer ones align to the plot edges */}
            {ticks.map((index, i) => {
              const x = indexToPixel(index, plot, win);
              const anchor = ticks.length > 1 && i === 0 ? "start" : ticks.length > 1 && i === ticks.length - 1 ? "end" : "middle";
              const timestamp = data[index].timestamp;
              if (!timestamp) return null;
              if (interval === "month") {
                return (
                  <text key={index} className="stats-axis-text" x={x} y={CHART_HEIGHT - 8} textAnchor={anchor}>
                    {formatBucket(timestamp, "month", tz, locale)}
                  </text>
                );
              }
              const year = yearOf(timestamp);
              const prev = i > 0 ? data[ticks[i - 1]].timestamp : 0;
              const yearChanged = i === 0 || !prev || yearOf(prev) !== year;
              return (
                <g key={index}>
                  <text className="stats-axis-text" x={x} y={plotBottom + 18} textAnchor={anchor}>
                    {new Date(timestamp).toLocaleDateString(locale, { day: "numeric", month: "short", timeZone: tz })}
                  </text>
                  {yearChanged && (
                    <text className="stats-axis-text" x={x} y={plotBottom + 34} textAnchor={anchor}>
                      {year}
                    </text>
                  )}
                </g>
              );
            })}

            {/* Y-axis labels: absolute values, also when a baseline sits above zero */}
            {[0, 0.5, 1].map((ratio) => (
              <text
                key={ratio}
                className="stats-axis-text"
                x={plot.left - 8}
                y={padding.top + plotHeight * (1 - ratio) + 4}
                textAnchor="end"
              >
                {Math.round(yMin + (yMax - yMin) * ratio).toLocaleString(locale)}
              </text>
            ))}
          </svg>

          {hoverPoint && tooltipStyle && (
            <div className="stats-tooltip" style={tooltipStyle} aria-hidden="true">
              {renderTooltip(hoverPoint.point)}
            </div>
          )}
        </div>
      )}
      <p className="visually-hidden" aria-live="polite">
        {announcement}
      </p>
    </div>
  );
}

/* ---------- Adaptive timelines: one range per chart, fetched at the interval it needs ---------- */

/** Answers per (from, to, interval, zone), shared by both charts: reset and repeated ranges show at once. */
const timelineCache = new TimelineCache<TimelineSeries>(40, 60_000);

const TREND_RANGES: QuickRange[] = [
  { key: "7d", days: 7 },
  { key: "30d", days: 30 },
  { key: "90d", days: 90 },
  { key: "1y", months: 12 },
  { key: "5y", months: 60 },
  { key: "all" },
];
const HISTORY_RANGES: QuickRange[] = [{ key: "1y", months: 12 }, { key: "5y", months: 60 }, { key: "10y", months: 120 }, { key: "all" }];

const rangeLabel = (key: string, t: TranslateFn): string => {
  switch (key) {
    case "7d":
      return t("7 days", "7 Tage");
    case "30d":
      return t("30 days", "30 Tage");
    case "90d":
      return t("90 days", "90 Tage");
    case "1y":
      return t("1 year", "1 Jahr");
    case "5y":
      return t("5 years", "5 Jahre");
    case "10y":
      return t("10 years", "10 Jahre");
    default:
      return t("All", "Alle");
  }
};

interface TimelineState {
  range: TimelineRange;
  series: TimelineSeries | null;
  refreshing: boolean;
  error: unknown;
}

interface Timeline extends TimelineState {
  zoomed: boolean;
  activePreset: string | null;
  presets: ChartPreset[];
  zoomTo: (win: ZoomWindow) => void;
  pick: (key: string) => void;
  reset: () => void;
  retry: () => void;
}

/**
 * One chart's range and the series for it. Every range change goes through
 * planNavigation: a cached answer or an exact slice shows at once; otherwise the
 * coarse slice (or the current series) stays up dimmed while the range is fetched
 * with `interval=auto`. A newer range aborts the older request, and a sequence
 * number drops any answer that still arrives for a range the user already left.
 */
const useTimeline = (quickRanges: QuickRange[], baseKey: string): Timeline => {
  const { t } = useI18n();
  const tz = useMemo(() => safeZone(getCurrentTimezone()), []);
  const base = useMemo(() => {
    const preset = quickRanges.find((range) => range.key === baseKey) ?? { key: baseKey };
    return quickRange(preset, Date.now(), tz);
  }, [quickRanges, baseKey, tz]);
  const [state, setState] = useState<TimelineState>({ range: base, series: null, refreshing: true, error: null });
  const seq = useRef(0);
  const controller = useRef<AbortController | null>(null);

  const navigate = useCallback(
    (range: TimelineRange, current: TimelineSeries | null) => {
      const key = rangeKey(range, tz);
      const plan = planNavigation(current, range, timelineCache.get(key), Date.now());
      controller.current?.abort();
      controller.current = null;
      const ticket = ++seq.current;
      setState({ range, series: plan.show, refreshing: plan.fetch, error: null });
      if (!plan.fetch) return;
      const request = new AbortController();
      controller.current = request;
      fetchTimeline(range, tz, { signal: request.signal })
        .then((series) => {
          timelineCache.set(key, series);
          if (ticket === seq.current) setState({ range, series, refreshing: false, error: null });
        })
        .catch((error: unknown) => {
          if (ticket !== seq.current || axios.isCancel(error)) return;
          console.error("Failed to load timeline", error);
          setState((prev) => ({ ...prev, refreshing: false, error }));
        });
    },
    [tz]
  );

  useEffect(() => {
    navigate(base, null);
    return () => controller.current?.abort();
  }, [navigate, base]);

  const { range, series } = state;
  return {
    ...state,
    zoomed: rangeKey(range, tz) !== rangeKey(base, tz),
    activePreset: range.preset ?? null,
    presets: quickRanges.map((preset) => ({ key: preset.key, label: rangeLabel(preset.key, t) })),
    zoomTo: (win) => {
      if (series) navigate(windowToRange(series, win), series);
    },
    pick: (key) => {
      const preset = quickRanges.find((candidate) => candidate.key === key);
      if (preset) navigate(quickRange(preset, Date.now(), tz), series);
    },
    reset: () => navigate(base, series),
    retry: () => navigate(range, series),
  };
};

/** Skeleton before the first answer, an error with retry, or the chart with a note when a later range failed. */
const TimelineFrame = ({ timeline, children }: { timeline: Timeline; children: ReactNode }) => {
  const { t } = useI18n();
  if (!timeline.series) {
    if (timeline.error) {
      return (
        <ErrorState
          title={t("Could not load the timeline.", "Die Zeitreihe konnte nicht geladen werden.")}
          error={timeline.error}
          onRetry={timeline.retry}
        />
      );
    }
    return (
      <LoadingRegion label={t("Loading timeline", "Zeitreihe wird geladen")}>
        <div className="stats-block">
          <SkeletonBlock height="var(--control-height)" width="60%" radius={4} />
          <SkeletonBlock height={`${CHART_HEIGHT}px`} radius={4} />
        </div>
      </LoadingRegion>
    );
  }
  return (
    <>
      {children}
      {timeline.error != null && (
        <p className="stats-timeline-error" role="alert">
          {t("Could not load this range; the coarser view stays up.", "Dieser Zeitraum konnte nicht geladen werden; die gröbere Ansicht bleibt stehen.")}{" "}
          <button type="button" className="btn-secondary" onClick={timeline.retry}>
            {t("Try again", "Erneut versuchen")}
          </button>
        </p>
      )}
    </>
  );
};

const TimelineChart = ({ timeline }: { timeline: Timeline }) => {
  const { t, locale } = useI18n();
  const series = timeline.series;

  return (
    <TimelineFrame timeline={timeline}>
      {series && (
        <TimeSeriesChart
          data={series.points}
          value={(point) => point.count}
          title={t("Publication trend", "Veröffentlichungstrend")}
          interval={series.interval}
          tz={series.tz}
          curve="smooth"
          presets={timeline.presets}
          activePreset={timeline.activePreset}
          onPreset={timeline.pick}
          zoomed={timeline.zoomed}
          onZoom={timeline.zoomTo}
          onReset={timeline.reset}
          busy={timeline.refreshing}
          baseline={0}
          renderTooltip={(point) => (
            <>
              <div className="stats-tooltip-value">
                {point.count.toLocaleString(locale)} {t("Vulnerabilities", "Schwachstellen")}
              </div>
              <div className="stats-tooltip-meta">{describeBucket(point.timestamp, series.interval, series.tz, locale, t)}</div>
            </>
          )}
          describePoint={(point) =>
            `${describeBucket(point.timestamp, series.interval, series.tz, locale, t)}: ${point.count.toLocaleString(locale)} ${t(
              "vulnerabilities",
              "Schwachstellen"
            )}`
          }
        />
      )}
    </TimelineFrame>
  );
};

type CumulativePoint = TimelineBucket & { cumulative: number };

const TimelineSummaryChart = ({ timeline }: { timeline: Timeline }) => {
  const { t, locale } = useI18n();
  const series = timeline.series;

  // The running total starts at what was published before the first bucket, so any
  // window keeps absolute values ("312,456 total"), not a count restarted at its start.
  const cumulativeData = useMemo<CumulativePoint[]>(() => {
    if (!series) return [];
    let runningTotal = series.totalBefore;
    return series.points.map((point) => {
      runningTotal += point.count;
      return { ...point, cumulative: runningTotal };
    });
  }, [series]);

  return (
    <TimelineFrame timeline={timeline}>
      {series && (
        <TimeSeriesChart
          data={cumulativeData}
          value={(point) => point.cumulative}
          title={t("Historical overview of published vulnerabilities", "Historischer Überblick von veröffentlichten Schwachstellen")}
          interval={series.interval}
          tz={series.tz}
          curve="linear"
          presets={timeline.presets}
          activePreset={timeline.activePreset}
          onPreset={timeline.pick}
          zoomed={timeline.zoomed}
          onZoom={timeline.zoomTo}
          onReset={timeline.reset}
          busy={timeline.refreshing}
          // The axis starts at the total before the window, so the window's growth fills the
          // plot instead of a flat line near the top; the labels stay absolute.
          baseline={series.totalBefore}
          renderTooltip={(point) => (
            <>
              <div className="stats-tooltip-value">
                {point.cumulative.toLocaleString(locale)} {t("total", "gesamt")}
              </div>
              <div className="stats-tooltip-meta">
                +{point.count.toLocaleString(locale)} {perBucketLabel(series.interval, t)}
              </div>
              <div className="stats-tooltip-meta">{describeBucket(point.timestamp, series.interval, series.tz, locale, t)}</div>
            </>
          )}
          describePoint={(point) =>
            `${describeBucket(point.timestamp, series.interval, series.tz, locale, t)}: ${point.cumulative.toLocaleString(locale)} ${t(
              "total",
              "gesamt"
            )}, +${point.count.toLocaleString(locale)} ${perBucketLabel(series.interval, t)}`
          }
        />
      )}
    </TimelineFrame>
  );
};

/**
 * Share basis of a ranking: `corpus` divides by all vulnerabilities (vendors, products,
 * assigners: counted per vulnerability), `shown` by the sum of the listed rows, for counts
 * that are not per vulnerability (reference domains add up the references per domain).
 */
type TopListBasis = { kind: "corpus"; total: number; note: string } | { kind: "shown" };

const TopList = ({
  data,
  emptyMessage,
  limit = 6,
  basis,
}: {
  data: TermsBucket[];
  emptyMessage: string;
  limit?: number;
  basis: TopListBasis;
}) => {
  const { t } = useI18n();
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

  const shareBasis =
    basis.kind === "corpus"
      ? corpusBasis(basis.total, basis.note)
      : {
          total: sumValues(items.map((item) => item.doc_count)),
          note: t(`Share among the ${items.length} shown.`, `Anteil unter den ${items.length} gezeigten.`),
        };

  return (
    <BarList
      variant="ranking"
      basis={shareBasis}
      items={items.map((item) => ({
        key: item.key,
        label: item.key || "n/a",
        value: item.doc_count,
        title: item.key,
      }))}
    />
  );
};

/* ---------- Asset catalogue: the entries most vulnerabilities name, each a link to its list ---------- */

const ASSET_PREVIEW = 8;
const CATALOG_SEARCH_MIN = 2;
const CATALOG_SEARCH_LIMIT = 8;
const CATALOG_SEARCH_DEBOUNCE_MS = 300;

type CatalogKind = "vendor" | "product";

const AssetSection = ({ assets, total }: { assets: StatsResponse["assets"]; total: number }) => {
  const { t, locale } = useI18n();
  const vendorTotal = assets.vendorTotal.toLocaleString(locale);
  const productTotal = assets.productTotal.toLocaleString(locale);
  return (
    <Section>
      <div className="stats-columns stats-columns--2">
        <ChartBlock title={t("Asset vendors", "Asset-Hersteller")}>
          <p className="stats-catalog-lead">
            {t(
              `The catalogue vendors most vulnerabilities name, of ${vendorTotal} in the catalogue. Select one to open its vulnerabilities.`,
              `Die Katalog-Hersteller, die die meisten Schwachstellen nennen, von ${vendorTotal} im Katalog. Auswählen öffnet ihre Schwachstellen.`
            )}
          </p>
          <CatalogRanking
            kind="vendor"
            total={total}
            rows={assets.topVendors.map((vendor) => ({
              slug: vendor.slug,
              name: vendor.name,
              aliases: vendor.aliases,
              count: vendor.vulnerabilityCount,
              detail:
                vendor.productCount != null
                  ? t(
                      `${vendor.productCount.toLocaleString(locale)} products in the catalogue`,
                      `${vendor.productCount.toLocaleString(locale)} Produkte im Katalog`
                    )
                  : null,
              owner: null,
            }))}
          />
          <CatalogSearch kind="vendor" />
        </ChartBlock>
        <ChartBlock title={t("Asset products", "Asset-Produkte")}>
          <p className="stats-catalog-lead">
            {t(
              `The catalogue products most vulnerabilities name, of ${productTotal} in the catalogue. Select one to open its vulnerabilities.`,
              `Die Katalog-Produkte, die die meisten Schwachstellen nennen, von ${productTotal} im Katalog. Auswählen öffnet ihre Schwachstellen.`
            )}
          </p>
          <CatalogRanking
            kind="product"
            total={total}
            rows={assets.topProducts.map((product) => ({
              slug: product.slug,
              name: product.name,
              aliases: product.aliases,
              count: product.vulnerabilityCount,
              detail:
                product.versionCount != null
                  ? t(
                      `${product.versionCount.toLocaleString(locale)} known versions`,
                      `${product.versionCount.toLocaleString(locale)} bekannte Versionen`
                    )
                  : null,
              owner: product.vendor,
            }))}
          />
          <CatalogSearch kind="product" />
        </ChartBlock>
      </div>
    </Section>
  );
};

interface CatalogRow {
  slug: string;
  name: string;
  aliases: string[];
  count: number;
  /** Catalogue breadth: products of a vendor, versions of a product. */
  detail: string | null;
  /** The vendor a product belongs to. */
  owner: { slug: string; name: string } | null;
}

const CatalogLink = ({ kind, slug, name }: { kind: CatalogKind; slug: string; name: string }) => {
  const { t } = useI18n();
  return (
    <Link
      to={catalogQueryHref(kind, slug)}
      className="stats-catalog-link"
      title={kind === "vendor" ? t(`Vulnerabilities of vendor ${name}`, `Schwachstellen von Hersteller ${name}`) : t(`Vulnerabilities of product ${name}`, `Schwachstellen von Produkt ${name}`)}
    >
      {name}
    </Link>
  );
};

/** Ranked bars whose label opens the vulnerability list for that slug; the first ASSET_PREVIEW show, the rest on request. */
const CatalogRanking = ({ kind, rows, total }: { kind: CatalogKind; rows: CatalogRow[]; total: number }) => {
  const { t, locale } = useI18n();
  const [expanded, setExpanded] = useState(false);
  const listId = useId();

  if (rows.length === 0) {
    return (
      <EmptyState
        title={kind === "vendor" ? t("No vendor ranking available.", "Keine Hersteller-Rangliste verfügbar.") : t("No product ranking available.", "Keine Produkt-Rangliste verfügbar.")}
      />
    );
  }

  const shown = expanded ? rows : rows.slice(0, ASSET_PREVIEW);
  const n = total.toLocaleString(locale);
  return (
    <>
      <div id={listId}>
        <BarList
          variant="ranking"
          basis={corpusBasis(
            total,
            kind === "vendor"
              ? t(
                  `Share of all ${n} vulnerabilities. Package registries and placeholders such as npm or n/a are left out.`,
                  `Anteil an allen ${n} Schwachstellen. Paket-Registries und Platzhalter wie npm oder n/a sind ausgelassen.`
                )
              : t(`Share of all ${n} vulnerabilities; one can name several products.`, `Anteil an allen ${n} Schwachstellen; eine kann mehrere Produkte nennen.`)
          )}
          items={shown.map((row) => {
            const aliases = distinctAliases(row.name, row.aliases);
            const meta = [
              row.owner ? (
                <span key="owner">
                  {t("by", "von")} <CatalogLink kind="vendor" slug={row.owner.slug} name={row.owner.name} />
                </span>
              ) : null,
              row.detail ? <span key="detail">{row.detail}</span> : null,
              aliases.length ? (
                <span key="aliases" title={aliases.join(", ")}>
                  {t("also", "auch")} {aliases.join(", ")}
                </span>
              ) : null,
            ].filter(Boolean);
            return {
              key: row.slug,
              label: <CatalogLink kind={kind} slug={row.slug} name={row.name} />,
              meta: meta.length ? meta : undefined,
              value: row.count,
            };
          })}
        />
      </div>
      {rows.length > ASSET_PREVIEW && (
        <button
          type="button"
          className="btn-secondary stats-catalog-more"
          aria-expanded={expanded}
          aria-controls={listId}
          onClick={() => setExpanded((value) => !value)}
        >
          {expanded ? t("Show fewer", "Weniger anzeigen") : t(`Show all ${rows.length}`, `Alle ${rows.length} anzeigen`)}
        </button>
      )}
    </>
  );
};

/**
 * Search the whole catalogue (the asset pickers' endpoint: relevance order, a
 * vulnerability count on the top hits) and open any hit's vulnerabilities.
 */
const CatalogSearch = ({ kind }: { kind: CatalogKind }) => {
  const { t, locale } = useI18n();
  const inputId = useId();
  const [term, setTerm] = useState("");
  const [result, setResult] = useState<{ term: string; items: Array<CatalogVendor | CatalogProduct>; total: number } | null>(null);
  const [error, setError] = useState(false);
  const query = term.trim();
  const active = query.length >= CATALOG_SEARCH_MIN;
  const loading = active && result?.term !== query && !error;

  useEffect(() => {
    if (!active) return;
    let cancelled = false;
    const timer = window.setTimeout(() => {
      const request = kind === "vendor" ? fetchVendors(query, CATALOG_SEARCH_LIMIT) : fetchProducts([], query, CATALOG_SEARCH_LIMIT);
      request
        .then((response) => {
          if (!cancelled) {
            setError(false);
            setResult({ term: query, items: response.items, total: response.total });
          }
        })
        .catch((err) => {
          if (cancelled) return;
          console.error("Catalogue search failed", err);
          setError(true);
        });
    }, CATALOG_SEARCH_DEBOUNCE_MS);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [active, kind, query]);

  const label = kind === "vendor" ? t("Search all vendors", "Alle Hersteller durchsuchen") : t("Search all products", "Alle Produkte durchsuchen");
  const items = active && result ? result.items : [];

  return (
    <div className="stats-catalog-search">
      <label htmlFor={inputId} className="stats-catalog-search-label">
        {label}
      </label>
      <input
        id={inputId}
        type="search"
        value={term}
        autoComplete="off"
        placeholder={kind === "vendor" ? t("e.g. apache", "z. B. apache") : t("e.g. tomcat", "z. B. tomcat")}
        onChange={(event) => {
          setTerm(event.target.value);
          setError(false);
        }}
      />
      {active && (
        <div className={`stats-catalog-hits${loading && result ? " is-refreshing" : ""}`} aria-busy={loading || undefined}>
          {error ? (
            <p className="stats-catalog-note">{t("The catalogue search failed.", "Die Katalogsuche ist fehlgeschlagen.")}</p>
          ) : !result ? (
            <LoadingState inline label={t("Searching…", "Wird gesucht…")} />
          ) : items.length === 0 ? (
            <p className="stats-catalog-note" role="status">
              {t("Nothing in the catalogue matches.", "Nichts im Katalog passt.")}
            </p>
          ) : (
            <>
              <ul className="stats-catalog-hit-list">
                {items.map((item) => (
                  <li key={item.slug}>
                    <CatalogLink kind={kind} slug={item.slug} name={item.name} />
                    <span className="stats-catalog-hit-slug mono">{item.slug}</span>
                    {item.vulnerabilityCount != null && (
                      <span className="stats-catalog-hit-count">
                        {item.vulnerabilityCount.toLocaleString(locale)} {t("vulnerabilities", "Schwachstellen")}
                      </span>
                    )}
                  </li>
                ))}
              </ul>
              <p className="stats-catalog-note" role="status">
                {result.total > items.length
                  ? t(
                      `${items.length} of ${result.total.toLocaleString(locale)} matches, best first.`,
                      `${items.length} von ${result.total.toLocaleString(locale)} Treffern, die besten zuerst.`
                    )
                  : t(`${items.length} matches.`, `${items.length} Treffer.`)}
              </p>
            </>
          )}
        </div>
      )}
    </div>
  );
};
