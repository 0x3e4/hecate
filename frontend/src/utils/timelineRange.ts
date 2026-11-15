/**
 * Time ranges for the adaptive timeline charts on the Statistics page.
 *
 * A chart shows one `TimelineSeries` (GET /api/v1/stats/timeline): buckets of one
 * interval in one zone, plus the count published before the first bucket. Zooming or
 * picking a quick range turns into a `TimelineRange`, fetched again with
 * `interval=auto` so a few months of the monthly history come back as weeks, then days.
 * While that loads the chart shows the coarse slice (`sliceSeries`); when the finer
 * interval would be the same one, the slice is already exact and nothing is fetched.
 */
import type { ZoomWindow } from "./timeZoom";

export type TimelineInterval = "day" | "week" | "month";

export interface TimelineBucket {
  key: string;
  count: number;
  /** Bucket start, epoch ms (a local midnight in `tz`). */
  timestamp: number;
}

export interface TimelineSeries {
  /** Start of the first bucket, ISO 8601. */
  from: string;
  /** End of the last bucket (exclusive), ISO 8601. */
  to: string;
  tz: string;
  interval: TimelineInterval;
  totalBefore: number;
  total: number;
  points: TimelineBucket[];
}

/** What a chart asks for. `from` omitted = the earliest publication, `to` omitted = now. */
export interface TimelineRange {
  from?: string;
  to?: string;
  /** The quick range this came from, for the pressed state; a drag-zoom has none. */
  preset?: string;
}

const DAY_MS = 86_400_000;
/** Mirrors choose_timeline_interval in backend/app/services/stats_service.py. */
export const DAY_MAX_DAYS = 120;
export const WEEK_MAX_DAYS = 1096;

/** The interval the backend's `auto` picks for a span. */
export const autoInterval = (fromMs: number, toMs: number): TimelineInterval => {
  const days = (toMs - fromMs) / DAY_MS;
  if (days <= DAY_MAX_DAYS) return "day";
  if (days <= WEEK_MAX_DAYS) return "week";
  return "month";
};

const toMs = (iso: string | undefined, fallback: number): number => {
  if (!iso) return fallback;
  const value = Date.parse(iso);
  return Number.isFinite(value) ? value : fallback;
};

/** The interval `auto` would pick for a range, or null when it starts at "the beginning". */
export const rangeInterval = (range: TimelineRange, now: number): TimelineInterval | null =>
  range.from ? autoInterval(toMs(range.from, now), toMs(range.to, now)) : null;

/** Cache key of a request: (from, to, interval, zone). */
export const rangeKey = (range: TimelineRange, tz: string, interval = "auto"): string =>
  `${range.from ?? ""}|${range.to ?? ""}|${interval}|${tz}`;

/** The range a selected window covers: first bucket start to the start of the bucket after the last. */
export const windowToRange = (series: TimelineSeries, win: ZoomWindow): TimelineRange => {
  const { points } = series;
  const start = points[win.start];
  const after = points[win.end + 1];
  return {
    from: new Date(start.timestamp).toISOString(),
    to: after ? new Date(after.timestamp).toISOString() : series.to,
  };
};

/** The window as a series of its own: same buckets, `totalBefore` grown by what it cut off. */
export const sliceSeries = (series: TimelineSeries, win: ZoomWindow): TimelineSeries => {
  const { points } = series;
  const before = points.slice(0, win.start).reduce((sum, point) => sum + point.count, 0);
  const kept = points.slice(win.start, win.end + 1);
  const after = points[win.end + 1];
  return {
    ...series,
    from: kept.length ? new Date(kept[0].timestamp).toISOString() : series.from,
    to: after ? new Date(after.timestamp).toISOString() : series.to,
    totalBefore: series.totalBefore + before,
    total: kept.reduce((sum, point) => sum + point.count, 0),
    points: kept,
  };
};

/**
 * The window of `series` a range covers, or null when the range reaches outside it
 * (or starts at "the beginning"). Bucket granularity: the first bucket is the one
 * holding `from`, the last the one holding the instant before `to`.
 */
export const rangeWindow = (series: TimelineSeries, range: TimelineRange, now: number): ZoomWindow | null => {
  const { points } = series;
  if (!range.from || points.length === 0) return null;
  const fromMs = toMs(range.from, now);
  const endMs = Math.min(toMs(range.to, now), toMs(series.to, now));
  if (fromMs < toMs(series.from, now) || toMs(range.to, now) > toMs(series.to, now) || endMs <= fromMs) return null;
  let start = 0;
  while (start + 1 < points.length && points[start + 1].timestamp <= fromMs) start += 1;
  let end = start;
  while (end + 1 < points.length && points[end + 1].timestamp < endMs) end += 1;
  return { start, end };
};

export interface NavigationPlan {
  /** What to show now: the answer, the coarse slice while the finer data loads, or the current series dimmed. */
  show: TimelineSeries | null;
  /** Whether the range still has to be fetched. */
  fetch: boolean;
}

/**
 * How a chart moves to a range. A cached answer shows at once. A range inside the
 * current series shows its slice; when `auto` would pick the interval the series
 * already has, that slice is exact and no request goes out (zooming inside daily
 * data, "7 d" from "30 d"). Otherwise the slice, or the current series, stays up
 * dimmed while the range is fetched.
 */
export const planNavigation = (
  current: TimelineSeries | null,
  range: TimelineRange,
  cached: TimelineSeries | undefined,
  now: number
): NavigationPlan => {
  if (cached) return { show: cached, fetch: false };
  const win = current ? rangeWindow(current, range, now) : null;
  const slice = current && win ? sliceSeries(current, win) : null;
  if (slice && current && rangeInterval(range, now) === current.interval) return { show: slice, fetch: false };
  return { show: slice ?? current, fetch: true };
};

/* ---- Calendar dates in a zone, without a date library ---- */

const partsFormatters = new Map<string, Intl.DateTimeFormat>();

const formatterFor = (tz: string): Intl.DateTimeFormat => {
  let formatter = partsFormatters.get(tz);
  if (!formatter) {
    formatter = new Intl.DateTimeFormat("en-US", {
      timeZone: tz,
      hourCycle: "h23",
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
    partsFormatters.set(tz, formatter);
  }
  return formatter;
};

/** A zone the browser knows; anything else reads as UTC, like the backend's fallback. */
export const safeZone = (tz: string | null | undefined): string => {
  if (!tz) return "UTC";
  try {
    formatterFor(tz);
    return tz;
  } catch {
    return "UTC";
  }
};

interface LocalParts {
  year: number;
  month: number;
  day: number;
  hour: number;
  minute: number;
  second: number;
}

const localParts = (at: number, tz: string): LocalParts => {
  const parts = formatterFor(safeZone(tz)).formatToParts(new Date(at));
  const get = (type: Intl.DateTimeFormatPartTypes) => Number(parts.find((part) => part.type === type)?.value ?? 0);
  return { year: get("year"), month: get("month"), day: get("day"), hour: get("hour") % 24, minute: get("minute"), second: get("second") };
};

/** Offset of `tz` from UTC at an instant, in ms (positive east of Greenwich). */
const zoneOffset = (at: number, tz: string): number => {
  const p = localParts(at, tz);
  return Date.UTC(p.year, p.month - 1, p.day, p.hour, p.minute, p.second) - Math.floor(at / 1000) * 1000;
};

/** The instant of local midnight on a calendar date in `tz` (month 1-based; overflowing days roll over). */
export const zonedMidnight = (year: number, month: number, day: number, tz: string): number => {
  const guess = Date.UTC(year, month - 1, day);
  const first = guess - zoneOffset(guess, tz);
  // Again at the corrected instant: the offset can differ across a DST change.
  return guess - zoneOffset(first, tz);
};

/** Local midnight `days` days and `months` months before the day holding `now` in `tz`. */
export const midnightBefore = (now: number, tz: string, { days = 0, months = 0 }: { days?: number; months?: number }): number => {
  const p = localParts(now, tz);
  const monthIndex = p.month - 1 - months;
  const year = p.year + Math.floor(monthIndex / 12);
  const month = ((monthIndex % 12) + 12) % 12;
  // 31 March minus a month is the last of February, not 3 March.
  const lastDay = new Date(Date.UTC(year, month + 1, 0)).getUTCDate();
  return zonedMidnight(year, month + 1, Math.min(p.day, lastDay) - days, tz);
};

export interface QuickRange {
  key: string;
  /** Calendar span back from today; neither = everything. */
  days?: number;
  months?: number;
}

/** The range of a quick-range button; a day count includes today ("7 d" = today and the six before). */
export const quickRange = (preset: QuickRange, now: number, tz: string): TimelineRange => {
  if (preset.days == null && preset.months == null) return { preset: preset.key };
  const from = midnightBefore(now, tz, { days: preset.days ? preset.days - 1 : 0, months: preset.months ?? 0 });
  return { from: new Date(from).toISOString(), preset: preset.key };
};

/* ---- A small cache so reset and repeated zooms answer at once ---- */

export class TimelineCache<T> {
  private readonly entries = new Map<string, { at: number; value: T }>();

  constructor(
    private readonly maxEntries = 40,
    private readonly ttlMs = 60_000,
    private readonly clock: () => number = Date.now
  ) {}

  get(key: string): T | undefined {
    const entry = this.entries.get(key);
    if (!entry) return undefined;
    if (this.clock() - entry.at > this.ttlMs) {
      this.entries.delete(key);
      return undefined;
    }
    // Most recently used last, so the oldest is evicted first.
    this.entries.delete(key);
    this.entries.set(key, entry);
    return entry.value;
  }

  set(key: string, value: T): void {
    this.entries.delete(key);
    this.entries.set(key, { at: this.clock(), value });
    while (this.entries.size > this.maxEntries) {
      const oldest = this.entries.keys().next().value;
      if (oldest === undefined) break;
      this.entries.delete(oldest);
    }
  }

  clear(): void {
    this.entries.clear();
  }
}
