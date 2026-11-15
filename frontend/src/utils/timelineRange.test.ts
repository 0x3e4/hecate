import { describe, expect, it } from "vitest";
import {
  TimelineCache,
  autoInterval,
  midnightBefore,
  planNavigation,
  quickRange,
  rangeInterval,
  rangeKey,
  rangeWindow,
  safeZone,
  sliceSeries,
  windowToRange,
  zonedMidnight,
  type TimelineSeries,
} from "./timelineRange";

const DAY = 86_400_000;
const day0 = Date.UTC(2026, 10, 1); // 1 Nov 2026, UTC

// Ten daily buckets in UTC with counts 1..10, 100 published before.
const daily: TimelineSeries = {
  from: new Date(day0).toISOString(),
  to: new Date(day0 + 10 * DAY).toISOString(),
  tz: "UTC",
  interval: "day",
  totalBefore: 100,
  total: 55,
  points: Array.from({ length: 10 }, (_, i) => ({
    key: `2026-11-${String(i + 1).padStart(2, "0")}`,
    count: i + 1,
    timestamp: day0 + i * DAY,
  })),
};

describe("autoInterval", () => {
  it("mirrors the backend thresholds", () => {
    expect(autoInterval(0, 30 * DAY)).toBe("day");
    expect(autoInterval(0, 120 * DAY)).toBe("day");
    expect(autoInterval(0, 121 * DAY)).toBe("week");
    expect(autoInterval(0, 1096 * DAY)).toBe("week");
    expect(autoInterval(0, 1097 * DAY)).toBe("month");
  });

  it("has no answer for a range from the beginning", () => {
    expect(rangeInterval({}, Date.now())).toBeNull();
    expect(rangeInterval({ from: "2026-01-01T00:00:00Z", to: "2026-02-01T00:00:00Z" }, 0)).toBe("day");
  });
});

describe("windowToRange / sliceSeries", () => {
  it("turns a window into bucket bounds", () => {
    expect(windowToRange(daily, { start: 2, end: 4 })).toEqual({
      from: new Date(day0 + 2 * DAY).toISOString(),
      to: new Date(day0 + 5 * DAY).toISOString(),
    });
    // The last bucket ends where the series ends.
    expect(windowToRange(daily, { start: 8, end: 9 }).to).toBe(daily.to);
  });

  it("keeps cumulative totals absolute", () => {
    const slice = sliceSeries(daily, { start: 3, end: 5 });
    expect(slice.points.map((p) => p.count)).toEqual([4, 5, 6]);
    expect(slice.totalBefore).toBe(100 + 1 + 2 + 3);
    expect(slice.total).toBe(15);
    expect(slice.from).toBe(new Date(day0 + 3 * DAY).toISOString());
    expect(slice.to).toBe(new Date(day0 + 6 * DAY).toISOString());
    expect(slice.interval).toBe("day");
  });
});

describe("rangeWindow", () => {
  const now = day0 + 9 * DAY + 3600_000;

  it("finds the buckets a range covers", () => {
    expect(rangeWindow(daily, { from: new Date(day0 + 7 * DAY).toISOString() }, now)).toEqual({ start: 7, end: 9 });
    expect(
      rangeWindow(daily, { from: new Date(day0 + 2 * DAY + 5).toISOString(), to: new Date(day0 + 4 * DAY).toISOString() }, now)
    ).toEqual({ start: 2, end: 3 });
  });

  it("is null outside the series or from the beginning", () => {
    expect(rangeWindow(daily, { from: new Date(day0 - DAY).toISOString() }, now)).toBeNull();
    expect(rangeWindow(daily, {}, now)).toBeNull();
    expect(rangeWindow(daily, { from: daily.from, to: new Date(day0 + 20 * DAY).toISOString() }, now)).toBeNull();
  });
});

describe("zoned calendar dates", () => {
  it("finds local midnight across DST", () => {
    // Vienna: CET (+1) in winter, CEST (+2) in summer; the switch is on 29 March 2026.
    expect(new Date(zonedMidnight(2026, 1, 15, "Europe/Vienna")).toISOString()).toBe("2026-01-14T23:00:00.000Z");
    expect(new Date(zonedMidnight(2026, 3, 30, "Europe/Vienna")).toISOString()).toBe("2026-03-29T22:00:00.000Z");
    expect(new Date(zonedMidnight(2026, 3, 29, "Europe/Vienna")).toISOString()).toBe("2026-03-28T23:00:00.000Z");
    expect(new Date(zonedMidnight(2026, 6, 1, "America/New_York")).toISOString()).toBe("2026-06-01T04:00:00.000Z");
  });

  it("steps back days and months from the local today", () => {
    // 00:30 on 14 Nov in Vienna is still 13 Nov in UTC.
    const now = Date.UTC(2026, 10, 13, 23, 30);
    expect(new Date(midnightBefore(now, "Europe/Vienna", {})).toISOString()).toBe("2026-11-13T23:00:00.000Z");
    expect(new Date(midnightBefore(now, "UTC", {})).toISOString()).toBe("2026-11-13T00:00:00.000Z");
    expect(new Date(midnightBefore(now, "Europe/Vienna", { days: 29 })).toISOString()).toBe("2026-10-15T22:00:00.000Z");
    expect(new Date(midnightBefore(now, "UTC", { months: 12 })).toISOString()).toBe("2025-11-13T00:00:00.000Z");
  });

  it("clamps the day when a month is shorter", () => {
    const now = Date.UTC(2026, 2, 31, 12); // 31 March
    expect(new Date(midnightBefore(now, "UTC", { months: 1 })).toISOString()).toBe("2026-02-28T00:00:00.000Z");
  });

  it("reads an unknown zone as UTC", () => {
    expect(safeZone("Mars/Olympus_Mons")).toBe("UTC");
    expect(safeZone(undefined)).toBe("UTC");
    expect(safeZone("Europe/Vienna")).toBe("Europe/Vienna");
  });
});

describe("quickRange", () => {
  const now = Date.UTC(2026, 10, 14, 12);

  it("counts today in a day range", () => {
    expect(quickRange({ key: "7d", days: 7 }, now, "UTC")).toEqual({ from: "2026-11-08T00:00:00.000Z", preset: "7d" });
    expect(quickRange({ key: "1y", months: 12 }, now, "UTC")).toEqual({ from: "2025-11-14T00:00:00.000Z", preset: "1y" });
  });

  it("leaves out from for everything", () => {
    expect(quickRange({ key: "all" }, now, "UTC")).toEqual({ preset: "all" });
  });

  it("keys requests by range, interval and zone", () => {
    expect(rangeKey({ from: "a", to: "b", preset: "x" }, "UTC")).toBe("a|b|auto|UTC");
    expect(rangeKey({ preset: "all" }, "Europe/Vienna")).toBe("||auto|Europe/Vienna");
  });
});

describe("TimelineCache", () => {
  it("expires and evicts the least recently used", () => {
    let clock = 0;
    const cache = new TimelineCache<number>(2, 1000, () => clock);
    cache.set("a", 1);
    cache.set("b", 2);
    expect(cache.get("a")).toBe(1); // a is now the most recent
    cache.set("c", 3);
    expect(cache.get("b")).toBeUndefined();
    expect(cache.get("a")).toBe(1);
    clock = 1500;
    expect(cache.get("c")).toBeUndefined();
  });
});

describe("planNavigation", () => {
  const now = day0 + 9 * DAY + 3600_000;
  const monthly: TimelineSeries = {
    from: "2026-01-01T00:00:00.000Z",
    to: "2026-12-01T00:00:00.000Z",
    tz: "UTC",
    interval: "month",
    totalBefore: 0,
    total: 11,
    points: Array.from({ length: 11 }, (_, i) => ({ key: `m${i}`, count: 1, timestamp: Date.UTC(2026, i, 1) })),
  };

  it("shows a cached answer without fetching", () => {
    expect(planNavigation(monthly, { preset: "all" }, daily, now)).toEqual({ show: daily, fetch: false });
  });

  it("serves a zoom inside daily data from the slice", () => {
    const plan = planNavigation(daily, windowToRange(daily, { start: 2, end: 5 }), undefined, now);
    expect(plan.fetch).toBe(false);
    expect(plan.show?.points.map((p) => p.count)).toEqual([3, 4, 5, 6]);
  });

  it("shows the coarse slice while a finer interval loads", () => {
    const range = windowToRange(monthly, { start: 2, end: 4 }); // three months: daily
    const plan = planNavigation(monthly, range, undefined, now);
    expect(plan.fetch).toBe(true);
    expect(plan.show?.interval).toBe("month");
    expect(plan.show?.points).toHaveLength(3);
    expect(plan.show?.totalBefore).toBe(2);
  });

  it("keeps the current series up for a range outside it", () => {
    const plan = planNavigation(daily, { from: "2020-01-01T00:00:00.000Z", preset: "5y" }, undefined, now);
    expect(plan).toEqual({ show: daily, fetch: true });
    expect(planNavigation(null, { preset: "all" }, undefined, now)).toEqual({ show: null, fetch: true });
  });
});
