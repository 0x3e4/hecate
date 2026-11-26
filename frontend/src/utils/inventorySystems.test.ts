import { describe, expect, it } from "vitest";

import type { InventorySystem } from "../types";
import {
  matchesSystemFilters,
  parseGroups,
  reportAgeDays,
  reportAgeLabel,
  sortSystems,
  systemStats,
} from "./inventorySystems";

const t = (en: string) => en;

const system = (overrides: Partial<InventorySystem>): InventorySystem => ({
  id: overrides.name ?? "x",
  name: "x",
  groups: [],
  source: "manual",
  reportStatus: "reporting",
  products: [],
  createdAt: "2026-11-01T00:00:00Z",
  updatedAt: "2026-11-01T00:00:00Z",
  ...overrides,
});

describe("report age", () => {
  const now = new Date(2026, 10, 26, 9, 0);
  it("counts calendar days", () => {
    expect(reportAgeDays(null, now)).toBeNull();
    expect(reportAgeDays(new Date(2026, 10, 26, 1, 0).toISOString(), now)).toBe(0);
    expect(reportAgeDays(new Date(2026, 10, 25, 23, 0).toISOString(), now)).toBe(1);
    expect(reportAgeDays(new Date(2026, 10, 20, 12, 0).toISOString(), now)).toBe(6);
    expect(reportAgeDays("junk", now)).toBeNull();
  });
  it("reads as words", () => {
    expect(reportAgeLabel(null, t, now)).toBe("never");
    expect(reportAgeLabel(new Date(2026, 10, 26, 8, 0).toISOString(), t, now)).toBe("today");
    expect(reportAgeLabel(new Date(2026, 10, 25, 8, 0).toISOString(), t, now)).toBe("yesterday");
    expect(reportAgeLabel(new Date(2026, 10, 21, 8, 0).toISOString(), t, now)).toBe("5 days ago");
  });
});

describe("systems list", () => {
  const systems = [
    system({ name: "web-10", exposure: "internet", latestSummary: { critical: 0, high: 2, medium: 0, low: 0, negligible: 0, unknown: 0, total: 2 } }),
    system({ name: "web-9", exposure: "internet", latestSummary: { critical: 1, high: 0, medium: 0, low: 0, negligible: 0, unknown: 0, total: 1 } }),
    system({ name: "db-01", reportStatus: "never", kind: "host", groups: ["DMZ"] }),
    system({ name: "node-1", reportStatus: "stale", kind: "kubernetes-node", products: [{ id: "p", name: "nginx", version: "1.24" }] }),
    system({ name: "app-2" }),
  ];

  it("counts", () => {
    expect(systemStats(systems)).toEqual({ total: 5, reporting: 3, stale: 1, never: 1, internet: 2 });
  });

  it("puts gaps, then exposure, then findings first", () => {
    expect(sortSystems(systems).map((s) => s.name)).toEqual(["node-1", "db-01", "web-9", "web-10", "app-2"]);
  });

  it("filters by status, kind and text over groups and products", () => {
    const base = { query: "", status: "" as const, kind: "" };
    expect(systems.filter((s) => matchesSystemFilters(s, { ...base, status: "never" })).map((s) => s.name)).toEqual(["db-01"]);
    expect(systems.filter((s) => matchesSystemFilters(s, { ...base, kind: "kubernetes-node" })).map((s) => s.name)).toEqual(["node-1"]);
    expect(systems.filter((s) => matchesSystemFilters(s, { ...base, query: "dmz" })).map((s) => s.name)).toEqual(["db-01"]);
    expect(systems.filter((s) => matchesSystemFilters(s, { ...base, query: "NGINX" })).map((s) => s.name)).toEqual(["node-1"]);
  });

  it("parses groups", () => {
    expect(parseGroups("dmz, web,  ,DMZ")).toEqual(["dmz", "web"]);
    expect(parseGroups("")).toEqual([]);
  });
});
