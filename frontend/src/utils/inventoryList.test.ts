import { describe, expect, it } from "vitest";

import type { AffectedVulnerabilityItem, EolStatus, InventoryItem } from "../types";
import {
  DEFAULT_INVENTORY_FILTERS,
  cveActivity,
  hasNewActivity,
  itemSignals,
  matchesInventoryFilters,
  sortInventoryItems,
  type ItemSignals,
} from "./inventoryList";

const item = (id: string, extra: Partial<InventoryItem> = {}): InventoryItem => ({
  id,
  name: id,
  vendorSlug: "v",
  productSlug: id,
  version: "1.0",
  deployment: "onprem",
  environment: "prod",
  instanceCount: 1,
  createdAt: "2026-01-01T00:00:00Z",
  updatedAt: "2026-01-01T00:00:00Z",
  ...extra,
});

const cve = (vulnId: string, extra: Partial<AffectedVulnerabilityItem> = {}): AffectedVulnerabilityItem => ({
  vulnId,
  ...extra,
});

const eol = (extra: Partial<EolStatus>): EolStatus => ({ linked: true, status: "active", statusLabel: "", ...extra });

describe("itemSignals", () => {
  it("takes the worst severity, the newest change and the KEV flag", () => {
    const signals = itemSignals(
      [
        cve("CVE-1", { severity: "MEDIUM", published: "2026-03-01T00:00:00Z" }),
        cve("CVE-2", { severity: "high", lastChangeAt: "2026-11-20T00:00:00Z", exploited: true }),
      ],
      eol({ status: "eol", isOutdated: true, eolDate: "2026-06-30" }),
    );
    expect(signals).toMatchObject({ known: true, count: 2, worst: 1, exploited: true, endOfLife: true, updateAvailable: true });
    expect(signals.lastActivity).toBe(Date.parse("2026-11-20T00:00:00Z"));
    expect(signals.supportEnds).toBe(Date.parse("2026-06-30"));
  });

  it("falls back to the publication date and marks loading items unknown", () => {
    expect(cveActivity(cve("CVE-3", { published: "2026-02-02T00:00:00Z" }))).toBe(Date.parse("2026-02-02T00:00:00Z"));
    expect(itemSignals(null, null)).toMatchObject({ known: false, count: 0, worst: 5, lastActivity: null });
  });
});

describe("matchesInventoryFilters", () => {
  const loaded = itemSignals([], null);
  const loading = itemSignals(null, null);

  it("filters environment case-insensitively, deployment and owner exactly", () => {
    const a = item("a", { environment: "Prod", owner: "team-a" });
    expect(matchesInventoryFilters(a, loaded, { ...DEFAULT_INVENTORY_FILTERS, environment: "prod" })).toBe(true);
    expect(matchesInventoryFilters(a, loaded, { ...DEFAULT_INVENTORY_FILTERS, deployment: "cloud" })).toBe(false);
    expect(matchesInventoryFilters(a, loaded, { ...DEFAULT_INVENTORY_FILTERS, owner: "team-b" })).toBe(false);
  });

  it("keeps an item whose CVEs are still loading", () => {
    const filters = { ...DEFAULT_INVENTORY_FILTERS, affectedOnly: true, exploitedOnly: true };
    expect(matchesInventoryFilters(item("a"), loaded, filters)).toBe(false);
    expect(matchesInventoryFilters(item("a"), loading, filters)).toBe(true);
  });
});

describe("sortInventoryItems", () => {
  const signals: Record<string, ItemSignals> = {
    old: itemSignals([cve("CVE-1", { severity: "critical", lastChangeAt: "2026-01-01T00:00:00Z" })], eol({ eolDate: "2027-01-01" })),
    fresh: itemSignals(
      [cve("CVE-2", { severity: "low", lastChangeAt: "2026-11-25T00:00:00Z" }), cve("CVE-3", { severity: "low" })],
      eol({ eolDate: "2026-12-01" }),
    ),
    clean: itemSignals([], null),
    pending: itemSignals(null, null),
  };
  const items = [item("pending"), item("clean"), item("old", { updatedAt: "2026-11-01T00:00:00Z" }), item("fresh")];
  const order = (key: Parameters<typeof sortInventoryItems>[2]) =>
    sortInventoryItems(items, (i) => signals[i.id], key).map((i) => i.id);

  it("puts the newest CVE activity first, items without any last", () => {
    expect(order("activity")).toEqual(["fresh", "old", "clean", "pending"]);
  });

  it("sorts by worst severity, by count and by support end", () => {
    expect(order("severity")).toEqual(["old", "fresh", "clean", "pending"]);
    expect(order("cves")).toEqual(["fresh", "old", "clean", "pending"]);
    expect(order("support")).toEqual(["fresh", "old", "clean", "pending"]);
  });

  it("sorts by last edit and by name", () => {
    expect(order("edited")[0]).toBe("old");
    expect(order("name")).toEqual(["clean", "fresh", "old", "pending"]);
  });
});

describe("hasNewActivity", () => {
  it("is new only after a known previous visit", () => {
    const signals = itemSignals([cve("CVE-1", { lastChangeAt: "2026-11-25T00:00:00Z" })], null);
    expect(hasNewActivity(signals, Date.parse("2026-11-24T00:00:00Z"))).toBe(true);
    expect(hasNewActivity(signals, Date.parse("2026-11-26T00:00:00Z"))).toBe(false);
    expect(hasNewActivity(signals, null)).toBe(false);
  });
});
