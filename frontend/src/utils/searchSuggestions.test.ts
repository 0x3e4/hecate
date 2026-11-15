import { describe, expect, it } from "vitest";

import type { VulnerabilitySuggestion } from "../api/vulnerabilities";

import { rankSuggestions, suggestionScanId } from "./searchSuggestions";

const s = (vulnId: string, overrides: Partial<VulnerabilitySuggestion> = {}): VulnerabilitySuggestion => ({
  vulnId,
  title: "",
  info: "",
  severity: "medium",
  cvssScore: null,
  epssScore: null,
  exploited: false,
  kevListed: false,
  aliases: [],
  products: [],
  vendors: [],
  inventoryMatchIds: [],
  sbomScanId: null,
  ...overrides,
});

const ctx = { query: "brotli", attentionIds: new Set<string>(), cveScan: {} as Record<string, string> };
const ids = (items: VulnerabilitySuggestion[]) => items.map((item) => item.vulnId);

describe("rankSuggestions", () => {
  it("puts attention before stack before severity, then KEV, EPSS and CVSS", () => {
    const items = [
      s("critical-kev", { severity: "critical", kevListed: true }),
      s("stack", { inventoryMatchIds: ["i1"] }),
      s("attention"),
      s("critical-epss", { severity: "critical", epssScore: 0.9 }),
      s("low"),
    ];
    const ranked = rankSuggestions(items, { ...ctx, attentionIds: new Set(["attention"]) });
    expect(ids(ranked)).toEqual(["attention", "stack", "critical-kev", "critical-epss", "low"]);
  });

  it("lifts the exact ID typed (or one of its aliases) above everything", () => {
    const items = [s("CVE-2026-1", { severity: "critical" }), s("CVE-2026-11"), s("GHSA-x", { aliases: ["CVE-2026-2"] })];
    expect(ids(rankSuggestions(items, { ...ctx, query: "cve-2026-11" }))[0]).toBe("CVE-2026-11");
    expect(ids(rankSuggestions(items, { ...ctx, query: "CVE-2026-2" }))[0]).toBe("GHSA-x");
  });

  it("counts a scan finding and a version-confirmed SBOM hit as your stack", () => {
    const items = [s("plain", { severity: "critical" }), s("sbom", { sbomScanId: "scan1" }), s("finding")];
    expect(ids(rankSuggestions(items, { ...ctx, cveScan: { finding: "scan2" } }))).toEqual(["sbom", "finding", "plain"]);
  });

  it("keeps the backend's order for full ties", () => {
    expect(ids(rankSuggestions([s("a"), s("b"), s("c")], ctx))).toEqual(["a", "b", "c"]);
  });
});

describe("suggestionScanId", () => {
  it("prefers a finding over an SBOM hit", () => {
    expect(suggestionScanId(s("x", { sbomScanId: "sbom" }), { x: "finding" })).toBe("finding");
    expect(suggestionScanId(s("x", { sbomScanId: "sbom" }), {})).toBe("sbom");
    expect(suggestionScanId(s("x"), {})).toBeNull();
  });
});
