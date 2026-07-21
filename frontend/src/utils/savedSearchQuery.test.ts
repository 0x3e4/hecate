import { describe, it, expect } from "vitest";

import type { SavedSearch } from "../types";
import {
  buildQueryFromSavedSearch,
  buildVulnerabilityRequestParams,
  readQueryModeFromParams,
  sanitizeList,
} from "./savedSearchQuery";
import type { AdvancedFiltersState } from "../components/AdvancedFilters";

const emptyAdvanced: AdvancedFiltersState = {
  includeRejected: false,
  includeReserved: false,
  exploitedOnly: false,
  aiAnalysedOnly: false,
  severity: [],
  sources: [],
  epssScoreMin: "",
  epssScoreMax: "",
  cvssVersion: "",
  cvssScoreMin: "",
  cvssScoreMax: "",
  cwes: "",
  assigner: "",
  publishedFrom: "",
  publishedTo: "",
  attackVector: [],
  attackComplexity: [],
  attackRequirements: [],
  privilegesRequired: [],
  userInteraction: [],
  scope: [],
  confidentialityImpact: [],
  integrityImpact: [],
  availabilityImpact: [],
};

const noFilters = { vendorSlugs: [], productSlugs: [], versionIds: [] };

const makeSaved = (overrides: Partial<SavedSearch>): SavedSearch => ({
  id: "s1",
  name: "test",
  queryParams: "",
  createdAt: "2026-01-01T00:00:00Z",
  updatedAt: "2026-01-01T00:00:00Z",
  ...overrides,
});

describe("sanitizeList", () => {
  it("trims, drops empties, and dedupes preserving first-seen order", () => {
    expect(sanitizeList([" a ", "b", "a", "", "  ", "b"])).toEqual(["a", "b"]);
  });
});

describe("readQueryModeFromParams", () => {
  it("maps the mode param, defaulting to keyword", () => {
    expect(readQueryModeFromParams(new URLSearchParams("mode=dql"))).toBe("dql");
    expect(readQueryModeFromParams(new URLSearchParams("mode=regex"))).toBe("regex");
    expect(readQueryModeFromParams(new URLSearchParams(""))).toBe("keyword");
    expect(readQueryModeFromParams(new URLSearchParams("mode=bogus"))).toBe("keyword");
  });
});

describe("buildVulnerabilityRequestParams", () => {
  const base = { filters: noFilters, advancedFilters: emptyAdvanced, limit: 10, offset: 0 };

  it("keyword mode sets searchTerm and does not force includeRejected", () => {
    const r = buildVulnerabilityRequestParams({ ...base, searchTerm: " log4j ", queryMode: "keyword" });
    expect(r.searchTerm).toBe("log4j");
    expect(r.dqlQuery).toBeUndefined();
    expect(r.includeRejected).toBeUndefined();
  });

  it("dql mode nulls searchTerm, sets dqlQuery, and forces includeRejected", () => {
    const r = buildVulnerabilityRequestParams({ ...base, searchTerm: "severity:CRITICAL", queryMode: "dql" });
    expect(r.searchTerm).toBeNull();
    expect(r.dqlQuery).toBe("severity:CRITICAL");
    expect(r.includeRejected).toBe(true);
  });

  it("regex mode nulls searchTerm and sets regexQuery", () => {
    const r = buildVulnerabilityRequestParams({ ...base, searchTerm: "CVE-2026-.*", queryMode: "regex" });
    expect(r.searchTerm).toBeNull();
    expect(r.regexQuery).toBe("CVE-2026-.*");
    expect(r.includeRejected).toBe(true);
  });

  it("scales EPSS percent inputs to 0..1 and strips CWE- prefixes", () => {
    const r = buildVulnerabilityRequestParams({
      ...base,
      searchTerm: "",
      queryMode: "keyword",
      advancedFilters: { ...emptyAdvanced, epssScoreMin: "38", epssScoreMax: "90", cwes: "CWE-79, 89 ,cwe-22" },
    });
    expect(r.epssScoreMin).toBeCloseTo(0.38, 10);
    expect(r.epssScoreMax).toBeCloseTo(0.9, 10);
    expect(r.cwes).toEqual(["79", "89", "22"]);
  });
});

describe("buildQueryFromSavedSearch", () => {
  it("honours an explicit dql queryMode using dqlQuery over the search param", () => {
    const saved = makeSaved({
      queryParams: "mode=dql&search=ignored",
      queryMode: "dql",
      dqlQuery: "vendors:acme",
    });
    const r = buildQueryFromSavedSearch(saved, 25);
    expect(r.dqlQuery).toBe("vendors:acme");
    expect(r.searchTerm).toBeNull();
    expect(r.limit).toBe(25);
    expect(r.offset).toBe(0);
  });

  it("honours regex queryMode using regexQuery", () => {
    const saved = makeSaved({ queryParams: "mode=regex", queryMode: "regex", regexQuery: "GHSA-.*" });
    expect(buildQueryFromSavedSearch(saved, 10).regexQuery).toBe("GHSA-.*");
  });

  it("falls back to the mode param for legacy saved searches without queryMode", () => {
    const saved = makeSaved({ queryParams: "mode=keyword&search=openssl" });
    const r = buildQueryFromSavedSearch(saved, 10);
    expect(r.searchTerm).toBe("openssl");
    expect(r.dqlQuery).toBeUndefined();
  });
});
