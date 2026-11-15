import { describe, expect, it } from "vitest";

import {
  EMPTY_FINDING_FILTERS,
  SCOPE_FILTER_VALUES,
  compareVex,
  hasActiveFindingFilters,
  matchesFindingFilters,
  mergeScope,
  scopeOf,
  toggleValue,
  vexRuleId,
  vexSetBy,
} from "./findingFilters";

describe("scope", () => {
  it("maps missing values to unknown", () => {
    expect(scopeOf("dev")).toBe("dev");
    expect(scopeOf(null)).toBe("unknown");
    expect(scopeOf("weird")).toBe("unknown");
  });

  it("merges with runtime winning and unknown never overriding", () => {
    expect(mergeScope("dev", "runtime")).toBe("runtime");
    expect(mergeScope("runtime", "dev")).toBe("runtime");
    expect(mergeScope("dev", "optional")).toBe("optional");
    expect(mergeScope("dev", null)).toBe("dev");
    expect(mergeScope(null, undefined)).toBeNull();
  });
});

describe("VEX sort", () => {
  it("orders affected, investigating, none, fixed, not affected", () => {
    const statuses = ["not_affected", null, "fixed", "affected", "under_investigation"];
    expect([...statuses].sort(compareVex)).toEqual(["affected", "under_investigation", null, "fixed", "not_affected"]);
  });
});

describe("set by", () => {
  it.each([
    ["user", "manual"],
    ["Claude - MCP", "manual"],
    ["carry-forward", "manual"],
    ["vex-import", "imported"],
    ["vex-source", "source"],
    ["vex-rule:abc", "rule"],
    ["reachability:govulncheck", "reachability"],
  ])("%s → %s", (actor, expected) => {
    expect(vexSetBy(actor, "not_affected")).toBe(expected);
  });

  it("is null without a status and reads the rule id", () => {
    expect(vexSetBy("vex-rule:abc", null)).toBeNull();
    expect(vexRuleId("vex-rule:abc")).toBe("abc");
    expect(vexRuleId("user")).toBeNull();
  });
});

describe("matchesFindingFilters", () => {
  const dev = { dependencyScope: "dev", vexStatus: "not_affected", vexUpdatedBy: "vex-rule:r1" };
  const runtime = { dependencyScope: "runtime", vexStatus: null, vexUpdatedBy: null };
  const unknown = { dependencyScope: null, vexStatus: "affected", vexUpdatedBy: "user", vexNeedsReview: true };

  it("passes everything with no filter", () => {
    expect(hasActiveFindingFilters(EMPTY_FINDING_FILTERS)).toBe(false);
    for (const row of [dev, runtime, unknown]) expect(matchesFindingFilters(row, EMPTY_FINDING_FILTERS)).toBe(true);
  });

  it("filters by scope, VEX status, writer and review", () => {
    const f = (patch: Partial<typeof EMPTY_FINDING_FILTERS>) => ({ ...EMPTY_FINDING_FILTERS, ...patch });
    expect(matchesFindingFilters(unknown, f({ scopes: ["unknown"] }))).toBe(true);
    expect(matchesFindingFilters(dev, f({ scopes: ["runtime", "optional"] }))).toBe(false);
    expect(matchesFindingFilters(runtime, f({ vex: ["none"] }))).toBe(true);
    expect(matchesFindingFilters(dev, f({ vex: ["none", "affected"] }))).toBe(false);
    expect(matchesFindingFilters(dev, f({ setBy: ["rule"] }))).toBe(true);
    expect(matchesFindingFilters(runtime, f({ setBy: ["manual"] }))).toBe(false);
    expect(matchesFindingFilters(unknown, f({ needsReview: true }))).toBe(true);
    expect(matchesFindingFilters(dev, f({ needsReview: true }))).toBe(false);
    expect(hasActiveFindingFilters(f({ needsReview: true }))).toBe(true);
  });
});

describe("toggleValue", () => {
  it("adds and removes while keeping the canonical order", () => {
    expect(toggleValue(["dev"], "runtime", SCOPE_FILTER_VALUES)).toEqual(["runtime", "dev"]);
    expect(toggleValue(["runtime", "dev"], "runtime", SCOPE_FILTER_VALUES)).toEqual(["dev"]);
  });
});
