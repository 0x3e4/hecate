import { describe, expect, it } from "vitest";

import type { SeverityProvenance, SeveritySource } from "../types";
import { disagreementRange, orderedSources, sourceKindLabel } from "./severitySources";

const t = (english: string) => english;

const row = (source: string, version: string, baseScore: number | null, isPrimary = false): SeveritySource => ({
  source,
  kind: "cna",
  version,
  baseScore,
  severity: null,
  vector: null,
  isPrimary,
});

describe("severitySources", () => {
  it("labels source kinds", () => {
    expect(sourceKindLabel("nvd", t)).toBe("NVD");
    expect(sourceKindLabel("cna", t)).toBe("CNA via NVD");
    expect(sourceKindLabel("euvd", t)).toBe("via EUVD");
    expect(sourceKindLabel("other", t)).toBe("other");
  });

  it("puts the shown score first, then newer versions and higher scores", () => {
    const ordered = orderedSources([row("A", "2.0", 9), row("B", "3.1", 4), row("C", "3.1", 9.8), row("D", "3.1", 5, true)]);
    expect(ordered.map((r) => r.source)).toEqual(["D", "C", "B", "A"]);
  });

  it("gives the range of the disagreeing CVSS version only", () => {
    const provenance: SeverityProvenance = {
      sources: [row("NVD", "3.1", 9.8), row("Apache", "3.1", 4.2), row("NVD", "2.0", 5)],
      primary: {},
      priorityDb: "NVD",
      disagreement: true,
      disagreementDetail: { cvssMajor: "3", spread: 5.6, bands: ["medium", "critical"], sources: ["Apache", "NVD"] },
    };
    expect(disagreementRange(provenance)).toEqual({ major: "3", min: 4.2, max: 9.8, sources: ["Apache", "NVD"] });
    expect(disagreementRange({ ...provenance, disagreement: false })).toBeNull();
    expect(disagreementRange(null)).toBeNull();
  });
});
