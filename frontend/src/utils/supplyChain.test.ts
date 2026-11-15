import { describe, expect, it } from "vitest";
import type { SbomComponent } from "../types";
import { ageInDays, hasSignal, signalCounts, signalDetail, signalLabel, signalsOf } from "./supplyChain";

const t = (en: string) => en;
const base: SbomComponent = { id: "x", scanId: "s", targetId: "t", name: "lib", version: "1.0.0", type: "library", licenses: [] };

describe("supply-chain signals", () => {
  it("lists the flags that are set, in display order", () => {
    expect(signalsOf(base)).toEqual([]);
    expect(signalsOf({ ...base, freshRelease: true, unmaintained: false, publisherChanged: null })).toEqual(["fresh"]);
    expect(signalsOf({ ...base, freshRelease: true, unmaintained: true, publisherChanged: true })).toEqual([
      "fresh",
      "publisher",
      "unmaintained",
    ]);
    expect(hasSignal({ ...base, unmaintained: true }, "unmaintained")).toBe(true);
    expect(hasSignal({ ...base, unmaintained: true }, "fresh")).toBe(false);
  });

  it("counts per signal", () => {
    const counts = signalCounts([
      { ...base, freshRelease: true },
      { ...base, freshRelease: true, publisherChanged: true },
      { ...base, unmaintained: true },
    ]);
    expect(counts).toEqual({ fresh: 2, publisher: 1, unmaintained: 1 });
  });

  it("computes whole days and tolerates junk", () => {
    const now = new Date("2026-11-15T12:00:00Z");
    expect(ageInDays("2026-11-12T13:00:00Z", now)).toBe(2);
    expect(ageInDays("2026-11-16T00:00:00Z", now)).toBe(0);
    expect(ageInDays("nope", now)).toBeNull();
    expect(ageInDays(null, now)).toBeNull();
  });

  it("explains each signal", () => {
    const now = new Date("2026-11-15T12:00:00Z");
    expect(signalLabel("publisher", t)).toBe("New publisher");
    expect(signalDetail("fresh", { ...base, publishedAt: "2026-11-13T12:00:00Z" }, t, now)).toBe("Published 2 day(s) ago");
    expect(
      signalDetail("publisher", { ...base, publisher: "mallory", previousPublishers: ["alice"], newMaintainers: ["mallory"] }, t, now),
    ).toBe("Published by npm account mallory, previous versions by alice; maintainers added: mallory");
    expect(
      signalDetail("unmaintained", { ...base, latestVersion: "0.4.0", latestPublishedAt: "2023-11-15T12:00:00Z" }, t, now),
    ).toBe("Latest release (0.4.0) 1096 day(s) ago");
  });
});
