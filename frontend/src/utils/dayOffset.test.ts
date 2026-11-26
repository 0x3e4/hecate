import { describe, expect, it } from "vitest";

import { dayOffsetFor } from "./dayOffset";

describe("dayOffsetFor", () => {
  it("counts calendar days back from today, across months and a DST change", () => {
    expect(dayOffsetFor("2026-11-26", "2026-11-26")).toBe(0);
    expect(dayOffsetFor("2026-11-26", "2026-10-20")).toBe(37);
    expect(dayOffsetFor("2026-03-30", "2026-03-28")).toBe(2);
  });

  it("clamps the future to today and refuses junk", () => {
    expect(dayOffsetFor("2026-11-26", "2026-12-01")).toBe(0);
    expect(dayOffsetFor("2026-11-26", "")).toBeNull();
    expect(dayOffsetFor("2026-11-26", "26.11.2026")).toBeNull();
  });
});
