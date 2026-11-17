import { describe, expect, it } from "vitest";

import { isNoFixState, mergeFixState } from "./fixState";

describe("mergeFixState", () => {
  it("lets a fix win, then the distribution's answer, then a bare not fixed", () => {
    expect(mergeFixState("wont_fix", "fixed")).toBe("fixed");
    expect(mergeFixState("not_fixed", "wont_fix")).toBe("wont_fix");
    expect(mergeFixState("fix_deferred", "end_of_life")).toBe("end_of_life");
    expect(mergeFixState("unknown", "not_fixed")).toBe("not_fixed");
    expect(mergeFixState(null, undefined)).toBe("unknown");
  });

  it("knows the no-fix states", () => {
    expect(isNoFixState("wont_fix")).toBe(true);
    expect(isNoFixState("not_fixed")).toBe(false);
  });
});
