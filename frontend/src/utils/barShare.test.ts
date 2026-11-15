import { describe, expect, it } from "vitest";
import { formatShare, shareOf, sumValues } from "./barShare";

describe("shareOf", () => {
  it("divides by the total", () => {
    expect(shareOf(25, 100)).toBe(0.25);
    expect(shareOf(0, 100)).toBe(0);
  });

  it("has no share without a usable total", () => {
    expect(shareOf(5, 0)).toBeNull();
    expect(shareOf(5, -1)).toBeNull();
    expect(shareOf(Number.NaN, 10)).toBeNull();
  });
});

describe("sumValues", () => {
  it("adds the buckets and skips junk", () => {
    expect(sumValues([1, 2, 3])).toBe(6);
    expect(sumValues([1, Number.NaN, 2])).toBe(3);
    expect(sumValues([])).toBe(0);
  });
});

describe("formatShare", () => {
  it("shows one decimal in the locale's spelling", () => {
    expect(formatShare(0.342, "en-US")).toBe("34.2%");
    expect(formatShare(0.342, "de-DE").replace(/\s/g, " ")).toBe("34,2 %");
    expect(formatShare(1, "en-US")).toBe("100.0%");
  });

  it("does not round a small non-zero share down to zero", () => {
    expect(formatShare(0.0004, "en-US")).toBe("<0.1%");
    expect(formatShare(0, "en-US")).toBe("0.0%");
  });

  it("is empty without a share", () => {
    expect(formatShare(null, "en-US")).toBe("");
  });
});
