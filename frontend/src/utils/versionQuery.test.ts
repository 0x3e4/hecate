import { describe, it, expect } from "vitest";

import { isConcreteVersion, representativeVersionInRange } from "./versionQuery";

const LE = "≤"; // ≤

describe("isConcreteVersion", () => {
  it("accepts dotted numeric releases", () => {
    expect(isConcreteVersion("7.0.1")).toBe(true);
    expect(isConcreteVersion("7")).toBe(true);
    expect(isConcreteVersion("v2.4")).toBe(true);
  });

  it("rejects range strings and sentinels", () => {
    expect(isConcreteVersion(">= 7.0.0, < 7.0.2")).toBe(false);
    expect(isConcreteVersion("n/a")).toBe(false);
    expect(isConcreteVersion("*")).toBe(false);
    expect(isConcreteVersion(`4.7 ${LE}4.7.30`)).toBe(false);
  });
});

describe("representativeVersionInRange", () => {
  it("returns a concrete version unchanged (minus a v prefix)", () => {
    expect(representativeVersionInRange("7.0.1")).toBe("7.0.1");
    expect(representativeVersionInRange("v2.4")).toBe("2.4");
  });

  it("picks the inclusive lower bound of a two-sided range", () => {
    // The reported bug: this chip must resolve to a version inside the range so
    // affectedVersion: finds the advisory (7.0.0 is in [7.0.0, 7.0.2)).
    expect(representativeVersionInRange(">= 7.0.0, < 7.0.2")).toBe("7.0.0");
  });

  it("picks the inclusive upper bound when there is no lower bound", () => {
    expect(representativeVersionInRange("<= 5.0.9")).toBe("5.0.9");
  });

  it("understands the EUVD typographic range shapes", () => {
    expect(representativeVersionInRange(`4.7 ${LE}4.7.30`)).toBe("4.7.30");
    expect(representativeVersionInRange(`n/a ${LE}5.0.0`)).toBe("5.0.0");
    expect(representativeVersionInRange(`n/a ${LE}${LE} 1.50.2`)).toBe("1.50.2");
    expect(representativeVersionInRange(`6.9 ${LE}6.9.1`)).toBe("6.9.1");
  });

  it("returns null for shapes with no usable in-range version", () => {
    // A lone exclusive upper bound names only the excluded fixed release.
    expect(representativeVersionInRange("< 5.0.9")).toBeNull();
    expect(representativeVersionInRange("n/a")).toBeNull();
    expect(representativeVersionInRange("*")).toBeNull();
    expect(representativeVersionInRange("-")).toBeNull();
    expect(representativeVersionInRange("")).toBeNull();
  });
});
