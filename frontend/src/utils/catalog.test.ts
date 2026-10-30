import { describe, expect, it } from "vitest";

import { distinctAliases, primaryVendorSlug } from "./catalog";

describe("primaryVendorSlug", () => {
  it("prefers the vendor named like the product over alphabetical plugin vendors", () => {
    expect(primaryVendorSlug("wordpress", ["ad-minister-project", "adazing", "wordpress"])).toBe("wordpress");
  });

  it("falls back to a vendor the product slug starts with", () => {
    expect(primaryVendorSlug("apache-tomcat", ["aaa", "apache"])).toBe("apache");
  });

  it("skips registries and placeholders", () => {
    expect(primaryVendorSlug("left-pad", ["n-a", "npm", "stevemao"])).toBe("stevemao");
  });

  it("uses a generic vendor only when nothing else exists", () => {
    expect(primaryVendorSlug("left-pad", ["npm"])).toBe("npm");
    expect(primaryVendorSlug("left-pad", [])).toBeNull();
  });
});

describe("distinctAliases", () => {
  it("drops case variants of the label and of each other", () => {
    expect(distinctAliases("WordPress", ["WordPress", "wordpress", "WP", "wp", "WordPress.org"])).toEqual([
      "WP",
      "WordPress.org",
    ]);
  });
});
