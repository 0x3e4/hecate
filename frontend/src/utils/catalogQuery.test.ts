import { describe, expect, it } from "vitest";
import { catalogQuery, catalogQueryHref, dqlPhrase } from "./catalogQuery";

describe("catalogQuery", () => {
  it("filters the list on the exact slug field", () => {
    expect(catalogQuery("vendor", "microsoft")).toBe('vendorSlugs:"microsoft"');
    expect(catalogQuery("product", "windows-10")).toBe('productSlugs:"windows-10"');
  });

  it("opens the list in DQL mode", () => {
    expect(catalogQueryHref("vendor", "apache")).toBe("/vulnerabilities?search=vendorSlugs%3A%22apache%22&mode=dql");
  });

  it("escapes what would end or break the phrase", () => {
    expect(dqlPhrase('a"b')).toBe('"a\\"b"');
    expect(dqlPhrase("a/b")).toBe('"a\\/b"');
    expect(dqlPhrase("a\\b")).toBe('"a\\\\b"');
  });
});
