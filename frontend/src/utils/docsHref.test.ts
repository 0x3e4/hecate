import { describe, expect, it } from "vitest";

import { docsHref } from "./docsHref";

describe("docsHref", () => {
  it("joins the site and the page without doubled slashes", () => {
    expect(docsHref("https://docs.hecate.pw/", "/guide/vulnerabilities/#severity-by-source")).toBe(
      "https://docs.hecate.pw/guide/vulnerabilities/#severity-by-source",
    );
    expect(docsHref("https://docs.example.org/hecate", "configuration/")).toBe(
      "https://docs.example.org/hecate/configuration/",
    );
  });

  it("gives no link without a docs URL", () => {
    expect(docsHref(null, "configuration/")).toBeNull();
    expect(docsHref("", "configuration/")).toBeNull();
  });
});
