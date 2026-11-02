import { describe, expect, it } from "vitest";

import { safeHref } from "./safeHref";

describe("safeHref", () => {
  it.each(["https://nvd.nist.gov/vuln/detail/CVE-2026-1", "http://example.org/a?b=c#d", "HTTPS://EXAMPLE.ORG/"])(
    "keeps a web link: %s",
    (value) => {
      expect(safeHref(value)).toBe(value);
    },
  );

  it.each([
    "javascript:alert(1)",
    " javascript:alert(1)",
    "JaVaScRiPt:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "file:///etc/passwd",
    "search-ms:query=x&crumb=location:\\\\attacker\\share",
    "ms-msdt:/id PCWDiagnostic",
    "vscode://file/x",
    "//evil.example/x",
    "/relative/path",
    "not a url",
    "",
    null,
    undefined,
  ])("drops anything else: %s", (value) => {
    expect(safeHref(value)).toBeUndefined();
  });
});
