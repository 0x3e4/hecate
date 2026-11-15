import { describe, expect, it } from "vitest";

import { loginUrl, roleAtLeast, safeReturnTo } from "./returnTo";

describe("safeReturnTo", () => {
  it.each(["/", "/scans", "/vulnerabilities?search=log4j&mode=dql", "/scans/targets/https%3A%2F%2Fgit%2Fx"])(
    "keeps a plain path: %s",
    (path) => {
      expect(safeReturnTo(path)).toBe(path);
    },
  );

  it.each([
    "//evil.test/x",
    "/\\evil.test",
    "https://evil.test/",
    "javascript:alert(1)",
    "scans",
    "/api/v1/things",
    "/api",
    "/x\ny",
    "",
    null,
    undefined,
    `/${"a".repeat(2001)}`,
  ])("falls back to the start page: %s", (path) => {
    expect(safeReturnTo(path)).toBe("/");
  });
});

describe("loginUrl", () => {
  it("points at the backend route with an encoded return path", () => {
    expect(loginUrl("/api", "/scans?tab=sbom")).toBe("/api/v1/auth/login?returnTo=%2Fscans%3Ftab%3Dsbom");
  });

  it("never carries an unsafe return path", () => {
    expect(loginUrl("/api/", "//evil.test")).toBe("/api/v1/auth/login?returnTo=%2F");
  });
});

describe("roleAtLeast", () => {
  it("orders viewer < editor < admin", () => {
    expect(roleAtLeast("admin", "editor")).toBe(true);
    expect(roleAtLeast("editor", "editor")).toBe(true);
    expect(roleAtLeast("viewer", "editor")).toBe(false);
    expect(roleAtLeast("editor", "admin")).toBe(false);
  });

  it("grants nothing to an unknown or missing role", () => {
    expect(roleAtLeast("root", "viewer")).toBe(false);
    expect(roleAtLeast(null, "viewer")).toBe(false);
  });
});
