import { describe, expect, it } from "vitest";

import { planSync, samePreferences, type UserPreferences } from "./sync";

const browser: UserPreferences = { language: "de", timezone: null, dashboardOnlyMyStack: true };

describe("planSync", () => {
  it("copies this browser's settings to an account that has none", () => {
    const account = { language: null, timezone: null, dashboardOnlyMyStack: false, updatedAt: null };
    expect(planSync(account, browser)).toEqual({ kind: "upload", preferences: browser });
  });

  it("applies what the account saved, keeping the browser's language when none was saved", () => {
    const account = { language: null, timezone: "Europe/Vienna", dashboardOnlyMyStack: false, updatedAt: "2026-11-26T09:00:00Z" };
    expect(planSync(account, browser)).toEqual({
      kind: "apply",
      preferences: { language: "de", timezone: "Europe/Vienna", dashboardOnlyMyStack: false },
    });
  });
});

describe("samePreferences", () => {
  it("compares every field", () => {
    expect(samePreferences(browser, { ...browser })).toBe(true);
    expect(samePreferences(browser, { ...browser, dashboardOnlyMyStack: false })).toBe(false);
  });
});
