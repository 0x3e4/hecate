import { afterEach, describe, expect, it, vi } from "vitest";

import {
  AI_PASSWORD_KEY,
  clearWriteSecrets,
  getAdminPassword,
  getTargetPassword,
  isAdminReadUrl,
  setAdminPassword,
  setTargetPassword,
  writePromptTarget,
} from "./writeAuth";

describe("writePromptTarget", () => {
  it("offers the target password where the target gate rejected", () => {
    expect(writePromptTarget("1", "https://github.com/x/y")).toBe("https://github.com/x/y");
  });

  it("asks for the admin password where only that helps, even on a target URL", () => {
    expect(writePromptTarget("admin", "https://github.com/x/y")).toBeNull();
  });

  it("asks for the admin password without a target", () => {
    expect(writePromptTarget("1", null)).toBeNull();
  });

  it.each([undefined, "", "0", "yes"])("leaves any other 401 to the page: %s", (marker) => {
    expect(writePromptTarget(marker, "t")).toBeUndefined();
  });
});

describe("clearWriteSecrets", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("drops the system, every target and the AI password, and nothing else", () => {
    const store = new Map<string, string>();
    vi.stubGlobal("localStorage", {
      getItem: (k: string) => store.get(k) ?? null,
      setItem: (k: string, v: string) => void store.set(k, v),
      removeItem: (k: string) => void store.delete(k),
    });
    setAdminPassword("sys");
    setTargetPassword("t1", "a");
    setTargetPassword("t2", "b");
    store.set(AI_PASSWORD_KEY, JSON.stringify("ai"));
    store.set("hecate.ui_timezone", "Europe/Vienna");

    clearWriteSecrets();

    expect(getAdminPassword()).toBeNull();
    expect(getTargetPassword("t1")).toBeNull();
    expect(getTargetPassword("t2")).toBeNull();
    expect(store.has(AI_PASSWORD_KEY)).toBe(false);
    expect(store.get("hecate.ui_timezone")).toBe("Europe/Vienna");
  });

  it("does not throw without storage", () => {
    vi.stubGlobal("localStorage", undefined);
    expect(() => clearWriteSecrets()).not.toThrow();
  });
});

describe("isAdminReadUrl", () => {
  it.each([
    "/v1/notifications/channels",
    "/v1/notifications/rules/abc",
    "/v1/backup/inventory/export",
    "/v1/sync/states",
    "/v1/advisory-feeds",
    "/v1/api-tokens",
    "/api/v1/sync/states?x=1",
    "/v1/audit/ingestion",
  ])("sends the system password on %s", (url) => {
    expect(isAdminReadUrl(url)).toBe(true);
  });

  it.each([undefined, "/v1/vulnerabilities", "/v1/license-policies", "/v1/vex-rules", "/v1/notificationsX", "/v1/scans/targets"])(
    "leaves %s alone",
    (url) => {
      expect(isAdminReadUrl(url)).toBe(false);
    },
  );
});
