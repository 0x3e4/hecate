import { afterEach, describe, expect, it, vi } from "vitest";

import {
  accessPromptFor,
  AI_PASSWORD_KEY,
  clearWriteSecrets,
  getAdminPassword,
  getTargetPassword,
  isAdminReadUrl,
  registerWritePrompt,
  requestAccess,
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
    "/v1/inventory/systems/sources",
    "/v1/inventory/systems/sources/abc/pull",
    "/v1/api-tokens",
    "/api/v1/sync/states?x=1",
    "/v1/audit/ingestion",
  ])("sends the system password on %s", (url) => {
    expect(isAdminReadUrl(url)).toBe(true);
  });

  it.each([undefined, "/v1/vulnerabilities", "/v1/license-policies", "/v1/vex-rules", "/v1/notificationsX", "/v1/scans/targets", "/v1/inventory/systems", "/v1/inventory/systems/abc"])(
    "leaves %s alone",
    (url) => {
      expect(isAdminReadUrl(url)).toBe(false);
    },
  );
});

describe("accessPromptFor", () => {
  it("leads with sign-in where OIDC would open the request", () => {
    expect(accessPromptFor(401, { "x-auth-required": "login" }, null)).toEqual({ signIn: true, password: false, targetId: null });
  });

  it("keeps the password as an alternative where the gate takes one", () => {
    expect(accessPromptFor(401, { "x-auth-required": "login", "x-write-auth-required": "1" }, "t1")).toEqual({
      signIn: true,
      password: true,
      targetId: "t1",
    });
  });

  it("asks for the password alone without sign-in", () => {
    expect(accessPromptFor(401, { "x-write-auth-required": "admin" }, "t1")).toEqual({ signIn: false, password: true, targetId: null });
  });

  it.each([
    [401, {}],
    [403, { "x-auth-role-required": "admin" }],
    [403, { "x-auth-required": "login" }],
    [500, { "x-write-auth-required": "1" }],
    [undefined, {}],
  ])("prompts for nothing on %s %o", (status, headers) => {
    expect(accessPromptFor(status, headers, null)).toBeUndefined();
  });
});

describe("requestAccess", () => {
  afterEach(() => registerWritePrompt(null));

  it("answers nothing without a mounted prompt", async () => {
    expect(await requestAccess({ signIn: true, password: false, targetId: null })).toBeNull();
  });

  it("asks once for requests refused together", async () => {
    let resolve: (value: { kind: "signed-in" }) => void = () => undefined;
    const prompt = vi.fn(() => new Promise<{ kind: "signed-in" }>((r) => (resolve = r)));
    registerWritePrompt(prompt);
    const ask = { signIn: true, password: false, targetId: null };
    const first = requestAccess(ask);
    const second = requestAccess(ask);
    resolve({ kind: "signed-in" });
    expect(await first).toEqual({ kind: "signed-in" });
    expect(await second).toEqual({ kind: "signed-in" });
    expect(prompt).toHaveBeenCalledTimes(1);
  });

  it("lets a sign-in answer a waiting request that asked for something else", async () => {
    let resolve: (value: { kind: "signed-in" }) => void = () => undefined;
    const prompt = vi.fn(() => new Promise<{ kind: "signed-in" }>((r) => (resolve = r)));
    registerWritePrompt(prompt);
    const first = requestAccess({ signIn: true, password: false, targetId: null });
    const second = requestAccess({ signIn: true, password: true, targetId: "t1" });
    resolve({ kind: "signed-in" });
    await first;
    expect(await second).toEqual({ kind: "signed-in" });
    expect(prompt).toHaveBeenCalledTimes(1);
  });

  it("asks again for another target after a password", async () => {
    const answers = ["one", "two"];
    const prompt = vi.fn(async () => ({ kind: "password" as const, password: answers.shift() ?? "" }));
    registerWritePrompt(prompt);
    const first = requestAccess({ signIn: false, password: true, targetId: "t1" });
    const second = requestAccess({ signIn: false, password: true, targetId: "t2" });
    expect(await first).toEqual({ kind: "password", password: "one" });
    expect(await second).toEqual({ kind: "password", password: "two" });
    expect(prompt).toHaveBeenCalledTimes(2);
  });

  it("cancels every request that waited on the same prompt", async () => {
    let resolve: (value: null) => void = () => undefined;
    registerWritePrompt(() => new Promise<null>((r) => (resolve = r)));
    const ask = { signIn: false, password: true, targetId: null };
    const first = requestAccess(ask);
    const second = requestAccess(ask);
    resolve(null);
    expect(await first).toBeNull();
    expect(await second).toBeNull();
  });
});
