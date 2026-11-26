import { describe, expect, it } from "vitest";

import type { InventoryListSource } from "../types";
import {
  EMPTY_LIST_SOURCE_FORM,
  formFromSource,
  intervalParts,
  listSourcePayload,
  resultChanges,
} from "./listSources";

const SOURCE: InventoryListSource = {
  id: "s1",
  source: "netbox",
  url: "https://netbox.example.com/api/export?token=***",
  format: "csv",
  mode: "replace",
  intervalMinutes: 360,
  enabled: true,
  authHeaderName: "Authorization",
  authSet: true,
  lastRunAt: null,
  lastStatus: null,
  lastErrorKind: null,
  lastError: null,
  lastResult: null,
  nextRunAt: null,
  createdAt: "2026-11-26T10:00:00Z",
  updatedAt: "2026-11-26T10:00:00Z",
};

describe("intervalParts", () => {
  it.each([
    [15, 15, "minutes"],
    [90, 90, "minutes"],
    [60, 1, "hours"],
    [720, 12, "hours"],
    [1440, 1, "days"],
    [10080, 1, "weeks"],
  ])("%i minutes", (minutes, value, unit) => {
    expect(intervalParts(minutes)).toEqual({ value, unit });
  });
});

describe("listSourcePayload", () => {
  it("sends everything for a new source, the credential only when typed", () => {
    const form = { ...EMPTY_LIST_SOURCE_FORM, source: " cmdb ", url: " https://cmdb.example.com/hosts " };
    expect(listSourcePayload(form)).toEqual({
      source: "cmdb",
      url: "https://cmdb.example.com/hosts",
      format: null,
      mode: "merge",
      intervalMinutes: 60,
    });
    expect(listSourcePayload({ ...form, authHeaderValue: "Token a", authHeaderName: "" })).toMatchObject({
      authHeaderValue: "Token a",
      authHeaderName: "Authorization",
    });
  });

  it("leaves the masked URL and the stored credential alone on an edit", () => {
    const payload = listSourcePayload({ ...formFromSource(SOURCE), intervalMinutes: 60 }, SOURCE);
    expect(payload).toEqual({ source: "netbox", format: "csv", mode: "replace", intervalMinutes: 60 });
  });

  it("sends a changed URL, a new credential or its removal", () => {
    const form = formFromSource(SOURCE);
    expect(listSourcePayload({ ...form, url: "https://netbox.example.com/v2" }, SOURCE).url).toBe("https://netbox.example.com/v2");
    expect(listSourcePayload({ ...form, authHeaderValue: "Token b" }, SOURCE).authHeaderValue).toBe("Token b");
    expect(listSourcePayload({ ...form, removeCredential: true, authHeaderValue: "ignored" }, SOURCE).authHeaderValue).toBe("");
    expect(listSourcePayload({ ...form, authHeaderName: "X-API-Key" }, SOURCE).authHeaderName).toBe("X-API-Key");
  });
});

describe("resultChanges", () => {
  it("keeps the non-zero changes in reading order", () => {
    expect(resultChanges({ createdCount: 2, updatedCount: 0, retiredCount: 1, restoredCount: 3 })).toEqual([
      { kind: "created", count: 2 },
      { kind: "restored", count: 3 },
      { kind: "retired", count: 1 },
    ]);
    expect(resultChanges({ createdCount: 0, updatedCount: 0, retiredCount: 0, restoredCount: 0 })).toEqual([]);
  });
});
