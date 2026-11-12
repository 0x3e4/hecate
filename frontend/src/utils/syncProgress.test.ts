import { describe, expect, it } from "vitest";
import { syncProgressView } from "./syncProgress";

describe("syncProgressView", () => {
  it("shows a bar for a full sync bounded by the source total", () => {
    expect(syncProgressView("nvd_initial_sync", { processed: 2500, remote_total: 10000 })).toEqual({
      processed: 2500, total: 10000, percent: 25,
    });
  });

  it("shows only a count for an incremental run, whose source total is not its size", () => {
    expect(syncProgressView("nvd_sync", { processed: 120, remote_total: 300000 })).toEqual({
      processed: 120, total: null, percent: null,
    });
  });

  it("uses a limit as the bound of any run and caps at 100", () => {
    expect(syncProgressView("osv_sync", { processed: 600, limit: 500 })?.percent).toBe(100);
  });

  it("ignores reports without a usable count", () => {
    expect(syncProgressView("cpe_sync", null)).toBeNull();
    expect(syncProgressView("cpe_sync", { processed: "12" })).toBeNull();
    expect(syncProgressView("cpe_sync", { processed: -1 })).toBeNull();
  });
});
