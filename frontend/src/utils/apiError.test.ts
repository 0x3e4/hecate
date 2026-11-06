import { AxiosError, AxiosHeaders, type AxiosResponse } from "axios";
import { describe, expect, it } from "vitest";

import { isAdvisoryId, normalizeAdvisoryId } from "./advisoryId";
import { describeError, errorHint } from "./apiError";

const t = (en: string) => en;

const axiosError = (status: number | null, detail?: unknown, code?: string): AxiosError => {
  const config = { method: "get", url: "/v1/vulnerabilities/CVE-1", headers: new AxiosHeaders() };
  const response = status === null
    ? undefined
    : ({ status, statusText: "", data: detail === undefined ? {} : { detail }, headers: {}, config } as AxiosResponse);
  return new AxiosError("Request failed", code, config, null, response);
};

describe("describeError", () => {
  it.each([
    [404, "not_found"],
    [401, "forbidden"],
    [403, "forbidden"],
    [429, "rate_limited"],
    [504, "timeout"],
    [500, "server"],
    [503, "server"],
    [400, "unknown"],
  ])("sorts HTTP %i as %s", (status, kind) => {
    expect(describeError(axiosError(status)).kind).toBe(kind);
  });

  it("calls a missing response offline, and an aborted one a timeout", () => {
    expect(describeError(axiosError(null)).kind).toBe("offline");
    expect(describeError(axiosError(null, undefined, "ECONNABORTED")).kind).toBe("timeout");
  });

  it("keeps the request, status and server detail for the technical details", () => {
    const described = describeError(axiosError(503, "OpenSearch unavailable"));
    expect(described).toMatchObject({ status: 503, detail: "OpenSearch unavailable", request: "GET /v1/vulnerabilities/CVE-1" });
  });

  it("ignores a detail that is not text", () => {
    expect(describeError(axiosError(422, [{ loc: ["body"] }])).detail).toBeNull();
  });

  it("handles plain errors and other values", () => {
    expect(describeError(new Error("boom"))).toMatchObject({ kind: "unknown", message: "boom" });
    expect(describeError("text")).toMatchObject({ kind: "unknown", message: "text" });
    expect(describeError(undefined)).toMatchObject({ kind: "unknown", message: null });
  });

  it("names the status in the hint where it helps", () => {
    expect(errorHint(describeError(axiosError(502)), t)).toContain("HTTP 502");
  });
});

describe("advisory ids", () => {
  it.each(["CVE-2026-115290", "cve-2026-1234", "GHSA-abcd-efgh-ijkl", "MAL-2026-3028", "EUVD-2026-114575", "PYSEC-2026-2", "GO-2026-5932"])(
    "accepts %s",
    (id) => expect(isAdvisoryId(id)).toBe(true),
  );

  it.each(["CVE-2026", "hello", "GHSA-abc", "../etc/passwd", ""])("refuses %s", (id) => {
    expect(isAdvisoryId(id)).toBe(false);
  });

  it("spells ids like the sources do", () => {
    expect(normalizeAdvisoryId(" cve-2026-1234 ")).toBe("CVE-2026-1234");
    expect(normalizeAdvisoryId("GHSA-ABCD-EFGH-IJKL")).toBe("GHSA-abcd-efgh-ijkl");
  });
});
