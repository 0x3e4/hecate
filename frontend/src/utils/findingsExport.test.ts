import { describe, expect, it } from "vitest";

import { csvCell, findingsExportFilename, findingsToCsv, findingsToJson, type ExportableFinding } from "./findingsExport";

const finding = (overrides: Partial<ExportableFinding> = {}): ExportableFinding => ({
  findingIds: ["f1", "f2"],
  vulnerabilityId: "CVE-2026-1234",
  severity: "high",
  cvssScore: 8.1,
  packageName: "lodash",
  packageVersion: "4.17.20",
  packageType: "npm",
  packagePath: "/app/package-lock.json",
  fixVersion: "4.17.21",
  fixState: "fixed",
  advisoryFixVersions: ["4.17.21"],
  title: "Prototype pollution",
  description: "A, \"quoted\"\nmultiline text",
  scanners: ["trivy", "grype"],
  dataSource: "nvd",
  vexStatus: null,
  vexJustification: null,
  vexDetail: null,
  dismissed: false,
  dismissedReason: null,
  urls: ["https://nvd.nist.gov/vuln/detail/CVE-2026-1234"],
  ...overrides,
});

const scan = { id: "0123456789abcdef", targetId: "https://github.com/acme/app", targetName: "acme/app" };

describe("csvCell", () => {
  it("quotes separators, quotes and newlines", () => {
    expect(csvCell('a,"b"\nc')).toBe('"a,""b""\nc"');
  });

  it.each(["=HYPERLINK(\"x\")", "+1", "-2+3", "@SUM(A1)"])("neutralises formula trigger: %s", (value) => {
    expect(csvCell(value).replace(/^"|"$/g, "").startsWith("'")).toBe(true);
  });

  it("keeps numbers, booleans and empty values", () => {
    expect(csvCell(-1.5)).toBe("-1.5");
    expect(csvCell(true)).toBe("true");
    expect(csvCell(null)).toBe("");
  });
});

describe("findingsToCsv", () => {
  it("writes a header and one row per finding", () => {
    const csv = findingsToCsv([finding(), finding({ vulnerabilityId: null, packageName: "=cmd" })]);
    const rows = csv.trimEnd().split("\r\n");
    expect(rows[0].startsWith("vulnerability_id,severity,cvss_score,package_name")).toBe(true);
    expect(rows[1].startsWith("CVE-2026-1234,high,8.1,lodash,4.17.20,")).toBe(true);
    expect(csv).toContain(",'=cmd,");
    expect(csv).toContain("trivy grype");
  });
});

describe("findingsToJson", () => {
  it("carries scan metadata, scope and VEX", () => {
    const parsed = JSON.parse(findingsToJson(
      [finding({ vexStatus: "not_affected", vexJustification: "code_not_reachable" })],
      scan,
      "selected",
      new Date("2026-11-10T12:00:00Z"),
    ));
    expect(parsed.metadata).toMatchObject({ scope: "selected", count: 1, exportedAt: "2026-11-10T12:00:00.000Z" });
    expect(parsed.metadata.scan.targetName).toBe("acme/app");
    expect(parsed.findings[0].vex).toEqual({ status: "not_affected", justification: "code_not_reachable", detail: null });
    expect(parsed.findings[0].findingIds).toEqual(["f1", "f2"]);
  });
});

describe("findingsExportFilename", () => {
  it("builds a file-system safe name", () => {
    expect(findingsExportFilename(scan, "csv")).toBe("findings-acme_app-01234567.csv");
    expect(findingsExportFilename({ id: "abc", targetId: "https://ghcr.io/x/y:1.0" }, "json")).toBe("findings-ghcr.io_x_y_1.0-abc.json");
  });
});
