import { describe, expect, it } from "vitest";

import { resolveCveScanId, scanChip } from "./CoverageChips";

describe("resolveCveScanId", () => {
  const cveScan = { "CVE-1": "scan-finding" };

  it("prefers a finding on the CVE id", () => {
    expect(resolveCveScanId({ vulnId: "CVE-1", sbomScanId: "scan-sbom" }, cveScan)).toBe("scan-finding");
  });

  it("falls back to the version-checked SBOM hit from the backend", () => {
    expect(resolveCveScanId({ vulnId: "CVE-2", sbomScanId: "scan-sbom" }, cveScan)).toBe("scan-sbom");
  });

  it("does not match on a product name alone", () => {
    // A CVE naming a product some SBOM ships, but outside its version range: no sbomScanId.
    expect(
      resolveCveScanId({ vulnId: "CVE-3", vendorSlugs: ["npm"], productSlugs: ["lodash"], sbomScanId: null }, cveScan),
    ).toBeUndefined();
    expect(resolveCveScanId({ vulnId: "CVE-4", productSlugs: ["node"] }, {})).toBeUndefined();
  });
});

describe("scanChip", () => {
  it("labels the chip with the target name and links to the scan", () => {
    expect(scanChip("s1", { s1: "web" }, "SCA scan")).toEqual({ label: "web", href: "/scans/s1", scan: true, title: "web" });
    expect(scanChip("s2", {}, "SCA scan").label).toBe("SCA scan");
  });
});
