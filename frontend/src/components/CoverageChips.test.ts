import { describe, expect, it } from "vitest";

import { productScanHit, resolveCveScanId } from "./CoverageChips";

// Shape of /v1/scans/coverage: OS / binary packages by name, registry packages per vendor.
const productScan = {
  node: "scan-os",
  "npm|console": "scan-npm",
  "console|console": "scan-npm",
  "npm|lodash": "scan-npm",
};

describe("productScanHit", () => {
  it("does not let npm's console cover Citrix NetScaler Console", () => {
    expect(productScanHit(["citrix-netscaler"], "console", productScan)).toBeUndefined();
  });

  it("matches a registry package through its vendor", () => {
    expect(productScanHit(["npm"], "lodash", productScan)).toBe("scan-npm");
    expect(productScanHit(["console"], "console", productScan)).toBe("scan-npm");
  });

  it("matches an OS or binary package by name alone", () => {
    expect(productScanHit(["nodejs"], "node", productScan)).toBe("scan-os");
    expect(productScanHit(undefined, "node", productScan)).toBe("scan-os");
  });
});

describe("resolveCveScanId", () => {
  it("prefers a finding, then a fitting SBOM package", () => {
    const cveScan = { "CVE-1": "scan-finding" };
    expect(resolveCveScanId({ vulnId: "CVE-1", productSlugs: ["console"] }, cveScan, productScan)).toBe("scan-finding");
    expect(
      resolveCveScanId({ vulnId: "CVE-2", vendorSlugs: ["citrix-netscaler"], productSlugs: ["console"] }, cveScan, productScan),
    ).toBeUndefined();
    expect(
      resolveCveScanId({ vulnId: "CVE-3", vendorSlugs: ["npm"], productSlugs: ["lodash"] }, cveScan, productScan),
    ).toBe("scan-npm");
  });
});
