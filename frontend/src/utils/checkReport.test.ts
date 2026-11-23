import { describe, expect, it } from "vitest";

import { checkSubject, componentEcosystem, countBySeverity, isCheckRunning, sbomOverview, splitReportRows } from "./checkReport";
import type { MergedFinding } from "./mergeFindings";

const row = (packageType: string, severity = "high"): MergedFinding =>
  ({ key: `${packageType}-${severity}`, packageType, severity }) as MergedFinding;

describe("splitReportRows", () => {
  it("puts malware, secrets, SAST and compliance apart from vulnerabilities, keeping order", () => {
    const rows = [row("npm", "critical"), row("secret-finding"), row("", "low"), row("sast-finding"), row("malicious-indicator")];
    const { vulnerabilities, other } = splitReportRows(rows);
    expect(vulnerabilities.map((r) => r.key)).toEqual(["npm-critical", "-low"]);
    expect(other.map((r) => r.packageType)).toEqual(["secret-finding", "sast-finding", "malicious-indicator"]);
  });
});

describe("countBySeverity", () => {
  it("counts each severity and files anything else as unknown", () => {
    expect(countBySeverity([row("npm", "Critical"), row("npm", "high"), row("npm", "high"), row("npm", "bogus")])).toEqual({
      critical: 1,
      high: 2,
      medium: 0,
      low: 0,
      negligible: 0,
      unknown: 1,
    });
  });
});

describe("componentEcosystem", () => {
  it("prefers the purl type, then the scanner type", () => {
    expect(componentEcosystem({ purl: "pkg:npm/%40scope/x@1.0.0", type: "library" })).toBe("npm");
    expect(componentEcosystem({ purl: "pkg:PyPI/requests@2", type: "python" })).toBe("pypi");
    expect(componentEcosystem({ purl: null, type: "go-module" })).toBe("go-module");
    expect(componentEcosystem({ purl: "not-a-purl", type: " " })).toBe("unknown");
  });
});

describe("sbomOverview", () => {
  it("ranks ecosystems and licenses and counts components without a license", () => {
    const overview = sbomOverview(
      [
        { purl: "pkg:npm/a@1", type: "library", licenses: ["MIT"] },
        { purl: "pkg:npm/b@1", type: "library", licenses: ["MIT", "MIT", " Apache-2.0 "] },
        { purl: "pkg:pypi/c@1", type: "library", licenses: [] },
      ],
      1,
    );
    expect(overview.ecosystems).toEqual([{ name: "npm", count: 2 }]);
    expect(overview.licenses).toEqual([{ name: "MIT", count: 2 }]);
    expect(overview.unlicensed).toBe(1);
  });
});

describe("checkSubject", () => {
  it("tells an SBOM, an image and a source check apart", () => {
    expect(checkSubject({ source: "sbom-import", scanners: ["sbom-import"], imageRef: null })).toBe("sbom");
    expect(checkSubject({ source: "manual", scanners: ["trivy"], imageRef: "ghcr.io/o/a@sha256:1" })).toBe("container_image");
    expect(checkSubject({ source: "ci_cd", scanners: ["trivy"], imageRef: null })).toBe("source_repo");
  });
});

describe("isCheckRunning", () => {
  it("is true while pending or running only", () => {
    expect(isCheckRunning("pending")).toBe(true);
    expect(isCheckRunning("running")).toBe(true);
    expect(isCheckRunning("completed")).toBe(false);
    expect(isCheckRunning(undefined)).toBe(false);
  });
});
