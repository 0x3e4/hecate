import { describe, expect, it } from "vitest";

import { cleanAdvisoryText, formatEcosystemName } from "./advisoryText";

describe("cleanAdvisoryText", () => {
  it("drops the OSV marker and per-source headings", () => {
    const raw = [
      "---",
      "_-= Per source details. Do not edit below this line.=-_",
      "",
      "## Source: ghsa-malware (4295f9675d8088438ae91b0dd10004814c4b1f74b4363857)",
      "Any computer that has this package installed is compromised.",
      "",
      "## Source: ossf-package-analysis (c1d5a2e721c5f8b33b0530ddf98150cadf034a8cd16483e143fc2925b2cfa70c)",
      "The OpenSSF Package Analysis project identified the package.",
    ].join("\n");
    expect(cleanAdvisoryText(raw)).toBe(
      "Any computer that has this package installed is compromised.\n\nThe OpenSSF Package Analysis project identified the package.",
    );
  });

  it("leaves ordinary advisory text alone", () => {
    expect(cleanAdvisoryText("A buffer overflow in foo.")).toBe("A buffer overflow in foo.");
  });

  it("handles empty input", () => {
    expect(cleanAdvisoryText(null)).toBe("");
    expect(cleanAdvisoryText("")).toBe("");
  });
});

describe("formatEcosystemName", () => {
  it("shows the host of a registry-qualified ecosystem", () => {
    expect(formatEcosystemName("Packagist:https://packages.drupal.org/8")).toBe("Packagist (packages.drupal.org)");
  });

  it("leaves plain names alone", () => {
    expect(formatEcosystemName("Google")).toBe("Google");
  });
});
