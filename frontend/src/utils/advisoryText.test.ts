import { describe, expect, it } from "vitest";

import { cleanAdvisoryText, formatEcosystemName, splitSentences, toAdvisoryBlocks } from "./advisoryText";

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

const PHP_OOM =
  "PHP uses longjmp() for out-of-memory (OOM) errors to exit the current context and abort handling of the request. " +
  "Some contexts may not properly account for this scenario and leave request memory in an uninitialized state before performing an allocation. " +
  "The subsequent request cleanup procedure may read or branch on this memory. " +
  "Multiple OOM strategies can consistently trigger this condition and lead to remote code execution (RCE).";

describe("splitSentences", () => {
  it("splits at sentence ends", () => {
    expect(splitSentences(PHP_OOM)).toHaveLength(4);
  });

  it("keeps abbreviations, initials and versions inside a sentence", () => {
    expect(
      splitSentences("Affects Foo Inc. Server, e.g. Bar and the U.S. Edition before 1.2.3. Fixed in 1.2.4."),
    ).toEqual(["Affects Foo Inc. Server, e.g. Bar and the U.S. Edition before 1.2.3.", "Fixed in 1.2.4."]);
  });

  it("does not split inside file names or dotted identifiers", () => {
    expect(splitSentences("The file config.Php is read. Then it runs.")).toEqual([
      "The file config.Php is read.",
      "Then it runs.",
    ]);
  });
});

describe("toAdvisoryBlocks", () => {
  it("splits a long single block into paragraphs", () => {
    const blocks = toAdvisoryBlocks(PHP_OOM);
    expect(blocks).toHaveLength(2);
    expect(blocks.map((b) => b[0]).join(" ")).toBe(PHP_OOM);
  });

  it("leaves a short block whole", () => {
    expect(toAdvisoryBlocks("A buffer overflow in foo. Fixed in 1.2.")).toEqual([["A buffer overflow in foo. Fixed in 1.2."]]);
  });

  it("reflows hard-wrapped lines and keeps bullet lists", () => {
    expect(toAdvisoryBlocks("A flaw in\nfoo.\n\n- one\n- two")).toEqual([["A flaw in foo."], ["- one", "- two"]]);
  });

  it("folds a short trailing sentence into the paragraph before it", () => {
    const long = `${"A sentence that is long enough to matter here. ".repeat(6).trim()} Fix it.`;
    const blocks = toAdvisoryBlocks(long);
    expect(blocks[blocks.length - 1][0].endsWith("Fix it.")).toBe(true);
    expect(blocks.every((b) => b[0].length >= 80)).toBe(true);
  });
});
