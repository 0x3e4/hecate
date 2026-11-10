import { describe, expect, it } from "vitest";

import {
  BLUESKY_MAX,
  buildMarkdownSnippet,
  buildShareHref,
  buildShortShareText,
  shareHeadline,
  vulnJsonFilename,
  vulnShareUrl,
} from "./vulnShare";

const info = {
  id: "CVE-2026-1234",
  title: "Remote code execution in Example Server",
  severity: "CRITICAL",
  cvssScore: 9.8,
  exploited: true,
  summary: "An attacker can send a crafted request.\n\nThis leads to *code execution*.",
};
const url = "https://hecate.pw/vulnerability/CVE-2026-1234";

describe("vulnShareUrl", () => {
  it("encodes the id and drops a trailing slash", () => {
    expect(vulnShareUrl("https://hecate.pw/", "GHSA-x/y")).toBe("https://hecate.pw/vulnerability/GHSA-x%2Fy");
  });
});

describe("shareHeadline", () => {
  it("lists only what is known", () => {
    expect(shareHeadline(info)).toBe("CVE-2026-1234 · Critical · CVSS 9.8 · Exploited");
    expect(shareHeadline({ id: "MAL-2026-1", severity: "unknown" })).toBe("MAL-2026-1");
  });
});

describe("buildShortShareText", () => {
  it("keeps headline, title and link", () => {
    expect(buildShortShareText(info, url)).toBe(
      `🔐 CVE-2026-1234 · Critical · CVSS 9.8 · Exploited\nRemote code execution in Example Server\n\n${url}`,
    );
  });

  it("shortens a long title to fit the limit", () => {
    const text = buildShortShareText({ ...info, title: "x".repeat(1000) }, url);
    expect(Array.from(text).length).toBeLessThanOrEqual(BLUESKY_MAX);
    expect(text).toContain("…");
    expect(text.endsWith(url)).toBe(true);
  });

  it("skips a title that only repeats the id", () => {
    expect(buildShortShareText({ id: "CVE-1", title: "CVE-1" }, url)).toBe(`🔐 CVE-1\n\n${url}`);
  });
});

describe("buildShareHref", () => {
  it.each([
    ["bluesky", "https://bsky.app/intent/compose?text="],
    ["x", "https://x.com/intent/post?text="],
    ["linkedin", "https://www.linkedin.com/feed/?shareActive=true&text="],
    ["teams", "https://teams.microsoft.com/share?href="],
  ] as const)("%s points at its composer", (network, prefix) => {
    const href = buildShareHref(network, info, url);
    expect(href.startsWith(prefix)).toBe(true);
    expect(decodeURIComponent(href)).toContain(url);
  });
});

describe("buildMarkdownSnippet", () => {
  it("links the id and quotes the summary on one line", () => {
    expect(buildMarkdownSnippet(info, url)).toBe(
      `**[CVE-2026-1234](${url})** · Critical · CVSS 9.8 · Exploited\n\nRemote code execution in Example Server\n\n` +
        "> An attacker can send a crafted request. This leads to \\*code execution\\*.",
    );
  });
});

describe("vulnJsonFilename", () => {
  it("is file-system safe", () => {
    expect(vulnJsonFilename("GHSA-abcd/1:2")).toBe("GHSA-abcd_1_2.json");
  });
});
