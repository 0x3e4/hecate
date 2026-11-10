/**
 * Share targets and texts for a single vulnerability (detail page share menu).
 * Pure functions so the texts and limits are testable.
 */

export interface ShareInfo {
  id: string;
  title?: string | null;
  severity?: string | null;
  cvssScore?: number | null;
  exploited?: boolean | null;
  summary?: string | null;
}

export type ShareNetwork = "bluesky" | "linkedin" | "teams" | "x";

/** Bluesky counts graphemes, the limit is 300; X counts every link as 23. */
export const BLUESKY_MAX = 300;
const X_MAX = 280;
const X_LINK_LENGTH = 23;

export function vulnShareUrl(origin: string, id: string): string {
  return `${origin.replace(/\/+$/, "")}/vulnerability/${encodeURIComponent(id)}`;
}

function capitalize(value: string): string {
  return value ? value.charAt(0).toUpperCase() + value.slice(1).toLowerCase() : value;
}

function graphemes(value: string): string[] {
  return Array.from(value);
}

function truncate(value: string, max: number): string {
  const chars = graphemes(value);
  if (chars.length <= max) return value;
  if (max <= 1) return "";
  return chars.slice(0, max - 1).join("").trimEnd() + "…";
}

/** `Critical`, `CVSS 9.8`, `Exploited` — whatever is known. */
function factParts(info: ShareInfo): string[] {
  const parts: string[] = [];
  if (info.severity && info.severity.toLowerCase() !== "unknown") parts.push(capitalize(info.severity));
  if (typeof info.cvssScore === "number") parts.push(`CVSS ${info.cvssScore.toFixed(1)}`);
  if (info.exploited) parts.push("Exploited");
  return parts;
}

/** `CVE-2026-1 · Critical · CVSS 9.8 · Exploited` */
export function shareHeadline(info: ShareInfo): string {
  return [info.id, ...factParts(info)].join(" · ");
}

/**
 * A short post: headline, title, link. The title is shortened so the whole
 * text fits `max` (counting the link as `linkLength` when the network does).
 */
export function buildShortShareText(info: ShareInfo, url: string, max = BLUESKY_MAX, linkLength?: number): string {
  const head = `🔐 ${shareHeadline(info)}`;
  const urlCost = linkLength ?? graphemes(url).length;
  const title = info.title && info.title !== info.id ? info.title.trim() : "";
  // head + "\n" + title + "\n\n" + url
  const fixed = graphemes(head).length + 2 + urlCost;
  const room = max - fixed - 1;
  const titleLine = title && room > 10 ? `\n${truncate(title, room)}` : "";
  return `${head}${titleLine}\n\n${url}`;
}

export function buildShareHref(network: ShareNetwork, info: ShareInfo, url: string): string {
  switch (network) {
    case "bluesky":
      return `https://bsky.app/intent/compose?text=${encodeURIComponent(buildShortShareText(info, url, BLUESKY_MAX))}`;
    case "x":
      return `https://x.com/intent/post?text=${encodeURIComponent(buildShortShareText(info, url, X_MAX, X_LINK_LENGTH))}`;
    case "linkedin":
      // LinkedIn's share-offsite takes only a URL and needs a public preview, which
      // an internal instance can't give; the composer takes the text with the link.
      return `https://www.linkedin.com/feed/?shareActive=true&text=${encodeURIComponent(buildShortShareText(info, url, 3000))}`;
    case "teams":
      return `https://teams.microsoft.com/share?href=${encodeURIComponent(url)}&msgText=${encodeURIComponent(shareHeadline(info) + (info.title && info.title !== info.id ? ` — ${info.title}` : ""))}&preview=true`;
  }
}

function escapeMarkdown(value: string): string {
  return value.replace(/([\\`*_[\]<>|])/g, "\\$1");
}

/**
 * Markdown for tickets, issues and chats (Jira, GitHub, GitLab, Teams, Slack):
 * a linked headline, the title and the first part of the summary as a quote.
 */
export function buildMarkdownSnippet(info: ShareInfo, url: string, summaryMax = 500): string {
  const lines = [[`**[${escapeMarkdown(info.id)}](${url})**`, ...factParts(info)].join(" · ")];
  if (info.title && info.title !== info.id) lines.push("", escapeMarkdown(info.title.trim()));
  const summary = (info.summary ?? "").replace(/\s+/g, " ").trim();
  if (summary) lines.push("", `> ${escapeMarkdown(truncate(summary, summaryMax))}`);
  return lines.join("\n");
}

/** File name for the JSON download, e.g. `CVE-2026-1234.json`. */
export function vulnJsonFilename(id: string): string {
  return `${id.replace(/[^A-Za-z0-9._-]+/g, "_") || "vulnerability"}.json`;
}
