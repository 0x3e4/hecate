import type { VulnerabilitySuggestion } from "../api/vulnerabilities";

import { severityRank } from "./cveGroups";

export interface SuggestionContext {
  query: string;
  /** CVEs in the dashboard's "Needs attention" panel. */
  attentionIds: ReadonlySet<string>;
  /** CVE → latest scan with a finding for it. */
  cveScan: Record<string, string>;
}

/** The scan a suggestion touches: a finding first, else an SBOM package at an affected version. */
export const suggestionScanId = (item: VulnerabilitySuggestion, cveScan: Record<string, string>): string | null =>
  cveScan[item.vulnId] ?? item.sbomScanId ?? null;

const inYourStack = (item: VulnerabilitySuggestion, cveScan: Record<string, string>): boolean =>
  item.inventoryMatchIds.length > 0 || suggestionScanId(item, cveScan) !== null;

const isExactId = (item: VulnerabilitySuggestion, query: string): boolean => {
  const wanted = query.trim().toUpperCase();
  return item.vulnId.toUpperCase() === wanted || item.aliases.some((alias) => alias.toUpperCase() === wanted);
};

/**
 * The order of the dashboard's suggestion list: the exact ID typed, then what needs
 * attention, then what is in your inventory or scans, then severity, a KEV listing,
 * EPSS and CVSS. The backend's relevance order breaks the remaining ties (stable sort).
 */
export const rankSuggestions = (items: VulnerabilitySuggestion[], context: SuggestionContext): VulnerabilitySuggestion[] =>
  items
    .map((item, index) => ({ item, index }))
    .sort((a, b) => {
      const x = a.item;
      const y = b.item;
      return (
        Number(isExactId(y, context.query)) - Number(isExactId(x, context.query)) ||
        Number(context.attentionIds.has(y.vulnId)) - Number(context.attentionIds.has(x.vulnId)) ||
        Number(inYourStack(y, context.cveScan)) - Number(inYourStack(x, context.cveScan)) ||
        severityRank(x.severity) - severityRank(y.severity) ||
        Number(y.kevListed) - Number(x.kevListed) ||
        (y.epssScore ?? -1) - (x.epssScore ?? -1) ||
        (y.cvssScore ?? -1) - (x.cvssScore ?? -1) ||
        a.index - b.index
      );
    })
    .map(({ item }) => item);
