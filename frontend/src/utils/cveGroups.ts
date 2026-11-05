export const SEVERITY_ORDER = ["critical", "high", "medium", "low", "unknown"];

const SEVERITY_LABELS: Record<string, [string, string]> = {
  critical: ["Critical", "Kritisch"],
  high: ["High", "Hoch"],
  medium: ["Medium", "Mittel"],
  low: ["Low", "Niedrig"],
  unknown: ["Unknown", "Unbekannt"],
};

export const severityLabel = (severity: string, t: (english: string, german: string) => string): string => {
  const label = SEVERITY_LABELS[severity];
  return label ? t(label[0], label[1]) : severity;
};

export const severityRank = (severity: string): number => {
  const rank = SEVERITY_ORDER.indexOf(severity || "unknown");
  return rank === -1 ? SEVERITY_ORDER.length : rank;
};

export interface GroupableCve {
  vulnId: string;
  severity: string;
  vendorSlugs?: string[];
  productSlugs?: string[];
}

export interface SeverityCount {
  severity: string;
  count: number;
}

export interface CveGroup<T> {
  key: string;
  cves: T[];
  worst: string;
  tally: SeverityCount[];
}

const knownSeverity = (severity: string): string =>
  SEVERITY_ORDER.includes(severity) ? severity : "unknown";

// One CERT or vendor naming a CVE is routine; several within a week is what makes it trend.
// Community posts (Mastodon accounts, blogs) never count towards it: two people tooting is not two CERTs.
export const CERT_TRENDING_MIN = 2;

export interface AttentionCandidate {
  severity: string;
  kevListed: boolean;
  sources: { kind?: string }[];
  dateAdded: string | null;
  inventoryMatchIds?: string[];
}

/** The CERTs and vendors among an item's sources. */
export const voiceCount = (item: Pick<AttentionCandidate, "sources">): number =>
  item.sources.filter((source) => source.kind !== "community").length;

const trending = (item: AttentionCandidate): boolean =>
  item.kevListed || voiceCount(item) >= CERT_TRENDING_MIN || (item.inventoryMatchIds?.length ?? 0) > 0;

/**
 * What earns a row: a new KEV listing, several CERTs or vendors, or a version-confirmed
 * inventory hit. A scan finding alone does not: one CERT round-up names dozens of kernel
 * CVEs that every container image carries, and those are routine patching, not an alarm.
 * `stackRank` orders what is left: the higher the closer to the user's stack; community
 * posts only break ties.
 */
export const attentionRows = <T extends AttentionCandidate>(items: T[], stackRank: (item: T) => number): T[] => {
  const signals = (item: T) => voiceCount(item) + Number(item.kevListed);
  return items
    .filter(trending)
    .sort(
      (a, b) =>
        stackRank(b) - stackRank(a) ||
        signals(b) - signals(a) ||
        b.sources.length - a.sources.length ||
        severityRank(knownSeverity(a.severity)) - severityRank(knownSeverity(b.severity)) ||
        (b.dateAdded ?? "").localeCompare(a.dateAdded ?? ""),
    );
};

/** Scan findings only one CERT or vendor (or only the community) named: real, but kept out of the rows and folded per product. */
export const quietFindings = <T extends AttentionCandidate>(items: T[], isFinding: (item: T) => boolean): T[] =>
  items.filter((item) => isFinding(item) && !trending(item));

/** One product is the unit a team acts on, so a CVE without one stands alone rather than joining a vendor's other products. */
export const productKey = (cve: GroupableCve, matchedProduct?: string): string =>
  matchedProduct ?? cve.productSlugs?.[0] ?? cve.vulnId;

/**
 * Groups CVEs that need the same action: worst severity first, then `leads`
 * (inventory hits went through the version-aware matcher), then the larger group.
 */
export const groupCves = <T extends GroupableCve>(
  cves: T[],
  keyOf: (cve: T) => string,
  leads: (cve: T) => boolean = () => false,
): CveGroup<T>[] => {
  const byKey = new Map<string, T[]>();
  for (const cve of cves) {
    const key = keyOf(cve);
    byKey.set(key, [...(byKey.get(key) ?? []), cve]);
  }

  const groups = [...byKey].map(([key, members]) => {
    const sorted = [...members].sort((a, b) => severityRank(knownSeverity(a.severity)) - severityRank(knownSeverity(b.severity)));
    return {
      key,
      cves: sorted,
      worst: knownSeverity(sorted[0].severity),
      tally: SEVERITY_ORDER.map((severity) => ({
        severity,
        count: sorted.filter((cve) => knownSeverity(cve.severity) === severity).length,
      })).filter((entry) => entry.count > 0),
    };
  });

  return groups.sort(
    (a, b) =>
      severityRank(a.worst) - severityRank(b.worst) ||
      Number(b.cves.some(leads)) - Number(a.cves.some(leads)) ||
      b.cves.length - a.cves.length ||
      a.key.localeCompare(b.key),
  );
};
