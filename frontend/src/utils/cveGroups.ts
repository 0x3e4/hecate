export const SEVERITY_ORDER = ["critical", "high", "medium", "low", "unknown"];

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

// One CERT naming a CVE is routine; several within a week is what makes it trend.
export const CERT_TRENDING_MIN = 2;

export interface AttentionCandidate {
  kevListed: boolean;
  certs: unknown[];
  dateAdded: string | null;
}

/**
 * What the attention panel shows: anything newly KEV-listed, anything several CERTs
 * named, and anything in the user's stack. The stack leads, then the most signals,
 * then the newest listing.
 */
export const attentionRows = <T extends AttentionCandidate>(items: T[], inStack: (item: T) => boolean): T[] => {
  const signals = (item: T) => item.certs.length + Number(item.kevListed);
  return items
    .filter((item) => item.kevListed || item.certs.length >= CERT_TRENDING_MIN || inStack(item))
    .sort(
      (a, b) =>
        Number(inStack(b)) - Number(inStack(a)) ||
        signals(b) - signals(a) ||
        (b.dateAdded ?? "").localeCompare(a.dateAdded ?? ""),
    );
};

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
