/**
 * One row per vulnerability + package + version across scanners: the rows the
 * scan's Findings tab and the check report show. Moved out of ScanDetailPage
 * so both use the same merge.
 */
import type { ScanFinding } from "../types";
import { mergeScope } from "./findingFilters";
import { mergeFixState } from "./fixState";

const MERGE_SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };

/** Strip common version prefixes (go1.24.6 → 1.24.6, v1.25.5 → 1.25.5) for comparison */
export function normalizeVersion(v: string): string {
  if (v.startsWith("go")) return v.slice(2);
  if (v.startsWith("v")) return v.slice(1);
  return v;
}

/** Merged finding: same CVE + package across scanners */
export interface MergedFinding {
  key: string;
  findingIds: string[];
  vulnerabilityId: string | null;
  matchedFrom: string | null;
  packageName: string;
  packageVersion: string;
  packageType: string;
  packagePath: string | null;
  severity: string;
  title: string | null;
  description: string | null;
  fixVersion: string | null;
  fixState: string;
  advisoryFixVersions: string[];
  dataSource: string | null;
  scanners: string[];
  cvssScore: number | null;
  urls: string[];
  vexStatus: string | null;
  vexJustification: string | null;
  vexDetail: string | null;
  vexUpdatedBy: string | null;
  vexAssessedVersion: string | null;
  vexReviewDue: string | null;
  vexNeedsReview: boolean;
  vexReviewReason: string | null;
  dependencyScope: string | null;
  dismissed: boolean;
  dismissedReason: string | null;
}

/** Pick the best fix version: reject downgrades (fix major < pkg major), prefer same-major */
export function pickBestFixVersion(packageVersion: string, candidates: (string | null | undefined)[]): string | null {
  const valid = candidates.filter(Boolean) as string[];
  if (valid.length === 0) return null;
  const pkgMajor = parseInt(packageVersion.split(".")[0] ?? "0", 10);
  // Discard fix versions whose major is lower than installed — they're not valid upgrades
  const nonDowngrades = valid.filter(v => parseInt(v.split(".")[0] ?? "0", 10) >= pkgMajor);
  if (nonDowngrades.length === 0) return null;
  // Among valid upgrades, prefer same major (closest upgrade path)
  const sameMajor = nonDowngrades.filter(v => parseInt(v.split(".")[0] ?? "0", 10) === pkgMajor);
  return sameMajor[0] ?? nonDowngrades[0];
}

/** Advisory fix versions the scanner's fix value does not already state. */
export function newAdvisoryVersions(fixVersion: string | null, advisoryVersions: string[]): string[] {
  const stated = new Set((fixVersion ?? "").split(/[,\s]+/).filter(Boolean).map(normalizeVersion));
  return advisoryVersions.filter(v => !stated.has(normalizeVersion(v)));
}

export function mergeFindings(findings: ScanFinding[]): MergedFinding[] {
  type Entry = MergedFinding & { _fixCandidates: (string | null)[] };
  const map = new Map<string, Entry>();

  const mergeInto = (existing: Entry, f: ScanFinding) => {
    if (!existing.findingIds.includes(f.id)) existing.findingIds.push(f.id);
    if (!existing.scanners.includes(f.scanner)) existing.scanners.push(f.scanner);
    if (f.fixVersion) existing._fixCandidates.push(normalizeVersion(f.fixVersion));
    for (const v of f.advisoryFixVersions ?? []) {
      if (v && !existing.advisoryFixVersions.includes(v)) existing.advisoryFixVersions.push(v);
    }
    if (!existing.cvssScore && f.cvssScore) existing.cvssScore = f.cvssScore;
    if (!existing.packageType && f.packageType) existing.packageType = f.packageType;
    if (!existing.matchedFrom && f.matchedFrom) existing.matchedFrom = f.matchedFrom;
    // Promote CVE if the existing entry has none
    if (!existing.vulnerabilityId && f.vulnerabilityId) existing.vulnerabilityId = f.vulnerabilityId;
    // VEX: take first non-null
    if (!existing.vexStatus && f.vexStatus) {
      existing.vexStatus = f.vexStatus;
      existing.vexJustification = f.vexJustification ?? null;
      existing.vexDetail = f.vexDetail ?? null;
      existing.vexUpdatedBy = f.vexUpdatedBy ?? null;
      existing.vexAssessedVersion = f.vexAssessedVersion ?? null;
      existing.vexReviewDue = f.vexReviewDue ?? null;
    }
    if (f.vexStatus && f.vexNeedsReview && !existing.vexNeedsReview) {
      existing.vexNeedsReview = true;
      existing.vexReviewReason = f.vexReviewReason ?? null;
    }
    existing.dependencyScope = mergeScope(existing.dependencyScope, f.dependencyScope);
    existing.fixState = mergeFixState(existing.fixState, f.fixState);
    // Dismissed: any sub-finding dismissed → merged row counted as dismissed
    if (f.dismissed) {
      existing.dismissed = true;
      if (!existing.dismissedReason && f.dismissedReason) {
        existing.dismissedReason = f.dismissedReason;
      }
    }
  };

  for (const f of findings) {
    const ver = normalizeVersion(f.packageVersion);
    const fix = f.fixVersion ? normalizeVersion(f.fixVersion) : "";
    // Non-CVE finding types — use title + path to keep them distinct
    const nonCveType = f.packageType === "malicious-indicator" || f.packageType === "sast-finding" || f.packageType === "secret-finding";
    const keyId = nonCveType
      ? `${f.title ?? ""}:${f.packagePath ?? ""}`
      : (f.vulnerabilityId ?? "");
    const key = `${keyId}:${f.packageName}:${ver}`;

    // If this finding has no CVE, try to merge into an existing entry with a CVE
    // that shares the same package + version + fix (skip non-CVE types)
    if (!f.vulnerabilityId && fix && !nonCveType) {
      let merged = false;
      for (const entry of map.values()) {
        if (entry.packageName === f.packageName && entry.packageVersion === ver
          && entry._fixCandidates.length > 0 && entry._fixCandidates.includes(fix)) {
          mergeInto(entry, f);
          merged = true;
          break;
        }
      }
      if (merged) continue;
    }

    const existing = map.get(key);
    if (existing) {
      mergeInto(existing, f);
    } else {
      // If this finding HAS a CVE, check if there's a no-CVE entry with same pkg+ver+fix to absorb
      let absorbKey: string | null = null;
      if (f.vulnerabilityId && fix) {
        const noCveKey = `:${f.packageName}:${ver}`;
        const noCveEntry = map.get(noCveKey);
        if (noCveEntry && noCveEntry._fixCandidates.includes(fix)) {
          absorbKey = noCveKey;
        }
      }
      if (absorbKey) {
        const absorbed = map.get(absorbKey)!;
        map.delete(absorbKey);
        absorbed.key = key;
        absorbed.vulnerabilityId = f.vulnerabilityId ?? null;
        mergeInto(absorbed, f);
        map.set(key, absorbed);
      } else {
        map.set(key, {
          key,
          findingIds: [f.id],
          vulnerabilityId: f.vulnerabilityId ?? null,
          matchedFrom: f.matchedFrom ?? null,
          packageName: f.packageName,
          packageVersion: ver,
          packageType: f.packageType ?? "",
          packagePath: f.packagePath ?? null,
          severity: f.severity,
          title: f.title ?? null,
          description: f.description ?? null,
          fixVersion: f.fixVersion ?? null,
          fixState: f.fixState,
          advisoryFixVersions: [...(f.advisoryFixVersions ?? [])],
          dataSource: f.dataSource ?? null,
          scanners: [f.scanner],
          cvssScore: f.cvssScore ?? null,
          urls: f.urls ?? [],
          vexStatus: f.vexStatus ?? null,
          vexJustification: f.vexJustification ?? null,
          vexDetail: f.vexDetail ?? null,
          vexUpdatedBy: f.vexUpdatedBy ?? null,
          vexAssessedVersion: f.vexAssessedVersion ?? null,
          vexReviewDue: f.vexReviewDue ?? null,
          vexNeedsReview: !!(f.vexStatus && f.vexNeedsReview),
          vexReviewReason: f.vexStatus && f.vexNeedsReview ? f.vexReviewReason ?? null : null,
          dependencyScope: f.dependencyScope ?? null,
          dismissed: f.dismissed ?? false,
          dismissedReason: f.dismissedReason ?? null,
          _fixCandidates: f.fixVersion ? [normalizeVersion(f.fixVersion)] : [],
        });
      }
    }
  }
  const results: MergedFinding[] = Array.from(map.values()).map(({ _fixCandidates, ...f }) => ({
    ...f,
    fixVersion: pickBestFixVersion(f.packageVersion, _fixCandidates),
  }));
  results.sort((a, b) => (MERGE_SEVERITY_ORDER[a.severity] ?? 4) - (MERGE_SEVERITY_ORDER[b.severity] ?? 4));
  return results;
}
