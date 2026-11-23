/**
 * Pure helpers for the check report (/scans/check/:scanId): a scan without a
 * target, shown once and deleted after a few days.
 */
import type { SbomComponent, Scan } from "../types";
import type { MergedFinding } from "./mergeFindings";

/** Finding types that are not package vulnerabilities, with their labels. */
export const OTHER_FINDING_KINDS = ["malicious-indicator", "secret-finding", "sast-finding", "compliance-check"] as const;
export type OtherFindingKind = (typeof OTHER_FINDING_KINDS)[number];

const OTHER = new Set<string>(OTHER_FINDING_KINDS);

export const isOtherFinding = (row: Pick<MergedFinding, "packageType">): boolean => OTHER.has(row.packageType);

/** Vulnerabilities first, then the rest; both keep their order (severity first from mergeFindings). */
export function splitReportRows(rows: MergedFinding[]): { vulnerabilities: MergedFinding[]; other: MergedFinding[] } {
  const vulnerabilities: MergedFinding[] = [];
  const other: MergedFinding[] = [];
  for (const row of rows) (isOtherFinding(row) ? other : vulnerabilities).push(row);
  return { vulnerabilities, other };
}

export const SEVERITIES = ["critical", "high", "medium", "low", "negligible", "unknown"] as const;

/** Rows per severity; anything outside the scale counts as unknown. */
export function countBySeverity(rows: Pick<MergedFinding, "severity">[]): Record<(typeof SEVERITIES)[number], number> {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, negligible: 0, unknown: 0 };
  for (const row of rows) {
    const key = (row.severity ?? "").toLowerCase();
    if (key in counts) counts[key as keyof typeof counts] += 1;
    else counts.unknown += 1;
  }
  return counts;
}

export interface FacetCount {
  name: string;
  count: number;
}

/** purl type (`pkg:npm/...` → npm), else the scanner's type, else "unknown". */
export function componentEcosystem(component: Pick<SbomComponent, "purl" | "type">): string {
  const match = /^pkg:([a-z0-9.+-]+)\//i.exec(component.purl ?? "");
  if (match) return match[1].toLowerCase();
  return component.type?.trim() || "unknown";
}

const topCounts = (counts: Map<string, number>, limit: number): FacetCount[] =>
  [...counts.entries()]
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name))
    .slice(0, limit);

/** Ecosystems and licenses of the loaded components, most frequent first. */
export function sbomOverview(
  components: Pick<SbomComponent, "purl" | "type" | "licenses">[],
  limit = 8,
): { ecosystems: FacetCount[]; licenses: FacetCount[]; unlicensed: number } {
  const ecosystems = new Map<string, number>();
  const licenses = new Map<string, number>();
  let unlicensed = 0;
  for (const component of components) {
    const eco = componentEcosystem(component);
    ecosystems.set(eco, (ecosystems.get(eco) ?? 0) + 1);
    const own = [...new Set((component.licenses ?? []).map((l) => l.trim()).filter(Boolean))];
    if (own.length === 0) unlicensed += 1;
    for (const license of own) licenses.set(license, (licenses.get(license) ?? 0) + 1);
  }
  return { ecosystems: topCounts(ecosystems, limit), licenses: topCounts(licenses, limit), unlicensed };
}

export type CheckSubject = "container_image" | "source_repo" | "sbom";

/** What was checked, from what the scan document records. */
export function checkSubject(scan: Pick<Scan, "imageRef" | "source" | "scanners">): CheckSubject {
  if (scan.source === "sbom-import" || scan.scanners?.includes("sbom-import")) return "sbom";
  if (scan.imageRef) return "container_image";
  return "source_repo";
}

/** A check is still producing results. */
export const isCheckRunning = (status: Scan["status"] | undefined): boolean => status === "pending" || status === "running";
