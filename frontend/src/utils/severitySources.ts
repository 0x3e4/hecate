import type { SeverityProvenance, SeveritySource } from "../types";

type Translate = (english: string, german: string) => string;

/** Who a score comes from, as a short tag next to the source name. */
export function sourceKindLabel(kind: string | null | undefined, t: Translate): string {
  switch (kind) {
    case "nvd":
      return "NVD";
    case "cna":
      return t("CNA via NVD", "CNA über NVD");
    case "euvd":
      return t("via EUVD", "über EUVD");
    case "ghsa":
      return "GHSA";
    case "osv":
      return "OSV";
    default:
      return kind ?? "";
  }
}

/** The score range the sources span on the CVSS major version they disagree on. */
export function disagreementRange(
  provenance: SeverityProvenance | null | undefined,
): { major: string; min: number; max: number; sources: string[] } | null {
  const detail = provenance?.disagreementDetail;
  if (!provenance?.disagreement || !detail) return null;
  const scores = provenance.sources
    .filter((s) => (s.version ?? "").split(".")[0] === detail.cvssMajor && s.baseScore != null)
    .map((s) => s.baseScore as number);
  if (scores.length === 0) return null;
  return { major: detail.cvssMajor, min: Math.min(...scores), max: Math.max(...scores), sources: detail.sources };
}

/** Rows for the table: the shown score first, then newest CVSS version, highest score. */
export function orderedSources(sources: SeveritySource[]): SeveritySource[] {
  return [...sources].sort((a, b) => {
    if (a.isPrimary !== b.isPrimary) return a.isPrimary ? -1 : 1;
    const va = Number.parseFloat(a.version ?? "0") || 0;
    const vb = Number.parseFloat(b.version ?? "0") || 0;
    if (va !== vb) return vb - va;
    return (b.baseScore ?? -1) - (a.baseScore ?? -1);
  });
}
