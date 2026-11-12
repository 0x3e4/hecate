import { useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { LuBox, LuScanLine } from "react-icons/lu";

export interface CoverageCve {
  vulnId: string;
  vendorSlugs?: string[];
  productSlugs?: string[];
  inventoryMatchIds?: string[];
}

// The scan whose SBOM ships this product for this CVE. An OS or binary package is
// keyed by its name; a language-registry package (npm, PyPI, Maven, …) only as
// "vendor|product" for the vendors that may name it (the registry, its
// namespace, itself — backend/app/services/sbom_ecosystem.py), so npm's
// `console` does not cover Citrix NetScaler Console.
export const productScanHit = (
  vendorSlugs: readonly string[] | undefined,
  productSlug: string,
  scanProductScan: Record<string, string>,
): string | undefined => {
  if (scanProductScan[productSlug]) return scanProductScan[productSlug];
  for (const vendor of vendorSlugs ?? []) {
    const sid = scanProductScan[`${vendor}|${productSlug}`];
    if (sid) return sid;
  }
  return undefined;
};

// A highlight chip on a CVE. Inventory chips link to /inventory; scan chips link
// to the covering scan's detail page.
export interface CoverageChip {
  label: string;
  href: string;
  title?: string;
  scan?: boolean;
}

// A CVE counts as "in your environment" only when the backend's precise,
// version-aware matcher (`items_for_vuln`, same logic as the Inventory page and
// the vulnerability detail page) confirmed at least one inventory item is
// actually affected by this CVE's version range.
export const cveMatchesInventory = (cve: CoverageCve): boolean =>
  (cve.inventoryMatchIds?.length ?? 0) > 0;

// Resolve the most-recent scan covering a CVE: a finding hit on the CVE id,
// else the first SBOM-package hit on one of its product slugs. Undefined = not scanned.
export const resolveCveScanId = (
  cve: CoverageCve,
  scanCveScan: Record<string, string>,
  scanProductScan: Record<string, string>,
): string | undefined => {
  if (scanCveScan[cve.vulnId]) return scanCveScan[cve.vulnId];
  for (const p of cve.productSlugs ?? []) {
    const sid = productScanHit(cve.vendorSlugs, p, scanProductScan);
    if (sid) return sid;
  }
  return undefined;
};

// An "in scans" chip labelled with the covering scan's target name (truncated),
// linking to that scan's detail page. Falls back to a generic label.
export const scanChip = (
  sid: string,
  scanTargets: Record<string, string>,
  fallbackLabel: string,
): CoverageChip => {
  const target = scanTargets[sid];
  const label = target && target.length > 26 ? `${target.slice(0, 25)}…` : target;
  return {
    label: label || fallbackLabel,
    href: `/scans/${sid}`,
    scan: true,
    title: target || fallbackLabel,
  };
};

// Per-CVE chips (inventory and/or scan), keyed by vulnId.
export const useCveChips = (
  cves: CoverageCve[],
  scanCveScan: Record<string, string>,
  scanProductScan: Record<string, string>,
  scanTargets: Record<string, string>,
  invLabel: string,
  scanFallback: string,
) =>
  useMemo(() => {
    const map = new Map<string, CoverageChip[]>();
    const hasScan =
      Object.keys(scanCveScan).length > 0 || Object.keys(scanProductScan).length > 0;
    for (const cve of cves) {
      const chips: CoverageChip[] = [];
      if (cveMatchesInventory(cve)) {
        chips.push({ label: invLabel, href: "/inventory" });
      }
      if (hasScan) {
        const sid = resolveCveScanId(cve, scanCveScan, scanProductScan);
        if (sid) chips.push(scanChip(sid, scanTargets, scanFallback));
      }
      if (chips.length) map.set(cve.vulnId, chips);
    }
    return map;
  }, [cves, scanCveScan, scanProductScan, scanTargets, invLabel, scanFallback]);

// Chips of a group: one per place it matched, however many CVEs share it.
export const uniqueChips = (chips: CoverageChip[]): CoverageChip[] => [
  ...new Map(chips.map((chip) => [`${chip.href}|${chip.label}`, chip])).values(),
];

// Chips are navigable spans so they work inside a row that is itself a link:
// preventDefault on the chip cancels the row navigation so the chip's own link
// wins (no nested <a>).
export const ChipLinks = ({ chips }: { chips: CoverageChip[] }) => {
  const navigate = useNavigate();
  if (chips.length === 0) return null;
  return (
    <>
      {chips.map((c, i) => (
        <span
          key={`${c.scan ? "s" : "i"}-${i}`}
          className="chip chip-link coverage-chip"
          role="link"
          tabIndex={0}
          title={c.title}
          onClick={(e) => {
            e.preventDefault();
            e.stopPropagation();
            navigate(c.href);
          }}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              e.stopPropagation();
              navigate(c.href);
            }
          }}
        >
          {c.scan ? <LuScanLine aria-hidden="true" /> : <LuBox aria-hidden="true" />}
          {c.label}
        </span>
      ))}
    </>
  );
};
