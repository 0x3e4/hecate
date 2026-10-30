import "../screens/scan-detail.css";

import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { AiMarkdown } from "../components/AiMarkdown";
import {
  LuArrowLeft,
  LuArrowLeftRight,
  LuArrowRight,
  LuCheck,
  LuChevronDown,
  LuChevronUp,
  LuCircleAlert,
  LuExternalLink,
  LuList,
  LuMinus,
  LuPlus,
  LuTriangleAlert,
  LuX,
} from "react-icons/lu";

import { fetchScan, fetchScanFindings, fetchScanSbom, fetchScanLayers, fetchScans, fetchTargetHistory, compareScans, exportScanSbom, updateFindingVex, exportVex, importVex, bulkUpdateVexByIds, dismissFindings, triggerScanAiAnalysis } from "../api/scans";
import { getAiProviders } from "../api/vulnerabilities";
import type { AIProviderInfo } from "../types";
import { TriggeredByBadge } from "../ui/TriggeredByBadge";
import { TabPill } from "../ui/TabPill";
import { EmptyState, ErrorState, IconButton, PageHeader, SeverityTag, Stat, severityLevel, severityVar } from "../ui/primitives";
import { stripAiSummaryFooter } from "../utils/aiSummary";
import { cleanAdvisoryText } from "../utils/advisoryText";
import { fetchScanLicenseCompliance, fetchLicensePolicies } from "../api/licensePolicy";
import { SkeletonBlock } from "../components/Skeleton";
import { useI18n } from "../i18n/context";
import { useServerConfig } from "../server-config/context";
import { ScanFindingAttackPath } from "../components/ScanFindingAttackPath";
import { ScanAttackChainView } from "../components/ScanAttackChainView";
import { Toast, useToast } from "../components/Toast";
import { useToastContext } from "../components/ToastProvider";
import { usePersistentState } from "../hooks/usePersistentState";
import { formatDateTime } from "../utils/dateFormat";
import { getCurrentTimezone } from "../timezone/storage";
import {
  TYPE_ALIASES,
  buildDepsDevUrl,
  buildSnykUrl,
  buildRegistryUrl,
  buildSocketUrl,
  buildBundlephobiaUrl,
  buildNpmGraphUrl,
  buildAikidoUrl,
} from "../utils/sbomLinks";
import type {
  Scan,
  ScanAiAnalysis,
  ScanFinding,
  ScanSummary,
  ScanHistoryEntry,
  ScanComparisonResponse,
  ScanLayerAnalysis,
  SbomComponent,
  LicenseComplianceResult,
  ScannerBreakdownEntry,
} from "../types";

type Tab = "findings" | "sbom" | "history" | "ai-analysis" | "compare" | "alerts" | "bestpractices" | "layers" | "sast" | "secrets" | "license-compliance" | "attack-chain" | "scanner-breakdown";

/** Format bytes to human-readable string */
function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / Math.pow(1024, i);
  return `${value.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

/** Strip scanner temp directory prefix from file paths for display */
function stripScanPath(path: string | null | undefined): string {
  if (!path) return "";
  return path.replace(/^\/tmp\/hecate-(?:scan|upload)-[^/]+\//, "");
}

/** Extract domain from URL for display */
function urlDomain(url: string): string {
  try { return new URL(url).hostname.replace(/^www\./, ""); } catch { return url; }
}

/** Build a clickable source URL from image ref or target id.
 *  For source repos: links to the specific commit when commitSha is available.
 *  For container images: links to the registry-specific package page with digest when available.
 */
function buildSourceUrl(scan: Scan): string | null {
  // Source repo: use repositoryUrl or targetId (which IS the repo URL for source repos)
  if (!scan.imageRef) {
    const repoUrl = scan.repositoryUrl || scan.targetId;
    if (!repoUrl) return null;
    const base = repoUrl.startsWith("http://") || repoUrl.startsWith("https://") ? repoUrl : `https://${repoUrl}`;
    const cleanBase = base.replace(/\/$/, "");
    if (scan.commitSha) return `${cleanBase}/commit/${scan.commitSha}`;
    return cleanBase;
  }
  // Container image
  const ref = scan.imageRef;
  const digest = ref.includes("@") ? ref.split("@")[1] : null;
  const withoutDigest = ref.split("@")[0];
  const cleaned = withoutDigest.split(":")[0];
  const tag = withoutDigest.includes(":") ? withoutDigest.split(":").pop() : "latest";
  // ghcr.io: github.com package page
  if (cleaned.startsWith("ghcr.io/")) {
    const parts = cleaned.replace("ghcr.io/", "").split("/");
    const owner = parts[0];
    const pkg = parts.slice(1).join("/");
    if (owner && pkg) return `https://github.com/${owner}/pkgs/container/${pkg}`;
  }
  // Docker Hub
  if (cleaned.startsWith("docker.io/")) {
    const path = cleaned.replace("docker.io/", "");
    return `https://hub.docker.com/layers/${path}/${tag}/images${digest ? `/${digest}` : ""}`;
  }
  // Generic registry with domain
  if (cleaned.includes(".") && cleaned.includes("/")) {
    return `https://${cleaned}`;
  }
  return null;
}

/** Build a base source URL (without commit/digest specifics) for the repo/image header link */
function buildBaseSourceUrl(scan: Scan): string | null {
  if (!scan.imageRef) {
    const repoUrl = scan.repositoryUrl || scan.targetId;
    if (!repoUrl) return null;
    return repoUrl.startsWith("http://") || repoUrl.startsWith("https://") ? repoUrl.replace(/\/$/, "") : `https://${repoUrl}`;
  }
  const ref = scan.imageRef;
  const withoutDigest = ref.split("@")[0];
  const cleaned = withoutDigest.split(":")[0];
  const tag = withoutDigest.includes(":") ? withoutDigest.split(":").pop() : "latest";
  if (cleaned.startsWith("ghcr.io/")) {
    const parts = cleaned.replace("ghcr.io/", "").split("/");
    const owner = parts[0];
    const pkg = parts.slice(1).join("/");
    if (owner && pkg) return `https://github.com/${owner}/pkgs/container/${pkg}`;
  }
  if (cleaned.startsWith("docker.io/")) {
    const path = cleaned.replace("docker.io/", "");
    return `https://hub.docker.com/layers/${path}/${tag}/images`;
  }
  if (cleaned.includes(".") && cleaned.includes("/")) {
    return `https://${cleaned}`;
  }
  return null;
}

/** Extract sha256 digest from image ref (the @sha256:... part) */
function getImageDigest(imageRef: string | null | undefined): string | null {
  if (!imageRef) return null;
  const atIdx = imageRef.indexOf("@");
  return atIdx !== -1 ? imageRef.substring(atIdx + 1) : null;
}

/** Extract tag from image ref (the :tag part before any @digest) */
function getImageTag(imageRef: string | null | undefined): string | null {
  if (!imageRef) return null;
  const withoutDigest = imageRef.split("@")[0];
  const colonIdx = withoutDigest.lastIndexOf(":");
  if (colonIdx === -1) return null;
  const afterColon = withoutDigest.substring(colonIdx + 1);
  // Only treat as tag if there's a "/" before the colon (i.e. it's not a port)
  const slashIdx = withoutDigest.lastIndexOf("/");
  return slashIdx < colonIdx ? afterColon : null;
}

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };

/** Strip common version prefixes (go1.24.6 → 1.24.6, v1.25.5 → 1.25.5) for comparison */
function normalizeVersion(v: string): string {
  if (v.startsWith("go")) return v.slice(2);
  if (v.startsWith("v")) return v.slice(1);
  return v;
}

/** Merged finding: same CVE + package across scanners */
interface MergedFinding {
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
  dismissed: boolean;
  dismissedReason: string | null;
}

/** Pick the best fix version: reject downgrades (fix major < pkg major), prefer same-major */
function pickBestFixVersion(packageVersion: string, candidates: (string | null | undefined)[]): string | null {
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
function newAdvisoryVersions(fixVersion: string | null, advisoryVersions: string[]): string[] {
  const stated = new Set((fixVersion ?? "").split(/[,\s]+/).filter(Boolean).map(normalizeVersion));
  return advisoryVersions.filter(v => !stated.has(normalizeVersion(v)));
}

function mergeFindings(findings: ScanFinding[]): MergedFinding[] {
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
    }
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
  results.sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 4) - (SEVERITY_ORDER[b.severity] ?? 4));
  return results;
}

const SBOM_PAGE_SIZE = 500;

export const ScanDetailPage = () => {
  const { scanId } = useParams<{ scanId: string }>();
  const { t } = useI18n();
  const { aiEnabled } = useServerConfig();
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<ScanFinding[]>([]);
  const [findingsTotal, setFindingsTotal] = useState(0);
  const [sbomComponents, setSbomComponents] = useState<SbomComponent[]>([]);
  const [sbomTotal, setSbomTotal] = useState(0);
  const [sbomFetched, setSbomFetched] = useState(false);
  const [sbomLoadingMore, setSbomLoadingMore] = useState(false);
  const [tab, setTab] = useState<Tab>("findings");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string | undefined>();
  const [findingsSearch, setFindingsSearch] = useState("");
  const [findingsSort, setFindingsSort] = useState<{ col: string; dir: "asc" | "desc" }>({ col: "severity", dir: "asc" });
  const [sbomSearch, setSbomSearch] = useState("");
  const [sbomSort, setSbomSort] = useState<{ col: string; dir: "asc" | "desc" }>({ col: "name", dir: "asc" });
  const [sbomFilterEco, setSbomFilterEco] = useState<string | null>(null);
  const [sbomFilterLicense, setSbomFilterLicense] = useState<string | null>(null);
  const [sbomFilterType, setSbomFilterType] = useState<string | null>(null);
  const [sbomFilterProvenance, setSbomFilterProvenance] = useState<string | null>(null);
  const [sbomExporting, setSbomExporting] = useState<string | null>(null);
  const [vexExporting, setVexExporting] = useState(false);
  const { toast, showToast, dismiss } = useToast();
  // Adapter so existing setToast({type,message}) / setToast(null) call sites keep working.
  const setToast = (next: { message: string; type: "success" | "error" } | null) =>
    next ? showToast(next.message, next.type) : dismiss();

  // License compliance
  const [licenseCompliance, setLicenseCompliance] = useState<LicenseComplianceResult | null>(null);
  const [licenseComplianceLoading, setLicenseComplianceLoading] = useState(false);
  const [hasLicensePolicy, setHasLicensePolicy] = useState<boolean>(false);

  useEffect(() => {
    let cancelled = false;
    fetchLicensePolicies()
      .then(res => {
        if (!cancelled) setHasLicensePolicy((res.items?.length ?? 0) > 0);
      })
      .catch(() => {
        if (!cancelled) setHasLicensePolicy(false);
      });
    return () => { cancelled = true; };
  }, []);

  // VEX editing (single, expandable row)
  const [vexEditingId, setVexEditingId] = useState<string | null>(null);
  const [detailExpandedId, setDetailExpandedId] = useState<string | null>(null);
  const [attackPathExpandedId, setAttackPathExpandedId] = useState<string | null>(null);
  const [vexEditStatus, setVexEditStatus] = useState("");
  const [vexEditJustification, setVexEditJustification] = useState("");
  const [vexEditDetail, setVexEditDetail] = useState("");
  const [vexSaving, setVexSaving] = useState(false);

  // Multi-select bulk edit + dismiss
  const [selectedKeys, setSelectedKeys] = useState<Set<string>>(new Set());
  const [bulkVexStatus, setBulkVexStatus] = useState<string>("not_affected");
  const [bulkVexJustification, setBulkVexJustification] = useState("");
  const [bulkVexDetail, setBulkVexDetail] = useState("");
  const [bulkBusy, setBulkBusy] = useState(false);
  const [showDismissed, setShowDismissed] = usePersistentState<boolean>("hecate.scan.showDismissed", false);
  const vexImportRef = useRef<HTMLInputElement | null>(null);
  const [vexImporting, setVexImporting] = useState(false);

  // History chart state
  type HistoryRange = "7d" | "30d" | "90d" | "all";
  const [history, setHistory] = useState<ScanHistoryEntry[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyRange, setHistoryRange] = useState<HistoryRange>("30d");

  // Comparison state
  const [otherScans, setOtherScans] = useState<Scan[]>([]);
  const [compareTargetId, setCompareTargetId] = useState<string | null>(null);
  const [compareScanId, setCompareScanId] = useState<string | null>(null);
  const [comparison, setComparison] = useState<ScanComparisonResponse | null>(null);
  const [compareLoading, setCompareLoading] = useState(false);

  const merged = useMemo(() => mergeFindings(findings), [findings]);

  // Layer analysis state (Dive)
  const [layerAnalysis, setLayerAnalysis] = useState<ScanLayerAnalysis | null>(null);
  const [layerLoading, setLayerLoading] = useState(false);

  /** Separate findings by type into dedicated tabs */
  const alertFindings = useMemo(
    () => merged.filter(f => f.packageType === "malicious-indicator"),
    [merged],
  );
  const complianceFindings = useMemo(
    () => merged.filter(f => f.packageType === "compliance-check"),
    [merged],
  );
  const sastFindings = useMemo(
    () => merged.filter(f => f.packageType === "sast-finding"),
    [merged],
  );
  const sastScannerLabel = useMemo(() => {
    const names = Array.from(new Set(sastFindings.flatMap(f => f.scanners).filter(Boolean)));
    if (names.length === 0) return "SAST";
    return names.map(n => n.charAt(0).toUpperCase() + n.slice(1)).join(", ");
  }, [sastFindings]);
  const secretFindings = useMemo(
    () => merged.filter(f => f.packageType === "secret-finding"),
    [merged],
  );
  const vulnFindings = useMemo(
    () => merged.filter(f =>
      f.packageType !== "malicious-indicator" &&
      f.packageType !== "compliance-check" &&
      f.packageType !== "sast-finding" &&
      f.packageType !== "secret-finding"
    ),
    [merged],
  );

  const isContainerImage = !!scan?.imageRef;

  /** Client-side severity + search filter on vulnerability findings (excludes alerts) */
  const filteredMerged = useMemo(() => {
    let result = vulnFindings;
    if (severityFilter) result = result.filter(f => f.severity === severityFilter);
    if (findingsSearch.trim()) {
      const q = findingsSearch.trim().toLowerCase();
      result = result.filter(f =>
        (f.vulnerabilityId && f.vulnerabilityId.toLowerCase().includes(q)) ||
        f.packageName.toLowerCase().includes(q) ||
        (f.packageVersion && f.packageVersion.toLowerCase().includes(q)) ||
        f.severity.toLowerCase().includes(q) ||
        (f.fixVersion && f.fixVersion.toLowerCase().includes(q)) ||
        f.scanners.some(s => s.toLowerCase().includes(q))
      );
    }
    // Sort
    const { col, dir } = findingsSort;
    const mult = dir === "asc" ? 1 : -1;
    result = [...result].sort((a, b) => {
      if (col === "severity") return mult * ((SEVERITY_ORDER[a.severity] ?? 4) - (SEVERITY_ORDER[b.severity] ?? 4));
      if (col === "cve") return mult * (a.vulnerabilityId ?? "").localeCompare(b.vulnerabilityId ?? "");
      if (col === "package") return mult * a.packageName.localeCompare(b.packageName);
      if (col === "version") return mult * (a.packageVersion ?? "").localeCompare(b.packageVersion ?? "");
      if (col === "fix") return mult * (a.fixVersion ?? "").localeCompare(b.fixVersion ?? "");
      if (col === "scanner") return mult * a.scanners.join(",").localeCompare(b.scanners.join(","));
      return 0;
    });
    return result;
  }, [vulnFindings, severityFilter, findingsSearch, findingsSort]);

  /** Summary computed from CVE-deduplicated vulnerability findings (excludes alerts).
   *  Same CVE across multiple packages counts as 1 vulnerability (highest severity wins). */
  const mergedSummary = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, negligible: 0, unknown: 0, total: 0 };
    const sevRank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, negligible: 4, unknown: 5 };
    const seen = new Map<string, string>(); // dedup_key -> best severity
    for (const f of vulnFindings) {
      const sev = f.severity.toLowerCase();
      // CVE findings: dedup by vulnerability ID only
      // No-CVE findings: dedup by package+version
      const key = f.vulnerabilityId || `:${f.packageName}:${f.packageVersion}`;
      const prev = seen.get(key);
      if (prev === undefined || (sevRank[sev] ?? 5) < (sevRank[prev] ?? 5)) {
        seen.set(key, sev);
      }
    }
    for (const sev of seen.values()) {
      const k = sev as keyof typeof counts;
      if (k in counts && k !== "total") counts[k] = (counts[k] as number) + 1;
      else counts.unknown++;
      counts.total++;
    }
    return counts;
  }, [vulnFindings]);

  const sbomStats = useMemo(() => {
    const ecosystems: Record<string, number> = {};
    const licenses: Record<string, number> = {};
    const types: Record<string, number> = {};
    for (const c of sbomComponents) {
      // Ecosystem from PURL
      const ecoMatch = c.purl?.match(/^pkg:([^/]+)\//);
      const eco = ecoMatch ? ecoMatch[1] : "unknown";
      ecosystems[eco] = (ecosystems[eco] || 0) + 1;
      // Licenses
      for (const lic of c.licenses) {
        licenses[lic] = (licenses[lic] || 0) + 1;
      }
      // Types
      const t = c.type || "unknown";
      types[t] = (types[t] || 0) + 1;
    }
    const sortDesc = (obj: Record<string, number>) =>
      Object.entries(obj).sort((a, b) => b[1] - a[1]);
    return {
      ecosystems: sortDesc(ecosystems),
      licenses: sortDesc(licenses),
      types: sortDesc(types),
    };
  }, [sbomComponents]);

  const hasAnyProvenance = useMemo(() => sbomComponents.some(c => c.provenanceVerified != null), [sbomComponents]);
  const hasAnySupplier = useMemo(() => sbomComponents.some(c => !!c.supplier), [sbomComponents]);

  const filteredSortedSbom = useMemo(() => {
    let items = sbomComponents;
    if (sbomFilterEco) {
      items = items.filter(c => {
        const m = c.purl?.match(/^pkg:([^/]+)\//);
        return (m ? m[1] : "unknown") === sbomFilterEco;
      });
    }
    if (sbomFilterLicense) {
      items = items.filter(c => c.licenses.includes(sbomFilterLicense));
    }
    if (sbomFilterType) {
      items = items.filter(c => (c.type || "unknown") === sbomFilterType);
    }
    if (sbomFilterProvenance === "verified") {
      items = items.filter(c => c.provenanceVerified === true);
    } else if (sbomFilterProvenance === "unverified") {
      items = items.filter(c => c.provenanceVerified === false);
    } else if (sbomFilterProvenance === "unknown") {
      items = items.filter(c => c.provenanceVerified == null);
    }
    const sorted = [...items];
    const dir = sbomSort.dir === "asc" ? 1 : -1;
    sorted.sort((a, b) => {
      let av: string, bv: string;
      switch (sbomSort.col) {
        case "version": av = a.version || ""; bv = b.version || ""; break;
        case "type": av = a.type || ""; bv = b.type || ""; break;
        case "licenses": av = a.licenses[0] || ""; bv = b.licenses[0] || ""; break;
        case "provenance": {
          const pv = (v: boolean | null | undefined) => v === true ? "a" : v === false ? "b" : "c";
          av = pv(a.provenanceVerified); bv = pv(b.provenanceVerified); break;
        }
        default: av = a.name || ""; bv = b.name || "";
      }
      return av.localeCompare(bv) * dir;
    });
    return sorted;
  }, [sbomComponents, sbomSort, sbomFilterEco, sbomFilterLicense, sbomFilterType, sbomFilterProvenance]);

  const handleSbomExport = async (format: "cyclonedx-json" | "spdx-json") => {
    if (!scanId || sbomExporting) return;
    setSbomExporting(format);
    try {
      const { data, filename } = await exportScanSbom(scanId, format);
      const fallback = `sbom-${scanId}.${format === "spdx-json" ? "spdx" : "cdx"}.json`;
      const url = URL.createObjectURL(data);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = filename ?? fallback;
      document.body.appendChild(anchor);
      anchor.click();
      document.body.removeChild(anchor);
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error("SBOM export failed", err);
    } finally {
      setSbomExporting(null);
    }
  };

  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const prevStatusRef = useRef<string | null>(null);

  useEffect(() => {
    document.title = t("Hecate Cyber Defense - Scan Details", "Hecate Cyber Defense - Scan-Details");
    return () => { document.title = "Hecate Cyber Defense"; };
  }, [t]);

  const loadScanData = useCallback(async (isInitial = false) => {
    if (!scanId) return;
    if (isInitial) { setLoading(true); setError(null); }
    try {
      const data = await fetchScan(scanId);
      setScan(data);

      const wasRunning = prevStatusRef.current === "running" || prevStatusRef.current === "pending";
      const isRunning = data.status === "running" || data.status === "pending";
      const justFinished = wasRunning && !isRunning;
      prevStatusRef.current = data.status;

      // Load findings+sbom on initial load, while running (incremental results), or when just finished
      if (isInitial || isRunning || justFinished) {
        const trimmedSearch = sbomSearch.trim();
        const [findingsData, sbomData] = await Promise.all([
          fetchScanFindings(scanId, { limit: 5000, includeDismissed: showDismissed }),
          fetchScanSbom(scanId, { search: trimmedSearch || undefined, limit: SBOM_PAGE_SIZE }),
        ]);
        setFindings(findingsData.items);
        setFindingsTotal(findingsData.total);
        setSbomComponents(sbomData.items);
        setSbomTotal(sbomData.total);
        setSbomFetched(true);
      }
    } catch (err) {
      console.error("Failed to load scan", err);
      if (isInitial) setError(t("Could not load scan.", "Scan konnte nicht geladen werden."));
    } finally {
      if (isInitial) setLoading(false);
    }
  }, [scanId, sbomSearch, showDismissed, t]);

  // Initial load
  useEffect(() => {
    loadScanData(true);
  }, [scanId]);

  // Reload findings when toggling "show dismissed"
  useEffect(() => {
    if (!scanId || loading) return;
    fetchScanFindings(scanId, { limit: 5000, includeDismissed: showDismissed })
      .then(data => { setFindings(data.items); setFindingsTotal(data.total); })
      .catch(err => console.error("Failed to reload findings", err));
    // Drop selection on toggle to avoid stale IDs
    setSelectedKeys(new Set());
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [showDismissed]);

  // Auto-poll while scan is running (every 3s)
  useEffect(() => {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
    if (scan && (scan.status === "running" || scan.status === "pending")) {
      pollRef.current = setInterval(() => loadScanData(false), 3000);
    }
    return () => { if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; } };
  }, [scan?.status, loadScanData]);

  // Reload SBOM when search changes (findings are filtered client-side)
  useEffect(() => {
    if (!scanId || loading) return;
    const trimmedSearch = sbomSearch.trim();
    fetchScanSbom(scanId, { search: trimmedSearch || undefined, limit: SBOM_PAGE_SIZE }).then(data => {
      setSbomComponents(data.items);
      setSbomTotal(data.total);
      setSbomFetched(true);
    }).catch(err => console.error("Failed to load SBOM", err));
  }, [sbomSearch]);

  const handleSbomLoadMore = useCallback(async () => {
    if (!scanId || sbomLoadingMore) return;
    setSbomLoadingMore(true);
    try {
      const trimmedSearch = sbomSearch.trim();
      const data = await fetchScanSbom(scanId, {
        search: trimmedSearch || undefined,
        limit: SBOM_PAGE_SIZE,
        offset: sbomComponents.length,
      });
      setSbomComponents(prev => [...prev, ...data.items]);
      setSbomTotal(data.total);
    } catch (err) {
      console.error("Failed to load more SBOM components", err);
    } finally {
      setSbomLoadingMore(false);
    }
  }, [scanId, sbomSearch, sbomComponents.length, sbomLoadingMore]);

  // Load license compliance data on tab switch
  useEffect(() => {
    if (tab !== "license-compliance" || !scanId || licenseCompliance) return;
    setLicenseComplianceLoading(true);
    fetchScanLicenseCompliance(scanId)
      .then(setLicenseCompliance)
      .catch(err => console.error("Failed to load license compliance", err))
      .finally(() => setLicenseComplianceLoading(false));
  }, [tab, scanId]);

  if (loading) return (
    <div className="page scan-detail">
      <div className="scan-detail-skeleton">
        <SkeletonBlock height="0.75rem" width="120px" radius={4} />
        <SkeletonBlock height="1.5rem" width="40%" radius={4} />
        <div className="scan-detail-skeleton-row">
          {Array.from({ length: 4 }).map((_, i) => (
            <SkeletonBlock key={i} height="3rem" width="80px" radius={4} />
          ))}
        </div>
        <SkeletonBlock height={4} radius={4} />
      </div>
      <div className="scan-detail-skeleton">
        {Array.from({ length: 8 }).map((_, i) => (
          <SkeletonBlock key={i} height={36} radius={4} />
        ))}
      </div>
    </div>
  );
  if (error) return <div className="page scan-detail"><ErrorState title={error} /></div>;
  if (!scan) return <div className="page scan-detail"><EmptyState title={t("Scan not found.", "Scan nicht gefunden.")} /></div>;

  const sourceUrl = buildSourceUrl(scan);
  const baseSourceUrl = buildBaseSourceUrl(scan);

  const loadHistory = (range: HistoryRange) => {
    setHistoryLoading(true);
    const params: { since?: string; limit?: number } = {};
    if (range !== "all") {
      const days = range === "7d" ? 7 : range === "30d" ? 30 : 90;
      const since = new Date();
      since.setDate(since.getDate() - days);
      params.since = since.toISOString();
    }
    params.limit = 500;
    fetchTargetHistory(scan.targetId, params)
      .then(res => setHistory(res.items))
      .catch(err => console.error("Failed to load history", err))
      .finally(() => setHistoryLoading(false));
  };

  const findingSortColumns = [
    ["severity", t("Severity", "Schweregrad")],
    ["package", t("Package", "Paket")],
    ["version", t("Version", "Version")],
    ["cve", "CVE"],
    ["fix", "Fix"],
  ] as const;
  const sbomSortColumns = ([
    { col: "name", label: t("Component", "Komponente"), show: true },
    { col: "version", label: t("Version", "Version"), show: true },
    { col: "type", label: t("Type", "Typ"), show: true },
    { col: "provenance", label: t("Provenance", "Provenienz"), show: hasAnyProvenance },
    { col: "licenses", label: t("Licenses", "Lizenzen"), show: true },
  ] as const).filter(h => h.show);
  const allVisibleSelected = filteredMerged.length > 0 && filteredMerged.every(f => selectedKeys.has(f.key));
  const toggleAllVisible = (checked: boolean) =>
    setSelectedKeys(checked ? new Set(filteredMerged.map(f => f.key)) : new Set<string>());

  return (
    <div className="page scan-detail">
      <Link to="/scans" className="scan-detail-back">
        <LuArrowLeft aria-hidden="true" />
        {t("Back to Scans", "Zurück zu Scans")}
      </Link>
      <PageHeader
        title={
          <span className="scan-detail-title">
            <span>{scan.targetName || scan.targetId}</span>
            {baseSourceUrl && (
              <a
                href={baseSourceUrl}
                target="_blank"
                rel="noopener noreferrer"
                title={t("Open source", "Quelle öffnen")}
                aria-label={t("Open source", "Quelle öffnen")}
                className="scan-detail-icon-link"
              >
                <LuExternalLink aria-hidden="true" />
              </a>
            )}
          </span>
        }
      />

      <div className="scan-detail-overview">
        <SeveritySummaryBar summary={vulnFindings.length > 0 ? mergedSummary : scan.summary} />
        <dl className="scan-detail-meta">
          <MetaItem label={t("Status", "Status")}>
            <StatusBadge status={scan.status} />
          </MetaItem>
          <MetaItem label={t("Scanners", "Scanner")}>{scan.scanners.join(", ")}</MetaItem>
          {scan.startedAt && (
            <MetaItem label={t("Started", "Gestartet")}>{formatDateTime(scan.startedAt)}</MetaItem>
          )}
          {scan.durationSeconds != null && (
            <MetaItem label={t("Duration", "Dauer")}>{scan.durationSeconds.toFixed(1)}s</MetaItem>
          )}
          {scan.imageRef && (() => {
            const tag = getImageTag(scan.imageRef);
            const digest = getImageDigest(scan.imageRef);
            const baseRef = scan.imageRef.split("@")[0].split(":")[0];
            return (
              <>
                <MetaItem label={t("Image", "Image")}>
                  <span className="scan-detail-inline">
                    <span className="mono">{baseRef}{tag ? `:${tag}` : ""}</span>
                    {sourceUrl && (
                      <a
                        href={sourceUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        title={t("Open source", "Quelle öffnen")}
                        aria-label={t("Open source", "Quelle öffnen")}
                        className="scan-detail-icon-link"
                      >
                        <LuExternalLink aria-hidden="true" />
                      </a>
                    )}
                  </span>
                </MetaItem>
                {digest && (
                  <MetaItem label={t("Digest", "Digest")}>
                    <span className="mono" title={digest}>
                      {digest.length > 20 ? `${digest.substring(0, 20)}…` : digest}
                    </span>
                  </MetaItem>
                )}
              </>
            );
          })()}
          {!scan.imageRef && scan.commitSha && (
            <MetaItem label={t("Commit", "Commit")}>
              {sourceUrl ? (
                <a href={sourceUrl} target="_blank" rel="noopener noreferrer" title={scan.commitSha} className="scan-detail-link scan-detail-inline">
                  <span className="mono">{scan.commitSha.substring(0, 12)}</span>
                  <LuExternalLink aria-hidden="true" />
                </a>
              ) : (
                <span className="mono" title={scan.commitSha}>{scan.commitSha.substring(0, 12)}</span>
              )}
            </MetaItem>
          )}
          {scan.branch && <MetaItem label={t("Branch", "Branch")}><span className="mono">{scan.branch}</span></MetaItem>}
          {scan.source === "ci_cd" && <MetaItem label={t("Source", "Quelle")}>CI/CD</MetaItem>}
          {scan.source === "scheduled" && <MetaItem label={t("Source", "Quelle")}>Auto</MetaItem>}
        </dl>

        {scan.error && (
          <p className="well scan-detail-error" role="alert">
            <LuCircleAlert aria-hidden="true" />
            <span>{scan.error}</span>
          </p>
        )}
      </div>

      {/* Findings / SBOM / History / Compare tabs */}
      <div className="scan-detail-tabs">
        <TabPill active={tab === "findings"} onClick={() => setTab("findings")} count={findings.length > 0 ? vulnFindings.length : findingsTotal}>
          {t("Findings", "Ergebnisse")}
        </TabPill>
        <TabPill active={tab === "attack-chain"} onClick={() => setTab("attack-chain")}>
          {t("Attack chain", "Angriffskette")}
        </TabPill>
        <TabPill active={tab === "sbom"} onClick={() => setTab("sbom")} count={sbomFetched ? sbomTotal : (scan.sbomComponentCount ?? 0)}>
          SBOM
        </TabPill>
        <TabPill
          active={tab === "history"}
          onClick={() => {
            setTab("history");
            if (history.length === 0 && !historyLoading) {
              loadHistory(historyRange);
            }
          }}
        >
          {t("History", "Verlauf")}
        </TabPill>
        <TabPill
          active={tab === "ai-analysis"}
          onClick={() => setTab("ai-analysis")}
          count={scan.aiAnalyses && scan.aiAnalyses.length > 0 ? scan.aiAnalyses.length : null}
        >
          {t("AI analysis", "KI-Analyse")}
        </TabPill>
        <TabPill
          active={tab === "compare"}
          onClick={() => {
            setTab("compare");
            if (otherScans.length === 0 && !compareLoading) {
              fetchScans({ targetId: scan.targetId, limit: 200 }).then(res => {
                setOtherScans(res.items.filter(s => s.id !== scanId && s.status === "completed"));
                setCompareTargetId(scan.targetId);
              }).catch(err => console.error("Failed to load scans", err));
            }
          }}
        >
          {t("Compare", "Vergleichen")}
        </TabPill>
        <TabPill active={tab === "alerts"} onClick={() => setTab("alerts")} count={alertFindings.length}>
          {t("Security alerts", "Sicherheitswarnungen")}
        </TabPill>
        {isContainerImage && (
          <>
            <TabPill active={tab === "bestpractices"} onClick={() => setTab("bestpractices")} count={complianceFindings.length}>
              {t("Best practices", "Best Practices")}
            </TabPill>
            <TabPill
              active={tab === "layers"}
              onClick={() => {
                setTab("layers");
                if (!layerAnalysis && !layerLoading && scan?.layerAnalysisAvailable) {
                  setLayerLoading(true);
                  fetchScanLayers(scan.id)
                    .then(setLayerAnalysis)
                    .catch(err => console.error("Failed to load layer analysis", err))
                    .finally(() => setLayerLoading(false));
                }
              }}
            >
              {t("Layer analysis", "Schichtanalyse")}
            </TabPill>
          </>
        )}
        {sastFindings.length > 0 && (
          <TabPill active={tab === "sast"} onClick={() => setTab("sast")} count={sastFindings.length}>
            SAST
          </TabPill>
        )}
        {secretFindings.length > 0 && (
          <TabPill active={tab === "secrets"} onClick={() => setTab("secrets")} count={secretFindings.length}>
            {t("Secrets", "Secrets")}
          </TabPill>
        )}
        {sbomTotal > 0 && hasLicensePolicy && (
          <TabPill active={tab === "license-compliance"} onClick={() => setTab("license-compliance")}>
            {t("Licenses", "Lizenzen")}
          </TabPill>
        )}
        <TabPill active={tab === "scanner-breakdown"} onClick={() => setTab("scanner-breakdown")} count={scan.scanners?.length ?? 0}>
          {t("Scanner breakdown", "Scanner-Übersicht")}
        </TabPill>
      </div>

      {tab === "findings" && (
        <>
          {/* Library vulnerability bubble chart */}
          {vulnFindings.length > 0 && <BubbleChart findings={vulnFindings} />}

          {/* Search + severity filter + actions */}
          <div className="filter-row">
            <input
              type="text"
              className="scan-detail-search"
              value={findingsSearch}
              onChange={e => setFindingsSearch(e.target.value)}
              placeholder={t("Search by CVE, package, scanner...", "Nach CVE, Paket, Scanner suchen...")}
              aria-label={t("Search by CVE, package, scanner...", "Nach CVE, Paket, Scanner suchen...")}
            />
            <span className="scan-detail-count">
              {filteredMerged.length} {t("findings", "Ergebnisse")}
            </span>
          </div>
          <div className="filter-row">
            {[undefined, "critical", "high", "medium", "low"].map(sev => (
              <button
                key={sev ?? "all"}
                type="button"
                className="scan-detail-filter"
                aria-pressed={severityFilter === sev}
                onClick={() => setSeverityFilter(sev)}
              >
                {sev ? sentenceCase(sev) : t("All", "Alle")}
              </button>
            ))}
            <label className="scan-detail-toggle">
              <input
                type="checkbox"
                checked={showDismissed}
                onChange={e => setShowDismissed(e.target.checked)}
              />
              {t("Show dismissed", "Verworfene anzeigen")}
            </label>
            <input
              ref={vexImportRef}
              type="file"
              accept=".json,application/json"
              className="scan-detail-file-input"
              onChange={async e => {
                const file = e.target.files?.[0];
                e.target.value = "";
                if (!file || !scan) return;
                setVexImporting(true);
                try {
                  const text = await file.text();
                  const doc = JSON.parse(text);
                  const result = await importVex({ vexDocument: doc, targetId: scan.targetId });
                  setToast({ type: "success", message: t(
                    `VEX imported: ${result.applied} applied, ${result.skipped} skipped, ${result.notFound} not found`,
                    `VEX importiert: ${result.applied} angewendet, ${result.skipped} übersprungen, ${result.notFound} nicht gefunden`,
                  ) });
                  if (scanId) {
                    const data = await fetchScanFindings(scanId, { limit: 5000, includeDismissed: showDismissed });
                    setFindings(data.items);
                    setFindingsTotal(data.total);
                  }
                } catch (err) {
                  console.error("VEX import failed", err);
                  setToast({ type: "error", message: t("VEX import failed. Check file format.", "VEX-Import fehlgeschlagen. Dateiformat prüfen.") });
                } finally {
                  setVexImporting(false);
                }
              }}
            />
            <button
              type="button"
              className="btn"
              onClick={() => vexImportRef.current?.click()}
              disabled={vexImporting}
              title={t("Import a CycloneDX VEX document and apply to matching findings", "CycloneDX VEX-Dokument importieren und auf passende Ergebnisse anwenden")}
            >
              {vexImporting ? "..." : t("Import VEX", "VEX importieren")}
            </button>
            {/* Open all CVEs in vulnerability list */}
            {(() => {
              const cveIds = [...new Set(filteredMerged.map(f => f.vulnerabilityId).filter((v): v is string => !!v))];
              if (cveIds.length === 0) return null;
              const dql = `vuln_id:(${cveIds.join(" OR ")})`;
              return (
                <Link
                  to={`/vulnerabilities?search=${encodeURIComponent(dql)}&mode=dql`}
                  className="btn scan-detail-push"
                  title={t("Open all CVEs in vulnerability list", "Alle CVEs in Schwachstellenliste öffnen")}
                >
                  <LuList aria-hidden="true" />
                  {t("Open in vulnerability list", "In Schwachstellenliste öffnen")} ({cveIds.length})
                </Link>
              );
            })()}
          </div>

          {selectedKeys.size > 0 && (() => {
            // Collect raw finding IDs across all selected merged rows
            const selectedRows = filteredMerged.filter(f => selectedKeys.has(f.key));
            const allFindingIds = selectedRows.flatMap(f => f.findingIds);
            const anyDismissed = selectedRows.some(f => f.dismissed);
            const refetch = async () => {
              if (!scanId) return;
              const data = await fetchScanFindings(scanId, { limit: 5000, includeDismissed: showDismissed });
              setFindings(data.items);
              setFindingsTotal(data.total);
            };
            return (
              <div className="scan-detail-toolbar">
                <span className="scan-detail-toolbar-count">
                  {selectedKeys.size} {t("selected", "ausgewählt")} ({allFindingIds.length} {t("findings", "Ergebnisse")})
                </span>
                <select
                  value={bulkVexStatus}
                  onChange={e => setBulkVexStatus(e.target.value)}
                  disabled={bulkBusy}
                  aria-label={t("Status", "Status")}
                >
                  <option value="not_affected">{t("Not Affected", "Nicht betroffen")}</option>
                  <option value="affected">{t("Affected", "Betroffen")}</option>
                  <option value="fixed">{t("Fixed", "Behoben")}</option>
                  <option value="under_investigation">{t("Investigating", "In Prüfung")}</option>
                </select>
                <input
                  type="text"
                  className="scan-detail-toolbar-input"
                  value={bulkVexJustification}
                  onChange={e => setBulkVexJustification(e.target.value)}
                  placeholder={t("Justification (optional)", "Begründung (optional)")}
                  aria-label={t("Justification (optional)", "Begründung (optional)")}
                  disabled={bulkBusy}
                />
                <input
                  type="text"
                  className="scan-detail-toolbar-input"
                  value={bulkVexDetail}
                  onChange={e => setBulkVexDetail(e.target.value)}
                  placeholder={t("Detail (optional)", "Detail (optional)")}
                  aria-label={t("Detail (optional)", "Detail (optional)")}
                  disabled={bulkBusy}
                />
                <button
                  type="button"
                  className="btn-primary"
                  disabled={bulkBusy || allFindingIds.length === 0}
                  onClick={async () => {
                    setBulkBusy(true);
                    try {
                      const res = await bulkUpdateVexByIds({
                        findingIds: allFindingIds,
                        vexStatus: bulkVexStatus,
                        vexJustification: bulkVexJustification || undefined,
                        vexDetail: bulkVexDetail || undefined,
                      });
                      setToast({ type: "success", message: t(`Updated ${res.updated} findings`, `${res.updated} Ergebnisse aktualisiert`) });
                      setSelectedKeys(new Set());
                      setBulkVexJustification("");
                      setBulkVexDetail("");
                      await refetch();
                    } catch (err) {
                      console.error("Bulk VEX update failed", err);
                      setToast({ type: "error", message: t("Bulk update failed", "Bulk-Update fehlgeschlagen") });
                    } finally {
                      setBulkBusy(false);
                    }
                  }}
                >
                  {t("Apply VEX", "VEX anwenden")}
                </button>
                <button
                  type="button"
                  className="btn"
                  disabled={bulkBusy || allFindingIds.length === 0}
                  onClick={async () => {
                    setBulkBusy(true);
                    try {
                      const res = await dismissFindings({
                        findingIds: allFindingIds,
                        dismissed: !anyDismissed,
                        reason: bulkVexJustification || undefined,
                      });
                      setToast({ type: "success", message: anyDismissed
                        ? t(`Restored ${res.updated} findings`, `${res.updated} Ergebnisse wiederhergestellt`)
                        : t(`Dismissed ${res.updated} findings`, `${res.updated} Ergebnisse verworfen`) });
                      setSelectedKeys(new Set());
                      await refetch();
                    } catch (err) {
                      console.error("Dismiss failed", err);
                      setToast({ type: "error", message: t("Dismiss failed", "Verwerfen fehlgeschlagen") });
                    } finally {
                      setBulkBusy(false);
                    }
                  }}
                >
                  {anyDismissed ? t("Restore", "Wiederherstellen") : t("Dismiss", "Verwerfen")}
                </button>
                <button type="button" className="btn" onClick={() => setSelectedKeys(new Set())} disabled={bulkBusy}>
                  {t("Clear", "Leeren")}
                </button>
              </div>
            );
          })()}

          {filteredMerged.length === 0 ? (
            <EmptyState title={t("No findings.", "Keine Ergebnisse.")} />
          ) : (
            <div className="table-scroll">
              <PhoneSortBar
                id="scan-detail-sort-findings"
                columns={[...findingSortColumns, ["scanner", t("Scanner", "Scanner")]]}
                sort={findingsSort}
                onSort={setFindingsSort}
              >
                <input
                  type="checkbox"
                  checked={allVisibleSelected}
                  onChange={e => toggleAllVisible(e.target.checked)}
                  title={t("Select all visible", "Alle sichtbaren auswählen")}
                  aria-label={t("Select all visible", "Alle sichtbaren auswählen")}
                />
              </PhoneSortBar>
              <table className="scan-detail-table scan-detail-stack">
                <thead>
                  <tr>
                    <th className="scan-detail-cell-check">
                      <input
                        type="checkbox"
                        checked={allVisibleSelected}
                        onChange={e => toggleAllVisible(e.target.checked)}
                        title={t("Select all visible", "Alle sichtbaren auswählen")}
                        aria-label={t("Select all visible", "Alle sichtbaren auswählen")}
                      />
                    </th>
                    {findingSortColumns.map(([col, label]) => (
                      <SortHeader
                        key={col}
                        label={label}
                        active={findingsSort.col === col}
                        dir={findingsSort.dir}
                        onClick={() => setFindingsSort(prev => prev.col === col ? { col, dir: prev.dir === "asc" ? "desc" : "asc" } : { col, dir: "asc" })}
                      />
                    ))}
                    <th>VEX</th>
                    <SortHeader
                      label={t("Scanner", "Scanner")}
                      active={findingsSort.col === "scanner"}
                      dir={findingsSort.dir}
                      onClick={() => setFindingsSort(prev => prev.col === "scanner" ? { col: "scanner", dir: prev.dir === "asc" ? "desc" : "asc" } : { col: "scanner", dir: "asc" })}
                    />
                  </tr>
                </thead>
                <tbody>
                  {filteredMerged.map(f => {
                    const isSelected = selectedKeys.has(f.key);
                    const isVexExpanded = vexEditingId === f.key;
                    const isDetailExpanded = detailExpandedId === f.key;
                    const advisoryExtras = newAdvisoryVersions(f.fixVersion, f.advisoryFixVersions);
                    const rowClass = [
                      "scan-detail-finding",
                      f.dismissed ? "scan-detail-finding--dismissed" : "",
                      isSelected ? "scan-detail-finding--selected" : "",
                    ].filter(Boolean).join(" ");
                    return (
                      <Fragment key={f.key}>
                      <tr className={rowClass}>
                        <td className="scan-detail-cell-check">
                          <input
                            type="checkbox"
                            checked={isSelected}
                            aria-label={f.vulnerabilityId ?? f.packageName}
                            onChange={e => {
                              setSelectedKeys(prev => {
                                const next = new Set(prev);
                                if (e.target.checked) next.add(f.key); else next.delete(f.key);
                                return next;
                              });
                            }}
                          />
                        </td>
                        <td className="scan-detail-cell-sev"><SeverityWord severity={f.severity} /></td>
                        <td className="scan-detail-cell-name">
                          <button
                            type="button"
                            className="scan-detail-link-button"
                            aria-expanded={isDetailExpanded}
                            onClick={() => setDetailExpandedId(prev => prev === f.key ? null : f.key)}
                            title={t("Click to show details", "Klicken für Details")}
                          >
                            {f.packageName}
                          </button>
                        </td>
                        <td className="scan-detail-cell-version" data-label={t("Version", "Version")}>
                          {f.packageVersion ? <span className="mono">{f.packageVersion}</span> : <NotAvailable />}
                        </td>
                        <td className="scan-detail-cell-id">
                          <span className="scan-detail-inline">
                            {f.dismissed && (
                              <span className="tag" title={f.dismissedReason || t("Dismissed", "Verworfen")}>
                                {t("dismissed", "verworfen")}
                              </span>
                            )}
                            {f.vulnerabilityId ? (
                              <>
                                <Link to={`/vulnerability/${f.vulnerabilityId}`} className="scan-detail-link mono">
                                  {f.vulnerabilityId}
                                </Link>
                                {f.matchedFrom && (
                                  <span className="chip" title={t("Auto-matched from local DB", "Automatisch aus lokaler DB zugeordnet")}>
                                    auto
                                  </span>
                                )}
                              </>
                            ) : (
                              <NotAvailable />
                            )}
                          </span>
                        </td>
                        <td className="scan-detail-cell-fix" data-label="Fix">
                          <div className="scan-detail-fix">
                            {f.fixVersion ? (
                              <span className="mono">{f.fixVersion}</span>
                            ) : advisoryExtras.length === 0 ? (
                              f.fixState === "not_fixed" ? <span className="muted">{t("No fix", "Kein Fix")}</span> : <NotAvailable />
                            ) : null}
                            {advisoryExtras.length > 0 && (
                              <span
                                className="chip"
                                title={t(
                                  `Unaffected/patched per advisory: ${f.advisoryFixVersions.join(", ")}`,
                                  `Nicht betroffen/gepatcht laut Advisory: ${f.advisoryFixVersions.join(", ")}`,
                                )}
                              >
                                {t("adv", "adv")}:&nbsp;
                                <span className="mono">{advisoryExtras.slice(0, 2).join(", ")}</span>
                                {advisoryExtras.length > 2 ? ` +${advisoryExtras.length - 2}` : ""}
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="scan-detail-cell-vex" data-label="VEX">
                          <button
                            type="button"
                            className="scan-detail-vex-toggle"
                            aria-expanded={isVexExpanded}
                            aria-label={f.vexStatus ? undefined : t("Click to set VEX status", "Klicken um VEX-Status zu setzen")}
                            onClick={() => {
                              if (vexEditingId === f.key) {
                                setVexEditingId(null);
                              } else {
                                setVexEditingId(f.key);
                                setVexEditStatus(f.vexStatus || "");
                                setVexEditJustification(f.vexJustification || "");
                                setVexEditDetail(f.vexDetail || "");
                              }
                            }}
                            title={f.vexJustification || t("Click to set VEX status", "Klicken um VEX-Status zu setzen")}
                          >
                            {f.vexStatus ? <span className="chip">{vexStatusLabel(f.vexStatus, t)}</span> : null}
                            {isVexExpanded ? <LuChevronUp aria-hidden="true" /> : <LuChevronDown aria-hidden="true" />}
                          </button>
                        </td>
                        <td className="scan-detail-cell-scanner" data-label={t("Scanner", "Scanner")}>{f.scanners.join(", ")}</td>
                      </tr>
                      {isDetailExpanded && (
                        <tr className="scan-detail-expansion">
                          <td colSpan={FINDING_COLUMNS}>
                            <dl className="scan-detail-facts">
                              {f.packagePath && (
                                <>
                                  <dt>{t("Source", "Quelle")}</dt>
                                  <dd className="mono">{stripScanPath(f.packagePath)}</dd>
                                </>
                              )}
                              {f.packageType && (
                                <>
                                  <dt>{t("Type", "Typ")}</dt>
                                  <dd>{TYPE_ALIASES[f.packageType] || f.packageType}</dd>
                                </>
                              )}
                              {f.cvssScore != null && (
                                <>
                                  <dt>CVSS</dt>
                                  <dd>{f.cvssScore.toFixed(1)}</dd>
                                </>
                              )}
                              {f.dataSource && (
                                <>
                                  <dt>{t("Data Source", "Datenquelle")}</dt>
                                  <dd>{f.dataSource}</dd>
                                </>
                              )}
                              {f.title && (
                                <>
                                  <dt>{t("Title", "Titel")}</dt>
                                  <dd>{f.title}</dd>
                                </>
                              )}
                              {f.urls.length > 0 && (
                                <>
                                  <dt>{t("References", "Referenzen")}</dt>
                                  <dd className="link-list">
                                    {f.urls.slice(0, 5).map((url, i) => (
                                      <a key={i} href={url} target="_blank" rel="noopener noreferrer">
                                        {urlDomain(url)}
                                      </a>
                                    ))}
                                    {f.urls.length > 5 && <span className="muted">+{f.urls.length - 5}</span>}
                                  </dd>
                                </>
                              )}
                              <dt>{t("Links", "Links")}</dt>
                              <dd><PackageLinks name={f.packageName} version={f.packageVersion} type={f.packageType} fallback={<NotAvailable />} /></dd>
                            </dl>
                            {f.vulnerabilityId && (
                              <button
                                type="button"
                                className="btn scan-detail-expansion-action"
                                onClick={() =>
                                  setAttackPathExpandedId(prev => prev === f.key ? null : f.key)
                                }
                              >
                                {attackPathExpandedId === f.key
                                  ? t("Hide attack path", "Angriffspfad ausblenden")
                                  : t("Show attack path", "Angriffspfad anzeigen")}
                              </button>
                            )}
                          </td>
                        </tr>
                      )}
                      {attackPathExpandedId === f.key && f.vulnerabilityId && (
                        <tr className="scan-detail-expansion">
                          <td colSpan={FINDING_COLUMNS}>
                            <ScanFindingAttackPath
                              vulnerabilityId={f.vulnerabilityId}
                              scanId={scanId}
                              targetId={scan?.targetId}
                              packageName={f.packageName}
                              packageVersion={f.packageVersion}
                              aiEnabled={aiEnabled}
                            />
                          </td>
                        </tr>
                      )}
                      {isVexExpanded && (
                        <tr className="scan-detail-expansion">
                          <td colSpan={FINDING_COLUMNS}>
                            <div className="scan-detail-vex-form">
                              <p className="scan-detail-form-title">
                                {t("Edit VEX annotation", "VEX-Annotation bearbeiten")}
                              </p>
                              <label htmlFor="scan-detail-vex-status">{t("Status", "Status")}</label>
                              <select id="scan-detail-vex-status" value={vexEditStatus} onChange={e => setVexEditStatus(e.target.value)}>
                                <option value="">{t("Clear", "Löschen")}</option>
                                <option value="not_affected">{t("Not Affected", "Nicht betroffen")}</option>
                                <option value="affected">{t("Affected", "Betroffen")}</option>
                                <option value="fixed">{t("Fixed", "Behoben")}</option>
                                <option value="under_investigation">{t("Investigating", "In Prüfung")}</option>
                              </select>
                              <label htmlFor="scan-detail-vex-justification">{t("Justification", "Begründung")}</label>
                              <input
                                id="scan-detail-vex-justification"
                                type="text"
                                value={vexEditJustification}
                                onChange={e => setVexEditJustification(e.target.value)}
                                placeholder={t("Short reason (e.g. code_not_reachable)", "Kurze Begründung (z.B. code_not_reachable)")}
                              />
                              <label htmlFor="scan-detail-vex-detail">{t("Detail", "Detail")}</label>
                              <textarea
                                id="scan-detail-vex-detail"
                                value={vexEditDetail}
                                onChange={e => setVexEditDetail(e.target.value)}
                                rows={3}
                                placeholder={t("Longer explanation (optional)", "Längere Erläuterung (optional)")}
                              />
                              <div className="scan-detail-form-actions">
                                <button type="button" className="btn" disabled={vexSaving} onClick={async () => {
                                  setVexSaving(true);
                                  try {
                                    // Update every raw finding (multi-scanner duplicates) so the merged view is consistent
                                    await Promise.all(f.findingIds.map(fid => updateFindingVex(fid, {
                                      vexStatus: vexEditStatus || null,
                                      vexJustification: vexEditJustification || undefined,
                                      vexDetail: vexEditDetail || undefined,
                                    })));
                                    setVexEditingId(null);
                                    if (scanId) {
                                      const data = await fetchScanFindings(scanId, { limit: 5000, includeDismissed: showDismissed });
                                      setFindings(data.items);
                                      setFindingsTotal(data.total);
                                    }
                                  } catch (err) {
                                    console.error("VEX save failed", err);
                                    setToast({ type: "error", message: t("VEX save failed", "VEX-Speichern fehlgeschlagen") });
                                  } finally {
                                    setVexSaving(false);
                                  }
                                }}>
                                  {vexSaving ? "..." : t("Save", "Speichern")}
                                </button>
                                <button type="button" className="btn" onClick={() => setVexEditingId(null)} disabled={vexSaving}>
                                  {t("Cancel", "Abbrechen")}
                                </button>
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                      </Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}

      {tab === "sbom" && (
        <>
          <div className="filter-row">
            <input
              type="text"
              className="scan-detail-search"
              value={sbomSearch}
              onChange={e => setSbomSearch(e.target.value)}
              placeholder={t("Search by name, type, license, purl...", "Nach Name, Typ, Lizenz, PURL suchen...")}
              aria-label={t("Search by name, type, license, purl...", "Nach Name, Typ, Lizenz, PURL suchen...")}
            />
            {hasAnyProvenance && (
              <select
                value={sbomFilterProvenance || ""}
                onChange={e => setSbomFilterProvenance(e.target.value || null)}
                aria-label={t("All Provenance", "Alle Provenienz")}
              >
                <option value="">{t("All Provenance", "Alle Provenienz")}</option>
                <option value="verified">{t("Verified", "Verifiziert")}</option>
                <option value="unverified">{t("Unverified", "Nicht verifiziert")}</option>
                <option value="unknown">{t("Unknown", "Unbekannt")}</option>
              </select>
            )}
            <span className="scan-detail-count">
              {filteredSortedSbom.length !== sbomComponents.length
                ? `${filteredSortedSbom.length} / ${sbomComponents.length}`
                : sbomComponents.length}
              {sbomComponents.length < sbomTotal ? ` / ${sbomTotal}` : ""}{" "}
              {t("components", "Komponenten")}
            </span>
            <div className="scan-detail-actions scan-detail-push">
              <button
                type="button"
                className="btn"
                onClick={() => void handleSbomExport("cyclonedx-json")}
                disabled={!!sbomExporting || sbomComponents.length === 0}
              >
                {sbomExporting === "cyclonedx-json" ? "..." : "CycloneDX"}
              </button>
              <button
                type="button"
                className="btn"
                onClick={() => void handleSbomExport("spdx-json")}
                disabled={!!sbomExporting || sbomComponents.length === 0}
              >
                {sbomExporting === "spdx-json" ? "..." : "SPDX"}
              </button>
              <button
                type="button"
                className="btn"
                onClick={async () => {
                  if (!scanId || vexExporting) return;
                  setVexExporting(true);
                  try {
                    const blob = await exportVex(scanId);
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement("a");
                    a.href = url;
                    a.download = `vex-${scanId}.cdx.json`;
                    a.click();
                    URL.revokeObjectURL(url);
                  } catch {
                    setToast({ type: "error", message: t("No VEX data available. Set VEX statuses on findings first.", "Keine VEX-Daten vorhanden. Setzen Sie zuerst VEX-Status bei den Findings.") });
                  } finally {
                    setVexExporting(false);
                  }
                }}
                disabled={vexExporting}
              >
                {vexExporting ? "..." : "VEX"}
              </button>
            </div>
          </div>

          {sbomComponents.length > 0 && (
            <div className="scan-detail-facets">
              {([
                { title: t("Ecosystems", "Ökosysteme"), data: sbomStats.ecosystems, filterKey: "eco" as const, activeFilter: sbomFilterEco },
                { title: t("Licenses", "Lizenzen"), data: sbomStats.licenses, filterKey: "license" as const, activeFilter: sbomFilterLicense },
                { title: t("Types", "Typen"), data: sbomStats.types, filterKey: "type" as const, activeFilter: sbomFilterType },
              ] as const).map(card => (
                <div key={card.title} className="scan-detail-facet">
                  <p className="scan-detail-facet-title">{card.title}</p>
                  <div className="scan-detail-facet-values">
                    {card.data.slice(0, 5).map(([name, count]) => {
                      const isActive = card.activeFilter === name;
                      return (
                        <button
                          key={name}
                          type="button"
                          className="scan-detail-facet-value"
                          aria-pressed={isActive}
                          onClick={() => {
                            if (card.filterKey === "eco") setSbomFilterEco(isActive ? null : name);
                            else if (card.filterKey === "license") setSbomFilterLicense(isActive ? null : name);
                            else setSbomFilterType(isActive ? null : name);
                          }}
                        >
                          <span className="scan-detail-facet-name">{name}</span>
                          <span className="scan-detail-facet-count">{count}</span>
                        </button>
                      );
                    })}
                    {card.data.length > 5 && (
                      <span className="scan-detail-count">
                        +{card.data.length - 5} {t("more", "weitere")}
                      </span>
                    )}
                    {card.data.length === 0 && <NotAvailable />}
                    {card.activeFilter && (
                      <IconButton
                        label={t("Clear", "Leeren")}
                        onClick={() => {
                          if (card.filterKey === "eco") setSbomFilterEco(null);
                          else if (card.filterKey === "license") setSbomFilterLicense(null);
                          else setSbomFilterType(null);
                        }}
                      >
                        <LuX aria-hidden="true" />
                      </IconButton>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}

          {sbomComponents.length === 0 ? (
            <EmptyState title={t("No SBOM components.", "Keine SBOM-Komponenten.")} />
          ) : (
            <>
              <div className="table-scroll">
                <PhoneSortBar
                  id="scan-detail-sort-sbom"
                  columns={sbomSortColumns.map(h => [h.col, h.label] as const)}
                  sort={sbomSort}
                  onSort={setSbomSort}
                />
                <table className="scan-detail-table scan-detail-stack">
                  <thead>
                    <tr>
                      {sbomSortColumns.map(h => (
                        <SortHeader
                          key={h.col}
                          label={h.label}
                          active={sbomSort.col === h.col}
                          dir={sbomSort.dir}
                          onClick={() => setSbomSort(prev => ({ col: h.col, dir: prev.col === h.col && prev.dir === "asc" ? "desc" : "asc" }))}
                        />
                      ))}
                      {hasAnySupplier && <th>{t("Supplier", "Lieferant")}</th>}
                      <th>{t("Links", "Links")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredSortedSbom.map(c => (
                      <tr key={c.id}>
                        <td className="scan-detail-cell-full">
                          <div>{c.name}</div>
                          {c.purl && <div className="scan-detail-purl mono">{c.purl}</div>}
                        </td>
                        <td data-label={t("Version", "Version")}>{c.version ? <span className="mono">{c.version}</span> : <NotAvailable />}</td>
                        <td data-label={t("Type", "Typ")}>{c.type ? <span className="chip">{c.type}</span> : <NotAvailable />}</td>
                        {hasAnyProvenance && (
                          <td data-label={t("Provenance", "Provenienz")}>
                            {c.provenanceVerified === true ? (
                              <span
                                className="scan-detail-inline scan-detail-outcome--ok scan-detail-help"
                                title={[
                                  c.provenanceAttestationType && `Attestation: ${c.provenanceAttestationType}`,
                                  c.provenanceBuildSystem && `Build: ${c.provenanceBuildSystem}`,
                                  c.provenanceSourceRepo && `Source: ${c.provenanceSourceRepo}`,
                                ].filter(Boolean).join("\n") || t("Provenance verified", "Provenienz verifiziert")}
                              >
                                <LuCheck aria-hidden="true" />
                                {c.provenanceAttestationType || t("Verified", "Verifiziert")}
                              </span>
                            ) : c.provenanceVerified === false ? (
                              <span className="scan-detail-inline muted" title={t("No provenance attestation found", "Keine Provenienz-Attestierung gefunden")}>
                                <LuTriangleAlert aria-hidden="true" />
                                {t("Unverified", "Nicht verifiziert")}
                              </span>
                            ) : null}
                          </td>
                        )}
                        <td data-label={t("Licenses", "Lizenzen")}>
                          {c.licenses.length > 0 ? (
                            <span className="scan-detail-chips">
                              {c.licenses.map((lic, i) => <span key={i} className="chip">{lic}</span>)}
                            </span>
                          ) : null}
                        </td>
                        {hasAnySupplier && (
                          <td className="muted" data-label={t("Supplier", "Lieferant")}>{c.supplier}</td>
                        )}
                        <td className="scan-detail-cell-full">
                          <PackageLinks name={c.name} version={c.version} type={c.type} purl={c.purl} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {sbomComponents.length < sbomTotal && (
                <div className="scan-detail-more">
                  <button
                    type="button"
                    className="btn"
                    onClick={() => void handleSbomLoadMore()}
                    disabled={sbomLoadingMore}
                  >
                    {sbomLoadingMore
                      ? t("Loading...", "Lädt...")
                      : t(
                          `Load more (${sbomComponents.length} / ${sbomTotal})`,
                          `Mehr laden (${sbomComponents.length} / ${sbomTotal})`,
                        )}
                  </button>
                </div>
              )}
            </>
          )}
        </>
      )}

      {/* History tab */}
      {tab === "history" && (
        <>
          <div className="filter-row">
            {(["7d", "30d", "90d", "all"] as HistoryRange[]).map(range => (
              <button
                key={range}
                type="button"
                className="scan-detail-filter"
                aria-pressed={historyRange === range}
                onClick={() => { setHistoryRange(range); loadHistory(range); }}
              >
                {range === "all" ? t("All", "Alle") : range}
              </button>
            ))}
            <span className="scan-detail-count scan-detail-push">
              {history.length} {t("scans", "Scans")}
            </span>
          </div>
          {historyLoading ? (
            <div className="scan-detail-skeleton">
              {Array.from({ length: 4 }).map((_, i) => (
                <SkeletonBlock key={i} height={40} radius={4} />
              ))}
            </div>
          ) : history.length < 2 ? (
            <EmptyState title={t("Not enough scan history for a chart. Run more scans.", "Nicht genügend Scan-Verlauf für ein Diagramm. Führen Sie weitere Scans durch.")} />
          ) : (
            <>
              <HistoryChart history={history} />
              <HistoryChangesTable history={history} targetId={scan.targetId} />
            </>
          )}
        </>
      )}

      {/* Attack Chain tab */}
      {tab === "attack-chain" && scanId && (
        <ScanAttackChainView
          scanId={scanId}
          aiEnabled={aiEnabled}
          onPersistedNarrativeChange={() => {
            fetchScan(scanId).then(setScan).catch(() => {});
          }}
        />
      )}

      {/* AI Analysis tab */}
      {tab === "ai-analysis" && (
        <ScanAiAnalysisTab scan={scan} onRefresh={() => {
          if (!scanId) return;
          fetchScan(scanId).then(setScan).catch(() => {});
        }} />
      )}

      {/* Compare tab */}
      {tab === "compare" && (
        <>
          <div className="filter-row">
            <label htmlFor="scan-detail-compare" className="scan-detail-count">
              {t("Compare with:", "Vergleichen mit:")}
            </label>
            <select
              id="scan-detail-compare"
              value={compareScanId || ""}
              onChange={async (e) => {
                const selected = e.target.value || null;
                setCompareScanId(selected);
                setComparison(null);
                if (!selected || !scanId) return;
                setCompareLoading(true);
                try {
                  const result = await compareScans(selected, scanId);
                  setComparison(result);
                } catch (err) {
                  console.error("Compare failed", err);
                } finally {
                  setCompareLoading(false);
                }
              }}
            >
              <option value="">{t("Select a scan...", "Scan auswählen...")}</option>
              {otherScans.map(s => (
                <option key={s.id} value={s.id}>
                  {formatDateTime(s.startedAt)}: {s.summary.total} findings
                </option>
              ))}
            </select>
            {compareLoading && <span className="scan-detail-count">{t("Comparing...", "Vergleiche...")}</span>}
          </div>

          {comparison && <ComparisonView comparison={comparison} />}
          {!comparison && !compareScanId && !compareLoading && (
            <EmptyState title={t("Select another scan of this target to compare.", "Wählen Sie einen anderen Scan dieses Ziels zum Vergleich.")} />
          )}
        </>
      )}

      {tab === "bestpractices" && (
        <>
          {complianceFindings.length === 0 ? (
            <EmptyState title={t("All CIS Docker Benchmark checks passed.", "Alle CIS-Docker-Benchmark-Checks bestanden.")} />
          ) : (
            <>
              <ItemsSummary
                title={t(
                  `${complianceFindings.length} compliance issue${complianceFindings.length !== 1 ? "s" : ""} found`,
                  `${complianceFindings.length} Compliance-Problem${complianceFindings.length !== 1 ? "e" : ""} gefunden`,
                )}
              >
                <SeverityCounts items={complianceFindings} />
              </ItemsSummary>

              {/* Compliance items */}
              <div className="scan-detail-items">
                {complianceFindings.map((check, idx) => {
                  const category = check.dataSource?.includes("cis") ? "CIS" : "DKL";
                  const alerts = (check.description || "").split("\n").filter(Boolean);

                  return (
                    <article key={idx} className="scan-detail-item">
                      <div className="scan-detail-item-head">
                        <SeverityWord severity={check.severity} />
                        <h3>{check.title}</h3>
                        <span className="chip">{category}</span>
                      </div>

                      {/* Alert messages as bullet list */}
                      {alerts.length > 0 && (
                        <ul className="scan-detail-item-list">
                          {alerts.map((msg, i) => <li key={i}>{msg}</li>)}
                        </ul>
                      )}
                    </article>
                  );
                })}
              </div>
            </>
          )}
        </>
      )}

      {tab === "layers" && (
        <>
          {layerLoading ? (
            <SkeletonBlock height={160} radius={4} />
          ) : !scan?.layerAnalysisAvailable ? (
            <EmptyState
              title={t(
                "No layer analysis available. Run a scan with Dive enabled to see layer data.",
                "Keine Schichtanalyse verfügbar. Führen Sie einen Scan mit aktiviertem Dive durch.",
              )}
            />
          ) : layerAnalysis ? (
            <>
              {/* Efficiency & Waste summary */}
              <div className="scan-detail-layer-summary">
                <dl className="stat-row">
                  <Stat
                    label={t("Image Efficiency", "Image-Effizienz")}
                    value={(
                      <>
                        {(layerAnalysis.efficiency * 100).toFixed(1)}%
                        <span className="scan-detail-meter" aria-hidden="true">
                          <span style={{ width: `${Math.min(layerAnalysis.efficiency * 100, 100)}%` }} />
                        </span>
                      </>
                    )}
                  />
                  <Stat
                    label={t("Wasted Space", "Verschwendeter Speicher")}
                    value={(
                      <>
                        {formatBytes(layerAnalysis.wastedBytes)}
                        <span className="scan-detail-stat-note">
                          {(layerAnalysis.userWastedPercent * 100).toFixed(1)}% {t("of total", "vom Gesamten")}
                        </span>
                      </>
                    )}
                  />
                  <Stat
                    label={t("Total Image Size", "Gesamte Image-Größe")}
                    value={(
                      <>
                        {formatBytes(layerAnalysis.totalImageSize)}
                        <span className="scan-detail-stat-note">
                          {layerAnalysis.layers.length} {t("layers", "Schichten")}
                        </span>
                      </>
                    )}
                  />
                </dl>
                <span className={`scan-detail-verdict scan-detail-outcome--${layerAnalysis.passThreshold ? "ok" : "error"}`}>
                  {layerAnalysis.passThreshold ? t("Pass", "OK") : t("Fail", "Fehler")}
                </span>
              </div>

              {/* Layer table */}
              <div className="table-scroll">
                <table className="scan-detail-table scan-detail-pin">
                  <thead>
                    <tr>
                      <th>#</th>
                      <th>{t("Command", "Befehl")}</th>
                      <th className="scan-detail-num">{t("Size", "Größe")}</th>
                      <th className="scan-detail-num">%</th>
                    </tr>
                  </thead>
                  <tbody>
                    {layerAnalysis.layers.map((layer) => {
                      const pct = layerAnalysis.totalImageSize > 0
                        ? (layer.sizeBytes / layerAnalysis.totalImageSize) * 100
                        : 0;
                      return (
                        <tr key={layer.index}>
                          <td className="muted">{layer.index + 1}</td>
                          <td className="scan-detail-layer-command mono" title={layer.command}>
                            {layer.command || layer.digest.substring(0, 12)}
                          </td>
                          <td className="scan-detail-num">{formatBytes(layer.sizeBytes)}</td>
                          <td className="scan-detail-num">
                            <span className="scan-detail-layer-share">
                              <span className="scan-detail-meter" aria-hidden="true">
                                <span style={{ width: `${Math.min(pct, 100)}%` }} />
                              </span>
                              <span className="muted">{pct.toFixed(1)}%</span>
                            </span>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </>
          ) : null}
        </>
      )}

      {tab === "alerts" && (
        <>
          {alertFindings.length === 0 ? (
            <EmptyState title={t("No malicious package indicators detected.", "Keine Hinweise auf bösartige Pakete erkannt.")} />
          ) : (
            <>
              <ItemsSummary
                title={t(
                  `${alertFindings.length} security alert${alertFindings.length !== 1 ? "s" : ""} detected`,
                  `${alertFindings.length} Sicherheitswarnung${alertFindings.length !== 1 ? "en" : ""} erkannt`,
                )}
              >
                {(() => {
                  const cats: Record<string, number> = {};
                  for (const f of alertFindings) {
                    const cat = f.dataSource?.replace("hecate-malware-detector:", "") || "unknown";
                    cats[cat] = (cats[cat] || 0) + 1;
                  }
                  return Object.entries(cats).map(([cat, count]) => (
                    <span key={cat} className="chip">{count} {cat.replace(/_/g, " ")}</span>
                  ));
                })()}
              </ItemsSummary>

              {/* Alert items */}
              <div className="scan-detail-items">
                {alertFindings.map((alert, idx) => {
                  const category = alert.dataSource?.replace("hecate-malware-detector:", "") || "";
                  // Split description into main text and evidence
                  const descParts = (alert.description || "").split("\n\nEvidence: ");
                  const mainDesc = cleanAdvisoryText(descParts[0]);
                  const evidenceAndConf = descParts[1] || "";
                  const evidenceParts = evidenceAndConf.split("\nConfidence: ");
                  const evidence = evidenceParts[0] || "";
                  const confidence = evidenceParts[1] || "medium";

                  return (
                    <article key={idx} className="scan-detail-item">
                      {/* Title with severity */}
                      <div className="scan-detail-item-head">
                        <SeverityWord severity={alert.severity} />
                        <h3>{alert.title}</h3>
                        <span className="scan-detail-chips">
                          {category && <span className="chip">{category.replace(/_/g, " ")}</span>}
                          <span className="chip">{confidence} {t("confidence", "Konfidenz")}</span>
                        </span>
                      </div>

                      {/* Package info */}
                      <p className="scan-detail-item-package">
                        <span>{alert.packageName}</span>
                        {alert.packageVersion && <span className="mono">@ {alert.packageVersion}</span>}
                        {alert.packagePath && <span className="mono muted">{alert.packagePath}</span>}
                      </p>

                      {/* Description */}
                      {mainDesc && <p className="scan-detail-item-text">{mainDesc}</p>}

                      {/* Evidence block */}
                      {evidence && <pre className="scan-detail-code">{evidence}</pre>}
                    </article>
                  );
                })}
              </div>
            </>
          )}
        </>
      )}

      {tab === "sast" && (
        <>
          {sastFindings.length === 0 ? (
            <EmptyState title={t("No SAST findings.", "Keine SAST-Ergebnisse.")} />
          ) : (
            <>
              <ItemsSummary
                title={t(
                  `${sastFindings.length} code issue${sastFindings.length !== 1 ? "s" : ""} found by ${sastScannerLabel}`,
                  `${sastFindings.length} Code-Problem${sastFindings.length !== 1 ? "e" : ""} von ${sastScannerLabel} gefunden`,
                )}
              >
                <SeverityCounts items={sastFindings} />
              </ItemsSummary>

              {/* SAST items */}
              <div className="scan-detail-items">
                {sastFindings.map((finding, idx) => {
                  const ruleId = finding.packageName || "";
                  // Parse structured sections from description
                  const desc = finding.description || "";
                  const codeSplit = desc.split("\n\nCode:\n");
                  const textPart = codeSplit[0] || "";
                  const codeRaw = codeSplit[1]?.replace(/^```\n?/, "").replace(/\n?```$/, "") || "";
                  const codeBlock = (codeRaw && codeRaw !== "requires login") ? codeRaw : "";
                  // Extract CWE, OWASP, and main message from text
                  const lines = textPart.split("\n\n");
                  const message = lines[0] || "";
                  const cweLines: string[] = [];
                  const owaspItems: string[] = [];
                  for (const line of lines.slice(1)) {
                    if (line.startsWith("CWE: ")) cweLines.push(...line.slice(5).split(", ").map(s => s.trim()));
                    else if (line.startsWith("OWASP: ")) owaspItems.push(...line.slice(7).split(", ").map(s => s.trim()));
                  }

                  return (
                    <article key={idx} className="scan-detail-item">
                      <div className="scan-detail-item-head">
                        <SeverityWord severity={finding.severity} />
                        <h3>{finding.title}</h3>
                        <span className="scan-detail-chips">
                          {finding.scanners.length > 0 && <span className="chip">{finding.scanners.join(", ")}</span>}
                          <span className="chip mono scan-detail-rule" title={ruleId}>{ruleId.split(".").slice(-2).join(".")}</span>
                        </span>
                      </div>

                      {/* File path (stripped) */}
                      {finding.packagePath && (
                        <p className="scan-detail-item-path mono">{stripScanPath(finding.packagePath)}</p>
                      )}

                      {/* Message */}
                      <p className="scan-detail-item-text">{message}</p>

                      {/* CWE chips */}
                      {cweLines.length > 0 && (
                        <div className="scan-detail-chips scan-detail-item-row">
                          {cweLines.map((cwe, i) => {
                            const idMatch = cwe.match(/^(CWE-\d+):?\s*(.*)/);
                            return (
                              <span key={i} className="chip scan-detail-gap-chip">
                                <span className="mono">{idMatch?.[1] || cwe}</span>
                                {idMatch?.[2] && <span className="muted">{idMatch[2]}</span>}
                              </span>
                            );
                          })}
                        </div>
                      )}

                      {/* OWASP chips */}
                      {owaspItems.length > 0 && (
                        <div className="scan-detail-chips scan-detail-item-row">
                          {owaspItems.map((item, i) => {
                            const parts = item.split(" - ");
                            return (
                              <span key={i} className="chip scan-detail-gap-chip">
                                <span className="mono">{parts[0]}</span>
                                {parts[1] && <span className="muted">{parts[1]}</span>}
                              </span>
                            );
                          })}
                        </div>
                      )}

                      {/* Code snippet */}
                      {codeBlock && <pre className="scan-detail-code scan-detail-code--source">{codeBlock}</pre>}

                      {/* Reference links with domain + icon */}
                      {finding.urls && finding.urls.length > 0 && (
                        <div className="link-list scan-detail-item-row">
                          {finding.urls.slice(0, 3).map((url, i) => (
                            <a key={i} href={url} target="_blank" rel="noopener noreferrer" className="scan-detail-inline">
                              <LuExternalLink aria-hidden="true" />
                              {urlDomain(url)}
                            </a>
                          ))}
                        </div>
                      )}
                    </article>
                  );
                })}
              </div>
            </>
          )}
        </>
      )}

      {tab === "license-compliance" && (
        <>
          {licenseComplianceLoading ? (
            <div className="scan-detail-skeleton">
              {Array.from({ length: 6 }).map((_, i) => (
                <SkeletonBlock key={i} height={40} radius={4} />
              ))}
            </div>
          ) : !licenseCompliance || !licenseCompliance.policyId ? (
            <EmptyState title={t("No license policy configured. Create a default policy on the System page.", "Keine Lizenzrichtlinie konfiguriert. Erstellen Sie eine Standardrichtlinie auf der Systemseite.")} />
          ) : (
            <>
              {/* Summary */}
              <div className="scan-detail-summary">
                <p className="scan-detail-policy">
                  {t("Policy", "Richtlinie")}: <strong>{licenseCompliance.policyName}</strong>
                </p>
                <div className="scan-detail-chips">
                  {(["allowed", "denied", "warned", "unknown"] as const).map(status => (
                    <span key={status} className={`chip${licenseCompliance.summary[status] > 0 ? ` scan-detail-license--${status}` : ""}`}>
                      {licenseCompliance.summary[status]} {status}
                    </span>
                  ))}
                </div>
              </div>

              {/* Violations list */}
              {licenseCompliance.violations.length === 0 ? (
                <EmptyState title={t("All components comply with the license policy.", "Alle Komponenten entsprechen der Lizenzrichtlinie.")} />
              ) : (
                <div className="table-scroll">
                  <table className="scan-detail-table scan-detail-pin">
                    <thead>
                      <tr>
                        <th>{t("Component", "Komponente")}</th>
                        <th>{t("Version", "Version")}</th>
                        <th>{t("Licenses", "Lizenzen")}</th>
                        <th>{t("Status", "Status")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {licenseCompliance.violations.map((v, i) => (
                        <tr key={i}>
                          <td>{v.name}</td>
                          <td className="mono">{v.version}</td>
                          <td>
                            <span className="scan-detail-chips">
                              {v.evaluatedLicenses.map((el, j) => (
                                <span key={j} className={`chip mono scan-detail-license--${el.status}`} title={el.status}>
                                  {el.licenseId}
                                </span>
                              ))}
                            </span>
                          </td>
                          <td><span className={`scan-detail-license--${v.status}`}>{v.status}</span></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </>
          )}
        </>
      )}

      {tab === "secrets" && (
        <>
          {secretFindings.length === 0 ? (
            <EmptyState title={t("No secrets detected.", "Keine Secrets erkannt.")} />
          ) : (
            <>
              <ItemsSummary
                title={t(
                  `${secretFindings.length} secret${secretFindings.length !== 1 ? "s" : ""} detected by TruffleHog`,
                  `${secretFindings.length} Secret${secretFindings.length !== 1 ? "s" : ""} von TruffleHog erkannt`,
                )}
              >
                {(() => {
                  const types: Record<string, number> = {};
                  for (const f of secretFindings) {
                    types[f.packageName] = (types[f.packageName] || 0) + 1;
                  }
                  return Object.entries(types).slice(0, 8).map(([type, count]) => (
                    <span key={type} className="chip">{count} {type}</span>
                  ));
                })()}
              </ItemsSummary>

              {/* Secret items */}
              <div className="scan-detail-items">
                {secretFindings.map((secret, idx) => {
                  // Parse verified status from description (set by backend: "Status: Verified" or "Status: Unverified")
                  const isVerified = /Status:\s*Verified/i.test(secret.description || "");
                  const detectorType = secret.packageName || "Unknown";

                  return (
                    <article key={idx} className="scan-detail-item">
                      <div className="scan-detail-item-head">
                        <SeverityWord severity={secret.severity} />
                        <h3>{secret.title}</h3>
                        <span className="scan-detail-chips">
                          <span className="chip">{detectorType}</span>
                          <span className="chip">{isVerified ? t("Verified", "Verifiziert") : t("Unverified", "Unverifiziert")}</span>
                        </span>
                      </div>

                      {/* File path (stripped) */}
                      {secret.packagePath && (
                        <p className="scan-detail-item-path mono">{stripScanPath(secret.packagePath)}</p>
                      )}

                      {/* Description */}
                      <p className="scan-detail-item-text">{secret.description}</p>
                    </article>
                  );
                })}
              </div>
            </>
          )}
        </>
      )}

      {tab === "scanner-breakdown" && (
        <ScannerBreakdownPanel scan={scan} findings={findings} />
      )}

      <Toast toast={toast} />
    </div>
  );
};

// --- Sub-components ---

/** Column count of the findings table; expansion rows span all of them. */
const FINDING_COLUMNS = 8;

const sentenceCase = (value: string): string => value.charAt(0).toUpperCase() + value.slice(1);

const vexStatusLabel = (status: string, t: (english: string, german: string) => string): string => {
  const labels: Record<string, string> = {
    not_affected: t("Not Affected", "Nicht betroffen"),
    affected: t("Affected", "Betroffen"),
    fixed: t("Fixed", "Behoben"),
    under_investigation: t("Investigating", "In Prüfung"),
  };
  return labels[status] || status;
};

const NotAvailable = () => <span className="muted">n/a</span>;

const SeverityWord = ({ severity }: { severity: string }) => (
  <SeverityTag severity={severity}>{sentenceCase(severity)}</SeverityTag>
);

const MetaItem = ({ label, children }: { label: ReactNode; children: ReactNode }) => (
  <div className="scan-detail-meta-item">
    <dt>{label}</dt>
    <dd>{children}</dd>
  </div>
);

const SortHeader = ({ label, active, dir, onClick }: {
  label: ReactNode;
  active: boolean;
  dir: "asc" | "desc";
  onClick: () => void;
}) => (
  <th aria-sort={active ? (dir === "asc" ? "ascending" : "descending") : undefined}>
    <button type="button" className="scan-detail-sort" onClick={onClick}>
      {label}
      {active && (dir === "asc" ? <LuChevronUp aria-hidden="true" /> : <LuChevronDown aria-hidden="true" />)}
    </button>
  </th>
);

/**
 * Stacked rows drop the column heads on phones, so sorting moves here.
 * Hidden by CSS above the phone breakpoint, where SortHeader does the job.
 */
const PhoneSortBar = ({ id, columns, sort, onSort, children }: {
  id: string;
  columns: readonly (readonly [string, string])[];
  sort: { col: string; dir: "asc" | "desc" };
  onSort: (next: { col: string; dir: "asc" | "desc" }) => void;
  children?: ReactNode;
}) => {
  const { t } = useI18n();
  return (
    <div className="scan-detail-sortbar">
      {children}
      <label htmlFor={id}>{t("Sort by", "Sortieren nach")}</label>
      <select id={id} value={sort.col} onChange={e => onSort({ col: e.target.value, dir: "asc" })}>
        {columns.map(([col, label]) => <option key={col} value={col}>{label}</option>)}
      </select>
      <IconButton
        label={t("Sort direction", "Sortierrichtung")}
        onClick={() => onSort({ col: sort.col, dir: sort.dir === "asc" ? "desc" : "asc" })}
      >
        {sort.dir === "asc" ? <LuChevronUp aria-hidden="true" /> : <LuChevronDown aria-hidden="true" />}
      </IconButton>
    </div>
  );
};

/** A tab's headline count with its neutral breakdown beside it. */
const ItemsSummary = ({ title, children }: { title: ReactNode; children?: ReactNode }) => (
  <div className="scan-detail-summary">
    <h2>{title}</h2>
    {children ? <div className="scan-detail-chips">{children}</div> : null}
  </div>
);

const SeverityCounts = ({ items }: { items: MergedFinding[] }) => {
  const sevs: Record<string, number> = {};
  for (const f of items) {
    const s = f.severity.toLowerCase();
    sevs[s] = (sevs[s] || 0) + 1;
  }
  const entries = Object.entries(sevs).sort(([a], [b]) => (SEVERITY_ORDER[a] ?? 9) - (SEVERITY_ORDER[b] ?? 9));
  return (
    <span className="severity-rollup">
      {entries.map(([s, count]) => (
        <SeverityTag key={s} severity={s}>{count} {s}</SeverityTag>
      ))}
    </span>
  );
};

/** Third-party lookups for one package. Neutral: a link carries no brand or severity colour. */
const PackageLinks = ({ name, version, type, purl, fallback = null }: {
  name: string;
  version: string;
  type: string;
  purl?: string | null;
  fallback?: ReactNode;
}) => {
  const registry = buildRegistryUrl(name, version, type, purl);
  const links = [
    { url: buildDepsDevUrl(name, version, type, purl), label: "deps.dev", title: "deps.dev" },
    { url: buildSnykUrl(name, version, type, purl), label: "Snyk", title: "Snyk" },
    { url: registry?.url ?? null, label: registry?.label ?? "", title: registry?.label ?? "" },
    { url: buildSocketUrl(name, version, type, purl), label: "socket.dev", title: "socket.dev" },
    { url: buildAikidoUrl(name, version, type, purl), label: "aikido", title: "intel.aikido.dev" },
    { url: buildBundlephobiaUrl(name, version, type, purl), label: "bundlephobia", title: "bundlephobia" },
    { url: buildNpmGraphUrl(name, version, type, purl), label: "npmgraph", title: "npmgraph" },
  ].filter(link => !!link.url);
  if (links.length === 0) return fallback;
  return (
    <div className="link-list">
      {links.map(link => (
        <a key={link.title} href={link.url ?? undefined} target="_blank" rel="noopener noreferrer" title={link.title}>
          {link.label}
        </a>
      ))}
    </div>
  );
};

const SEVERITY_ZONES = ["low", "medium", "high", "critical"] as const;

interface BubbleData {
  packageName: string;
  severity: string;
  count: number;
  cves: string[];
  maxCvss: number | null;
}

const BubbleChart = ({ findings }: { findings: MergedFinding[] }) => {
  const { t } = useI18n();
  const navigate = useNavigate();
  const containerRef = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(600);
  const [hovered, setHovered] = useState<BubbleData | null>(null);
  const [mousePos, setMousePos] = useState({ x: 0, y: 0 });

  useEffect(() => {
    if (!containerRef.current) return;
    const observer = new ResizeObserver(entries => {
      for (const entry of entries) setWidth(entry.contentRect.width);
    });
    observer.observe(containerRef.current);
    setWidth(containerRef.current.clientWidth);
    return () => observer.disconnect();
  }, []);

  // Group by package + severity, collect CVE IDs
  const bubbles = useMemo(() => {
    const map = new Map<string, BubbleData>();
    for (const f of findings) {
      const sev = f.severity.toLowerCase();
      if (!(SEVERITY_ZONES as readonly string[]).includes(sev)) continue;
      const key = `${f.packageName}:${sev}`;
      const existing = map.get(key);
      if (existing) {
        existing.count++;
        if (f.vulnerabilityId && !existing.cves.includes(f.vulnerabilityId)) existing.cves.push(f.vulnerabilityId);
        if (f.cvssScore != null && (existing.maxCvss == null || f.cvssScore > existing.maxCvss)) existing.maxCvss = f.cvssScore;
      } else {
        map.set(key, { packageName: f.packageName, severity: sev, count: 1, cves: f.vulnerabilityId ? [f.vulnerabilityId] : [], maxCvss: f.cvssScore ?? null });
      }
    }
    return Array.from(map.values());
  }, [findings]);

  if (bubbles.length === 0) return null;

  const height = 200;
  const padding = { top: 16, right: 20, bottom: 32, left: 44 };
  const chartW = width - padding.left - padding.right;
  const chartH = height - padding.top - padding.bottom;

  // Add +1 headroom so count=maxCount doesn't sit at the very top edge
  const maxCount = Math.max(...bubbles.map(b => b.count), 1) + 1;
  const yTicks = maxCount <= 5
    ? Array.from({ length: maxCount }, (_, i) => i)
    : [0, Math.round((maxCount - 1) / 2), maxCount - 1];

  // CVSS ranges per severity zone for x-axis positioning within each zone
  const CVSS_RANGES: Record<string, [number, number]> = {
    low: [0.1, 3.9],
    medium: [4.0, 6.9],
    high: [7.0, 8.9],
    critical: [9.0, 10.0],
  };

  // Deterministic small jitter for bubbles with identical CVSS to avoid perfect overlap
  const hashStr = (s: string) => {
    let h = 0;
    for (let i = 0; i < s.length; i++) h = ((h << 5) - h + s.charCodeAt(i)) | 0;
    return h;
  };

  const zoneWidth = chartW / SEVERITY_ZONES.length;
  const maxR = Math.min(zoneWidth / 4, chartH / 6, 24);

  return (
    <details className="scan-detail-chart">
      <summary>{t("Library Vulnerability Analysis", "Bibliothek-Schwachstellen-Analyse")}</summary>
      <p className="scan-detail-chart-note">
        {t(
          "Each bubble is a library. X-axis: severity & CVSS score, Y-axis: count, size: count. Hover for details.",
          "Jede Blase ist eine Bibliothek. X-Achse: Schweregrad & CVSS-Score, Y-Achse: Anzahl, Größe: Anzahl. Hover für Details."
        )}
      </p>
      <div ref={containerRef} className="scan-detail-chart-plot">
        <svg
          width={width} height={height}
          role="img"
          aria-label={t("Library Vulnerability Analysis", "Bibliothek-Schwachstellen-Analyse")}
          onMouseMove={e => {
            const rect = (e.currentTarget as SVGSVGElement).getBoundingClientRect();
            setMousePos({ x: e.clientX - rect.left, y: e.clientY - rect.top });
          }}
          onMouseLeave={() => setHovered(null)}
        >
          {/* Grid lines */}
          {yTicks.map(tick => {
            const y = padding.top + chartH - (tick / maxCount) * chartH;
            return (
              <g key={tick}>
                <line x1={padding.left} x2={padding.left + chartW} y1={y} y2={y} stroke="var(--color-rule)" />
                <text x={padding.left - 8} y={y + 4} fill="var(--color-muted)" fontSize="12" textAnchor="end">{tick}</text>
              </g>
            );
          })}
          {/* Zone separators */}
          {SEVERITY_ZONES.map((_, i) => i > 0 && (
            <line key={i} x1={padding.left + i * zoneWidth} x2={padding.left + i * zoneWidth} y1={padding.top} y2={padding.top + chartH} stroke="var(--color-rule)" />
          ))}
          {/* Zone labels */}
          {SEVERITY_ZONES.map((sev, i) => (
            <text key={sev} x={padding.left + (i + 0.5) * zoneWidth} y={height - 6} fill={severityVar(sev)} fontSize="12" textAnchor="middle">
              {sentenceCase(sev)}
            </text>
          ))}
          {/* Bubbles */}
          {bubbles.map((b, i) => {
            const zoneIdx = SEVERITY_ZONES.indexOf(b.severity as typeof SEVERITY_ZONES[number]);
            if (zoneIdx === -1) return null;
            const r = Math.max(4, Math.sqrt(b.count / maxCount) * maxR);
            // Position within zone based on CVSS score
            const [rangeMin, rangeMax] = CVSS_RANGES[b.severity] ?? [0, 10];
            const cvss = b.maxCvss ?? (rangeMin + rangeMax) / 2;
            const rangeSpan = rangeMax - rangeMin || 1;
            const cvssNorm = Math.max(0, Math.min(1, (cvss - rangeMin) / rangeSpan));
            // Map to zone with margin so bubbles don't sit on zone edges
            const margin = r + 4;
            const usableWidth = Math.max(0, zoneWidth - 2 * margin);
            const baseX = padding.left + zoneIdx * zoneWidth + margin + cvssNorm * usableWidth;
            // Tiny deterministic jitter to separate overlapping bubbles (same CVSS)
            const microJitter = ((hashStr(b.packageName) % 100) / 100 - 0.5) * Math.min(r * 2, usableWidth * 0.1);
            const cx = Math.max(padding.left + zoneIdx * zoneWidth + r, Math.min(padding.left + (zoneIdx + 1) * zoneWidth - r, baseX + microJitter));
            const cy = padding.top + chartH - (b.count / maxCount) * chartH;
            const color = severityVar(b.severity);
            const isHovered = hovered?.packageName === b.packageName && hovered?.severity === b.severity;
            return (
              <circle
                key={i}
                className="scan-detail-bubble"
                cx={cx} cy={cy} r={isHovered ? r + 2 : r}
                fill={color}
                fillOpacity={isHovered ? 0.9 : 0.55}
                stroke={color}
                strokeWidth={isHovered ? 2 : 1}
                strokeOpacity={0.8}
                onMouseEnter={() => setHovered(b)}
                onMouseLeave={() => setHovered(null)}
                onClick={() => {
                  if (b.cves.length > 0) {
                    const query = `vuln_id:(${b.cves.join(" OR ")})`;
                    navigate(`/vulnerabilities?search=${encodeURIComponent(query)}&mode=dql`);
                  }
                }}
              />
            );
          })}
        </svg>
        {/* Tooltip */}
        {hovered && (
          <div
            className="scan-detail-tooltip"
            style={{
              top: Math.max(0, mousePos.y - 10),
              ...(mousePos.x > width * 0.6 ? { right: width - mousePos.x + 12 } : { left: mousePos.x + 12 }),
            }}
          >
            <div className="scan-detail-tooltip-title">{hovered.packageName}</div>
            <div className={`scan-detail-tooltip-row sev-${severityLevel(hovered.severity)}`}>
              <span>{sentenceCase(hovered.severity)}</span>
              <strong>{hovered.count} CVE{hovered.count !== 1 ? "s" : ""}</strong>
            </div>
            {hovered.maxCvss != null && (
              <div className="muted">
                CVSS: <strong>{hovered.maxCvss.toFixed(1)}</strong>
              </div>
            )}
            {hovered.cves.length > 0 && (
              <div className="scan-detail-tooltip-foot">
                {hovered.cves.slice(0, 8).map(cve => (
                  <div key={cve} className="mono muted">{cve}</div>
                ))}
                {hovered.cves.length > 8 && (
                  <div className="muted">+{hovered.cves.length - 8} more</div>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </details>
  );
};

const ScannerBreakdownPanel = ({ scan, findings }: { scan: Scan; findings: ScanFinding[] }) => {
  const { t } = useI18n();

  const SEV_KEYS = ["critical", "high", "medium", "low", "negligible", "unknown"] as const;

  const persisted = scan.scannerBreakdown ?? null;

  // Fallback: aggregate from in-memory findings grouped by scanner. SBOM
  // counts are unavailable in this path (the SBOM rows don't carry a scanner
  // field), so those cells show "n/a".
  const fallbackErrors: Record<string, string> = useMemo(() => {
    const out: Record<string, string> = {};
    if (persisted) return out;
    const raw = scan.error ?? "";
    if (!raw) return out;
    for (const piece of raw.split(";")) {
      const idx = piece.indexOf(":");
      if (idx <= 0) continue;
      const name = piece.slice(0, idx).trim();
      const msg = piece.slice(idx + 1).trim();
      if (!name || !msg) continue;
      out[name] = out[name] ? `${out[name]}; ${msg}` : msg;
    }
    return out;
  }, [persisted, scan.error]);

  const fallbackEntries: ScannerBreakdownEntry[] = useMemo(() => {
    if (persisted) return [];
    const byScanner = new Map<string, ScannerBreakdownEntry>();
    const ensure = (name: string): ScannerBreakdownEntry => {
      let e = byScanner.get(name);
      if (!e) {
        e = {
          scanner: name,
          status: "empty",
          findings_total: 0,
          by_severity: { critical: 0, high: 0, medium: 0, low: 0, negligible: 0, unknown: 0 },
          sbom_components: 0,
          error_message: fallbackErrors[name] ?? null,
        };
        byScanner.set(name, e);
      }
      return e;
    };
    for (const s of (scan.scanners ?? [])) ensure(s);
    for (const f of findings) {
      if (!f.scanner) continue;
      const e = ensure(f.scanner);
      e.findings_total += 1;
      const sev = (f.severity || "unknown").toLowerCase();
      if (sev === "critical" || sev === "high" || sev === "medium" || sev === "low" || sev === "negligible" || sev === "unknown") {
        e.by_severity[sev] += 1;
      } else {
        e.by_severity.unknown += 1;
      }
    }
    for (const e of byScanner.values()) {
      if (e.error_message) e.status = "error";
      else if (e.findings_total > 0) e.status = "ok";
      else e.status = "empty";
    }
    return Array.from(byScanner.values()).sort((a, b) => a.scanner.localeCompare(b.scanner));
  }, [persisted, scan.scanners, findings, fallbackErrors]);

  const entries = persisted ?? fallbackEntries;

  if (entries.length === 0) {
    return <EmptyState title={t("No scanner data recorded for this scan.", "Keine Scanner-Daten zu diesem Scan gespeichert.")} />;
  }

  const statusWord = (status: ScannerBreakdownEntry["status"]) => {
    const labels: Record<ScannerBreakdownEntry["status"], string> = {
      ok: t("ok", "ok"),
      empty: t("empty", "leer"),
      error: t("error", "Fehler"),
    };
    return <span className={`scan-detail-outcome--${status}`}>{labels[status]}</span>;
  };

  return (
    <div>
      {!persisted && (
        <p className="scan-detail-note">
          {t(
            "Computed client-side from this scan’s findings. SBOM contributions are not available for older scans.",
            "Im Browser aus den Findings dieses Scans berechnet. SBOM-Beiträge sind für ältere Scans nicht verfügbar.",
          )}
        </p>
      )}
      <div className="table-scroll">
        <table className="scan-detail-table scan-detail-pin">
          <thead>
            <tr>
              <th>{t("Scanner", "Scanner")}</th>
              <th>{t("Status", "Status")}</th>
              <th className="scan-detail-num">{t("Findings", "Findings")}</th>
              <th>{t("By severity", "Nach Schweregrad")}</th>
              <th className="scan-detail-num">{t("SBOM rows", "SBOM-Einträge")}</th>
              <th>{t("Error", "Fehler")}</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((e) => (
              <tr key={e.scanner}>
                <td className="scan-detail-strong">{e.scanner}</td>
                <td>{statusWord(e.status)}</td>
                <td className="scan-detail-num">{e.findings_total}</td>
                <td>
                  {e.findings_total > 0 && (
                    <span className="severity-rollup">
                      {SEV_KEYS.map((k) => {
                        const n = e.by_severity[k];
                        if (!n) return null;
                        return <SeverityTag key={k} severity={k}>{n} {k}</SeverityTag>;
                      })}
                    </span>
                  )}
                </td>
                <td className="scan-detail-num">
                  {persisted ? e.sbom_components : <NotAvailable />}
                </td>
                <td className="scan-detail-scanner-error">
                  {e.error_message}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

const ScanAiAnalysisTab = ({ scan, onRefresh }: { scan: Scan; onRefresh: () => void }) => {
  const { t } = useI18n();
  const { showToast } = useToastContext();
  const [aiAnalysisPassword] = usePersistentState<string>("ai_analysis_password", "");
  const [providers, setProviders] = useState<AIProviderInfo[]>([]);
  const [selectedProvider, setSelectedProvider] = useState<string>("");
  const [additionalContext, setAdditionalContext] = useState<string>("");
  const [aiLoading, setAiLoading] = useState<boolean>(false);

  useEffect(() => {
    let cancelled = false;
    getAiProviders()
      .then(list => {
        if (cancelled) return;
        setProviders(list);
        if (list.length > 0) setSelectedProvider(prev => prev || list[0].id);
      })
      .catch(() => { if (!cancelled) setProviders([]); });
    return () => { cancelled = true; };
  }, []);

  const handleStart = async () => {
    if (!selectedProvider) return;
    setAiLoading(true);
    try {
      await triggerScanAiAnalysis(scan.id, {
        provider: selectedProvider,
        additionalContext: additionalContext.trim() || undefined,
      }, aiAnalysisPassword.trim() || undefined);
      // Background task: poll the scan a couple times to catch the result
      const poll = async (attempt: number) => {
        if (attempt > 30) { setAiLoading(false); return; }
        await new Promise(r => setTimeout(r, 4000));
        try {
          const fresh = await fetchScan(scan.id);
          const before = scan.aiAnalyses?.length ?? 0;
          const after = fresh.aiAnalyses?.length ?? 0;
          if (after > before) {
            setAiLoading(false);
            onRefresh();
            return;
          }
        } catch { /* ignore */ }
        poll(attempt + 1);
      };
      void poll(0);
    } catch (err) {
      const status = (err as { response?: { status?: number } })?.response?.status;
      const detail = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail;
      const message =
        status === 401
          ? t("AI password is missing or invalid.", "AI-Passwort fehlt oder ist ungültig.")
          : detail ?? (err instanceof Error ? err.message : String(err));
      showToast(message, "error");
      setAiLoading(false);
    }
  };

  const analyses = useMemo<ScanAiAnalysis[]>(() => {
    const arr: ScanAiAnalysis[] = Array.isArray(scan.aiAnalyses) ? [...scan.aiAnalyses] : [];
    // Ensure the latest-mirror field is included if legacy scans stored only `ai_analysis`
    if (scan.aiAnalysis) {
      const hasMatch = arr.some(a => a.generatedAt === scan.aiAnalysis?.generatedAt);
      if (!hasMatch) arr.unshift(scan.aiAnalysis);
    }
    // Newest first
    arr.sort((a, b) => (b.generatedAt || "").localeCompare(a.generatedAt || ""));
    return arr;
  }, [scan.aiAnalyses, scan.aiAnalysis]);

  const scanRef: { label: string; value: string } | null = useMemo(() => {
    if (scan.commitSha) {
      return { label: t("Commit", "Commit"), value: scan.commitSha.slice(0, 12) };
    }
    if (scan.imageRef) {
      // Container images may expose a digest suffix `@sha256:...`
      const atIdx = scan.imageRef.indexOf("@sha256:");
      if (atIdx >= 0) {
        return { label: t("Digest", "Digest"), value: scan.imageRef.slice(atIdx + 8, atIdx + 20) };
      }
      return { label: t("Image", "Image"), value: scan.imageRef };
    }
    return null;
  }, [scan, t]);

  const triggerForm = (
    <div className="scan-detail-ai-form">
      {providers.length === 0 ? (
        <EmptyState title={t("No AI providers configured.", "Keine AI-Provider konfiguriert.")} />
      ) : (
        <>
          <div className="scan-detail-ai-controls">
            <label htmlFor="scan-ai-provider">{t("Provider", "Anbieter")}</label>
            <select
              id="scan-ai-provider"
              value={selectedProvider}
              onChange={(e) => setSelectedProvider(e.target.value)}
              disabled={aiLoading}
            >
              {providers.map(p => <option key={p.id} value={p.id}>{p.label}</option>)}
            </select>
            <button
              type="button"
              className="btn-primary"
              onClick={() => void handleStart()}
              disabled={aiLoading || !selectedProvider}
            >
              {aiLoading ? t("Analysis running...", "Analyse läuft...") : t("Start AI analysis", "AI-Analyse starten")}
            </button>
          </div>
          <label htmlFor="scan-ai-context">
            {t("Additional information (optional)", "Zusätzliche Informationen (optional)")}
          </label>
          <textarea
            id="scan-ai-context"
            value={additionalContext}
            onChange={(e) => setAdditionalContext(e.target.value)}
            disabled={aiLoading}
            placeholder={t(
              "Enter additional information to include in the AI analysis...",
              "Geben Sie zusätzliche Informationen ein, die bei der AI-Analyse berücksichtigt werden sollen..."
            )}
          />
        </>
      )}
    </div>
  );

  if (analyses.length === 0) {
    return triggerForm;
  }

  return (
    <div>
      {triggerForm}
      <div className="scan-detail-items">
        {analyses.map((analysis, idx) => {
          const originChipLabel = analysis.triggeredBy ? "MCP - Scan" : "API - Scan";
          const cleanedSummary = stripAiSummaryFooter(analysis.summary);
          return (
            <article key={`${analysis.generatedAt}-${idx}`} className="scan-detail-item">
              <div className="scan-detail-item-head">
                <span className="scan-detail-chips scan-detail-push-end">
                  {scanRef && (
                    <span className="chip scan-detail-gap-chip">
                      {scanRef.label}: <span className="mono">{scanRef.value}</span>
                    </span>
                  )}
                  <TriggeredByBadge triggeredBy={analysis.triggeredBy} />
                </span>
                <span className="chip">{originChipLabel}</span>
              </div>
              {cleanedSummary ? (
                <div className="scan-detail-ai-text">
                  <AiMarkdown>{cleanedSummary}</AiMarkdown>
                </div>
              ) : (
                <p className="scan-detail-note">{t("No summary available.", "Keine Zusammenfassung verfügbar.")}</p>
              )}
              {(analysis.provider || analysis.language || analysis.generatedAt || analysis.tokenUsage) && (
                <div className="scan-detail-ai-meta">
                  {analysis.provider && <span>{analysis.provider}</span>}
                  {analysis.language && <span>{t("Language", "Sprache")}: {analysis.language.toUpperCase()}</span>}
                  {analysis.generatedAt && <span>{formatDateTime(analysis.generatedAt)}</span>}
                  {analysis.tokenUsage && analysis.tokenUsage.inputTokens !== undefined && (
                    <span>{t("Tokens", "Tokens")}: {analysis.tokenUsage.inputTokens.toLocaleString()} in / {(analysis.tokenUsage.outputTokens ?? 0).toLocaleString()} out</span>
                  )}
                </div>
              )}
            </article>
          );
        })}
      </div>
    </div>
  );
};

const HistoryChart = ({ history }: { history: ScanHistoryEntry[] }) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(600);
  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null);

  useEffect(() => {
    if (!containerRef.current) return;
    const observer = new ResizeObserver(entries => {
      for (const entry of entries) setWidth(entry.contentRect.width);
    });
    observer.observe(containerRef.current);
    setWidth(containerRef.current.clientWidth);
    return () => observer.disconnect();
  }, []);

  const height = 220;
  const padding = { top: 20, right: 20, bottom: 40, left: 50 };
  const chartW = width - padding.left - padding.right;
  const chartH = height - padding.top - padding.bottom;

  const maxTotal = Math.max(...history.map(h => h.summary.total), 1);
  const yTicks = [0, Math.round(maxTotal / 2), maxTotal];

  const xStep = history.length > 1 ? chartW / (history.length - 1) : chartW;

  const severities = ["critical", "high", "medium", "low"] as const;

  const getX = (i: number) => padding.left + (history.length > 1 ? i * xStep : chartW / 2);

  return (
    <div ref={containerRef} className="scan-detail-chart-plot">
      <svg width={width} height={height} aria-hidden="true">
        {/* Grid lines */}
        {yTicks.map(tick => {
          const y = padding.top + chartH - (tick / maxTotal) * chartH;
          return (
            <g key={tick}>
              <line x1={padding.left} x2={padding.left + chartW} y1={y} y2={y} stroke="var(--color-rule)" />
              <text x={padding.left - 8} y={y + 4} fill="var(--color-muted)" fontSize="12" textAnchor="end">{tick}</text>
            </g>
          );
        })}
        {/* Lines per severity */}
        {severities.map(sev => {
          const color = severityVar(sev);
          const points = history.map((h, i) => {
            const x = getX(i);
            const y = padding.top + chartH - (h.summary[sev] / maxTotal) * chartH;
            return `${x},${y}`;
          });
          return (
            <g key={sev}>
              <polyline points={points.join(" ")} fill="none" stroke={color} strokeWidth="2" strokeLinejoin="round" />
              {history.map((h, i) => {
                const x = getX(i);
                const y = padding.top + chartH - (h.summary[sev] / maxTotal) * chartH;
                const isHovered = hoveredIndex === i;
                return h.summary[sev] > 0 ? (
                  <circle key={i} cx={x} cy={y} r={isHovered ? 5 : 3} fill={color} />
                ) : null;
              })}
            </g>
          );
        })}
        {/* Hover vertical line */}
        {hoveredIndex !== null && (
          <line
            x1={getX(hoveredIndex)} x2={getX(hoveredIndex)}
            y1={padding.top} y2={padding.top + chartH}
            stroke="var(--color-rule-strong)" strokeDasharray="4,3"
          />
        )}
        {/* X axis labels */}
        {history.map((h, i) => {
          const x = getX(i);
          const step = Math.max(1, Math.floor(history.length / 8));
          if (i % step !== 0 && i !== history.length - 1) return null;
          const label = new Date(h.startedAt).toLocaleDateString("de-DE", {
            day: "numeric", month: "numeric", timeZone: getCurrentTimezone(),
          });
          return (
            <text key={i} x={x} y={height - 5} fill={hoveredIndex === i ? "var(--color-ink-2)" : "var(--color-muted)"} fontSize="12" textAnchor="middle">{label}</text>
          );
        })}
        {/* Invisible hover areas (must be last so they're on top) */}
        {history.map((_, i) => {
          const x = getX(i);
          const halfStep = history.length > 1 ? xStep / 2 : chartW / 2;
          return (
            <rect
              key={i}
              className="scan-detail-chart-hit"
              x={x - halfStep}
              y={padding.top}
              width={halfStep * 2}
              height={chartH}
              fill="transparent"
              onMouseEnter={() => setHoveredIndex(i)}
              onMouseLeave={() => setHoveredIndex(null)}
            />
          );
        })}
      </svg>

      {/* Hover tooltip */}
      {hoveredIndex !== null && (() => {
        const h = history[hoveredIndex];
        const x = getX(hoveredIndex);
        const xPct = (x - padding.left) / chartW;
        const d = new Date(h.startedAt);
        const tz = getCurrentTimezone();
        const dateStr = d.toLocaleDateString("de-DE", {
          day: "2-digit", month: "2-digit", year: "numeric", timeZone: tz,
        });
        const timeStr = d.toLocaleTimeString("de-DE", {
          hour: "2-digit", minute: "2-digit", hour12: false, timeZone: tz,
        });
        return (
          <div
            className="scan-detail-tooltip"
            style={{
              top: padding.top,
              ...(xPct > 0.6
                ? { right: width - x + 8 }
                : { left: x + 8 }),
            }}
          >
            <div className="scan-detail-tooltip-title">
              {dateStr} {timeStr}
            </div>
            {severities.map(sev => h.summary[sev] > 0 && (
              <div key={sev} className={`scan-detail-tooltip-row sev-${sev}`}>
                <span>{sentenceCase(sev)}</span>
                <strong>{h.summary[sev]}</strong>
              </div>
            ))}
            <div className="scan-detail-tooltip-row scan-detail-tooltip-foot muted">
              <span>Total</span>
              <strong>{h.summary.total}</strong>
            </div>
          </div>
        );
      })()}

      {/* Legend */}
      <div className="scan-detail-legend">
        {severities.map(sev => (
          <div key={sev} className="scan-detail-inline">
            <span className="scan-detail-swatch" style={{ background: severityVar(sev) }} />
            <span className="muted">{sentenceCase(sev)}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

/** A change in a count: up is worse, down is better, zero stays quiet. */
const Delta = ({ value }: { value: number }) => {
  if (value === 0) return <span className="muted">0</span>;
  if (value > 0) return <span className="scan-detail-delta scan-detail-outcome--error">+{value}</span>;
  return <span className="scan-detail-delta scan-detail-outcome--ok">{value}</span>;
};

const HistoryChangesTable = ({ history, targetId }: { history: ScanHistoryEntry[]; targetId?: string }) => {
  const { t } = useI18n();
  const sevs = ["critical", "high", "medium", "low"] as const;

  // Build commit URL base from targetId (works for GitHub, GitLab, Gitea repos)
  const commitUrlBase = (() => {
    if (!targetId) return null;
    // targetId for source repos is typically the repo URL or slug
    const clean = targetId.replace(/\.git$/, "");
    if (clean.includes("/") && !clean.startsWith("http")) return `https://${clean}/commit/`;
    if (clean.startsWith("http")) return `${clean}/commit/`;
    return null;
  })();

  // Compare consecutive scans (history is oldest-first from API), collect newest-first
  const changes: { newer: ScanHistoryEntry; deltas: Record<string, number> }[] = [];
  for (let i = history.length - 1; i > 0; i--) {
    const newer = history[i];
    const older = history[i - 1];
    const deltas: Record<string, number> = {};
    let hasChange = false;
    for (const sev of sevs) {
      const d = newer.summary[sev] - older.summary[sev];
      deltas[sev] = d;
      if (d !== 0) hasChange = true;
    }
    deltas.total = newer.summary.total - older.summary.total;
    if (deltas.total !== 0) hasChange = true;
    if (hasChange) changes.push({ newer, deltas });
  }

  if (changes.length === 0) return null;

  const hasAnyCommit = changes.some(c => c.newer.commitSha);

  return (
    <div className="scan-detail-group">
      <h2>{t("Significant Changes", "Wesentliche Änderungen")}</h2>
      <div className="table-scroll">
        <table className="scan-detail-table scan-detail-pin">
          <thead>
            <tr>
              <th>{t("Date", "Datum")}</th>
              {hasAnyCommit && <th>Commit</th>}
              {sevs.map(sev => (
                <th key={sev} className={`scan-detail-num sev-${sev}`}>{sentenceCase(sev)}</th>
              ))}
              <th className="scan-detail-num">Total</th>
            </tr>
          </thead>
          <tbody>
            {changes.map(({ newer, deltas }, i) => (
              <tr key={i}>
                <td className="scan-detail-nowrap">{formatDateTime(newer.startedAt)}</td>
                {hasAnyCommit && (
                  <td className="scan-detail-nowrap">
                    {newer.commitSha ? (
                      <span className="scan-detail-inline">
                        <span className="mono">{newer.commitSha.slice(0, 7)}</span>
                        {commitUrlBase && (
                          <a
                            href={`${commitUrlBase}${newer.commitSha}`}
                            target="_blank"
                            rel="noreferrer"
                            className="scan-detail-icon-link"
                            title={t("View commit", "Commit anzeigen")}
                            aria-label={t("View commit", "Commit anzeigen")}
                          >
                            <LuExternalLink aria-hidden="true" />
                          </a>
                        )}
                      </span>
                    ) : (
                      <NotAvailable />
                    )}
                  </td>
                )}
                {sevs.map(sev => (
                  <td key={sev} className="scan-detail-num"><Delta value={deltas[sev]} /></td>
                ))}
                <td className="scan-detail-num"><Delta value={deltas.total} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

const ComparisonTable = ({ items }: { items: ScanComparisonResponse["added"] }) => {
  const { t } = useI18n();
  return (
    <div className="table-scroll">
      <table className="scan-detail-table scan-detail-pin">
        <thead>
          <tr>
            <th>CVE</th>
            <th>{t("Package", "Paket")}</th>
            <th>{t("Version", "Version")}</th>
            <th>{t("Severity", "Schweregrad")}</th>
            <th>Fix</th>
          </tr>
        </thead>
        <tbody>
          {items.map((f, i) => (
            <tr key={i}>
              <td>
                {f.vulnerabilityId ? (
                  <Link to={`/vulnerability/${f.vulnerabilityId}`} className="scan-detail-link mono">{f.vulnerabilityId}</Link>
                ) : <NotAvailable />}
              </td>
              <td>{f.packageName}</td>
              <td>{f.packageVersion ? <span className="mono">{f.packageVersion}</span> : <NotAvailable />}</td>
              <td><SeverityWord severity={f.severity} /></td>
              <td>{f.fixVersion ? <span className="mono">{f.fixVersion}</span> : <NotAvailable />}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

const ComparisonView = ({ comparison }: { comparison: ScanComparisonResponse }) => {
  const { t } = useI18n();
  const summaryA = comparison.summaryA;
  const summaryB = comparison.summaryB;

  return (
    <div>
      {/* Summary comparison */}
      <dl className="stat-row scan-detail-compare">
        {(["critical", "high", "medium", "low", "total"] as const).map(sev => (
          <Stat
            key={sev}
            label={sentenceCase(sev)}
            value={(
              <span className="scan-detail-inline">
                <span>{(summaryA as any)[sev]}</span>
                <LuArrowRight aria-hidden="true" />
                <span>{(summaryB as any)[sev]}</span>
                <Delta value={(summaryB as any)[sev] - (summaryA as any)[sev]} />
              </span>
            )}
          />
        ))}
      </dl>

      <p className="scan-detail-note">
        {t("Unchanged", "Unverändert")}: {comparison.unchangedCount} findings
      </p>

      {/* Added findings */}
      {comparison.added.length > 0 && (
        <div className="scan-detail-group">
          <h2 className="scan-detail-inline">
            <LuPlus aria-hidden="true" />
            {t("Added", "Hinzugefügt")} ({comparison.added.length})
          </h2>
          <ComparisonTable items={comparison.added} />
        </div>
      )}

      {/* Changed findings (same package, different vuln ID) */}
      {(comparison.changed?.length ?? 0) > 0 && (
        <div className="scan-detail-group">
          <h2 className="scan-detail-inline">
            <LuArrowLeftRight aria-hidden="true" />
            {t("Changed", "Geändert")} ({comparison.changed!.length})
          </h2>
          <div className="table-scroll">
            <table className="scan-detail-table scan-detail-pin">
              <thead>
                <tr>
                  <th>{t("Package", "Paket")}</th>
                  <th>{t("Version", "Version")}</th>
                  <th>{t("Before", "Vorher")}</th>
                  <th>{t("After", "Nachher")}</th>
                  <th>{t("Severity", "Schweregrad")}</th>
                </tr>
              </thead>
              <tbody>
                {comparison.changed!.map((c, i) => (
                  <tr key={i}>
                    <td>{c.after.packageName}</td>
                    <td>{c.after.packageVersion ? <span className="mono">{c.after.packageVersion}</span> : <NotAvailable />}</td>
                    <td>
                      {c.before.vulnerabilityId ? (
                        <Link to={`/vulnerability/${c.before.vulnerabilityId}`} className="scan-detail-link mono">{c.before.vulnerabilityId}</Link>
                      ) : <NotAvailable />}
                    </td>
                    <td>
                      {c.after.vulnerabilityId ? (
                        <Link to={`/vulnerability/${c.after.vulnerabilityId}`} className="scan-detail-link mono">{c.after.vulnerabilityId}</Link>
                      ) : <NotAvailable />}
                    </td>
                    <td>
                      <span className="scan-detail-inline">
                        <SeverityWord severity={c.after.severity} />
                        {c.before.severity !== c.after.severity && (
                          <span className="scan-detail-count">
                            ({t("was", "war")} {c.before.severity})
                          </span>
                        )}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Removed findings */}
      {comparison.removed.length > 0 && (
        <div className="scan-detail-group">
          <h2 className="scan-detail-inline">
            <LuMinus aria-hidden="true" />
            {t("Removed", "Entfernt")} ({comparison.removed.length})
          </h2>
          <ComparisonTable items={comparison.removed} />
        </div>
      )}

      {comparison.added.length === 0 && comparison.removed.length === 0 && (comparison.changed?.length ?? 0) === 0 && (
        <EmptyState title={t("No differences found between the two scans.", "Keine Unterschiede zwischen den beiden Scans gefunden.")} />
      )}
    </div>
  );
};

const SeveritySummaryBar = ({ summary }: { summary: ScanSummary }) => {
  const { t } = useI18n();
  if (summary.total === 0) {
    return (
      <p className="scan-detail-clean">
        {t("No vulnerabilities found", "Keine Schwachstellen gefunden")}
      </p>
    );
  }

  const segments = [
    { label: "Critical", count: summary.critical, level: "critical" },
    { label: "High", count: summary.high, level: "high" },
    { label: "Medium", count: summary.medium, level: "medium" },
    { label: "Low", count: summary.low, level: "low" },
    { label: "Negligible", count: summary.negligible, level: "none" },
    { label: "Unknown", count: summary.unknown, level: "none" },
  ].filter(s => s.count > 0);

  return (
    <div className="scan-detail-severity">
      <dl className="stat-row">
        {segments.map(s => <Stat key={s.label} label={s.label} value={s.count} tone={s.level} />)}
      </dl>
      {/* Share of each severity; the words and figures above carry the meaning */}
      <div className="scan-detail-sevbar" aria-hidden="true">
        {segments.map(s => (
          <span key={s.label} style={{ width: `${(s.count / summary.total) * 100}%`, background: severityVar(s.level) }} />
        ))}
      </div>
    </div>
  );
};

const StatusBadge = ({ status }: { status: string }) => {
  const outcome: Record<string, string> = {
    completed: "ok",
    running: "info",
    pending: "info",
    failed: "error",
  };
  return <span className={`scan-detail-outcome--${outcome[status] ?? "empty"}`}>{status}</span>;
};
