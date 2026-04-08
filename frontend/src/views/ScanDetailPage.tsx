import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";

import { fetchScan, fetchScanFindings, fetchScanSbom, fetchScanLayers, fetchScans, fetchTargetHistory, compareScans, exportScanSbom, updateFindingVex, exportVex } from "../api/scans";
import { fetchScanLicenseCompliance } from "../api/licensePolicy";
import { SkeletonBlock } from "../components/Skeleton";
import { useI18n } from "../i18n/context";
import { formatDateTime } from "../utils/dateFormat";
import type {
  Scan,
  ScanFinding,
  ScanSummary,
  ScanHistoryEntry,
  ScanComparisonResponse,
  ScanLayerAnalysis,
  SbomComponent,
  LicenseComplianceResult,
} from "../types";

type Tab = "findings" | "sbom" | "history" | "compare" | "alerts" | "bestpractices" | "layers" | "sast" | "secrets" | "license-compliance";

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

/** Map purl/type to deps.dev ecosystem name */
const DEPS_DEV_ECOSYSTEM: Record<string, string> = {
  npm: "npm",
  pypi: "pypi",
  nuget: "nuget",
  maven: "maven",
  golang: "go",
  go: "go",
  cargo: "cargo",
  gem: "rubygems",
  rubygems: "rubygems",
  composer: "packagist",
  packagist: "packagist",
};

/** Map purl/type to Snyk package type */
const SNYK_ECOSYSTEM: Record<string, string> = {
  npm: "npm",
  pypi: "pip",
  nuget: "nuget",
  maven: "maven",
  golang: "golang",
  go: "golang",
  gem: "rubygems",
  rubygems: "rubygems",
  composer: "composer",
};

function getEcosystemFromPurl(purl: string | null | undefined): string | null {
  if (!purl) return null;
  // purl format: pkg:<type>/<namespace>/<name>@<version>
  const match = purl.match(/^pkg:([^/]+)\//);
  return match ? match[1].toLowerCase() : null;
}

function buildDepsDevUrl(name: string, version: string, type: string, purl?: string | null): string | null {
  const eco = getEcosystemFromPurl(purl) ?? type.toLowerCase();
  const mapped = DEPS_DEV_ECOSYSTEM[eco];
  if (!mapped || !name || !version) return null;
  return `https://deps.dev/${mapped}/${encodeURIComponent(name)}/${encodeURIComponent(version)}`;
}

function buildSnykUrl(name: string, version: string, type: string, purl?: string | null): string | null {
  const eco = getEcosystemFromPurl(purl) ?? type.toLowerCase();
  const mapped = SNYK_ECOSYSTEM[eco];
  if (!mapped || !name || !version) return null;
  return `https://security.snyk.io/package/${mapped}/${encodeURIComponent(name)}/${encodeURIComponent(version)}`;
}

/** Build a direct link to the package on its native registry */
function buildRegistryUrl(name: string, version: string, type: string, purl?: string | null): { url: string; label: string } | null {
  const eco = getEcosystemFromPurl(purl) ?? type.toLowerCase();
  if (!name) return null;
  const v = version ? encodeURIComponent(version) : "";
  const n = encodeURIComponent(name);
  switch (eco) {
    case "npm":
      return { url: `https://www.npmjs.com/package/${name}${v ? `/v/${v}` : ""}`, label: "npm" };
    case "pypi":
      return { url: `https://pypi.org/project/${n}/${v || ""}`, label: "PyPI" };
    case "maven": {
      // Maven purl: pkg:maven/group/artifact — name may contain the group
      const parts = name.split("/");
      if (parts.length === 2) {
        return { url: `https://central.sonatype.com/artifact/${parts[0]}/${parts[1]}${v ? `/${v}` : ""}`, label: "Maven" };
      }
      return { url: `https://central.sonatype.com/search?q=${n}`, label: "Maven" };
    }
    case "golang":
      return { url: `https://pkg.go.dev/${name}${v ? `@${v}` : ""}`, label: "Go" };
    case "nuget":
      return { url: `https://www.nuget.org/packages/${n}${v ? `/${v}` : ""}`, label: "NuGet" };
    case "cargo":
      return { url: `https://crates.io/crates/${n}${v ? `/${v}` : ""}`, label: "crates.io" };
    case "gem":
      return { url: `https://rubygems.org/gems/${n}${v ? `/versions/${v}` : ""}`, label: "RubyGems" };
    case "composer":
    case "packagist":
      return { url: `https://packagist.org/packages/${name}`, label: "Packagist" };
    case "cocoapods":
      return { url: `https://cocoapods.org/pods/${n}`, label: "CocoaPods" };
    case "hex":
      return { url: `https://hex.pm/packages/${n}${v ? `/${v}` : ""}`, label: "Hex" };
    case "pub":
      return { url: `https://pub.dev/packages/${n}${v ? `/versions/${v}` : ""}`, label: "pub.dev" };
    case "swift":
      return { url: `https://swiftpackageindex.com/search?query=${n}`, label: "Swift" };
    case "docker":
    case "oci":
      // Docker Hub or generic registry
      if (!name.includes(".") && !name.includes(":")) {
        const dockerName = name.includes("/") ? name : `library/${name}`;
        return { url: `https://hub.docker.com/r/${dockerName}`, label: "Docker Hub" };
      }
      return null;
    default:
      return null;
  }
}

/** Build a clickable source URL from image ref or target id */
function buildSourceUrl(scan: Scan): string | null {
  const ref = scan.imageRef || scan.targetId;
  if (!ref) return null;
  // If it already looks like a URL
  if (ref.startsWith("http://") || ref.startsWith("https://")) return ref;
  const withoutDigest = ref.split("@")[0];
  const cleaned = withoutDigest.split(":")[0];
  const tag = withoutDigest.includes(":") ? withoutDigest.split(":").pop() : "latest";
  // Docker Hub images: docker.io/library/X or docker.io/org/X → hub.docker.com/layers/...
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
  dataSource: string | null;
  scanners: string[];
  cvssScore: number | null;
  urls: string[];
  vexStatus: string | null;
  vexJustification: string | null;
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

function mergeFindings(findings: ScanFinding[]): MergedFinding[] {
  type Entry = MergedFinding & { _fixCandidates: (string | null)[] };
  const map = new Map<string, Entry>();

  const mergeInto = (existing: Entry, f: ScanFinding) => {
    if (!existing.findingIds.includes(f.id)) existing.findingIds.push(f.id);
    if (!existing.scanners.includes(f.scanner)) existing.scanners.push(f.scanner);
    if (f.fixVersion) existing._fixCandidates.push(normalizeVersion(f.fixVersion));
    if (!existing.cvssScore && f.cvssScore) existing.cvssScore = f.cvssScore;
    if (!existing.packageType && f.packageType) existing.packageType = f.packageType;
    if (!existing.matchedFrom && f.matchedFrom) existing.matchedFrom = f.matchedFrom;
    // Promote CVE if the existing entry has none
    if (!existing.vulnerabilityId && f.vulnerabilityId) existing.vulnerabilityId = f.vulnerabilityId;
    // VEX: take first non-null
    if (!existing.vexStatus && f.vexStatus) {
      existing.vexStatus = f.vexStatus;
      existing.vexJustification = f.vexJustification ?? null;
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
          dataSource: f.dataSource ?? null,
          scanners: [f.scanner],
          cvssScore: f.cvssScore ?? null,
          urls: f.urls ?? [],
          vexStatus: f.vexStatus ?? null,
          vexJustification: f.vexJustification ?? null,
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

export const ScanDetailPage = () => {
  const { scanId } = useParams<{ scanId: string }>();
  const { t } = useI18n();
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<ScanFinding[]>([]);
  const [findingsTotal, setFindingsTotal] = useState(0);
  const [sbomComponents, setSbomComponents] = useState<SbomComponent[]>([]);
  const [sbomTotal, setSbomTotal] = useState(0);
  const [tab, setTab] = useState<Tab>("findings");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string | undefined>();
  const [findingsSearch, setFindingsSearch] = useState("");
  const [findingsSort, setFindingsSort] = useState<{ col: string; dir: "asc" | "desc" }>({ col: "severity", dir: "asc" });
  const [sbomSearch, setSbomSearch] = useState("");
  const [sbomExporting, setSbomExporting] = useState<string | null>(null);

  // License compliance
  const [licenseCompliance, setLicenseCompliance] = useState<LicenseComplianceResult | null>(null);
  const [licenseComplianceLoading, setLicenseComplianceLoading] = useState(false);

  // VEX editing
  const [vexEditingId, setVexEditingId] = useState<string | null>(null);
  const [vexEditStatus, setVexEditStatus] = useState("");
  const [vexEditJustification, setVexEditJustification] = useState("");

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

  /** Summary computed from deduplicated vulnerability findings (excludes alerts) */
  const mergedSummary = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, negligible: 0, unknown: 0, total: 0 };
    for (const f of vulnFindings) {
      const sev = f.severity.toLowerCase() as keyof typeof counts;
      if (sev in counts && sev !== "total") (counts[sev] as number)++;
      else counts.unknown++;
      counts.total++;
    }
    return counts;
  }, [vulnFindings]);

  /** Deduplicate SBOM components: merge rows with same name+version */
  const dedupedSbom = useMemo(() => {
    const map = new Map<string, SbomComponent>();
    for (const c of sbomComponents) {
      const key = `${c.name}::${c.version}`;
      const existing = map.get(key);
      if (!existing) {
        map.set(key, { ...c });
      } else {
        // Prefer a more specific type over "library"
        if (existing.type === "library" && c.type && c.type !== "library") {
          existing.type = c.type;
        }
        // Prefer purl if missing
        if (!existing.purl && c.purl) existing.purl = c.purl;
        // Merge licenses
        const allLicenses = new Set([...existing.licenses, ...c.licenses]);
        existing.licenses = [...allLicenses];
      }
    }
    return [...map.values()];
  }, [sbomComponents]);

  const sbomStats = useMemo(() => {
    const ecosystems: Record<string, number> = {};
    const licenses: Record<string, number> = {};
    const types: Record<string, number> = {};
    for (const c of dedupedSbom) {
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
  }, [dedupedSbom]);

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
        const [findingsData, sbomData] = await Promise.all([
          fetchScanFindings(scanId, { limit: 5000 }),
          fetchScanSbom(scanId, { search: sbomSearch || undefined, limit: 500 }),
        ]);
        setFindings(findingsData.items);
        setFindingsTotal(findingsData.total);
        setSbomComponents(sbomData.items);
        setSbomTotal(sbomData.total);
      }
    } catch (err) {
      console.error("Failed to load scan", err);
      if (isInitial) setError(t("Could not load scan.", "Scan konnte nicht geladen werden."));
    } finally {
      if (isInitial) setLoading(false);
    }
  }, [scanId, sbomSearch, t]);

  // Initial load
  useEffect(() => {
    loadScanData(true);
  }, [scanId]);

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
    fetchScanSbom(scanId, { search: sbomSearch || undefined, limit: 500 }).then(data => {
      setSbomComponents(data.items);
      setSbomTotal(data.total);
    }).catch(err => console.error("Failed to load SBOM", err));
  }, [sbomSearch]);

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
    <div className="page">
      <section className="card">
        <SkeletonBlock height="1rem" width="120px" style={{ marginBottom: "0.75rem" }} />
        <SkeletonBlock height="1.5rem" width="60%" style={{ marginBottom: "0.5rem" }} />
        <SkeletonBlock height="0.85rem" width="40%" style={{ marginBottom: "1rem" }} />
        <SkeletonBlock height={8} radius={4} style={{ marginBottom: "0.75rem" }} />
        <div style={{ display: "flex", gap: "1rem" }}>
          {Array.from({ length: 4 }).map((_, i) => (
            <SkeletonBlock key={i} height="0.85rem" width="80px" />
          ))}
        </div>
      </section>
      <section className="card" style={{ marginTop: "1rem" }}>
        {Array.from({ length: 8 }).map((_, i) => (
          <SkeletonBlock key={i} height={36} radius={4} style={{ marginBottom: "0.5rem" }} />
        ))}
      </section>
    </div>
  );
  if (error) return <div className="page"><section className="card"><p className="muted">{error}</p></section></div>;
  if (!scan) return <div className="page"><section className="card"><p className="muted">{t("Scan not found.", "Scan nicht gefunden.")}</p></section></div>;

  const sourceUrl = buildSourceUrl(scan);

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

  return (
    <div className="page">
      {/* Header */}
      <section className="card" style={{ overflow: "visible" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: "1rem" }}>
          <div>
            <Link to="/scans" style={{ color: "rgba(255,255,255,0.4)", textDecoration: "none", fontSize: "0.8125rem" }}>
              ← {t("Back to Scans", "Zurück zu Scans")}
            </Link>
            <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", margin: "0.5rem 0 0.25rem" }}>
              <h2 style={{ margin: 0 }}>{scan.targetName || scan.targetId}</h2>
              {sourceUrl && (
                <a
                  href={sourceUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  title={t("Open source", "Quelle öffnen")}
                  style={{ color: "#ffd43b", textDecoration: "none", fontSize: "1rem", lineHeight: 1 }}
                >
                  ↗
                </a>
              )}
            </div>
            <div style={{ display: "flex", gap: "0.75rem", flexWrap: "wrap", alignItems: "center" }}>
              <StatusBadge status={scan.status} />
              <span style={{ fontSize: "0.8125rem", color: "rgba(255,255,255,0.5)" }}>
                {scan.scanners.join(", ")}
              </span>
              {scan.startedAt && (
                <span style={{ fontSize: "0.8125rem", color: "rgba(255,255,255,0.4)" }}>
                  {formatDateTime(scan.startedAt)}
                </span>
              )}
              {scan.durationSeconds != null && (
                <span style={{ fontSize: "0.8125rem", color: "rgba(255,255,255,0.4)" }}>
                  ({scan.durationSeconds.toFixed(1)}s)
                </span>
              )}
            </div>
          </div>
          <div style={{ textAlign: "right", fontSize: "0.8125rem", color: "rgba(255,255,255,0.5)", marginLeft: "auto" }}>
            {scan.imageRef && (() => {
              const tag = getImageTag(scan.imageRef);
              const digest = getImageDigest(scan.imageRef);
              const baseRef = scan.imageRef.split("@")[0].split(":")[0];
              return (
                <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: "0.2rem" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "0.375rem" }}>
                    <span style={{ wordBreak: "break-all" }}>{baseRef}{tag ? `:${tag}` : ""}</span>
                    {sourceUrl && (
                      <a href={sourceUrl} target="_blank" rel="noopener noreferrer" style={{ color: "#ffd43b", fontSize: "0.75rem", flexShrink: 0 }}>↗</a>
                    )}
                  </div>
                  {digest && (
                    <div title={digest} style={{ fontFamily: "monospace", fontSize: "0.7rem", color: "rgba(255,255,255,0.3)", wordBreak: "break-all", maxWidth: "320px" }}>
                      {digest.length > 20 ? `${digest.substring(0, 20)}…` : digest}
                    </div>
                  )}
                </div>
              );
            })()}
            {!scan.imageRef && scan.commitSha && (
              <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: "0.2rem" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "0.375rem" }}>
                  <span style={{ wordBreak: "break-all" }}>{scan.targetName || scan.targetId}</span>
                  {sourceUrl && (
                    <a href={sourceUrl} target="_blank" rel="noopener noreferrer" style={{ color: "#ffd43b", fontSize: "0.75rem", flexShrink: 0 }}>↗</a>
                  )}
                </div>
                <div title={scan.commitSha} style={{ fontFamily: "monospace", fontSize: "0.7rem", color: "rgba(255,255,255,0.3)" }}>
                  {scan.commitSha.substring(0, 12)}
                </div>
              </div>
            )}
            {scan.branch && <div>Branch: {scan.branch}</div>}
            {scan.source === "ci_cd" && <div style={{ color: "#5c84ff" }}>CI/CD</div>}
            {scan.source === "scheduled" && <div style={{ color: "#69db7c" }}>Auto</div>}
          </div>
        </div>

        {scan.error && (
          <div style={{ marginTop: "0.75rem", padding: "0.5rem 0.75rem", background: "rgba(255,107,107,0.08)", border: "1px solid rgba(255,107,107,0.2)", borderRadius: "6px", color: "#ff6b6b", fontSize: "0.8125rem" }}>
            {scan.error}
          </div>
        )}

        {/* Severity summary bar */}
        <SeveritySummaryBar summary={vulnFindings.length > 0 ? mergedSummary : scan.summary} />

        {/* Library vulnerability bubble chart */}
        {vulnFindings.length > 0 && <BubbleChart findings={vulnFindings} />}
      </section>

      {/* Findings / SBOM / History / Compare tabs */}
      <section className="card" style={{ marginTop: "1rem" }}>
        <div style={{ display: "flex", gap: "0.5rem", marginBottom: "1rem", flexWrap: "wrap" }}>
          <button
            type="button"
            onClick={() => setTab("findings")}
            style={tabStyle(tab === "findings")}
          >
            {t("Findings", "Ergebnisse")} ({findings.length > 0 ? vulnFindings.length : (scan.findingsCount || findingsTotal)})
          </button>
          <button
            type="button"
            onClick={() => setTab("sbom")}
            style={tabStyle(tab === "sbom")}
          >
            SBOM ({dedupedSbom.length || scan.sbomComponentCount || sbomTotal})
          </button>
          <button
            type="button"
            onClick={() => {
              setTab("history");
              if (history.length === 0 && !historyLoading) {
                loadHistory(historyRange);
              }
            }}
            style={tabStyle(tab === "history")}
          >
            {t("History", "Verlauf")}
          </button>
          <button
            type="button"
            onClick={() => {
              setTab("compare");
              if (otherScans.length === 0 && !compareLoading) {
                fetchScans({ targetId: scan.targetId, limit: 200 }).then(res => {
                  setOtherScans(res.items.filter(s => s.id !== scanId && s.status === "completed"));
                  setCompareTargetId(scan.targetId);
                }).catch(err => console.error("Failed to load scans", err));
              }
            }}
            style={tabStyle(tab === "compare")}
          >
            {t("Compare", "Vergleichen")}
          </button>
          <button
            type="button"
            onClick={() => setTab("alerts")}
            style={{
              ...tabStyle(tab === "alerts"),
              ...(alertFindings.length > 0 ? {
                borderColor: tab === "alerts" ? "rgba(255,107,107,0.5)" : "rgba(255,107,107,0.3)",
                background: tab === "alerts" ? "rgba(255,107,107,0.15)" : "rgba(255,107,107,0.05)",
                color: tab === "alerts" ? "#ff6b6b" : "#ff8787",
              } : {}),
            }}
          >
            {t("Security Alerts", "Sicherheitswarnungen")} ({alertFindings.length})
          </button>
          {isContainerImage && (
            <>
              <button
                type="button"
                onClick={() => setTab("bestpractices")}
                style={{
                  ...tabStyle(tab === "bestpractices"),
                  ...(complianceFindings.length > 0 ? {
                    borderColor: tab === "bestpractices" ? "rgba(252,196,25,0.5)" : "rgba(252,196,25,0.3)",
                    background: tab === "bestpractices" ? "rgba(252,196,25,0.15)" : "rgba(252,196,25,0.05)",
                    color: tab === "bestpractices" ? "#fcc419" : "#ffd43b",
                  } : {}),
                }}
              >
                {t("Best Practices", "Best Practices")} ({complianceFindings.length})
              </button>
              <button
                type="button"
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
                style={tabStyle(tab === "layers")}
              >
                {t("Layer Analysis", "Schichtanalyse")}
              </button>
            </>
          )}
          {sastFindings.length > 0 && (
            <button
              type="button"
              onClick={() => setTab("sast")}
              style={{
                ...tabStyle(tab === "sast"),
                borderColor: tab === "sast" ? "rgba(167,139,250,0.5)" : "rgba(167,139,250,0.3)",
                background: tab === "sast" ? "rgba(167,139,250,0.15)" : "rgba(167,139,250,0.05)",
                color: tab === "sast" ? "#a78bfa" : "#c4b5fd",
              }}
            >
              SAST ({sastFindings.length})
            </button>
          )}
          {secretFindings.length > 0 && (
            <button
              type="button"
              onClick={() => setTab("secrets")}
              style={{
                ...tabStyle(tab === "secrets"),
                borderColor: tab === "secrets" ? "rgba(56,189,248,0.5)" : "rgba(56,189,248,0.3)",
                background: tab === "secrets" ? "rgba(56,189,248,0.15)" : "rgba(56,189,248,0.05)",
                color: tab === "secrets" ? "#38bdf8" : "#7dd3fc",
              }}
            >
              {t("Secrets", "Secrets")} ({secretFindings.length})
            </button>
          )}
          {sbomTotal > 0 && (
            <button
              type="button"
              onClick={() => setTab("license-compliance")}
              style={{
                ...tabStyle(tab === "license-compliance"),
                borderColor: tab === "license-compliance" ? "rgba(99,230,190,0.5)" : "rgba(99,230,190,0.3)",
                background: tab === "license-compliance" ? "rgba(99,230,190,0.15)" : "rgba(99,230,190,0.05)",
                color: tab === "license-compliance" ? "#63e6be" : "#96f2d7",
              }}
            >
              {t("Licenses", "Lizenzen")}
            </button>
          )}
        </div>

        {tab === "findings" && (
          <>
            {/* Search + severity filter + actions */}
            <div style={{ marginBottom: "0.5rem", display: "flex", flexWrap: "wrap", alignItems: "center", gap: "0.5rem" }}>
              <input
                type="text"
                value={findingsSearch}
                onChange={e => setFindingsSearch(e.target.value)}
                placeholder={t("Search by CVE, package, scanner...", "Nach CVE, Paket, Scanner suchen...")}
                style={{
                  padding: "0.375rem 0.75rem",
                  borderRadius: "6px",
                  border: "1px solid rgba(255,255,255,0.15)",
                  background: "rgba(255,255,255,0.05)",
                  color: "#fff",
                  fontSize: "0.8125rem",
                  flex: "1 1 200px",
                  maxWidth: "500px",
                  minWidth: 0,
                  boxSizing: "border-box",
                  outline: "none",
                }}
              />
              <span style={{ fontSize: "0.75rem", color: "rgba(255,255,255,0.4)", whiteSpace: "nowrap" }}>
                {filteredMerged.length} {t("findings", "Ergebnisse")}
              </span>
            </div>
            <div style={{ display: "flex", gap: "0.375rem", marginBottom: "1rem", flexWrap: "wrap", alignItems: "center" }}>
              {[undefined, "critical", "high", "medium", "low"].map(sev => (
                <button
                  key={sev ?? "all"}
                  type="button"
                  onClick={() => setSeverityFilter(sev)}
                  style={{
                    padding: "0.25rem 0.625rem",
                    borderRadius: "4px",
                    border: severityFilter === sev ? "1px solid rgba(255,193,7,0.5)" : "1px solid rgba(255,255,255,0.1)",
                    background: severityFilter === sev ? "rgba(255,193,7,0.1)" : "transparent",
                    color: severityFilter === sev ? "#ffd43b" : "rgba(255,255,255,0.5)",
                    cursor: "pointer",
                    fontSize: "0.75rem",
                  }}
                >
                  {sev ? sev.charAt(0).toUpperCase() + sev.slice(1) : t("All", "Alle")}
                </button>
              ))}
              {/* Open all CVEs in vulnerability list */}
              {(() => {
                const cveIds = [...new Set(filteredMerged.map(f => f.vulnerabilityId).filter((v): v is string => !!v))];
                if (cveIds.length === 0) return null;
                const dql = `vuln_id:(${cveIds.join(" OR ")})`;
                return (
                  <Link
                    to={`/vulnerabilities?search=${encodeURIComponent(dql)}&mode=dql`}
                    style={{
                      marginLeft: "auto",
                      padding: "0.25rem 0.625rem",
                      borderRadius: "4px",
                      border: "1px solid rgba(255,193,7,0.3)",
                      background: "rgba(255,193,7,0.08)",
                      color: "#ffd43b",
                      textDecoration: "none",
                      fontSize: "0.75rem",
                      fontWeight: 500,
                      display: "inline-flex",
                      alignItems: "center",
                      gap: "0.25rem",
                    }}
                    title={t("Open all CVEs in vulnerability list", "Alle CVEs in Schwachstellenliste öffnen")}
                  >
                    ☰ {t("Open in vulnerability list", "In Schwachstellenliste öffnen")} ({cveIds.length})
                  </Link>
                );
              })()}
            </div>

            {filteredMerged.length === 0 ? (
              <p className="muted">{t("No findings.", "Keine Ergebnisse.")}</p>
            ) : (
              <div style={{ overflowX: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.8125rem" }}>
                  <thead>
                    <tr style={{ borderBottom: "1px solid rgba(255,255,255,0.1)" }}>
                      {([
                        ["cve", "CVE"],
                        ["package", t("Package", "Paket")],
                        ["version", t("Version", "Version")],
                        ["severity", t("Severity", "Schweregrad")],
                        ["fix", "Fix"],
                        ["scanner", t("Scanner", "Scanner")],
                      ] as const).map(([col, label]) => (
                        <th
                          key={col}
                          style={{ ...thStyle, cursor: "pointer", userSelect: "none", whiteSpace: "nowrap" }}
                          onClick={() => setFindingsSort(prev => prev.col === col ? { col, dir: prev.dir === "asc" ? "desc" : "asc" } : { col, dir: "asc" })}
                        >
                          {label} {findingsSort.col === col ? (findingsSort.dir === "asc" ? "\u25B2" : "\u25BC") : ""}
                        </th>
                      ))}
                      <th style={thStyle}>VEX</th>
                      <th style={thStyle}>{t("Links", "Links")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredMerged.map(f => {
                      const fDepsUrl = buildDepsDevUrl(f.packageName, f.packageVersion, f.packageType);
                      const fSnykUrl = buildSnykUrl(f.packageName, f.packageVersion, f.packageType);
                      return (
                        <tr key={f.key} style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                          <td style={tdStyle}>
                            {f.vulnerabilityId ? (
                              <span style={{ display: "inline-flex", alignItems: "center", gap: "0.25rem" }}>
                                <Link to={`/vulnerability/${f.vulnerabilityId}`} style={{ color: "#ffd43b", textDecoration: "none" }}>
                                  {f.vulnerabilityId}
                                </Link>
                                {f.matchedFrom && (
                                  <span style={{ fontSize: "0.625rem", color: "rgba(255,193,7,0.6)", padding: "0 0.25rem", borderRadius: "3px", background: "rgba(255,193,7,0.08)" }} title={t("Auto-matched from local DB", "Automatisch aus lokaler DB zugeordnet")}>
                                    auto
                                  </span>
                                )}
                              </span>
                            ) : (
                              <span style={{ color: "rgba(255,255,255,0.3)" }}>—</span>
                            )}
                          </td>
                          <td style={tdStyle}>{f.packageName}</td>
                          <td style={tdStyle}>{f.packageVersion || "—"}</td>
                          <td style={tdStyle}><SeverityChip severity={f.severity} /></td>
                          <td style={tdStyle}>
                            {f.fixVersion ? (
                              <span style={{ color: "#69db7c", fontSize: "0.75rem" }}>{f.fixVersion}</span>
                            ) : (
                              <span style={{ color: "rgba(255,255,255,0.3)", fontSize: "0.75rem" }}>
                                {f.fixState === "not_fixed" ? t("No fix", "Kein Fix") : "—"}
                              </span>
                            )}
                          </td>
                          <td style={tdStyle}>
                            <span style={{ color: "rgba(255,255,255,0.4)" }}>{f.scanners.join(", ")}</span>
                          </td>
                          <td style={tdStyle}>
                            {vexEditingId === f.key ? (
                              <div style={{ display: "flex", flexDirection: "column", gap: "0.25rem", minWidth: "140px" }}>
                                <select value={vexEditStatus} onChange={e => setVexEditStatus(e.target.value)}
                                  style={{ padding: "0.25rem 0.375rem", borderRadius: "4px", border: "1px solid rgba(255,255,255,0.15)", background: "rgba(255,255,255,0.05)", color: "#fff", fontSize: "0.6875rem" }}>
                                  <option value="">{t("— Clear —", "— Löschen —")}</option>
                                  <option value="not_affected">{t("Not Affected", "Nicht betroffen")}</option>
                                  <option value="affected">{t("Affected", "Betroffen")}</option>
                                  <option value="fixed">{t("Fixed", "Behoben")}</option>
                                  <option value="under_investigation">{t("Investigating", "In Prüfung")}</option>
                                </select>
                                <input type="text" value={vexEditJustification} onChange={e => setVexEditJustification(e.target.value)}
                                  placeholder={t("Justification...", "Begründung...")}
                                  style={{ padding: "0.25rem 0.375rem", borderRadius: "4px", border: "1px solid rgba(255,255,255,0.12)", background: "rgba(255,255,255,0.05)", color: "#fff", fontSize: "0.6875rem" }} />
                                <div style={{ display: "flex", gap: "0.25rem" }}>
                                  <button type="button" onClick={async () => {
                                    if (f.findingIds.length > 0) {
                                      await updateFindingVex(f.findingIds[0], { vexStatus: vexEditStatus || null, vexJustification: vexEditJustification || undefined });
                                    }
                                    setVexEditingId(null);
                                    if (scanId) {
                                      const data = await fetchScanFindings(scanId, { limit: 500 });
                                      setFindings(data.items);
                                      setFindingsTotal(data.total);
                                    }
                                  }} style={{ fontSize: "0.625rem", padding: "0.125rem 0.375rem", borderRadius: "3px", background: "rgba(99,230,190,0.15)", color: "#63e6be", border: "1px solid rgba(99,230,190,0.25)", cursor: "pointer" }}>
                                    {t("Save", "OK")}
                                  </button>
                                  <button type="button" onClick={() => setVexEditingId(null)}
                                    style={{ fontSize: "0.625rem", padding: "0.125rem 0.375rem", borderRadius: "3px", background: "rgba(255,255,255,0.06)", color: "rgba(255,255,255,0.5)", border: "1px solid rgba(255,255,255,0.1)", cursor: "pointer" }}>
                                    {t("Cancel", "X")}
                                  </button>
                                </div>
                              </div>
                            ) : (
                              <span
                                onClick={() => { setVexEditingId(f.key); setVexEditStatus(f.vexStatus || ""); setVexEditJustification(f.vexJustification || ""); }}
                                style={{ cursor: "pointer" }}
                                title={f.vexJustification || t("Click to set VEX status", "Klicken um VEX-Status zu setzen")}
                              >
                                {f.vexStatus ? (() => {
                                  const vexColors: Record<string, string> = { not_affected: "#69db7c", affected: "#ff6b6b", fixed: "#5c84ff", under_investigation: "#fcc419" };
                                  const vexLabels: Record<string, string> = { not_affected: "Not Affected", affected: "Affected", fixed: "Fixed", under_investigation: "Investigating" };
                                  const c = vexColors[f.vexStatus] || "rgba(255,255,255,0.4)";
                                  return (
                                    <span style={{ padding: "0.0625rem 0.375rem", borderRadius: "4px", fontSize: "0.6875rem", fontWeight: 500, background: `${c}15`, color: c, border: `1px solid ${c}30` }}>
                                      {vexLabels[f.vexStatus] || f.vexStatus}
                                    </span>
                                  );
                                })() : (
                                  <span style={{ color: "rgba(255,255,255,0.2)", fontSize: "0.6875rem" }}>—</span>
                                )}
                              </span>
                            )}
                          </td>
                          <td style={tdStyle}>
                            <div style={{ display: "flex", gap: "0.375rem" }}>
                              {fDepsUrl && (
                                <a href={fDepsUrl} target="_blank" rel="noopener noreferrer" title="deps.dev"
                                  style={{ color: "#ffd43b", textDecoration: "none", fontSize: "0.7rem", padding: "0.125rem 0.375rem", borderRadius: "3px", background: "rgba(255,193,7,0.1)", border: "1px solid rgba(255,193,7,0.2)" }}>
                                  deps.dev
                                </a>
                              )}
                              {fSnykUrl && (
                                <a href={fSnykUrl} target="_blank" rel="noopener noreferrer" title="Snyk"
                                  style={{ color: "#a78bfa", textDecoration: "none", fontSize: "0.7rem", padding: "0.125rem 0.375rem", borderRadius: "3px", background: "rgba(167,139,250,0.1)", border: "1px solid rgba(167,139,250,0.2)" }}>
                                  Snyk
                                </a>
                              )}
                            </div>
                          </td>
                        </tr>
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
            <div style={{ marginBottom: "1rem", display: "flex", flexWrap: "wrap", alignItems: "center", gap: "0.5rem" }}>
              <input
                type="text"
                value={sbomSearch}
                onChange={e => setSbomSearch(e.target.value)}
                placeholder={t("Search by name, type, license, purl...", "Nach Name, Typ, Lizenz, PURL suchen...")}
                style={{
                  padding: "0.375rem 0.75rem",
                  borderRadius: "6px",
                  border: "1px solid rgba(255,255,255,0.15)",
                  background: "rgba(255,255,255,0.05)",
                  color: "#fff",
                  fontSize: "0.8125rem",
                  flex: "1 1 200px",
                  maxWidth: "500px",
                  minWidth: 0,
                  boxSizing: "border-box",
                  outline: "none",
                }}
              />
              <span style={{ fontSize: "0.75rem", color: "rgba(255,255,255,0.4)", whiteSpace: "nowrap" }}>
                {dedupedSbom.length} {t("components", "Komponenten")}
              </span>
              <div style={{ display: "flex", gap: "0.375rem", marginLeft: "auto" }}>
                <button
                  onClick={() => void handleSbomExport("cyclonedx-json")}
                  disabled={!!sbomExporting || dedupedSbom.length === 0}
                  style={{
                    padding: "0.25rem 0.625rem", borderRadius: "4px", fontSize: "0.7rem", fontWeight: 600, cursor: sbomExporting ? "wait" : "pointer",
                    background: "rgba(105,219,124,0.12)", color: "#69db7c", border: "1px solid rgba(105,219,124,0.3)",
                  }}
                >
                  {sbomExporting === "cyclonedx-json" ? "..." : "CycloneDX"}
                </button>
                <button
                  onClick={() => void handleSbomExport("spdx-json")}
                  disabled={!!sbomExporting || dedupedSbom.length === 0}
                  style={{
                    padding: "0.25rem 0.625rem", borderRadius: "4px", fontSize: "0.7rem", fontWeight: 600, cursor: sbomExporting ? "wait" : "pointer",
                    background: "rgba(139,148,252,0.12)", color: "#8b94fc", border: "1px solid rgba(139,148,252,0.3)",
                  }}
                >
                  {sbomExporting === "spdx-json" ? "..." : "SPDX"}
                </button>
                <button
                  onClick={async () => {
                    if (!scanId) return;
                    try {
                      const blob = await exportVex(scanId);
                      const url = URL.createObjectURL(blob);
                      const a = document.createElement("a");
                      a.href = url;
                      a.download = `vex-${scanId}.cdx.json`;
                      a.click();
                      URL.revokeObjectURL(url);
                    } catch {
                      // VEX export may fail if no VEX data
                    }
                  }}
                  style={{
                    padding: "0.25rem 0.625rem", borderRadius: "4px", fontSize: "0.7rem", fontWeight: 600, cursor: "pointer",
                    background: "rgba(99,230,190,0.12)", color: "#63e6be", border: "1px solid rgba(99,230,190,0.3)",
                  }}
                >
                  VEX
                </button>
              </div>
            </div>

            {dedupedSbom.length > 0 && (
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: "0.75rem", marginBottom: "1rem" }}>
                {[
                  { title: t("Ecosystems", "Ökosysteme"), data: sbomStats.ecosystems, color: "#ffd43b" },
                  { title: t("Licenses", "Lizenzen"), data: sbomStats.licenses, color: "#69db7c" },
                  { title: t("Types", "Typen"), data: sbomStats.types, color: "#8b94fc" },
                ].map(card => (
                  <div key={card.title} style={{ padding: "0.75rem", borderRadius: "8px", background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.06)" }}>
                    <div style={{ fontSize: "0.7rem", color: "rgba(255,255,255,0.4)", marginBottom: "0.5rem", fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.05em" }}>
                      {card.title}
                    </div>
                    {card.data.slice(0, 5).map(([name, count]) => (
                      <div key={name} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "0.125rem 0", fontSize: "0.75rem" }}>
                        <span style={{ color: "rgba(255,255,255,0.7)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", marginRight: "0.5rem" }}>{name}</span>
                        <span style={{ color: card.color, fontWeight: 600, flexShrink: 0 }}>{count}</span>
                      </div>
                    ))}
                    {card.data.length > 5 && (
                      <div style={{ fontSize: "0.7rem", color: "rgba(255,255,255,0.3)", marginTop: "0.25rem" }}>
                        +{card.data.length - 5} {t("more", "weitere")}
                      </div>
                    )}
                    {card.data.length === 0 && (
                      <div style={{ fontSize: "0.75rem", color: "rgba(255,255,255,0.2)" }}>—</div>
                    )}
                  </div>
                ))}
              </div>
            )}

            {dedupedSbom.length === 0 ? (
              <p className="muted">{t("No SBOM components.", "Keine SBOM-Komponenten.")}</p>
            ) : (
              <div style={{ overflowX: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.8125rem" }}>
                  <thead>
                    <tr style={{ borderBottom: "1px solid rgba(255,255,255,0.1)" }}>
                      <th style={thStyle}>{t("Component", "Komponente")}</th>
                      <th style={thStyle}>{t("Version", "Version")}</th>
                      <th style={thStyle}>{t("Type", "Typ")}</th>
                      <th style={thStyle}>{t("Provenance", "Provenienz")}</th>
                      <th style={thStyle}>{t("Licenses", "Lizenzen")}</th>
                      <th style={thStyle}>{t("Supplier", "Lieferant")}</th>
                      <th style={thStyle}>{t("Links", "Links")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {dedupedSbom.map(c => {
                      const depsUrl = buildDepsDevUrl(c.name, c.version, c.type, c.purl);
                      const snykUrl = buildSnykUrl(c.name, c.version, c.type, c.purl);
                      const registryLink = buildRegistryUrl(c.name, c.version, c.type, c.purl);
                      return (
                        <tr key={c.id} style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                          <td style={tdStyle}>
                            <div>{c.name}</div>
                            {c.purl && (
                              <div style={{ fontSize: "0.7rem", color: "rgba(255,255,255,0.3)", wordBreak: "break-all", marginTop: "0.125rem" }}>
                                {c.purl}
                              </div>
                            )}
                          </td>
                          <td style={tdStyle}>{c.version || "—"}</td>
                          <td style={tdStyle}>
                            <span style={{
                              padding: "0.125rem 0.375rem",
                              borderRadius: "3px",
                              fontSize: "0.7rem",
                              background: "rgba(255,255,255,0.06)",
                              color: "rgba(255,255,255,0.5)",
                            }}>
                              {c.type || "—"}
                            </span>
                          </td>
                          <td style={tdStyle}>
                            {c.provenanceVerified === true ? (
                              <span
                                title={[
                                  c.provenanceAttestationType && `Attestation: ${c.provenanceAttestationType}`,
                                  c.provenanceBuildSystem && `Build: ${c.provenanceBuildSystem}`,
                                  c.provenanceSourceRepo && `Source: ${c.provenanceSourceRepo}`,
                                ].filter(Boolean).join("\n") || t("Provenance verified", "Provenienz verifiziert")}
                                style={{ color: "#69db7c", fontSize: "0.8125rem", cursor: "help" }}
                              >
                                &#10003; {c.provenanceAttestationType || t("Verified", "Verifiziert")}
                              </span>
                            ) : c.provenanceVerified === false ? (
                              <span style={{ color: "#ffa94d", fontSize: "0.75rem" }} title={t("No provenance attestation found", "Keine Provenienz-Attestierung gefunden")}>
                                &#9888; {t("Unverified", "Nicht verifiziert")}
                              </span>
                            ) : (
                              <span style={{ color: "rgba(255,255,255,0.2)" }}>—</span>
                            )}
                          </td>
                          <td style={tdStyle}>
                            {c.licenses.length > 0
                              ? c.licenses.map((lic, i) => (
                                  <span key={i} style={{
                                    display: "inline-block",
                                    padding: "0.125rem 0.375rem",
                                    borderRadius: "3px",
                                    fontSize: "0.7rem",
                                    background: "rgba(105,219,124,0.1)",
                                    color: "#69db7c",
                                    marginRight: "0.25rem",
                                    marginBottom: "0.125rem",
                                  }}>
                                    {lic}
                                  </span>
                                ))
                              : <span style={{ color: "rgba(255,255,255,0.3)" }}>—</span>}
                          </td>
                          <td style={tdStyle}>
                            <span style={{ color: "rgba(255,255,255,0.4)", fontSize: "0.75rem" }}>{c.supplier || "—"}</span>
                          </td>
                          <td style={tdStyle}>
                            <div style={{ display: "flex", gap: "0.5rem" }}>
                              {depsUrl && (
                                <a href={depsUrl} target="_blank" rel="noopener noreferrer" title="deps.dev"
                                  style={{ color: "#ffd43b", textDecoration: "none", fontSize: "0.7rem", padding: "0.125rem 0.375rem", borderRadius: "3px", background: "rgba(255,193,7,0.1)", border: "1px solid rgba(255,193,7,0.2)" }}>
                                  deps.dev
                                </a>
                              )}
                              {snykUrl && (
                                <a href={snykUrl} target="_blank" rel="noopener noreferrer" title="Snyk"
                                  style={{ color: "#a78bfa", textDecoration: "none", fontSize: "0.7rem", padding: "0.125rem 0.375rem", borderRadius: "3px", background: "rgba(167,139,250,0.1)", border: "1px solid rgba(167,139,250,0.2)" }}>
                                  Snyk
                                </a>
                              )}
                              {registryLink && (
                                <a href={registryLink.url} target="_blank" rel="noopener noreferrer" title={registryLink.label}
                                  style={{ color: "#63e6be", textDecoration: "none", fontSize: "0.7rem", padding: "0.125rem 0.375rem", borderRadius: "3px", background: "rgba(99,230,190,0.1)", border: "1px solid rgba(99,230,190,0.2)" }}>
                                  {registryLink.label}
                                </a>
                              )}
                              {!depsUrl && !snykUrl && !registryLink && <span style={{ color: "rgba(255,255,255,0.2)" }}>—</span>}
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}

        {/* History tab */}
        {tab === "history" && (
          <>
            <div style={{ display: "flex", gap: "0.25rem", marginBottom: "1rem" }}>
              {(["7d", "30d", "90d", "all"] as HistoryRange[]).map(range => {
                const active = historyRange === range;
                const label = range === "all" ? t("All", "Alle") : range;
                return (
                  <button
                    key={range}
                    type="button"
                    onClick={() => { setHistoryRange(range); loadHistory(range); }}
                    style={{
                      padding: "0 0.625rem",
                      borderRadius: "4px",
                      border: `1px solid ${active ? "#ffd43b" : "rgba(255,255,255,0.1)"}`,
                      background: active ? "rgba(255,212,59,0.13)" : "transparent",
                      color: active ? "#ffd43b" : "rgba(255,255,255,0.4)",
                      cursor: "pointer",
                      fontSize: "0.75rem",
                      fontWeight: active ? 600 : 400,
                      height: "32px",
                      boxSizing: "border-box" as const,
                    }}
                  >
                    {label}
                  </button>
                );
              })}
              <span style={{ marginLeft: "auto", color: "rgba(255,255,255,0.3)", fontSize: "0.75rem", alignSelf: "center" }}>
                {history.length} {t("scans", "Scans")}
              </span>
            </div>
            {historyLoading ? (
              <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
                {Array.from({ length: 4 }).map((_, i) => (
                  <SkeletonBlock key={i} height={40} radius={4} />
                ))}
              </div>
            ) : history.length < 2 ? (
              <p className="muted">{t("Not enough scan history for a chart. Run more scans.", "Nicht genügend Scan-Verlauf für ein Diagramm. Führen Sie weitere Scans durch.")}</p>
            ) : (
              <>
                <HistoryChart history={history} />
                <HistoryChangesTable history={history} targetId={scan.targetId} />
              </>
            )}
          </>
        )}

        {/* Compare tab */}
        {tab === "compare" && (
          <>
            <div style={{ marginBottom: "1rem", display: "flex", gap: "0.75rem", alignItems: "center", flexWrap: "wrap" }}>
              <span style={{ fontSize: "0.8125rem", color: "rgba(255,255,255,0.5)" }}>
                {t("Compare with:", "Vergleichen mit:")}
              </span>
              <select
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
                style={{
                  padding: "0.375rem 0.75rem",
                  borderRadius: "6px",
                  border: "1px solid rgba(255,255,255,0.15)",
                  background: "rgba(255,255,255,0.05)",
                  color: "#fff",
                  fontSize: "0.8125rem",
                  outline: "none",
                }}
              >
                <option value="">{t("Select a scan...", "Scan auswählen...")}</option>
                {otherScans.map(s => (
                  <option key={s.id} value={s.id}>
                    {formatDateTime(s.startedAt)} — {s.summary.total} findings
                  </option>
                ))}
              </select>
              {compareLoading && <span style={{ fontSize: "0.8125rem", color: "rgba(255,255,255,0.4)" }}>{t("Comparing...", "Vergleiche...")}</span>}
            </div>

            {comparison && <ComparisonView comparison={comparison} />}
            {!comparison && !compareScanId && !compareLoading && (
              <p className="muted">{t("Select another scan of this target to compare.", "Wählen Sie einen anderen Scan dieses Ziels zum Vergleich.")}</p>
            )}
          </>
        )}

        {tab === "bestpractices" && (
          <>
            {complianceFindings.length === 0 ? (
              <div style={{ padding: "1.5rem", textAlign: "center", background: "rgba(99,230,190,0.05)", border: "1px solid rgba(99,230,190,0.15)", borderRadius: "8px" }}>
                <div style={{ fontSize: "1.5rem", marginBottom: "0.5rem" }}>&#x2713;</div>
                <p style={{ color: "#63e6be", margin: 0, fontSize: "0.875rem" }}>
                  {t("All CIS Docker Benchmark checks passed.", "Alle CIS-Docker-Benchmark-Checks bestanden.")}
                </p>
              </div>
            ) : (
              <>
                {/* Summary banner */}
                <div style={{
                  padding: "0.75rem 1rem",
                  marginBottom: "1rem",
                  background: "rgba(252,196,25,0.08)",
                  border: "1px solid rgba(252,196,25,0.2)",
                  borderRadius: "8px",
                  display: "flex",
                  gap: "1rem",
                  alignItems: "center",
                  flexWrap: "wrap",
                }}>
                  <span style={{ color: "#fcc419", fontWeight: 600, fontSize: "0.875rem" }}>
                    {t(
                      `${complianceFindings.length} compliance issue${complianceFindings.length !== 1 ? "s" : ""} found`,
                      `${complianceFindings.length} Compliance-Problem${complianceFindings.length !== 1 ? "e" : ""} gefunden`,
                    )}
                  </span>
                  <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
                    {(() => {
                      const sevs: Record<string, number> = {};
                      for (const f of complianceFindings) {
                        const s = f.severity.toLowerCase();
                        sevs[s] = (sevs[s] || 0) + 1;
                      }
                      return Object.entries(sevs).map(([s, count]) => (
                        <span key={s} style={{
                          padding: "0.125rem 0.5rem",
                          borderRadius: "4px",
                          fontSize: "0.7rem",
                          background: s === "critical" ? "rgba(255,107,107,0.1)" : s === "medium" ? "rgba(252,196,25,0.1)" : "rgba(255,255,255,0.06)",
                          color: s === "critical" ? "#ff6b6b" : s === "medium" ? "#fcc419" : "rgba(255,255,255,0.5)",
                        }}>
                          {count} {s}
                        </span>
                      ));
                    })()}
                  </div>
                </div>

                {/* Compliance cards */}
                <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
                  {complianceFindings.map((check, idx) => {
                    const sev = check.severity.toLowerCase();
                    const sevColor = sev === "critical" ? "#ff6b6b" : sev === "high" ? "#ff922b" : sev === "medium" ? "#fcc419" : sev === "low" ? "#69db7c" : "#868e96";
                    const category = check.dataSource?.includes("cis") ? "CIS" : "DKL";
                    const alerts = (check.description || "").split("\n").filter(Boolean);

                    return (
                      <div key={idx} style={{
                        background: "rgba(255,255,255,0.02)",
                        border: `1px solid ${sevColor}33`,
                        borderLeft: `4px solid ${sevColor}`,
                        borderRadius: "8px",
                        padding: "1rem",
                      }}>
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: "1rem", flexWrap: "wrap" }}>
                          <div style={{ flex: 1, minWidth: 0 }}>
                            <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.375rem", flexWrap: "wrap" }}>
                              <span style={{
                                padding: "0.125rem 0.5rem",
                                borderRadius: "4px",
                                fontSize: "0.7rem",
                                fontWeight: 700,
                                textTransform: "uppercase",
                                background: `${sevColor}20`,
                                color: sevColor,
                              }}>
                                {sev}
                              </span>
                              <span style={{ fontWeight: 600, fontSize: "0.875rem", color: "#fff" }}>
                                {check.title}
                              </span>
                            </div>

                            {/* Alert messages as bullet list */}
                            {alerts.length > 0 && (
                              <ul style={{ margin: "0.375rem 0 0 0", paddingLeft: "1.25rem", listStyle: "disc" }}>
                                {alerts.map((msg, i) => (
                                  <li key={i} style={{ fontSize: "0.8125rem", color: "rgba(255,255,255,0.5)", lineHeight: 1.5 }}>
                                    {msg}
                                  </li>
                                ))}
                              </ul>
                            )}
                          </div>

                          {/* Category badge */}
                          <span style={{
                            padding: "0.125rem 0.5rem",
                            borderRadius: "4px",
                            fontSize: "0.7rem",
                            background: "rgba(92,132,255,0.1)",
                            color: "#5c84ff",
                            border: "1px solid rgba(92,132,255,0.2)",
                            flexShrink: 0,
                          }}>
                            {category}
                          </span>
                        </div>
                      </div>
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
              <SkeletonBlock lines={6} />
            ) : !scan?.layerAnalysisAvailable ? (
              <div style={{ padding: "1.5rem", textAlign: "center", background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: "8px" }}>
                <p style={{ color: "rgba(255,255,255,0.4)", margin: 0, fontSize: "0.875rem" }}>
                  {t(
                    "No layer analysis available. Run a scan with Dive enabled to see layer data.",
                    "Keine Schichtanalyse verfügbar. Führen Sie einen Scan mit aktiviertem Dive durch.",
                  )}
                </p>
              </div>
            ) : layerAnalysis ? (
              <>
                {/* Efficiency & Waste summary */}
                <div style={{ display: "flex", gap: "1rem", marginBottom: "1rem", flexWrap: "wrap" }}>
                  {/* Efficiency gauge */}
                  <div style={{
                    flex: "1 1 200px",
                    padding: "1rem",
                    background: "rgba(255,255,255,0.02)",
                    border: "1px solid rgba(255,255,255,0.06)",
                    borderRadius: "8px",
                  }}>
                    <div style={{ fontSize: "0.75rem", color: "rgba(255,255,255,0.5)", marginBottom: "0.5rem" }}>
                      {t("Image Efficiency", "Image-Effizienz")}
                    </div>
                    <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
                      <span style={{
                        fontSize: "1.5rem",
                        fontWeight: 700,
                        color: layerAnalysis.efficiency >= 0.9 ? "#63e6be" : layerAnalysis.efficiency >= 0.7 ? "#fcc419" : "#ff6b6b",
                      }}>
                        {(layerAnalysis.efficiency * 100).toFixed(1)}%
                      </span>
                      <div style={{ flex: 1, height: "8px", background: "rgba(255,255,255,0.06)", borderRadius: "4px", overflow: "hidden" }}>
                        <div style={{
                          height: "100%",
                          width: `${Math.min(layerAnalysis.efficiency * 100, 100)}%`,
                          background: layerAnalysis.efficiency >= 0.9 ? "#63e6be" : layerAnalysis.efficiency >= 0.7 ? "#fcc419" : "#ff6b6b",
                          borderRadius: "4px",
                          transition: "width 0.3s",
                        }} />
                      </div>
                    </div>
                  </div>

                  {/* Wasted space */}
                  <div style={{
                    flex: "1 1 200px",
                    padding: "1rem",
                    background: "rgba(255,255,255,0.02)",
                    border: "1px solid rgba(255,255,255,0.06)",
                    borderRadius: "8px",
                  }}>
                    <div style={{ fontSize: "0.75rem", color: "rgba(255,255,255,0.5)", marginBottom: "0.5rem" }}>
                      {t("Wasted Space", "Verschwendeter Speicher")}
                    </div>
                    <div style={{ fontSize: "1.5rem", fontWeight: 700, color: layerAnalysis.wastedBytes > 0 ? "#ff922b" : "#63e6be" }}>
                      {formatBytes(layerAnalysis.wastedBytes)}
                    </div>
                    <div style={{ fontSize: "0.75rem", color: "rgba(255,255,255,0.4)", marginTop: "0.25rem" }}>
                      {(layerAnalysis.userWastedPercent * 100).toFixed(1)}% {t("of total", "vom Gesamten")}
                    </div>
                  </div>

                  {/* Total image size */}
                  <div style={{
                    flex: "1 1 200px",
                    padding: "1rem",
                    background: "rgba(255,255,255,0.02)",
                    border: "1px solid rgba(255,255,255,0.06)",
                    borderRadius: "8px",
                  }}>
                    <div style={{ fontSize: "0.75rem", color: "rgba(255,255,255,0.5)", marginBottom: "0.5rem" }}>
                      {t("Total Image Size", "Gesamte Image-Größe")}
                    </div>
                    <div style={{ fontSize: "1.5rem", fontWeight: 700, color: "#fff" }}>
                      {formatBytes(layerAnalysis.totalImageSize)}
                    </div>
                    <div style={{ fontSize: "0.75rem", color: "rgba(255,255,255,0.4)", marginTop: "0.25rem" }}>
                      {layerAnalysis.layers.length} {t("layers", "Schichten")}
                    </div>
                  </div>

                  {/* Pass/Fail badge */}
                  <div style={{
                    flex: "0 0 auto",
                    padding: "1rem",
                    background: layerAnalysis.passThreshold ? "rgba(99,230,190,0.05)" : "rgba(255,107,107,0.05)",
                    border: `1px solid ${layerAnalysis.passThreshold ? "rgba(99,230,190,0.15)" : "rgba(255,107,107,0.15)"}`,
                    borderRadius: "8px",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    minWidth: "80px",
                  }}>
                    <span style={{
                      fontSize: "1rem",
                      fontWeight: 700,
                      color: layerAnalysis.passThreshold ? "#63e6be" : "#ff6b6b",
                    }}>
                      {layerAnalysis.passThreshold ? t("PASS", "OK") : t("FAIL", "FEHLER")}
                    </span>
                  </div>
                </div>

                {/* Layer table */}
                <div style={{ overflowX: "auto" }}>
                  <table style={{ width: "100%", borderCollapse: "collapse" }}>
                    <thead>
                      <tr style={{ borderBottom: "1px solid rgba(255,255,255,0.08)" }}>
                        <th style={{ ...thStyle, width: "50px" }}>#</th>
                        <th style={thStyle}>{t("Command", "Befehl")}</th>
                        <th style={{ ...thStyle, width: "120px", textAlign: "right" }}>{t("Size", "Größe")}</th>
                        <th style={{ ...thStyle, width: "100px", textAlign: "right" }}>%</th>
                      </tr>
                    </thead>
                    <tbody>
                      {layerAnalysis.layers.map((layer) => {
                        const pct = layerAnalysis.totalImageSize > 0
                          ? (layer.sizeBytes / layerAnalysis.totalImageSize) * 100
                          : 0;
                        return (
                          <tr key={layer.index} style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                            <td style={{ ...tdStyle, color: "rgba(255,255,255,0.4)", fontFamily: "monospace", fontSize: "0.75rem" }}>
                              {layer.index + 1}
                            </td>
                            <td style={{ ...tdStyle, fontFamily: "monospace", fontSize: "0.75rem", maxWidth: "600px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                              title={layer.command}
                            >
                              {layer.command || layer.digest.substring(0, 12)}
                            </td>
                            <td style={{ ...tdStyle, textAlign: "right", fontFamily: "monospace", fontSize: "0.8125rem" }}>
                              {formatBytes(layer.sizeBytes)}
                            </td>
                            <td style={{ ...tdStyle, textAlign: "right" }}>
                              <div style={{ display: "flex", alignItems: "center", justifyContent: "flex-end", gap: "0.5rem" }}>
                                <div style={{
                                  width: "60px",
                                  height: "6px",
                                  background: "rgba(255,255,255,0.06)",
                                  borderRadius: "3px",
                                  overflow: "hidden",
                                }}>
                                  <div style={{
                                    height: "100%",
                                    width: `${Math.min(pct, 100)}%`,
                                    background: pct > 50 ? "#ff922b" : pct > 20 ? "#fcc419" : "#63e6be",
                                    borderRadius: "3px",
                                  }} />
                                </div>
                                <span style={{ fontSize: "0.75rem", color: "rgba(255,255,255,0.5)", minWidth: "40px", textAlign: "right" }}>
                                  {pct.toFixed(1)}%
                                </span>
                              </div>
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
              <div style={{ padding: "1.5rem", textAlign: "center", background: "rgba(99,230,190,0.05)", border: "1px solid rgba(99,230,190,0.15)", borderRadius: "8px" }}>
                <div style={{ fontSize: "1.5rem", marginBottom: "0.5rem" }}>&#x2713;</div>
                <p style={{ color: "#63e6be", margin: 0, fontSize: "0.875rem" }}>
                  {t("No malicious package indicators detected.", "Keine Hinweise auf bösartige Pakete erkannt.")}
                </p>
              </div>
            ) : (
              <>
                {/* Summary banner */}
                <div style={{
                  padding: "0.75rem 1rem",
                  marginBottom: "1rem",
                  background: "rgba(255,107,107,0.08)",
                  border: "1px solid rgba(255,107,107,0.2)",
                  borderRadius: "8px",
                  display: "flex",
                  gap: "1rem",
                  alignItems: "center",
                  flexWrap: "wrap",
                }}>
                  <span style={{ color: "#ff6b6b", fontWeight: 600, fontSize: "0.875rem" }}>
                    {t(
                      `${alertFindings.length} security alert${alertFindings.length !== 1 ? "s" : ""} detected`,
                      `${alertFindings.length} Sicherheitswarnung${alertFindings.length !== 1 ? "en" : ""} erkannt`,
                    )}
                  </span>
                  <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
                    {(() => {
                      const cats: Record<string, number> = {};
                      for (const f of alertFindings) {
                        const cat = f.dataSource?.replace("hecate-malware-detector:", "") || "unknown";
                        cats[cat] = (cats[cat] || 0) + 1;
                      }
                      return Object.entries(cats).map(([cat, count]) => (
                        <span key={cat} style={{
                          padding: "0.125rem 0.5rem",
                          borderRadius: "4px",
                          fontSize: "0.7rem",
                          background: "rgba(255,255,255,0.06)",
                          color: "rgba(255,255,255,0.5)",
                        }}>
                          {count} {cat.replace(/_/g, " ")}
                        </span>
                      ));
                    })()}
                  </div>
                </div>

                {/* Alert cards */}
                <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
                  {alertFindings.map((alert, idx) => {
                    const sev = alert.severity.toLowerCase();
                    const sevColor = sev === "critical" ? "#ff6b6b" : sev === "high" ? "#ff922b" : sev === "medium" ? "#fcc419" : "#69db7c";
                    const category = alert.dataSource?.replace("hecate-malware-detector:", "") || "";
                    // Split description into main text and evidence
                    const descParts = (alert.description || "").split("\n\nEvidence: ");
                    const mainDesc = descParts[0] || "";
                    const evidenceAndConf = descParts[1] || "";
                    const evidenceParts = evidenceAndConf.split("\nConfidence: ");
                    const evidence = evidenceParts[0] || "";
                    const confidence = evidenceParts[1] || "medium";

                    return (
                      <div key={idx} style={{
                        background: "rgba(255,255,255,0.02)",
                        border: `1px solid ${sevColor}33`,
                        borderLeft: `4px solid ${sevColor}`,
                        borderRadius: "8px",
                        padding: "1rem",
                      }}>
                        <div className="scan-card-row" style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: "1rem", flexWrap: "wrap" }}>
                          <div style={{ flex: 1, minWidth: 0 }}>
                            {/* Title with severity */}
                            <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.375rem", flexWrap: "wrap" }}>
                              <span style={{
                                padding: "0.125rem 0.5rem",
                                borderRadius: "4px",
                                fontSize: "0.7rem",
                                fontWeight: 700,
                                textTransform: "uppercase",
                                background: `${sevColor}20`,
                                color: sevColor,
                              }}>
                                {sev}
                              </span>
                              <span style={{ fontWeight: 600, fontSize: "0.875rem", color: "#fff" }}>
                                {alert.title}
                              </span>
                            </div>

                            {/* Package info */}
                            <div style={{ fontSize: "0.8125rem", color: "rgba(255,255,255,0.6)", marginBottom: "0.375rem" }}>
                              <span style={{ color: "rgba(255,255,255,0.8)" }}>{alert.packageName}</span>
                              {alert.packageVersion && <span> @ {alert.packageVersion}</span>}
                              {alert.packagePath && (
                                <span style={{ marginLeft: "0.75rem", color: "rgba(255,255,255,0.4)", fontFamily: "monospace", fontSize: "0.75rem" }}>
                                  {alert.packagePath}
                                </span>
                              )}
                            </div>

                            {/* Description */}
                            <p style={{ fontSize: "0.8125rem", color: "rgba(255,255,255,0.5)", margin: "0.375rem 0", lineHeight: 1.5 }}>
                              {mainDesc}
                            </p>

                            {/* Evidence block */}
                            {evidence && (
                              <div style={{
                                marginTop: "0.5rem",
                                padding: "0.5rem 0.75rem",
                                background: "rgba(0,0,0,0.3)",
                                borderRadius: "4px",
                                fontFamily: "monospace",
                                fontSize: "0.75rem",
                                color: "rgba(255,255,255,0.6)",
                                overflowX: "auto",
                                whiteSpace: "pre-wrap",
                                wordBreak: "break-all",
                                maxHeight: "120px",
                              }}>
                                {evidence}
                              </div>
                            )}
                          </div>

                          {/* Right side badges */}
                          <div className="scan-card-badges" style={{ display: "flex", flexDirection: "column", gap: "0.375rem", alignItems: "flex-end", flexShrink: 0 }}>
                            {category && (
                              <span style={{
                                padding: "0.125rem 0.5rem",
                                borderRadius: "4px",
                                fontSize: "0.7rem",
                                background: "rgba(92,132,255,0.1)",
                                color: "#5c84ff",
                                border: "1px solid rgba(92,132,255,0.2)",
                              }}>
                                {category.replace(/_/g, " ")}
                              </span>
                            )}
                            <span style={{
                              padding: "0.125rem 0.5rem",
                              borderRadius: "4px",
                              fontSize: "0.7rem",
                              background: confidence === "high" ? "rgba(255,107,107,0.1)" : confidence === "medium" ? "rgba(252,196,25,0.1)" : "rgba(255,255,255,0.05)",
                              color: confidence === "high" ? "#ff8787" : confidence === "medium" ? "#fcc419" : "rgba(255,255,255,0.4)",
                              border: `1px solid ${confidence === "high" ? "rgba(255,107,107,0.2)" : confidence === "medium" ? "rgba(252,196,25,0.2)" : "rgba(255,255,255,0.1)"}`,
                            }}>
                              {confidence} {t("confidence", "Konfidenz")}
                            </span>
                          </div>
                        </div>
                      </div>
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
              <div style={{ padding: "1.5rem", textAlign: "center", background: "rgba(99,230,190,0.05)", border: "1px solid rgba(99,230,190,0.15)", borderRadius: "8px" }}>
                <div style={{ fontSize: "1.5rem", marginBottom: "0.5rem" }}>&#x2713;</div>
                <p style={{ color: "#63e6be", margin: 0, fontSize: "0.875rem" }}>
                  {t("No SAST findings.", "Keine SAST-Ergebnisse.")}
                </p>
              </div>
            ) : (
              <>
                {/* Summary banner */}
                <div style={{
                  padding: "0.75rem 1rem",
                  marginBottom: "1rem",
                  background: "rgba(167,139,250,0.08)",
                  border: "1px solid rgba(167,139,250,0.2)",
                  borderRadius: "8px",
                  display: "flex",
                  gap: "1rem",
                  alignItems: "center",
                  flexWrap: "wrap",
                }}>
                  <span style={{ color: "#a78bfa", fontWeight: 600, fontSize: "0.875rem" }}>
                    {t(
                      `${sastFindings.length} code issue${sastFindings.length !== 1 ? "s" : ""} found by Semgrep`,
                      `${sastFindings.length} Code-Problem${sastFindings.length !== 1 ? "e" : ""} von Semgrep gefunden`,
                    )}
                  </span>
                  <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
                    {(() => {
                      const sevs: Record<string, number> = {};
                      for (const f of sastFindings) {
                        const s = f.severity.toLowerCase();
                        sevs[s] = (sevs[s] || 0) + 1;
                      }
                      return Object.entries(sevs).sort(([a], [b]) => {
                        const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
                        return (order[a] ?? 9) - (order[b] ?? 9);
                      }).map(([s, count]) => (
                        <span key={s} style={{
                          padding: "0.125rem 0.5rem",
                          borderRadius: "4px",
                          fontSize: "0.7rem",
                          background: s === "critical" ? "rgba(255,107,107,0.1)" : s === "high" ? "rgba(255,146,43,0.1)" : s === "medium" ? "rgba(252,196,25,0.1)" : "rgba(255,255,255,0.06)",
                          color: s === "critical" ? "#ff6b6b" : s === "high" ? "#ff922b" : s === "medium" ? "#fcc419" : "rgba(255,255,255,0.5)",
                        }}>
                          {count} {s}
                        </span>
                      ));
                    })()}
                  </div>
                </div>

                {/* SAST finding cards */}
                <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
                  {sastFindings.map((finding, idx) => {
                    const sev = finding.severity.toLowerCase();
                    const sevColor = sev === "critical" ? "#ff6b6b" : sev === "high" ? "#ff922b" : sev === "medium" ? "#fcc419" : sev === "low" ? "#69db7c" : "#868e96";
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
                    const chipStyle = { padding: "0.125rem 0.5rem", borderRadius: "4px", fontSize: "0.7rem", display: "inline-flex", alignItems: "center", gap: "0.25rem" };

                    return (
                      <div key={idx} style={{
                        background: "rgba(255,255,255,0.02)",
                        border: `1px solid ${sevColor}33`,
                        borderLeft: `4px solid ${sevColor}`,
                        borderRadius: "8px",
                        padding: "1rem",
                      }}>
                        <div className="scan-card-row" style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: "1rem", flexWrap: "wrap" }}>
                          <div style={{ flex: 1, minWidth: 0 }}>
                            <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.375rem", flexWrap: "wrap" }}>
                              <span style={{
                                padding: "0.125rem 0.5rem",
                                borderRadius: "4px",
                                fontSize: "0.7rem",
                                fontWeight: 700,
                                textTransform: "uppercase",
                                background: `${sevColor}20`,
                                color: sevColor,
                              }}>
                                {sev}
                              </span>
                              <span style={{ fontWeight: 600, fontSize: "0.875rem", color: "#fff" }}>
                                {finding.title}
                              </span>
                            </div>

                            {/* File path (stripped) */}
                            {finding.packagePath && (
                              <div style={{ fontSize: "0.75rem", color: "rgba(255,255,255,0.4)", fontFamily: "monospace", marginBottom: "0.375rem" }}>
                                {stripScanPath(finding.packagePath)}
                              </div>
                            )}

                            {/* Message */}
                            <p style={{ fontSize: "0.8125rem", color: "rgba(255,255,255,0.5)", margin: "0.375rem 0", lineHeight: 1.5 }}>
                              {message}
                            </p>

                            {/* CWE chips */}
                            {cweLines.length > 0 && (
                              <div style={{ display: "flex", gap: "0.375rem", flexWrap: "wrap", marginTop: "0.375rem" }}>
                                {cweLines.map((cwe, i) => {
                                  const idMatch = cwe.match(/^(CWE-\d+):?\s*(.*)/);
                                  return (
                                    <span key={i} style={{ ...chipStyle, background: "rgba(92,132,255,0.1)", border: "1px solid rgba(92,132,255,0.2)" }}>
                                      <span style={{ fontWeight: 700, color: "#5c84ff", fontSize: "0.7rem" }}>{idMatch?.[1] || cwe}</span>
                                      {idMatch?.[2] && <span style={{ color: "rgba(255,255,255,0.5)", fontSize: "0.7rem" }}>{idMatch[2]}</span>}
                                    </span>
                                  );
                                })}
                              </div>
                            )}

                            {/* OWASP chips */}
                            {owaspItems.length > 0 && (
                              <div style={{ display: "flex", gap: "0.375rem", flexWrap: "wrap", marginTop: "0.375rem" }}>
                                {owaspItems.map((item, i) => {
                                  const parts = item.split(" - ");
                                  return (
                                    <span key={i} style={{ ...chipStyle, background: "rgba(252,196,25,0.08)", border: "1px solid rgba(252,196,25,0.2)" }}>
                                      <span style={{ fontWeight: 700, color: "#fcc419", fontSize: "0.7rem" }}>{parts[0]}</span>
                                      {parts[1] && <span style={{ color: "rgba(255,255,255,0.5)", fontSize: "0.7rem" }}>{parts[1]}</span>}
                                    </span>
                                  );
                                })}
                              </div>
                            )}

                            {/* Code snippet */}
                            {codeBlock && (
                              <div style={{
                                marginTop: "0.5rem",
                                padding: "0.5rem 0.75rem",
                                background: "rgba(0,0,0,0.3)",
                                borderRadius: "4px",
                                fontFamily: "monospace",
                                fontSize: "0.75rem",
                                color: "rgba(255,255,255,0.6)",
                                overflowX: "auto",
                                whiteSpace: "pre",
                                maxHeight: "120px",
                              }}>
                                {codeBlock}
                              </div>
                            )}

                            {/* Reference links with domain + icon */}
                            {finding.urls && finding.urls.length > 0 && (
                              <div style={{ marginTop: "0.5rem", display: "flex", gap: "0.75rem", flexWrap: "wrap" }}>
                                {finding.urls.slice(0, 3).map((url, i) => (
                                  <a key={i} href={url} target="_blank" rel="noopener noreferrer"
                                    style={{ fontSize: "0.7rem", color: "#5c84ff", display: "inline-flex", alignItems: "center", gap: "0.25rem", textDecoration: "none" }}>
                                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6" /><polyline points="15 3 21 3 21 9" /><line x1="10" y1="14" x2="21" y2="3" /></svg>
                                    {urlDomain(url)}
                                  </a>
                                ))}
                              </div>
                            )}
                          </div>

                          {/* Rule ID badge */}
                          <span style={{
                            padding: "0.125rem 0.5rem",
                            borderRadius: "4px",
                            fontSize: "0.65rem",
                            fontFamily: "monospace",
                            background: "rgba(167,139,250,0.1)",
                            color: "#a78bfa",
                            border: "1px solid rgba(167,139,250,0.2)",
                            flexShrink: 0,
                            maxWidth: "200px",
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                            whiteSpace: "nowrap",
                          }}>
                            {ruleId.split(".").slice(-2).join(".")}
                          </span>
                        </div>
                      </div>
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
              <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
                {Array.from({ length: 6 }).map((_, i) => (
                  <SkeletonBlock key={i} height={40} radius={6} />
                ))}
              </div>
            ) : !licenseCompliance || !licenseCompliance.policyId ? (
              <div style={{ textAlign: "center", padding: "2rem 0" }}>
                <p className="muted">{t("No license policy configured. Create a default policy on the System page.", "Keine Lizenzrichtlinie konfiguriert. Erstellen Sie eine Standardrichtlinie auf der Systemseite.")}</p>
              </div>
            ) : (
              <>
                {/* Summary banner */}
                <div style={{
                  display: "flex", gap: "1rem", marginBottom: "1rem", flexWrap: "wrap",
                  padding: "0.75rem 1rem",
                  background: "rgba(255,255,255,0.02)",
                  border: "1px solid rgba(255,255,255,0.06)",
                  borderRadius: "8px",
                }}>
                  <div style={{ fontSize: "0.8125rem", color: "rgba(255,255,255,0.5)", alignSelf: "center" }}>
                    {t("Policy", "Richtlinie")}: <strong style={{ color: "#fff" }}>{licenseCompliance.policyName}</strong>
                  </div>
                  <div style={{ marginLeft: "auto", display: "flex", gap: "0.75rem" }}>
                    {(["allowed", "denied", "warned", "unknown"] as const).map(status => {
                      const count = licenseCompliance.summary[status];
                      const colors: Record<string, string> = { allowed: "#69db7c", denied: "#ff6b6b", warned: "#fcc419", unknown: "rgba(255,255,255,0.4)" };
                      return (
                        <span key={status} style={{
                          padding: "0.125rem 0.625rem",
                          borderRadius: "4px",
                          fontSize: "0.75rem",
                          fontWeight: 600,
                          background: `${colors[status]}15`,
                          color: colors[status],
                        }}>
                          {count} {status}
                        </span>
                      );
                    })}
                  </div>
                </div>

                {/* Violations list */}
                {licenseCompliance.violations.length === 0 ? (
                  <p style={{ textAlign: "center", padding: "1rem 0", color: "#69db7c", fontSize: "0.875rem" }}>
                    {t("All components comply with the license policy.", "Alle Komponenten entsprechen der Lizenzrichtlinie.")}
                  </p>
                ) : (
                  <div style={{ overflowX: "auto" }}>
                    <table style={{ width: "100%", borderCollapse: "collapse" }}>
                      <thead>
                        <tr style={{ borderBottom: "1px solid rgba(255,255,255,0.08)" }}>
                          <th style={{ textAlign: "left", padding: "0.5rem 0.75rem", color: "rgba(255,255,255,0.5)", fontWeight: 500, fontSize: "0.8125rem" }}>{t("Component", "Komponente")}</th>
                          <th style={{ textAlign: "left", padding: "0.5rem 0.75rem", color: "rgba(255,255,255,0.5)", fontWeight: 500, fontSize: "0.8125rem" }}>{t("Version", "Version")}</th>
                          <th style={{ textAlign: "left", padding: "0.5rem 0.75rem", color: "rgba(255,255,255,0.5)", fontWeight: 500, fontSize: "0.8125rem" }}>{t("Licenses", "Lizenzen")}</th>
                          <th style={{ textAlign: "left", padding: "0.5rem 0.75rem", color: "rgba(255,255,255,0.5)", fontWeight: 500, fontSize: "0.8125rem" }}>{t("Status", "Status")}</th>
                        </tr>
                      </thead>
                      <tbody>
                        {licenseCompliance.violations.map((v, i) => {
                          const statusColors: Record<string, string> = { denied: "#ff6b6b", warned: "#fcc419", unknown: "rgba(255,255,255,0.4)" };
                          const color = statusColors[v.status] || "rgba(255,255,255,0.4)";
                          return (
                            <tr key={i} style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                              <td style={{ padding: "0.625rem 0.75rem", verticalAlign: "middle" }}>
                                <span style={{ fontWeight: 500, color: "#fff" }}>{v.name}</span>
                              </td>
                              <td style={{ padding: "0.625rem 0.75rem", verticalAlign: "middle", fontFamily: "monospace", fontSize: "0.8125rem" }}>{v.version}</td>
                              <td style={{ padding: "0.625rem 0.75rem", verticalAlign: "middle" }}>
                                <div style={{ display: "flex", flexWrap: "wrap", gap: "0.25rem" }}>
                                  {v.evaluatedLicenses.map((el, j) => {
                                    const licColor = el.status === "denied" ? "#ff6b6b" : el.status === "warned" ? "#fcc419" : el.status === "allowed" ? "#69db7c" : "rgba(255,255,255,0.4)";
                                    return (
                                      <span key={j} style={{
                                        padding: "0.0625rem 0.375rem",
                                        borderRadius: "4px",
                                        fontSize: "0.6875rem",
                                        fontWeight: 500,
                                        background: `${licColor}15`,
                                        color: licColor,
                                        border: `1px solid ${licColor}30`,
                                      }}>
                                        {el.licenseId}
                                      </span>
                                    );
                                  })}
                                </div>
                              </td>
                              <td style={{ padding: "0.625rem 0.75rem", verticalAlign: "middle" }}>
                                <span style={{
                                  padding: "0.125rem 0.5rem",
                                  borderRadius: "4px",
                                  fontSize: "0.75rem",
                                  fontWeight: 600,
                                  background: `${color}15`,
                                  color,
                                }}>
                                  {v.status}
                                </span>
                              </td>
                            </tr>
                          );
                        })}
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
              <div style={{ padding: "1.5rem", textAlign: "center", background: "rgba(99,230,190,0.05)", border: "1px solid rgba(99,230,190,0.15)", borderRadius: "8px" }}>
                <div style={{ fontSize: "1.5rem", marginBottom: "0.5rem" }}>&#x2713;</div>
                <p style={{ color: "#63e6be", margin: 0, fontSize: "0.875rem" }}>
                  {t("No secrets detected.", "Keine Secrets erkannt.")}
                </p>
              </div>
            ) : (
              <>
                {/* Summary banner */}
                <div style={{
                  padding: "0.75rem 1rem",
                  marginBottom: "1rem",
                  background: "rgba(56,189,248,0.08)",
                  border: "1px solid rgba(56,189,248,0.2)",
                  borderRadius: "8px",
                  display: "flex",
                  gap: "1rem",
                  alignItems: "center",
                  flexWrap: "wrap",
                }}>
                  <span style={{ color: "#38bdf8", fontWeight: 600, fontSize: "0.875rem" }}>
                    {t(
                      `${secretFindings.length} secret${secretFindings.length !== 1 ? "s" : ""} detected by TruffleHog`,
                      `${secretFindings.length} Secret${secretFindings.length !== 1 ? "s" : ""} von TruffleHog erkannt`,
                    )}
                  </span>
                  <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
                    {(() => {
                      const types: Record<string, number> = {};
                      for (const f of secretFindings) {
                        types[f.packageName] = (types[f.packageName] || 0) + 1;
                      }
                      return Object.entries(types).slice(0, 8).map(([t, count]) => (
                        <span key={t} style={{
                          padding: "0.125rem 0.5rem",
                          borderRadius: "4px",
                          fontSize: "0.7rem",
                          background: "rgba(255,255,255,0.06)",
                          color: "rgba(255,255,255,0.5)",
                        }}>
                          {count} {t}
                        </span>
                      ));
                    })()}
                  </div>
                </div>

                {/* Secret finding cards */}
                <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
                  {secretFindings.map((secret, idx) => {
                    const sev = secret.severity.toLowerCase();
                    const sevColor = sev === "critical" ? "#ff6b6b" : sev === "high" ? "#ff922b" : sev === "medium" ? "#fcc419" : "#69db7c";
                    // Parse verified status from description (set by backend: "Status: Verified" or "Status: Unverified")
                    const isVerified = /Status:\s*Verified/i.test(secret.description || "");
                    const detectorType = secret.packageName || "Unknown";

                    return (
                      <div key={idx} style={{
                        background: "rgba(255,255,255,0.02)",
                        border: `1px solid ${sevColor}33`,
                        borderLeft: `4px solid ${sevColor}`,
                        borderRadius: "8px",
                        padding: "1rem",
                      }}>
                        <div className="scan-card-row" style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: "1rem", flexWrap: "wrap" }}>
                          <div style={{ flex: 1, minWidth: 0 }}>
                            <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.375rem", flexWrap: "wrap" }}>
                              <span style={{
                                padding: "0.125rem 0.5rem",
                                borderRadius: "4px",
                                fontSize: "0.7rem",
                                fontWeight: 700,
                                textTransform: "uppercase",
                                background: `${sevColor}20`,
                                color: sevColor,
                              }}>
                                {sev}
                              </span>
                              <span style={{ fontWeight: 600, fontSize: "0.875rem", color: "#fff" }}>
                                {secret.title}
                              </span>
                            </div>

                            {/* File path (stripped) */}
                            {secret.packagePath && (
                              <div style={{ fontSize: "0.75rem", color: "rgba(255,255,255,0.4)", fontFamily: "monospace", marginBottom: "0.375rem" }}>
                                {stripScanPath(secret.packagePath)}
                              </div>
                            )}

                            {/* Description */}
                            <p style={{ fontSize: "0.8125rem", color: "rgba(255,255,255,0.5)", margin: "0.375rem 0", lineHeight: 1.5, whiteSpace: "pre-wrap" }}>
                              {secret.description}
                            </p>
                          </div>

                          {/* Right side badges */}
                          <div className="scan-card-badges" style={{ display: "flex", flexDirection: "column", gap: "0.375rem", alignItems: "flex-end", flexShrink: 0 }}>
                            <span style={{
                              padding: "0.125rem 0.5rem",
                              borderRadius: "4px",
                              fontSize: "0.7rem",
                              background: "rgba(56,189,248,0.1)",
                              color: "#38bdf8",
                              border: "1px solid rgba(56,189,248,0.2)",
                            }}>
                              {detectorType}
                            </span>
                            <span style={{
                              padding: "0.125rem 0.5rem",
                              borderRadius: "4px",
                              fontSize: "0.7rem",
                              background: isVerified ? "rgba(99,230,190,0.1)" : "rgba(252,196,25,0.1)",
                              color: isVerified ? "#63e6be" : "#fcc419",
                              border: `1px solid ${isVerified ? "rgba(99,230,190,0.2)" : "rgba(252,196,25,0.2)"}`,
                            }}>
                              {isVerified ? t("Verified", "Verifiziert") : t("Unverified", "Unverifiziert")}
                            </span>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </>
            )}
          </>
        )}
      </section>
    </div>
  );
};

// --- Sub-components ---

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ff6b6b",
  high: "#ff922b",
  medium: "#fcc419",
  low: "#69db7c",
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
      if (!(sev in SEVERITY_COLORS)) continue;
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
    <div style={{ marginTop: "1rem" }}>
      <div style={{ fontSize: "0.8125rem", fontWeight: 600, marginBottom: "0.125rem" }}>
        {t("Library Vulnerability Analysis", "Bibliothek-Schwachstellen-Analyse")}
      </div>
      <div style={{ fontSize: "0.7rem", color: "rgba(255,255,255,0.4)", marginBottom: "0.5rem" }}>
        {t(
          "Each bubble is a library. X-axis: severity & CVSS score, Y-axis: count, size: count. Hover for details.",
          "Jede Blase ist eine Bibliothek. X-Achse: Schweregrad & CVSS-Score, Y-Achse: Anzahl, Größe: Anzahl. Hover für Details."
        )}
      </div>
      <div ref={containerRef} style={{ width: "100%", position: "relative", overflow: "visible" }}>
        <svg
          width={width} height={height} style={{ overflow: "visible" }}
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
                <line x1={padding.left} x2={padding.left + chartW} y1={y} y2={y} stroke="rgba(255,255,255,0.06)" />
                <text x={padding.left - 8} y={y + 4} fill="rgba(255,255,255,0.3)" fontSize="10" textAnchor="end">{tick}</text>
              </g>
            );
          })}
          {/* Zone separators */}
          {SEVERITY_ZONES.map((_, i) => i > 0 && (
            <line key={i} x1={padding.left + i * zoneWidth} x2={padding.left + i * zoneWidth} y1={padding.top} y2={padding.top + chartH} stroke="rgba(255,255,255,0.04)" />
          ))}
          {/* Zone labels */}
          {SEVERITY_ZONES.map((sev, i) => (
            <text key={sev} x={padding.left + (i + 0.5) * zoneWidth} y={height - 6} fill={SEVERITY_COLORS[sev] ?? "rgba(255,255,255,0.3)"} fontSize="10" textAnchor="middle" opacity={0.7}>
              {sev.charAt(0).toUpperCase() + sev.slice(1)}
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
            const color = SEVERITY_COLORS[b.severity] ?? "#888";
            const isHovered = hovered?.packageName === b.packageName && hovered?.severity === b.severity;
            return (
              <circle
                key={i}
                cx={cx} cy={cy} r={isHovered ? r + 2 : r}
                fill={color}
                fillOpacity={isHovered ? 0.9 : 0.55}
                stroke={color}
                strokeWidth={isHovered ? 2 : 1}
                strokeOpacity={0.8}
                style={{ cursor: "pointer", transition: "r 0.1s, fill-opacity 0.1s" }}
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
            style={{
              position: "absolute",
              top: Math.max(0, mousePos.y - 10),
              ...(mousePos.x > width * 0.6 ? { right: width - mousePos.x + 12 } : { left: mousePos.x + 12 }),
              background: "rgba(15,15,25,0.95)",
              border: "1px solid rgba(255,255,255,0.12)",
              borderRadius: "6px",
              padding: "0.5rem 0.75rem",
              fontSize: "0.75rem",
              pointerEvents: "none",
              zIndex: 10,
              maxWidth: "220px",
              boxShadow: "0 4px 12px rgba(0,0,0,0.4)",
            }}
          >
            <div style={{ fontWeight: 600, marginBottom: "0.25rem", wordBreak: "break-all", lineHeight: 1.3 }}>{hovered.packageName}</div>
            <div style={{ display: "flex", justifyContent: "space-between", gap: "0.75rem", color: SEVERITY_COLORS[hovered.severity], lineHeight: 1.6 }}>
              <span>{hovered.severity.charAt(0).toUpperCase() + hovered.severity.slice(1)}</span>
              <span style={{ fontWeight: 600 }}>{hovered.count} CVE{hovered.count !== 1 ? "s" : ""}</span>
            </div>
            {hovered.maxCvss != null && (
              <div style={{ fontSize: "0.6875rem", color: "rgba(255,255,255,0.5)", lineHeight: 1.5 }}>
                CVSS: <span style={{ fontWeight: 600, color: "rgba(255,255,255,0.7)" }}>{hovered.maxCvss.toFixed(1)}</span>
              </div>
            )}
            {hovered.cves.length > 0 && (
              <div style={{ marginTop: "0.25rem", borderTop: "1px solid rgba(255,255,255,0.07)", paddingTop: "0.25rem" }}>
                {hovered.cves.slice(0, 8).map(cve => (
                  <div key={cve} style={{ color: "rgba(255,255,255,0.5)", fontSize: "0.6875rem", lineHeight: 1.5 }}>{cve}</div>
                ))}
                {hovered.cves.length > 8 && (
                  <div style={{ color: "rgba(255,255,255,0.3)", fontSize: "0.6875rem" }}>+{hovered.cves.length - 8} more</div>
                )}
              </div>
            )}
          </div>
        )}
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
    <div ref={containerRef} style={{ width: "100%", position: "relative" }}>
      <svg width={width} height={height} style={{ overflow: "visible" }}>
        {/* Grid lines */}
        {yTicks.map(tick => {
          const y = padding.top + chartH - (tick / maxTotal) * chartH;
          return (
            <g key={tick}>
              <line x1={padding.left} x2={padding.left + chartW} y1={y} y2={y} stroke="rgba(255,255,255,0.06)" />
              <text x={padding.left - 8} y={y + 4} fill="rgba(255,255,255,0.3)" fontSize="10" textAnchor="end">{tick}</text>
            </g>
          );
        })}
        {/* Lines per severity */}
        {severities.map(sev => {
          const color = SEVERITY_COLORS[sev];
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
                  <circle key={i} cx={x} cy={y} r={isHovered ? 5 : 3} fill={color} style={{ transition: "r 0.1s" }} />
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
            stroke="rgba(255,255,255,0.15)" strokeDasharray="4,3"
          />
        )}
        {/* X axis labels */}
        {history.map((h, i) => {
          const x = getX(i);
          const step = Math.max(1, Math.floor(history.length / 8));
          if (i % step !== 0 && i !== history.length - 1) return null;
          const d = new Date(h.startedAt);
          const label = `${d.getDate()}.${d.getMonth() + 1}`;
          return (
            <text key={i} x={x} y={height - 5} fill={hoveredIndex === i ? "rgba(255,255,255,0.7)" : "rgba(255,255,255,0.3)"} fontSize="10" textAnchor="middle">{label}</text>
          );
        })}
        {/* Invisible hover areas (must be last so they're on top) */}
        {history.map((_, i) => {
          const x = getX(i);
          const halfStep = history.length > 1 ? xStep / 2 : chartW / 2;
          return (
            <rect
              key={i}
              x={x - halfStep}
              y={padding.top}
              width={halfStep * 2}
              height={chartH}
              fill="transparent"
              style={{ cursor: "crosshair" }}
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
        const dateStr = `${String(d.getDate()).padStart(2, "0")}.${String(d.getMonth() + 1).padStart(2, "0")}.${d.getFullYear()}`;
        const timeStr = `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
        return (
          <div
            style={{
              position: "absolute",
              top: padding.top,
              ...(xPct > 0.6
                ? { right: width - x + 8 }
                : { left: x + 8 }),
              background: "rgba(15,15,25,0.95)",
              border: "1px solid rgba(255,255,255,0.12)",
              borderRadius: "6px",
              padding: "0.5rem 0.75rem",
              fontSize: "0.75rem",
              pointerEvents: "none",
              zIndex: 10,
              minWidth: "110px",
              boxShadow: "0 4px 12px rgba(0,0,0,0.4)",
            }}
          >
            <div style={{ color: "rgba(255,255,255,0.6)", marginBottom: "0.375rem", fontWeight: 500 }}>
              {dateStr} {timeStr}
            </div>
            {severities.map(sev => h.summary[sev] > 0 && (
              <div key={sev} style={{ display: "flex", justifyContent: "space-between", gap: "0.75rem", color: SEVERITY_COLORS[sev], lineHeight: 1.6 }}>
                <span>{sev.charAt(0).toUpperCase() + sev.slice(1)}</span>
                <span style={{ fontWeight: 600 }}>{h.summary[sev]}</span>
              </div>
            ))}
            <div style={{ display: "flex", justifyContent: "space-between", gap: "0.75rem", color: "rgba(255,255,255,0.4)", borderTop: "1px solid rgba(255,255,255,0.07)", marginTop: "0.25rem", paddingTop: "0.25rem" }}>
              <span>Total</span>
              <span style={{ fontWeight: 600 }}>{h.summary.total}</span>
            </div>
          </div>
        );
      })()}

      {/* Legend */}
      <div style={{ display: "flex", gap: "1rem", marginTop: "0.5rem", justifyContent: "center" }}>
        {severities.map(sev => (
          <div key={sev} style={{ display: "flex", alignItems: "center", gap: "0.25rem", fontSize: "0.75rem" }}>
            <span style={{ width: "10px", height: "3px", background: SEVERITY_COLORS[sev], display: "inline-block", borderRadius: "1px" }} />
            <span style={{ color: "rgba(255,255,255,0.5)" }}>{sev.charAt(0).toUpperCase() + sev.slice(1)}</span>
          </div>
        ))}
      </div>
    </div>
  );
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

  const renderDelta = (d: number) => {
    if (d === 0) return <span style={{ color: "rgba(255,255,255,0.2)" }}>—</span>;
    if (d > 0) return <span style={{ color: "#ff6b6b", fontWeight: 600 }}>+{d}</span>;
    return <span style={{ color: "#69db7c", fontWeight: 600 }}>{d}</span>;
  };

  const hasAnyCommit = changes.some(c => c.newer.commitSha);
  const thCenter: React.CSSProperties = { ...thStyle, textAlign: "center" };

  return (
    <div style={{ marginTop: "1.25rem" }}>
      <h4 style={{ margin: "0 0 0.5rem", fontSize: "0.875rem", color: "rgba(255,255,255,0.7)" }}>
        {t("Significant Changes", "Wesentliche Änderungen")}
      </h4>
      <div style={{ overflowX: "auto" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.8125rem" }}>
          <thead>
            <tr style={{ borderBottom: "1px solid rgba(255,255,255,0.08)" }}>
              <th style={thStyle}>{t("Date", "Datum")}</th>
              {hasAnyCommit && <th style={thStyle}>Commit</th>}
              {sevs.map(sev => (
                <th key={sev} style={{ ...thCenter, color: SEVERITY_COLORS[sev] }}>{sev.charAt(0).toUpperCase() + sev.slice(1)}</th>
              ))}
              <th style={thCenter}>Total</th>
            </tr>
          </thead>
          <tbody>
            {changes.map(({ newer, deltas }, i) => (
              <tr key={i} style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                <td style={{ ...tdStyle, whiteSpace: "nowrap", fontSize: "0.75rem" }}>{formatDateTime(newer.startedAt)}</td>
                {hasAnyCommit && (
                  <td style={{ ...tdStyle, whiteSpace: "nowrap", fontSize: "0.75rem" }}>
                    {newer.commitSha ? (
                      <span style={{ display: "inline-flex", alignItems: "center", gap: "0.25rem" }}>
                        <code style={{ color: "#ffd43b", fontSize: "0.7rem" }}>{newer.commitSha.slice(0, 7)}</code>
                        {commitUrlBase && (
                          <a
                            href={`${commitUrlBase}${newer.commitSha}`}
                            target="_blank"
                            rel="noreferrer"
                            style={{ color: "rgba(255,255,255,0.35)", fontSize: "0.7rem", lineHeight: 1 }}
                            title={t("View commit", "Commit anzeigen")}
                          >
                            ↗
                          </a>
                        )}
                      </span>
                    ) : (
                      <span style={{ color: "rgba(255,255,255,0.15)" }}>—</span>
                    )}
                  </td>
                )}
                {sevs.map(sev => (
                  <td key={sev} style={{ ...tdStyle, textAlign: "center" }}>{renderDelta(deltas[sev])}</td>
                ))}
                <td style={{ ...tdStyle, textAlign: "center", fontWeight: 600 }}>{renderDelta(deltas.total)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

const ComparisonView = ({ comparison }: { comparison: ScanComparisonResponse }) => {
  const { t } = useI18n();
  const summaryA = comparison.summaryA;
  const summaryB = comparison.summaryB;

  const renderDelta = (a: number, b: number) => {
    const diff = b - a;
    if (diff === 0) return <span style={{ color: "rgba(255,255,255,0.3)" }}>—</span>;
    if (diff > 0) return <span style={{ color: "#ff6b6b", fontWeight: 600 }}>+{diff}</span>;
    return <span style={{ color: "#69db7c", fontWeight: 600 }}>{diff}</span>;
  };

  return (
    <div>
      {/* Summary comparison */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(120px, 1fr))", gap: "0.75rem", marginBottom: "1.5rem" }}>
        {(["critical", "high", "medium", "low", "total"] as const).map(sev => (
          <div key={sev} style={{ padding: "0.625rem", background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.06)", borderRadius: "6px", textAlign: "center" }}>
            <div style={{ fontSize: "0.7rem", color: "rgba(255,255,255,0.4)", textTransform: "uppercase", marginBottom: "0.25rem" }}>{sev}</div>
            <div style={{ display: "flex", justifyContent: "center", alignItems: "center", gap: "0.375rem" }}>
              <span style={{ fontSize: "0.875rem" }}>{(summaryA as any)[sev]}</span>
              <span style={{ color: "rgba(255,255,255,0.2)" }}>→</span>
              <span style={{ fontSize: "0.875rem" }}>{(summaryB as any)[sev]}</span>
              <span style={{ fontSize: "0.75rem" }}>{renderDelta((summaryA as any)[sev], (summaryB as any)[sev])}</span>
            </div>
          </div>
        ))}
      </div>

      <div style={{ fontSize: "0.8125rem", color: "rgba(255,255,255,0.5)", marginBottom: "1rem" }}>
        {t("Unchanged", "Unverändert")}: {comparison.unchangedCount} findings
      </div>

      {/* Added findings */}
      {comparison.added.length > 0 && (
        <div style={{ marginBottom: "1rem" }}>
          <h4 style={{ margin: "0 0 0.5rem", color: "#ff6b6b", fontSize: "0.875rem" }}>
            + {t("Added", "Hinzugefügt")} ({comparison.added.length})
          </h4>
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.8125rem" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid rgba(255,107,107,0.2)" }}>
                  <th style={thStyle}>CVE</th>
                  <th style={thStyle}>{t("Package", "Paket")}</th>
                  <th style={thStyle}>{t("Version", "Version")}</th>
                  <th style={thStyle}>{t("Severity", "Schweregrad")}</th>
                  <th style={thStyle}>Fix</th>
                </tr>
              </thead>
              <tbody>
                {comparison.added.map((f, i) => (
                  <tr key={i} style={{ borderBottom: "1px solid rgba(255,107,107,0.06)", background: "rgba(255,107,107,0.03)" }}>
                    <td style={tdStyle}>
                      {f.vulnerabilityId ? (
                        <Link to={`/vulnerability/${f.vulnerabilityId}`} style={{ color: "#ffd43b", textDecoration: "none" }}>{f.vulnerabilityId}</Link>
                      ) : <span style={{ color: "rgba(255,255,255,0.3)" }}>—</span>}
                    </td>
                    <td style={tdStyle}>{f.packageName}</td>
                    <td style={tdStyle}>{f.packageVersion || "—"}</td>
                    <td style={tdStyle}><SeverityChip severity={f.severity} /></td>
                    <td style={tdStyle}>{f.fixVersion ? <span style={{ color: "#69db7c", fontSize: "0.75rem" }}>{f.fixVersion}</span> : "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Changed findings (same package, different vuln ID) */}
      {(comparison.changed?.length ?? 0) > 0 && (
        <div style={{ marginBottom: "1rem" }}>
          <h4 style={{ margin: "0 0 0.5rem", color: "#ffd43b", fontSize: "0.875rem" }}>
            ↔ {t("Changed", "Geändert")} ({comparison.changed!.length})
          </h4>
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.8125rem" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid rgba(255,212,59,0.2)" }}>
                  <th style={thStyle}>{t("Package", "Paket")}</th>
                  <th style={thStyle}>{t("Version", "Version")}</th>
                  <th style={thStyle}>{t("Before", "Vorher")}</th>
                  <th style={thStyle}>{t("After", "Nachher")}</th>
                  <th style={thStyle}>{t("Severity", "Schweregrad")}</th>
                </tr>
              </thead>
              <tbody>
                {comparison.changed!.map((c, i) => (
                  <tr key={i} style={{ borderBottom: "1px solid rgba(255,212,59,0.06)", background: "rgba(255,212,59,0.03)" }}>
                    <td style={tdStyle}>{c.after.packageName}</td>
                    <td style={tdStyle}>{c.after.packageVersion || "—"}</td>
                    <td style={tdStyle}>
                      {c.before.vulnerabilityId ? (
                        <Link to={`/vulnerability/${c.before.vulnerabilityId}`} style={{ color: "rgba(255,255,255,0.4)", textDecoration: "none" }}>{c.before.vulnerabilityId}</Link>
                      ) : <span style={{ color: "rgba(255,255,255,0.3)" }}>—</span>}
                    </td>
                    <td style={tdStyle}>
                      {c.after.vulnerabilityId ? (
                        <Link to={`/vulnerability/${c.after.vulnerabilityId}`} style={{ color: "#ffd43b", textDecoration: "none" }}>{c.after.vulnerabilityId}</Link>
                      ) : <span style={{ color: "rgba(255,255,255,0.3)" }}>—</span>}
                    </td>
                    <td style={tdStyle}>
                      <SeverityChip severity={c.after.severity} />
                      {c.before.severity !== c.after.severity && (
                        <span style={{ fontSize: "0.7rem", color: "rgba(255,255,255,0.3)", marginLeft: "0.375rem" }}>
                          ({t("was", "war")} {c.before.severity})
                        </span>
                      )}
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
        <div>
          <h4 style={{ margin: "0 0 0.5rem", color: "#69db7c", fontSize: "0.875rem" }}>
            − {t("Removed", "Entfernt")} ({comparison.removed.length})
          </h4>
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.8125rem" }}>
              <thead>
                <tr style={{ borderBottom: "1px solid rgba(105,219,124,0.2)" }}>
                  <th style={thStyle}>CVE</th>
                  <th style={thStyle}>{t("Package", "Paket")}</th>
                  <th style={thStyle}>{t("Version", "Version")}</th>
                  <th style={thStyle}>{t("Severity", "Schweregrad")}</th>
                  <th style={thStyle}>Fix</th>
                </tr>
              </thead>
              <tbody>
                {comparison.removed.map((f, i) => (
                  <tr key={i} style={{ borderBottom: "1px solid rgba(105,219,124,0.06)", background: "rgba(105,219,124,0.03)" }}>
                    <td style={tdStyle}>
                      {f.vulnerabilityId ? (
                        <Link to={`/vulnerability/${f.vulnerabilityId}`} style={{ color: "#ffd43b", textDecoration: "none" }}>{f.vulnerabilityId}</Link>
                      ) : <span style={{ color: "rgba(255,255,255,0.3)" }}>—</span>}
                    </td>
                    <td style={tdStyle}>{f.packageName}</td>
                    <td style={tdStyle}>{f.packageVersion || "—"}</td>
                    <td style={tdStyle}><SeverityChip severity={f.severity} /></td>
                    <td style={tdStyle}>{f.fixVersion ? <span style={{ color: "#69db7c", fontSize: "0.75rem" }}>{f.fixVersion}</span> : "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {comparison.added.length === 0 && comparison.removed.length === 0 && (comparison.changed?.length ?? 0) === 0 && (
        <p className="muted">{t("No differences found between the two scans.", "Keine Unterschiede zwischen den beiden Scans gefunden.")}</p>
      )}
    </div>
  );
};

const SeveritySummaryBar = ({ summary }: { summary: ScanSummary }) => {
  const { t } = useI18n();
  if (summary.total === 0) {
    return (
      <div style={{ marginTop: "1rem", padding: "0.75rem", background: "rgba(105,219,124,0.08)", border: "1px solid rgba(105,219,124,0.2)", borderRadius: "6px", color: "#69db7c", textAlign: "center", fontSize: "0.875rem" }}>
        {t("No vulnerabilities found", "Keine Schwachstellen gefunden")}
      </div>
    );
  }

  const segments = [
    { label: "Unknown", count: summary.unknown, color: "#495057" },
    { label: "Negligible", count: summary.negligible, color: "#868e96" },
    { label: "Low", count: summary.low, color: "#69db7c" },
    { label: "Medium", count: summary.medium, color: "#fcc419" },
    { label: "High", count: summary.high, color: "#ff922b" },
    { label: "Critical", count: summary.critical, color: "#ff6b6b" },
  ].filter(s => s.count > 0);

  return (
    <div style={{ marginTop: "1rem" }}>
      {/* Bar */}
      <div style={{ display: "flex", height: "8px", borderRadius: "4px", overflow: "hidden", marginBottom: "0.75rem" }}>
        {segments.map(s => (
          <div key={s.label} style={{ width: `${(s.count / summary.total) * 100}%`, background: s.color }} />
        ))}
      </div>
      {/* Legend */}
      <div style={{ display: "flex", gap: "1rem", flexWrap: "wrap" }}>
        {segments.map(s => (
          <div key={s.label} style={{ display: "flex", alignItems: "center", gap: "0.375rem", fontSize: "0.8125rem" }}>
            <span style={{ width: "10px", height: "10px", borderRadius: "2px", background: s.color, display: "inline-block" }} />
            <span style={{ color: "rgba(255,255,255,0.6)" }}>{s.label}</span>
            <span style={{ fontWeight: 600 }}>{s.count}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

const StatusBadge = ({ status }: { status: string }) => {
  const colors: Record<string, string> = {
    completed: "#69db7c",
    running: "#5c84ff",
    pending: "#fcc419",
    failed: "#ff6b6b",
  };
  const color = colors[status] || "rgba(255,255,255,0.4)";
  return (
    <span style={{
      padding: "0.125rem 0.5rem",
      borderRadius: "4px",
      fontSize: "0.75rem",
      fontWeight: 600,
      background: `${color}20`,
      color,
    }}>
      {status}
    </span>
  );
};

const SeverityChip = ({ severity }: { severity: string }) => {
  const colors: Record<string, string> = {
    critical: "#ff6b6b",
    high: "#ff922b",
    medium: "#fcc419",
    low: "#69db7c",
    negligible: "#868e96",
    unknown: "#495057",
  };
  const color = colors[severity] || "#495057";
  return (
    <span style={{
      padding: "0.125rem 0.5rem",
      borderRadius: "4px",
      fontSize: "0.75rem",
      fontWeight: 600,
      background: `${color}20`,
      color,
    }}>
      {severity}
    </span>
  );
};

// Styles
const thStyle: React.CSSProperties = {
  textAlign: "left",
  padding: "0.5rem 0.75rem",
  color: "rgba(255,255,255,0.5)",
  fontWeight: 500,
  fontSize: "0.8125rem",
};

const tdStyle: React.CSSProperties = {
  padding: "0.5rem 0.75rem",
  verticalAlign: "middle",
};

const tabStyle = (active: boolean): React.CSSProperties => ({
  padding: "0.375rem 0.875rem",
  borderRadius: "6px",
  border: active ? "1px solid rgba(255,193,7,0.5)" : "1px solid rgba(255,255,255,0.1)",
  background: active ? "rgba(255,193,7,0.15)" : "transparent",
  color: active ? "#ffd43b" : "rgba(255,255,255,0.6)",
  cursor: "pointer",
  fontSize: "0.8125rem",
  fontWeight: 500,
});
