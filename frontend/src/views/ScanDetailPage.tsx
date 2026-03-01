import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";

import { fetchScan, fetchScanFindings, fetchScanSbom, fetchScans, fetchTargetHistory, compareScans } from "../api/scans";
import { SkeletonBlock } from "../components/Skeleton";
import { useI18n } from "../i18n/context";
import { formatDateTime } from "../utils/dateFormat";
import type {
  Scan,
  ScanFinding,
  ScanSummary,
  ScanHistoryEntry,
  ScanComparisonResponse,
  SbomComponent,
} from "../types";

type Tab = "findings" | "sbom" | "history" | "compare";

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
  vulnerabilityId: string | null;
  matchedFrom: string | null;
  packageName: string;
  packageVersion: string;
  packageType: string;
  severity: string;
  fixVersion: string | null;
  fixState: string;
  scanners: string[];
  cvssScore: number | null;
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
  const map = new Map<string, MergedFinding & { _fixCandidates: (string | null)[] }>();
  for (const f of findings) {
    const key = `${f.vulnerabilityId ?? ""}:${f.packageName}:${normalizeVersion(f.packageVersion)}`;
    const existing = map.get(key);
    if (existing) {
      if (!existing.scanners.includes(f.scanner)) existing.scanners.push(f.scanner);
      if (f.fixVersion) existing._fixCandidates.push(normalizeVersion(f.fixVersion));
      if (!existing.cvssScore && f.cvssScore) existing.cvssScore = f.cvssScore;
      if (!existing.packageType && f.packageType) existing.packageType = f.packageType;
      if (!existing.matchedFrom && f.matchedFrom) existing.matchedFrom = f.matchedFrom;
    } else {
      map.set(key, {
        key,
        vulnerabilityId: f.vulnerabilityId ?? null,
        matchedFrom: f.matchedFrom ?? null,
        packageName: f.packageName,
        packageVersion: normalizeVersion(f.packageVersion),
        packageType: f.packageType ?? "",
        severity: f.severity,
        fixVersion: f.fixVersion ?? null,
        fixState: f.fixState,
        scanners: [f.scanner],
        cvssScore: f.cvssScore ?? null,
        _fixCandidates: f.fixVersion ? [normalizeVersion(f.fixVersion)] : [],
      });
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
  const [sbomSearch, setSbomSearch] = useState("");

  // History chart state
  const [history, setHistory] = useState<ScanHistoryEntry[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);

  // Comparison state
  const [otherScans, setOtherScans] = useState<Scan[]>([]);
  const [compareTargetId, setCompareTargetId] = useState<string | null>(null);
  const [compareScanId, setCompareScanId] = useState<string | null>(null);
  const [comparison, setComparison] = useState<ScanComparisonResponse | null>(null);
  const [compareLoading, setCompareLoading] = useState(false);

  const merged = useMemo(() => mergeFindings(findings), [findings]);

  /** Client-side severity filter on already-merged findings */
  const filteredMerged = useMemo(
    () => severityFilter ? merged.filter(f => f.severity === severityFilter) : merged,
    [merged, severityFilter],
  );

  /** Summary computed from deduplicated findings (accurate counts) */
  const mergedSummary = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, negligible: 0, unknown: 0, total: 0 };
    for (const f of merged) {
      const sev = f.severity.toLowerCase() as keyof typeof counts;
      if (sev in counts && sev !== "total") (counts[sev] as number)++;
      else counts.unknown++;
      counts.total++;
    }
    return counts;
  }, [merged]);

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
          fetchScanFindings(scanId, { limit: 500 }),
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

  return (
    <div className="page">
      {/* Header */}
      <section className="card">
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
          <div style={{ textAlign: "right", fontSize: "0.8125rem", color: "rgba(255,255,255,0.5)" }}>
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
            {scan.commitSha && <div>Commit: <span style={{ fontFamily: "monospace" }}>{scan.commitSha.substring(0, 8)}</span></div>}
            {scan.branch && <div>Branch: {scan.branch}</div>}
            {scan.source === "ci_cd" && <div style={{ color: "#5c84ff" }}>CI/CD</div>}
          </div>
        </div>

        {scan.error && (
          <div style={{ marginTop: "0.75rem", padding: "0.5rem 0.75rem", background: "rgba(255,107,107,0.08)", border: "1px solid rgba(255,107,107,0.2)", borderRadius: "6px", color: "#ff6b6b", fontSize: "0.8125rem" }}>
            {scan.error}
          </div>
        )}

        {/* Severity summary bar */}
        <SeveritySummaryBar summary={merged.length > 0 ? mergedSummary : scan.summary} />
      </section>

      {/* Findings / SBOM / History / Compare tabs */}
      <section className="card" style={{ marginTop: "1rem" }}>
        <div style={{ display: "flex", gap: "0.5rem", marginBottom: "1rem", flexWrap: "wrap" }}>
          <button
            type="button"
            onClick={() => setTab("findings")}
            style={tabStyle(tab === "findings")}
          >
            {t("Findings", "Ergebnisse")} ({merged.length > 0 ? merged.length : (scan.findingsCount || findingsTotal)})
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
                setHistoryLoading(true);
                fetchTargetHistory(scan.targetId).then(res => {
                  setHistory(res.items);
                }).catch(err => console.error("Failed to load history", err)).finally(() => setHistoryLoading(false));
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
                fetchScans({ targetId: scan.targetId, limit: 50 }).then(res => {
                  setOtherScans(res.items.filter(s => s.id !== scanId && s.status === "completed"));
                  setCompareTargetId(scan.targetId);
                }).catch(err => console.error("Failed to load scans", err));
              }
            }}
            style={tabStyle(tab === "compare")}
          >
            {t("Compare", "Vergleichen")}
          </button>
        </div>

        {tab === "findings" && (
          <>
            {/* Severity filter + actions */}
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
                      <th style={thStyle}>CVE</th>
                      <th style={thStyle}>{t("Package", "Paket")}</th>
                      <th style={thStyle}>{t("Version", "Version")}</th>
                      <th style={thStyle}>{t("Severity", "Schweregrad")}</th>
                      <th style={thStyle}>Fix</th>
                      <th style={thStyle}>{t("Scanner", "Scanner")}</th>
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
            <div style={{ marginBottom: "1rem" }}>
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
                  width: "100%",
                  maxWidth: "500px",
                  outline: "none",
                }}
              />
              <span style={{ marginLeft: "0.75rem", fontSize: "0.75rem", color: "rgba(255,255,255,0.4)" }}>
                {dedupedSbom.length} {t("components", "Komponenten")}
              </span>
            </div>

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
                      <th style={thStyle}>{t("Licenses", "Lizenzen")}</th>
                      <th style={thStyle}>{t("Supplier", "Lieferant")}</th>
                      <th style={thStyle}>{t("Links", "Links")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {dedupedSbom.map(c => {
                      const depsUrl = buildDepsDevUrl(c.name, c.version, c.type, c.purl);
                      const snykUrl = buildSnykUrl(c.name, c.version, c.type, c.purl);
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
                              {!depsUrl && !snykUrl && <span style={{ color: "rgba(255,255,255,0.2)" }}>—</span>}
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
            {historyLoading ? (
              <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
                {Array.from({ length: 4 }).map((_, i) => (
                  <SkeletonBlock key={i} height={40} radius={4} />
                ))}
              </div>
            ) : history.length < 2 ? (
              <p className="muted">{t("Not enough scan history for a chart. Run more scans.", "Nicht genügend Scan-Verlauf für ein Diagramm. Führen Sie weitere Scans durch.")}</p>
            ) : (
              <HistoryChart history={history} />
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

      {comparison.added.length === 0 && comparison.removed.length === 0 && (
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
    { label: "Critical", count: summary.critical, color: "#ff6b6b" },
    { label: "High", count: summary.high, color: "#ff922b" },
    { label: "Medium", count: summary.medium, color: "#fcc419" },
    { label: "Low", count: summary.low, color: "#69db7c" },
    { label: "Negligible", count: summary.negligible, color: "#868e96" },
    { label: "Unknown", count: summary.unknown, color: "#495057" },
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
