import React, { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";

import { config } from "../config";

import {
  fetchScanTargets,
  fetchScans,
  fetchGlobalFindings,
  fetchGlobalSbom,
  fetchBadgeCounts,
  submitManualScan,
  submitManualSourceArchiveScan,
  deleteScanTarget,
  deleteScan,
  updateScanTarget,
  cancelScan,
  fetchScannerStats,
  importSbomFile,
} from "../api/scans";
import { fetchLicenseOverview } from "../api/licensePolicy";
import { SkeletonBlock } from "../components/Skeleton";
import { usePersistentState } from "../hooks/usePersistentState";
import { useI18n } from "../i18n/context";
import { formatDateTime } from "../utils/dateFormat";
import type {
  ScanTarget,
  Scan,
  ScanSummary,
  ConsolidatedFinding,
  ConsolidatedSbom,
  ScannerStats,
  SubmitScanResponse,
  LicenseOverviewItem,
} from "../types";

type Tab = "targets" | "scans" | "findings" | "sbom" | "licenses" | "manual" | "scanner";
type SourceRepoInputMode = "url" | "zip";

interface ConfirmModal {
  title: string;
  message: string;
  onConfirm: () => void;
}

export const ScansPage = () => {
  const { t } = useI18n();
  const [tab, setTab] = useState<Tab>("targets");
  const [targets, setTargets] = useState<ScanTarget[]>([]);
  const [collapsedGroups, setCollapsedGroups] = usePersistentState<Record<string, boolean>>(
    "hecate.scan.groupCollapsed",
    {},
  );
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirmModal, setConfirmModal] = useState<ConfirmModal | null>(null);

  // Scan filter (from target card click or dropdown)
  const [scanFilterTargetId, setScanFilterTargetId] = useState<string | null>(null);
  const [scanFilterTargetName, setScanFilterTargetName] = useState<string | null>(null);

  // Pagination for scans tab
  const [scanTotal, setScanTotal] = useState(0);
  const [scanOffset, setScanOffset] = useState(0);
  const scanLimit = 25;

  // Scanner stats
  const [scannerStats, setScannerStats] = useState<ScannerStats | null>(null);

  // License overview tab
  const [licenseOverview, setLicenseOverview] = useState<LicenseOverviewItem[]>([]);
  const [licenseOverviewTotal, setLicenseOverviewTotal] = useState(0);
  const [licensesLoading, setLicensesLoading] = useState(false);
  const [licenseSearch, setLicenseSearch] = useState("");

  // SBOM import
  const [sbomImportFile, setSbomImportFile] = useState<File | null>(null);
  const [sbomImportTargetName, setSbomImportTargetName] = useState("");
  const [sbomImportFormat, setSbomImportFormat] = useState("");
  const [sbomImportLoading, setSbomImportLoading] = useState(false);
  const [sbomImportResult, setSbomImportResult] = useState<SubmitScanResponse | null>(null);
  const [sbomImportError, setSbomImportError] = useState<string | null>(null);

  // Global findings tab
  const [globalFindings, setGlobalFindings] = useState<ConsolidatedFinding[]>([]);
  const [globalFindingsTotal, setGlobalFindingsTotal] = useState(0);
  const [findingsLoading, setFindingsLoading] = useState(false);
  const [findingsSearch, setFindingsSearch] = useState("");
  const [findingsSeverity, setFindingsSeverity] = useState<string | null>(null);
  const [findingsTargetId, setFindingsTargetId] = useState<string | null>(null);
  const [findingsSortBy, setFindingsSortBy] = useState("cvss_score");
  const [findingsSortOrder, setFindingsSortOrder] = useState<"asc" | "desc">("desc");
  const [findingsOffset, setFindingsOffset] = useState(0);
  const [expandedFindings, setExpandedFindings] = useState<Set<string>>(new Set());
  const findingsLimit = 50;
  const findingsSearchRef = useRef(findingsSearch);
  findingsSearchRef.current = findingsSearch;

  // Global SBOM tab
  const [sbomComponents, setSbomComponents] = useState<ConsolidatedSbom[]>([]);
  const [sbomTotal, setSbomTotal] = useState(0);
  const [sbomLoading, setSbomLoading] = useState(false);
  const [sbomSearch, setSbomSearch] = useState("");
  const [sbomType, setSbomType] = useState<string | null>(null);
  const [sbomTargetId, setSbomTargetId] = useState<string | null>(null);
  const [sbomOffset, setSbomOffset] = useState(0);
  const [expandedSboms, setExpandedSboms] = useState<Set<string>>(new Set());
  const [sbomSort, setSbomSort] = useState<{ col: string; dir: "asc" | "desc" }>({ col: "name", dir: "asc" });
  const [sbomFilterProvenance, setSbomFilterProvenance] = useState<string | null>(null);
  const sbomLimit = 50;
  const sbomSearchRef = useRef(sbomSearch);
  sbomSearchRef.current = sbomSearch;

  // History for live charts
  const [memHistory, setMemHistory] = useState<{ time: number; value: number }[]>([]);
  const [diskHistory, setDiskHistory] = useState<{ time: number; value: number }[]>([]);
  const [chartMinutes, setChartMinutes] = useState(5);
  const maxHistory = Math.ceil((chartMinutes * 60) / 5); // 5s poll interval

  // Manual scan form
  const [scanTarget, setScanTarget] = useState("");
  const [sourceRepoInputMode, setSourceRepoInputMode] = useState<SourceRepoInputMode>("url");
  const [sourceArchiveFile, setSourceArchiveFile] = useState<File | null>(null);
  const [sourceArchiveTargetName, setSourceArchiveTargetName] = useState("");
  const [scanType, setScanType] = useState<"container_image" | "source_repo">("container_image");
  const [scanners, setScanners] = useState<string[]>(["trivy", "grype", "syft", "dockle", "dive"]);
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState<SubmitScanResponse | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);

  useEffect(() => {
    document.title = t("Hecate Cyber Defense - SCA Scans", "Hecate Cyber Defense - SCA-Scans");
    return () => { document.title = "Hecate Cyber Defense"; };
  }, [t]);

  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    loadData();
  }, [tab, scanFilterTargetId, scanOffset]);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      if (tab === "targets") {
        const [targetsRes, scansRes, badgeCounts] = await Promise.all([
          fetchScanTargets({ limit: 100 }),
          fetchScans({ limit: 1 }),
          fetchBadgeCounts().catch(() => ({ findings: 0, sbom: 0, licenses: 0 })),
        ]);
        setTargets(targetsRes.items);
        setScanTotal(scansRes.total);
        setGlobalFindingsTotal(badgeCounts.findings);
        setSbomTotal(badgeCounts.sbom);
        setLicenseOverviewTotal(badgeCounts.licenses);
      } else if (tab === "scans") {
        // Load targets for filter dropdown if not yet loaded
        if (targets.length === 0) {
          const tRes = await fetchScanTargets({ limit: 100 });
          setTargets(tRes.items);
        }
        const res = await fetchScans({ limit: scanLimit, offset: scanOffset, targetId: scanFilterTargetId || undefined });
        setScans(res.items);
        setScanTotal(res.total);
      } else if (tab === "findings" || tab === "sbom") {
        // Ensure targets loaded for filter dropdown
        if (targets.length === 0) {
          const tRes = await fetchScanTargets({ limit: 100 });
          setTargets(tRes.items);
        }
      } else if (tab === "scanner") {
        try {
          const stats = await fetchScannerStats();
          setScannerStats(stats);
          if (!stats.error) {
            const now = Date.now();
            setMemHistory(prev => [...prev.slice(-(maxHistory - 1)), { time: now, value: stats.memoryUsedBytes }]);
            setDiskHistory(prev => [...prev.slice(-(maxHistory - 1)), { time: now, value: stats.tmpDiskUsedBytes }]);
          }
        } catch { setScannerStats(null); }
      } else if (tab === "licenses") {
        setLicensesLoading(true);
        try {
          const res = await fetchLicenseOverview();
          setLicenseOverview(res.items);
          setLicenseOverviewTotal(res.total);
        } catch { setLicenseOverview([]); setLicenseOverviewTotal(0); }
        setLicensesLoading(false);
      }
    } catch (err) {
      console.error("Failed to load scan data", err);
      setError(t("Could not load data.", "Daten konnten nicht geladen werden."));
    } finally {
      setLoading(false);
    }
  };

  // Debounced fetch for global findings tab
  useEffect(() => {
    if (tab !== "findings") return;
    setFindingsLoading(true);
    const timer = setTimeout(async () => {
      try {
        const res = await fetchGlobalFindings({
          search: findingsSearchRef.current || undefined,
          severity: findingsSeverity || undefined,
          targetId: findingsTargetId || undefined,
          sortBy: findingsSortBy,
          sortOrder: findingsSortOrder,
          limit: findingsLimit,
          offset: findingsOffset,
        });
        setGlobalFindings(res.items);
        setGlobalFindingsTotal(res.total);
      } catch (err) {
        console.error("Failed to load global findings", err);
      } finally {
        setFindingsLoading(false);
      }
    }, findingsSearch ? 300 : 0);
    return () => clearTimeout(timer);
  }, [tab, findingsSearch, findingsSeverity, findingsTargetId, findingsSortBy, findingsSortOrder, findingsOffset]);

  // Debounced fetch for global SBOM tab
  useEffect(() => {
    if (tab !== "sbom") return;
    setSbomLoading(true);
    const timer = setTimeout(async () => {
      try {
        const res = await fetchGlobalSbom({
          search: sbomSearchRef.current || undefined,
          type: sbomType || undefined,
          targetId: sbomTargetId || undefined,
          limit: sbomLimit,
          offset: sbomOffset,
        });
        setSbomComponents(res.items);
        setSbomTotal(res.total);
      } catch (err) {
        console.error("Failed to load global SBOM", err);
      } finally {
        setSbomLoading(false);
      }
    }, sbomSearch ? 300 : 0);
    return () => clearTimeout(timer);
  }, [tab, sbomSearch, sbomType, sbomTargetId, sbomOffset]);

  // SBOM summary stats (computed from loaded page)
  const sbomStats = useMemo(() => {
    const ecosystems: Record<string, number> = {};
    const licenses: Record<string, number> = {};
    const types: Record<string, number> = {};
    for (const c of sbomComponents) {
      const ecoMatch = c.purl?.match(/^pkg:([^/]+)\//);
      const eco = ecoMatch ? ecoMatch[1] : "unknown";
      ecosystems[eco] = (ecosystems[eco] || 0) + 1;
      for (const lic of c.licenses) {
        licenses[lic] = (licenses[lic] || 0) + 1;
      }
      const tp = c.type || "unknown";
      types[tp] = (types[tp] || 0) + 1;
    }
    const sortDesc = (obj: Record<string, number>) =>
      Object.entries(obj).sort((a, b) => b[1] - a[1]);
    return { ecosystems: sortDesc(ecosystems), licenses: sortDesc(licenses), types: sortDesc(types) };
  }, [sbomComponents]);

  // Client-side sort + provenance filter for loaded SBOM page
  const filteredSortedSbom = useMemo(() => {
    let items = sbomComponents;
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
        case "targets": av = String(a.targets.length).padStart(5, "0"); bv = String(b.targets.length).padStart(5, "0"); break;
        default: av = a.name || ""; bv = b.name || "";
      }
      return av.localeCompare(bv) * dir;
    });
    return sorted;
  }, [sbomComponents, sbomSort, sbomFilterProvenance]);

  // Auto-poll every 4s while any scan is running/pending (both tabs)
  useEffect(() => {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
    const hasRunningScans = tab === "scans" && scans.some((s: Scan) => s.status === "running" || s.status === "pending");
    const hasRunningTargets = tab === "targets" && targets.some((t: ScanTarget) => t.hasRunningScan);
    const isScanner = tab === "scanner";
    if (hasRunningScans || hasRunningTargets || isScanner) {
      pollRef.current = setInterval(async () => {
        try {
          if (tab === "scans") {
            const res = await fetchScans({ limit: scanLimit, offset: scanOffset, targetId: scanFilterTargetId || undefined });
            setScans(res.items);
            setScanTotal(res.total);
          } else if (tab === "targets") {
            const res = await fetchScanTargets({ limit: 100 });
            setTargets(res.items);
          } else if (tab === "scanner") {
            const stats = await fetchScannerStats();
            setScannerStats(stats);
            if (!stats.error) {
              const now = Date.now();
              setMemHistory(prev => [...prev.slice(-(maxHistory - 1)), { time: now, value: stats.memoryUsedBytes }]);
              setDiskHistory(prev => [...prev.slice(-(maxHistory - 1)), { time: now, value: stats.tmpDiskUsedBytes }]);
            }
          }
        } catch { /* ignore poll errors */ }
      }, isScanner ? 5000 : 4000);
    }
    return () => { if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; } };
  }, [tab, scans, targets]);

  const handleScannerToggle = (name: string) => {
    setScanners(prev =>
      prev.includes(name) ? prev.filter(s => s !== name) : [...prev, name]
    );
  };

  const handleSubmitScan = async (e: FormEvent) => {
    e.preventDefault();
    const needsTextTarget = scanType === "container_image" || (scanType === "source_repo" && sourceRepoInputMode === "url");
    if ((needsTextTarget && !scanTarget.trim()) || (!needsTextTarget && !sourceArchiveFile) || scanners.length === 0) return;
    setScanning(true);
    setScanResult(null);
    setScanError(null);
    try {
      const effectiveScanners = scanType === "container_image"
        ? scanners.filter((s: string) => s !== "osv-scanner" && s !== "hecate")
        : scanners.filter((s: string) => s !== "dockle" && s !== "dive");
      if (scanType === "source_repo" && sourceRepoInputMode === "zip" && sourceArchiveFile && !sourceArchiveFile.name.toLowerCase().endsWith(".zip")) {
        setScanError(t("Please upload a .zip archive.", "Bitte eine .zip-Datei hochladen."));
        setScanning(false);
        return;
      }
      const result = scanType === "source_repo" && sourceRepoInputMode === "zip" && sourceArchiveFile
        ? await submitManualSourceArchiveScan({
          archive: sourceArchiveFile,
          scanners: effectiveScanners,
          targetName: sourceArchiveTargetName.trim() || undefined,
        })
        : await submitManualScan({
          target: scanTarget.trim(),
          type: scanType,
          scanners: effectiveScanners,
        });
      setScanResult(result);
      // Switch to scans tab to show the running scan
      setTab("scans");
    } catch (err: any) {
      console.error("Scan failed", err);
      setScanError(err?.response?.data?.detail || t("Scan failed.", "Scan fehlgeschlagen."));
    } finally {
      setScanning(false);
    }
  };

  const handleRescan = async (target: ScanTarget) => {
    if (target.type === "sbom-import") return;
    try {
      const fallbackScanners = target.type === "container_image"
        ? ["trivy", "grype", "syft", "dockle", "dive"]
        : ["trivy", "grype", "syft", "osv-scanner", "hecate", "semgrep", "trufflehog"];
      await submitManualScan({
        target: target.id,
        type: target.type,
        scanners: target.scanners?.length ? target.scanners : fallbackScanners,
      });
      setTab("scans");
    } catch (err) {
      console.error("Rescan failed", err);
    }
  };

  const handleDeleteTarget = (targetId: string) => {
    setConfirmModal({
      title: t("Delete Target", "Ziel löschen"),
      message: t(
        "Delete this target and all its scan data? This action cannot be undone.",
        "Dieses Ziel und alle zugehörigen Scan-Daten löschen? Diese Aktion kann nicht rückgängig gemacht werden."
      ),
      onConfirm: async () => {
        try {
          await deleteScanTarget(targetId);
          setTargets(prev => prev.filter(t => t.id !== targetId));
        } catch (err) {
          console.error("Delete failed", err);
        }
        setConfirmModal(null);
      },
    });
  };

  const handleDeleteScan = (scanId: string, scanName: string) => {
    setConfirmModal({
      title: t("Delete Scan", "Scan löschen"),
      message: t(
        `Delete scan "${scanName}"? Findings and SBOM data will be removed.`,
        `Scan „${scanName}" löschen? Ergebnisse und SBOM-Daten werden entfernt.`
      ),
      onConfirm: async () => {
        try {
          await deleteScan(scanId);
          setScans(prev => prev.filter(s => s.id !== scanId));
        } catch (err) {
          console.error("Delete scan failed", err);
        }
        setConfirmModal(null);
      },
    });
  };

  const handleCancelScan = async (scanId: string) => {
    try {
      await cancelScan(scanId);
      loadData();
    } catch (err) {
      console.error("Cancel scan failed", err);
    }
  };

  const handleToggleAutoScan = async (target: ScanTarget) => {
    const newValue = target.autoScan === false; // toggle; default is true
    try {
      await updateScanTarget(target.id, { autoScan: newValue });
      setTargets(prev => prev.map((tt: ScanTarget) => tt.id === target.id ? { ...tt, autoScan: newValue } : tt));
    } catch (err) {
      console.error("Toggle auto-scan failed", err);
    }
  };

  const handleUpdateScanners = async (targetId: string, newScanners: string[]) => {
    try {
      await updateScanTarget(targetId, { scanners: newScanners });
      setTargets(prev => prev.map((tt: ScanTarget) => tt.id === targetId ? { ...tt, scanners: newScanners } : tt));
    } catch (err) {
      console.error("Update scanners failed", err);
    }
  };

  const handleUpdateGroup = async (targetId: string, group: string | null) => {
    const normalized = group && group.trim() ? group.trim() : null;
    try {
      await updateScanTarget(targetId, { group: normalized });
      setTargets(prev => prev.map((tt: ScanTarget) => tt.id === targetId ? { ...tt, group: normalized } : tt));
    } catch (err) {
      console.error("Update group failed", err);
    }
  };

  const isSubmitDisabled =
    scanning
    || scanners.length === 0
    || (
      scanType === "source_repo"
        ? (sourceRepoInputMode === "url" ? !scanTarget.trim() : !sourceArchiveFile)
        : !scanTarget.trim()
    );

  return (
    <div className="page">
      <section className="card">
        <h2>{t("Software Composition Analysis", "Software-Kompositionsanalyse")}</h2>
        <p className="muted">
          {t(
            "Scan container images and source repositories for vulnerabilities and generate SBOMs.",
            "Container-Images und Quellcode-Repositories auf Schwachstellen scannen und SBOMs generieren."
          )}
        </p>

        {/* Tab navigation */}
        <div className="tabs-scroll" style={{ display: "flex", gap: 0, marginBottom: "1.5rem", marginTop: "1rem", borderBottom: "1px solid rgba(255,255,255,0.08)" }}>
          {([
            { key: "targets" as Tab, label: t("Targets", "Ziele"), count: targets.length || undefined },
            { key: "scans" as Tab, label: t("Scans", "Scans"), count: scanTotal || undefined },
            { key: "findings" as Tab, label: t("Findings", "Funde"), count: globalFindingsTotal || undefined },
            { key: "sbom" as Tab, label: "SBOM", count: sbomTotal || undefined },
            { key: "licenses" as Tab, label: t("Licenses", "Lizenzen"), count: licenseOverviewTotal || undefined },
            { key: "manual" as Tab, label: t("New Scan", "Neuer Scan") },
            { key: "scanner" as Tab, label: t("Scanner", "Scanner") },
          ]).map(({ key, label, count }) => (
            <button
              key={key}
              type="button"
              onClick={() => { setTab(key); if (key === "scans") { setScanOffset(0); } }}
              style={{
                padding: "0.625rem 1.25rem",
                border: "none",
                borderBottom: tab === key ? "2px solid #ffd43b" : "2px solid transparent",
                background: "transparent",
                color: tab === key ? "#ffd43b" : "rgba(255,255,255,0.5)",
                cursor: "pointer",
                fontSize: "0.8125rem",
                fontWeight: tab === key ? 600 : 400,
                transition: "color 0.15s, border-color 0.15s",
                flexShrink: 0,
                whiteSpace: "nowrap",
              }}
            >
              {label}
              {count !== undefined && count > 0 && (
                <span style={{
                  marginLeft: "0.375rem",
                  padding: "0.0625rem 0.375rem",
                  borderRadius: "8px",
                  fontSize: "0.6875rem",
                  fontWeight: 600,
                  background: tab === key ? "rgba(255,193,7,0.15)" : "rgba(255,255,255,0.06)",
                  color: tab === key ? "#ffd43b" : "rgba(255,255,255,0.4)",
                }}>
                  {count}
                </span>
              )}
            </button>
          ))}
        </div>

        {error && <p className="muted">{error}</p>}

        {/* Targets tab */}
        {tab === "targets" && (
          <div>
            {loading && (
              <div style={{ display: "grid", gap: "1rem", gridTemplateColumns: "repeat(auto-fill, minmax(min(100%, 420px), 1fr))" }}>
                {Array.from({ length: 4 }).map((_, i) => (
                  <SkeletonBlock key={i} height={140} radius={8} />
                ))}
              </div>
            )}
            {!loading && targets.length === 0 && (
              <p className="muted">{t("No scan targets registered yet.", "Noch keine Scan-Ziele registriert.")}</p>
            )}
            {!loading && targets.length > 0 && (() => {
              // Group targets by their `group` field; ungrouped targets bucket last.
              const UNGROUPED = "__ungrouped__";
              const buckets = new Map<string, ScanTarget[]>();
              for (const tgt of targets) {
                const key = (tgt.group && tgt.group.trim()) || UNGROUPED;
                if (!buckets.has(key)) buckets.set(key, []);
                buckets.get(key)!.push(tgt);
              }
              const orderedKeys = Array.from(buckets.keys()).sort((a, b) => {
                if (a === UNGROUPED) return 1;
                if (b === UNGROUPED) return -1;
                return a.localeCompare(b);
              });
              const allGroupNames = orderedKeys.filter(k => k !== UNGROUPED);
              const sumSummary = (items: ScanTarget[]): ScanSummary => {
                const sum: ScanSummary = { critical: 0, high: 0, medium: 0, low: 0, negligible: 0, unknown: 0, total: 0 };
                for (const it of items) {
                  const s = it.latestSummary;
                  if (!s) continue;
                  sum.critical += s.critical || 0;
                  sum.high += s.high || 0;
                  sum.medium += s.medium || 0;
                  sum.low += s.low || 0;
                  sum.negligible += s.negligible || 0;
                  sum.unknown += s.unknown || 0;
                  sum.total += s.total || 0;
                }
                return sum;
              };
              const onFilterScansFn = (id: string, name: string) => {
                setScanFilterTargetId(id);
                setScanFilterTargetName(name);
                setScanOffset(0);
                setTab("scans");
              };
              return (
                <div style={{ display: "flex", flexDirection: "column", gap: "1.25rem" }}>
                  {orderedKeys.map(key => {
                    const items = buckets.get(key)!;
                    const isUngrouped = key === UNGROUPED;
                    const collapsed = !!collapsedGroups[key];
                    const rollup = sumSummary(items);
                    const label = isUngrouped ? t("Ungrouped", "Ohne Gruppe") : key;
                    return (
                      <div key={key}>
                        <div
                          role="button"
                          tabIndex={0}
                          onClick={() => setCollapsedGroups({ ...collapsedGroups, [key]: !collapsed })}
                          onKeyDown={e => {
                            if (e.key === "Enter" || e.key === " ") {
                              e.preventDefault();
                              setCollapsedGroups({ ...collapsedGroups, [key]: !collapsed });
                            }
                          }}
                          style={{
                            display: "flex",
                            alignItems: "center",
                            gap: "0.75rem",
                            padding: "0.5rem 0.75rem",
                            marginBottom: "0.625rem",
                            borderRadius: "6px",
                            background: "rgba(255,255,255,0.03)",
                            border: "1px solid rgba(255,255,255,0.06)",
                            cursor: "pointer",
                            userSelect: "none",
                          }}
                        >
                          <span style={{
                            display: "inline-block",
                            width: "0.75rem",
                            transform: collapsed ? "rotate(-90deg)" : "rotate(0deg)",
                            transition: "transform 0.15s",
                            color: "rgba(255,255,255,0.5)",
                            fontSize: "0.7rem",
                          }}>▼</span>
                          <span style={{
                            fontSize: "0.875rem",
                            fontWeight: 600,
                            color: isUngrouped ? "rgba(255,255,255,0.55)" : "#ffd43b",
                            wordBreak: "break-word",
                          }}>{label}</span>
                          <span style={{
                            fontSize: "0.7rem",
                            color: "rgba(255,255,255,0.4)",
                            padding: "0.0625rem 0.4rem",
                            borderRadius: "8px",
                            background: "rgba(255,255,255,0.05)",
                          }}>{items.length}</span>
                          <div style={{ marginLeft: "auto" }}>
                            <SeverityBadges summary={rollup} />
                          </div>
                        </div>
                        {!collapsed && (
                          <div style={{ display: "grid", gap: "1rem", gridTemplateColumns: "repeat(auto-fill, minmax(min(100%, 420px), 1fr))" }}>
                            {items.map(target => (
                              <TargetCard
                                key={target.id}
                                target={target}
                                groupSuggestions={allGroupNames}
                                onDelete={handleDeleteTarget}
                                onRescan={handleRescan}
                                onToggleAutoScan={handleToggleAutoScan}
                                onUpdateScanners={handleUpdateScanners}
                                onUpdateGroup={handleUpdateGroup}
                                onCancelScan={handleCancelScan}
                                onFilterScans={onFilterScansFn}
                              />
                            ))}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              );
            })()}
          </div>
        )}

        {/* Scans tab */}
        {tab === "scans" && (
          <div>
            {/* Filter bar */}
            <div style={{
              display: "flex",
              alignItems: "center",
              gap: "0.5rem",
              marginBottom: "1rem",
              flexWrap: "wrap",
            }}>
              <select
                value={scanFilterTargetId || ""}
                onChange={e => {
                  const val = e.target.value;
                  if (val) {
                    const tgt = targets.find(t => t.id === val);
                    setScanFilterTargetId(val);
                    setScanFilterTargetName(tgt?.name || val);
                  } else {
                    setScanFilterTargetId(null);
                    setScanFilterTargetName(null);
                  }
                  setScanOffset(0);
                }}
                style={{
                  padding: "0 0.625rem",
                  borderRadius: "6px",
                  border: "1px solid rgba(255,255,255,0.12)",
                  background: "rgba(255,255,255,0.05)",
                  color: scanFilterTargetId ? "#ffd43b" : "rgba(255,255,255,0.5)",
                  fontSize: "0.8125rem",
                  outline: "none",
                  cursor: "pointer",
                  minWidth: "180px",
                  maxWidth: "320px",
                  height: "32px",
                  boxSizing: "border-box" as const,
                }}
              >
                <option value="">{t("All targets", "Alle Ziele")}</option>
                {targets.map(tgt => (
                  <option key={tgt.id} value={tgt.id}>{tgt.name}</option>
                ))}
              </select>
              {scanFilterTargetId && (
                <button
                  type="button"
                  onClick={() => { setScanFilterTargetId(null); setScanFilterTargetName(null); setScanOffset(0); }}
                  style={{
                    background: "none",
                    border: "none",
                    color: "rgba(255,255,255,0.4)",
                    cursor: "pointer",
                    fontSize: "0.8125rem",
                    padding: "0.25rem",
                  }}
                  title={t("Clear filter", "Filter entfernen")}
                >
                  ×
                </button>
              )}
              <span style={{ marginLeft: "auto", fontSize: "0.75rem", color: "rgba(255,255,255,0.35)" }}>
                {scanTotal} {t("total", "gesamt")}
              </span>
            </div>

            {loading && (
              <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
                {Array.from({ length: 6 }).map((_, i) => (
                  <SkeletonBlock key={i} height={40} radius={4} />
                ))}
              </div>
            )}
            {!loading && scans.length === 0 && (
              <p className="muted">{t("No scans yet.", "Noch keine Scans.")}</p>
            )}
            {!loading && scans.length > 0 && (
              <>
                <div style={{ overflowX: "auto" }}>
                  <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.875rem" }}>
                    <thead>
                      <tr style={{ borderBottom: "1px solid rgba(255,255,255,0.1)" }}>
                        <th style={thStyle}>{t("Target", "Ziel")}</th>
                        <th style={thStyle}>{t("Ref", "Ref")}</th>
                        <th style={thStyle}>Status</th>
                        <th style={thStyle}>{t("Findings", "Ergebnisse")}</th>
                        <th style={thStyle}>{t("Source", "Quelle")}</th>
                        <th style={thStyle}>{t("Date", "Datum")}</th>
                        <th style={{ ...thStyle, width: "2.5rem" }} />
                      </tr>
                    </thead>
                    <tbody>
                      {scans.map(scan => {
                        const ref = scan.imageRef
                          ? (() => {
                              const digest = scan.imageRef!.includes("@") ? scan.imageRef!.split("@")[1] : null;
                              return digest ? `${digest.substring(0, 16)}…` : null;
                            })()
                          : scan.commitSha
                            ? scan.commitSha.substring(0, 8)
                            : null;
                        const refFull = scan.imageRef || scan.commitSha || null;
                        const refLabel = scan.imageRef ? "Digest" : "Commit";
                        const refUrl = (() => {
                          if (scan.commitSha) {
                            const repoUrl = scan.repositoryUrl || (scan.targetId.startsWith("http") ? scan.targetId : null);
                            if (repoUrl) return `${repoUrl.replace(/\/$/, "")}/commit/${scan.commitSha}`;
                          }
                          if (scan.imageRef) {
                            const imgRef = scan.imageRef;
                            if (imgRef.startsWith("http://") || imgRef.startsWith("https://")) return imgRef;
                            const withoutDigest = imgRef.split("@")[0];
                            const cleaned = withoutDigest.split(":")[0];
                            if (cleaned.startsWith("ghcr.io/")) {
                              const parts = cleaned.replace("ghcr.io/", "").split("/");
                              const owner = parts[0];
                              const pkg = parts.slice(1).join("/");
                              if (owner && pkg) return `https://github.com/${owner}/pkgs/container/${pkg}`;
                            }
                            if (cleaned.startsWith("docker.io/")) {
                              const path = cleaned.replace("docker.io/", "");
                              const tag = withoutDigest.includes(":") ? withoutDigest.split(":").pop() : "latest";
                              return `https://hub.docker.com/layers/${path}/${tag}/images`;
                            }
                            if (cleaned.includes(".") && cleaned.includes("/")) return `https://${cleaned}`;
                          }
                          return null;
                        })();
                        return (
                          <tr key={scan.id} style={{ borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
                            <td style={tdStyle}>
                              <Link to={`/scans/${scan.id}`} style={{ color: "#ffd43b", textDecoration: "none" }}>
                                {scan.targetName || scan.targetId}
                              </Link>
                            </td>
                            <td style={{ ...tdStyle, fontFamily: ref ? "monospace" : undefined, fontSize: ref ? "0.75rem" : "0.875rem", color: ref ? "rgba(255,255,255,0.45)" : "rgba(255,255,255,0.25)" }} title={refFull || undefined}>
                              {ref ? (
                                <span>
                                  {refLabel}: {ref}
                                  {refUrl && (
                                    <a href={refUrl} target="_blank" rel="noopener noreferrer" style={{ marginLeft: "0.35rem", color: "rgba(255,255,255,0.4)", textDecoration: "none", fontSize: "0.7rem" }} title={refUrl}>↗</a>
                                  )}
                                </span>
                              ) : "—"}
                            </td>
                            <td style={tdStyle}><StatusBadge status={scan.status} /></td>
                            <td style={tdStyle}><SeverityBadges summary={scan.summary} /></td>
                            <td style={tdStyle}><SourceBadge source={scan.source} /></td>
                            <td style={tdStyle}>{(() => {
                              const done = scan.status === "completed" || scan.status === "failed" || scan.status === "cancelled";
                              const ts = done ? (scan.finishedAt || scan.startedAt) : scan.startedAt;
                              return ts ? formatDateTime(ts) : "—";
                            })()}</td>
                            <td style={tdStyle}>
                              {(scan.status === "running" || scan.status === "pending") ? (
                                <button
                                  type="button"
                                  onClick={() => handleCancelScan(scan.id)}
                                  title={t("Stop scan", "Scan stoppen")}
                                  style={{ background: "none", border: "none", color: "#ff6b6b", cursor: "pointer", fontSize: "0.75rem", padding: "0.125rem 0.25rem", fontWeight: 500 }}
                                >
                                  ■
                                </button>
                              ) : (
                                <button
                                  type="button"
                                  onClick={() => handleDeleteScan(scan.id, scan.targetName || scan.targetId)}
                                  title={t("Delete scan", "Scan löschen")}
                                  style={{ background: "none", border: "none", color: "rgba(255,255,255,0.25)", cursor: "pointer", fontSize: "0.875rem", padding: "0.125rem 0.25rem" }}
                                >
                                  ×
                                </button>
                              )}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>

                {/* Pagination */}
                {scanTotal > scanLimit && (
                  <div style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    gap: "0.75rem",
                    marginTop: "1rem",
                    fontSize: "0.8125rem",
                  }}>
                    <button
                      type="button"
                      disabled={scanOffset === 0}
                      onClick={() => setScanOffset(Math.max(0, scanOffset - scanLimit))}
                      style={{
                        padding: "0.3rem 0.75rem",
                        borderRadius: "4px",
                        border: "1px solid rgba(255,255,255,0.1)",
                        background: scanOffset === 0 ? "transparent" : "rgba(255,255,255,0.05)",
                        color: scanOffset === 0 ? "rgba(255,255,255,0.2)" : "rgba(255,255,255,0.6)",
                        cursor: scanOffset === 0 ? "default" : "pointer",
                        fontSize: "0.8125rem",
                      }}
                    >
                      ← {t("Previous", "Zurück")}
                    </button>
                    <span style={{ color: "rgba(255,255,255,0.4)" }}>
                      {Math.floor(scanOffset / scanLimit) + 1} / {Math.ceil(scanTotal / scanLimit)}
                    </span>
                    <button
                      type="button"
                      disabled={scanOffset + scanLimit >= scanTotal}
                      onClick={() => setScanOffset(scanOffset + scanLimit)}
                      style={{
                        padding: "0.3rem 0.75rem",
                        borderRadius: "4px",
                        border: "1px solid rgba(255,255,255,0.1)",
                        background: scanOffset + scanLimit >= scanTotal ? "transparent" : "rgba(255,255,255,0.05)",
                        color: scanOffset + scanLimit >= scanTotal ? "rgba(255,255,255,0.2)" : "rgba(255,255,255,0.6)",
                        cursor: scanOffset + scanLimit >= scanTotal ? "default" : "pointer",
                        fontSize: "0.8125rem",
                      }}
                    >
                      {t("Next", "Weiter")} →
                    </button>
                  </div>
                )}
              </>
            )}
          </div>
        )}

        {/* Findings tab */}
        {tab === "findings" && (
          <div>
            {/* Filter bar */}
            <div className="findings-filter-bar" style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "1rem", flexWrap: "wrap" }}>
              <input
                type="text"
                value={findingsSearch}
                onChange={e => { setFindingsSearch(e.target.value); setFindingsOffset(0); }}
                placeholder={t("Search by CVE, package, title...", "Suche nach CVE, Paket, Titel...")}
                style={{
                  padding: "0.375rem 0.75rem",
                  borderRadius: "6px",
                  border: "1px solid rgba(255,255,255,0.15)",
                  background: "rgba(255,255,255,0.05)",
                  color: "#fff",
                  fontSize: "0.8125rem",
                  flex: "1 1 200px",
                  maxWidth: "400px",
                  minWidth: 0,
                  outline: "none",
                  height: "32px",
                  boxSizing: "border-box",
                }}
              />
              {/* Severity filter buttons */}
              <div className="findings-severity-buttons" style={{ display: "flex", gap: "0.25rem" }}>
                {([
                  { value: null, label: t("All", "Alle") },
                  { value: "critical", label: "Critical" },
                  { value: "high", label: "High" },
                  { value: "medium", label: "Medium" },
                  { value: "low", label: "Low" },
                ] as const).map(({ value, label }) => {
                  const active = findingsSeverity === value;
                  const sevColors: Record<string, string> = { critical: "#ff6b6b", high: "#ff922b", medium: "#fcc419", low: "#69db7c" };
                  const color = value ? sevColors[value] : "#ffd43b";
                  return (
                    <button
                      key={label}
                      type="button"
                      onClick={() => { setFindingsSeverity(value); setFindingsOffset(0); }}
                      style={{
                        padding: "0 0.5rem",
                        borderRadius: "4px",
                        border: `1px solid ${active ? color : "rgba(255,255,255,0.1)"}`,
                        background: active ? `${color}22` : "transparent",
                        color: active ? color : "rgba(255,255,255,0.4)",
                        cursor: "pointer",
                        fontSize: "0.75rem",
                        fontWeight: active ? 600 : 400,
                        height: "32px",
                        boxSizing: "border-box",
                      }}
                    >
                      {label}
                    </button>
                  );
                })}
              </div>
              <select
                value={findingsTargetId || ""}
                onChange={e => { setFindingsTargetId(e.target.value || null); setFindingsOffset(0); }}
                className="findings-target-select"
                style={{
                  padding: "0 0.625rem",
                  borderRadius: "6px",
                  border: "1px solid rgba(255,255,255,0.12)",
                  background: "rgba(255,255,255,0.05)",
                  color: findingsTargetId ? "#ffd43b" : "rgba(255,255,255,0.5)",
                  fontSize: "0.8125rem",
                  outline: "none",
                  cursor: "pointer",
                  minWidth: "140px",
                  maxWidth: "280px",
                  height: "32px",
                  boxSizing: "border-box",
                }}
              >
                <option value="">{t("All targets", "Alle Ziele")}</option>
                {targets.map(tgt => (
                  <option key={tgt.id} value={tgt.id}>{tgt.name}</option>
                ))}
              </select>
              <span style={{ color: "rgba(255,255,255,0.35)", fontSize: "0.75rem", marginLeft: "auto" }}>
                {globalFindingsTotal.toLocaleString()} {t("findings", "Funde")}
              </span>
            </div>

            {findingsLoading ? (
              <div style={{ overflowX: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr style={{ borderBottom: "1px solid rgba(255,255,255,0.08)" }}>
                      {[t("Vulnerability", "Schwachstelle"), t("Package", "Paket"), t("Version", "Version"), t("Severity", "Schweregrad"), "CVSS", t("Fix", "Fix"), t("Scanners", "Scanner"), t("Targets", "Ziele")].map(label => (
                        <th key={label} style={thStyle}>{label}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {Array.from({ length: 10 }).map((_, i) => (
                      <tr key={i} style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                        {Array.from({ length: 8 }).map((_, j) => (
                          <td key={j} style={tdStyle}>
                            <SkeletonBlock height={16} width={j === 0 ? "80%" : j === 4 ? "40px" : j === 7 ? "30px" : "60%"} radius={4} />
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : globalFindings.length === 0 ? (
              <p className="muted" style={{ textAlign: "center", padding: "2rem 0" }}>
                {findingsSearch || findingsSeverity || findingsTargetId
                  ? t("No findings match your filters.", "Keine Funde entsprechen Ihren Filtern.")
                  : t("No findings from latest scans.", "Keine Funde aus den letzten Scans.")}
              </p>
            ) : (
              <>
                <div style={{ overflowX: "auto" }}>
                  <table style={{ width: "100%", borderCollapse: "collapse" }}>
                    <thead>
                      <tr style={{ borderBottom: "1px solid rgba(255,255,255,0.08)" }}>
                        {([
                          { key: "vulnerability_id", label: t("Vulnerability", "Schwachstelle") },
                          { key: "package_name", label: t("Package", "Paket") },
                          { key: "package_version", label: t("Version", "Version") },
                          { key: "severity", label: t("Severity", "Schweregrad") },
                          { key: "cvss_score", label: "CVSS" },
                          { key: "fix_version", label: t("Fix", "Fix") },
                          { key: null as string | null, label: t("Scanners", "Scanner") },
                          { key: "targets", label: t("Targets", "Ziele") },
                        ] as const).map(({ key, label }) => (
                          <th
                            key={label}
                            style={{ ...thStyle, cursor: key ? "pointer" : "default", userSelect: "none", whiteSpace: "nowrap" }}
                            onClick={() => {
                              if (!key) return;
                              if (findingsSortBy === key) {
                                setFindingsSortOrder(prev => prev === "asc" ? "desc" : "asc");
                              } else {
                                setFindingsSortBy(key);
                                setFindingsSortOrder(key === "package_name" || key === "vulnerability_id" ? "asc" : "desc");
                              }
                              setFindingsOffset(0);
                            }}
                          >
                            {label}
                            {key && findingsSortBy === key && (
                              <span style={{ marginLeft: "0.25rem", fontSize: "0.625rem" }}>
                                {findingsSortOrder === "asc" ? "▲" : "▼"}
                              </span>
                            )}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {globalFindings.map((f, idx) => {
                        const sevColors: Record<string, string> = { critical: "#ff6b6b", high: "#ff922b", medium: "#fcc419", low: "#69db7c" };
                        const sev = (f.severity || "").toLowerCase();
                        const sevColor = sevColors[sev] || "#868e96";
                        const rowKey = `${f.vulnerabilityId || ""}|${f.packageName}|${f.packageVersion}`;
                        const isExpanded = expandedFindings.has(rowKey);
                        return (
                          <React.Fragment key={rowKey}>
                            <tr
                              onClick={() => setExpandedFindings(prev => { const next = new Set(prev); if (next.has(rowKey)) next.delete(rowKey); else next.add(rowKey); return next; })}
                              style={{ borderBottom: isExpanded ? "none" : "1px solid rgba(255,255,255,0.04)", cursor: "pointer", transition: "background 0.1s" }}
                              onMouseEnter={e => { (e.currentTarget as HTMLTableRowElement).style.background = "rgba(255,255,255,0.03)"; }}
                              onMouseLeave={e => { (e.currentTarget as HTMLTableRowElement).style.background = ""; }}
                            >
                              <td style={tdStyle}>
                                {f.vulnerabilityId ? (
                                  <Link to={`/vulnerability/${encodeURIComponent(f.vulnerabilityId)}`} onClick={e => e.stopPropagation()} style={{ color: "#ffd43b", textDecoration: "none", fontSize: "0.8125rem" }}>
                                    {f.vulnerabilityId}
                                  </Link>
                                ) : (
                                  <span style={{ color: "rgba(255,255,255,0.4)", fontSize: "0.8125rem" }}>{f.title || "—"}</span>
                                )}
                              </td>
                              <td style={{ ...tdStyle, fontSize: "0.8125rem", fontFamily: "monospace" }}>{f.packageName}</td>
                              <td style={{ ...tdStyle, fontSize: "0.75rem", color: "rgba(255,255,255,0.5)", fontFamily: "monospace" }}>{f.packageVersion}</td>
                              <td style={tdStyle}>
                                <span style={{
                                  display: "inline-block",
                                  padding: "0.125rem 0.5rem",
                                  borderRadius: "4px",
                                  fontSize: "0.6875rem",
                                  fontWeight: 600,
                                  background: `${sevColor}22`,
                                  color: sevColor,
                                  textTransform: "capitalize",
                                }}>
                                  {sev || "unknown"}
                                </span>
                              </td>
                              <td style={{ ...tdStyle, fontSize: "0.75rem", fontFamily: "monospace", color: f.cvssScore != null ? "#ffd43b" : "rgba(255,255,255,0.2)" }}>
                                {f.cvssScore != null ? f.cvssScore.toFixed(1) : "—"}
                              </td>
                              <td style={{ ...tdStyle, fontSize: "0.75rem", color: f.fixVersion ? "#69db7c" : "rgba(255,255,255,0.25)" }}>
                                {f.fixVersion || "—"}
                              </td>
                              <td style={{ ...tdStyle, fontSize: "0.75rem", color: "rgba(255,255,255,0.4)" }}>
                                {f.scanners.join(", ")}
                              </td>
                              <td style={{ ...tdStyle, fontSize: "0.75rem", color: "rgba(255,255,255,0.4)" }}>
                                {f.targets.length}
                              </td>
                            </tr>
                            {isExpanded && (
                              <tr>
                                <td colSpan={8} style={{ padding: "0 0.75rem 0.75rem 1.5rem", background: "rgba(255,255,255,0.02)", borderBottom: "1px solid rgba(255,255,255,0.06)", textAlign: "left" }}>
                                  <div style={{ fontSize: "0.75rem", color: "rgba(255,255,255,0.5)", marginTop: "0.5rem", marginBottom: "0.375rem", fontWeight: 500, textAlign: "left" }}>
                                    {t("Found in targets:", "Gefunden in Zielen:")}
                                  </div>
                                  <div style={{ display: "flex", flexDirection: "column", gap: "0.25rem", alignItems: "flex-start" }}>
                                    {f.targets.map(tgt => {
                                      const tgtName = targets.find(tt => tt.id === tgt.targetId)?.name || tgt.targetId;
                                      return (
                                        <Link
                                          key={`${tgt.targetId}-${tgt.scanId}`}
                                          to={`/scans/${encodeURIComponent(tgt.scanId)}`}
                                          onClick={e => e.stopPropagation()}
                                          style={{ color: "#ffd43b", textDecoration: "none", fontSize: "0.8125rem", display: "inline-flex", alignItems: "center", gap: "0.375rem" }}
                                        >
                                          <span style={{ color: "rgba(255,255,255,0.6)" }}>{tgtName}</span>
                                        </Link>
                                      );
                                    })}
                                  </div>
                                </td>
                              </tr>
                            )}
                          </React.Fragment>
                        );
                      })}
                    </tbody>
                  </table>
                </div>

                {/* Pagination */}
                {globalFindingsTotal > findingsLimit && (
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: "0.75rem", marginTop: "1rem", fontSize: "0.8125rem" }}>
                    <button
                      type="button"
                      disabled={findingsOffset === 0}
                      onClick={() => setFindingsOffset(Math.max(0, findingsOffset - findingsLimit))}
                      style={{
                        padding: "0.3rem 0.75rem", borderRadius: "4px",
                        border: "1px solid rgba(255,255,255,0.1)",
                        background: findingsOffset === 0 ? "transparent" : "rgba(255,255,255,0.05)",
                        color: findingsOffset === 0 ? "rgba(255,255,255,0.2)" : "rgba(255,255,255,0.6)",
                        cursor: findingsOffset === 0 ? "default" : "pointer",
                        fontSize: "0.8125rem",
                      }}
                    >
                      ← {t("Previous", "Zurück")}
                    </button>
                    <span style={{ color: "rgba(255,255,255,0.4)" }}>
                      {Math.floor(findingsOffset / findingsLimit) + 1} / {Math.ceil(globalFindingsTotal / findingsLimit)}
                    </span>
                    <button
                      type="button"
                      disabled={findingsOffset + findingsLimit >= globalFindingsTotal}
                      onClick={() => setFindingsOffset(findingsOffset + findingsLimit)}
                      style={{
                        padding: "0.3rem 0.75rem", borderRadius: "4px",
                        border: "1px solid rgba(255,255,255,0.1)",
                        background: findingsOffset + findingsLimit >= globalFindingsTotal ? "transparent" : "rgba(255,255,255,0.05)",
                        color: findingsOffset + findingsLimit >= globalFindingsTotal ? "rgba(255,255,255,0.2)" : "rgba(255,255,255,0.6)",
                        cursor: findingsOffset + findingsLimit >= globalFindingsTotal ? "default" : "pointer",
                        fontSize: "0.8125rem",
                      }}
                    >
                      {t("Next", "Weiter")} →
                    </button>
                  </div>
                )}
              </>
            )}
          </div>
        )}

        {/* SBOM tab */}
        {tab === "sbom" && (
          <div>
            {/* SBOM Import card */}
            {!sbomImportResult ? (
              <div
                onDragOver={e => { e.preventDefault(); e.stopPropagation(); }}
                onDrop={e => {
                  e.preventDefault(); e.stopPropagation();
                  const file = e.dataTransfer.files?.[0];
                  if (file && (file.name.endsWith(".json") || file.type === "application/json")) {
                    setSbomImportFile(file);
                    setSbomImportResult(null);
                    setSbomImportError(null);
                  }
                }}
                style={{
                  marginBottom: "1.25rem",
                  padding: "1rem 1.25rem",
                  border: "1px dashed rgba(255,212,59,0.25)",
                  borderRadius: "10px",
                  background: "rgba(255,212,59,0.03)",
                  display: "flex",
                  flexDirection: "column",
                  gap: "0.75rem",
                }}
              >
                <div style={{ flex: "1 1 0", minWidth: "140px" }}>
                  <div style={{ fontSize: "0.8125rem", fontWeight: 600, color: "rgba(255,255,255,0.8)", marginBottom: "0.25rem" }}>
                    {t("Import SBOM", "SBOM importieren")}
                  </div>
                  {sbomImportFile ? (
                    <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                      <span style={{
                        padding: "0.25rem 0.625rem", borderRadius: "6px", fontSize: "0.75rem", fontWeight: 500,
                        background: "rgba(255,212,59,0.12)", color: "#ffd43b", border: "1px solid rgba(255,212,59,0.25)",
                        maxWidth: "260px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                      }}>
                        {sbomImportFile.name}
                      </span>
                      <button type="button" onClick={() => { setSbomImportFile(null); setSbomImportError(null); }}
                        style={{ background: "none", border: "none", color: "rgba(255,255,255,0.35)", cursor: "pointer", fontSize: "0.875rem", padding: "0 0.25rem" }}>
                        ×
                      </button>
                    </div>
                  ) : (
                    <label style={{ cursor: "pointer" }}>
                      <span style={{ fontSize: "0.75rem", color: "rgba(255,255,255,0.4)" }}>
                        {t("Drop a CycloneDX / SPDX JSON file here or ", "CycloneDX / SPDX JSON-Datei hierher ziehen oder ")}
                        <span style={{ color: "#ffd43b", textDecoration: "underline" }}>{t("browse", "durchsuchen")}</span>
                      </span>
                      <input type="file" accept=".json,application/json" style={{ display: "none" }}
                        onChange={e => {
                          setSbomImportFile(e.target.files?.[0] || null);
                          setSbomImportResult(null);
                          setSbomImportError(null);
                          e.target.value = "";
                        }}
                      />
                    </label>
                  )}
                  {sbomImportError && (
                    <div style={{ fontSize: "0.75rem", color: "#ff6b6b", marginTop: "0.25rem" }}>{sbomImportError}</div>
                  )}
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", flexWrap: "wrap" }}>
                  <select
                    value={sbomImportFormat}
                    onChange={e => setSbomImportFormat(e.target.value)}
                    style={{
                      padding: "0.3rem 0.5rem", borderRadius: "6px",
                      border: "1px solid rgba(255,255,255,0.1)",
                      background: "rgba(255,255,255,0.05)", color: "rgba(255,255,255,0.6)",
                      fontSize: "0.75rem", outline: "none",
                    }}
                  >
                    <option value="">{t("Auto-detect", "Auto")}</option>
                    <option value="cyclonedx-json">CycloneDX</option>
                    <option value="spdx-json">SPDX</option>
                  </select>
                  <input
                    type="text"
                    value={sbomImportTargetName}
                    onChange={e => setSbomImportTargetName(e.target.value)}
                    placeholder={t("Target name (optional)", "Zielname (opt.)")}
                    style={{
                      padding: "0.3rem 0.5rem", borderRadius: "6px",
                      border: "1px solid rgba(255,255,255,0.1)",
                      background: "rgba(255,255,255,0.05)", color: "#fff",
                      fontSize: "0.75rem", outline: "none", width: "160px", minWidth: 0, flex: "1 1 100px",
                    }}
                  />
                  <button
                    type="button"
                    disabled={!sbomImportFile || sbomImportLoading}
                    onClick={async () => {
                      if (!sbomImportFile) return;
                      setSbomImportLoading(true);
                      setSbomImportError(null);
                      setSbomImportResult(null);
                      try {
                        const res = await importSbomFile(
                          sbomImportFile,
                          sbomImportTargetName || undefined,
                          sbomImportFormat || undefined,
                        );
                        setSbomImportResult(res);
                      } catch (err: any) {
                        setSbomImportError(err?.response?.data?.detail || err?.message || t("Import failed.", "Import fehlgeschlagen."));
                      } finally {
                        setSbomImportLoading(false);
                      }
                    }}
                    style={{
                      padding: "0.375rem 1rem",
                      borderRadius: "6px",
                      fontSize: "0.75rem",
                      fontWeight: 600,
                      cursor: sbomImportFile && !sbomImportLoading ? "pointer" : "default",
                      background: sbomImportFile && !sbomImportLoading ? "rgba(255,212,59,0.15)" : "rgba(255,255,255,0.04)",
                      border: `1px solid ${sbomImportFile && !sbomImportLoading ? "rgba(255,212,59,0.35)" : "rgba(255,255,255,0.08)"}`,
                      color: sbomImportFile && !sbomImportLoading ? "#ffd43b" : "rgba(255,255,255,0.25)",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {sbomImportLoading ? t("Importing...", "Importiert...") : t("Import", "Importieren")}
                  </button>
                </div>
              </div>
            ) : (
              <div style={{
                marginBottom: "1.25rem",
                padding: "0.75rem 1.25rem",
                border: "1px solid rgba(105,219,124,0.3)",
                borderRadius: "10px",
                background: "rgba(105,219,124,0.06)",
                display: "flex",
                alignItems: "center",
                gap: "1rem",
              }}>
                <div style={{ flex: 1 }}>
                  <span style={{ fontWeight: 600, color: "#69db7c", fontSize: "0.8125rem" }}>
                    {t("SBOM imported!", "SBOM importiert!")}
                  </span>
                  <span style={{ color: "rgba(255,255,255,0.5)", fontSize: "0.75rem", marginLeft: "0.5rem" }}>
                    {sbomImportResult.sbomComponentCount} {t("components", "Komponenten")} · {sbomImportResult.findingsCount} {t("findings", "Funde")}
                  </span>
                </div>
                <Link
                  to={`/scans/${sbomImportResult.scanId}`}
                  style={{ color: "#ffd43b", textDecoration: "none", fontSize: "0.75rem", fontWeight: 600, whiteSpace: "nowrap" }}
                >
                  {t("View details", "Details")} →
                </Link>
                <button type="button" onClick={() => { setSbomImportResult(null); setSbomImportFile(null); setSbomImportError(null); }}
                  style={{ background: "none", border: "none", color: "rgba(255,255,255,0.3)", cursor: "pointer", fontSize: "1rem", padding: "0 0.25rem" }}>
                  ×
                </button>
              </div>
            )}

            {/* Summary cards */}
            {sbomComponents.length > 0 && (
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
                  </div>
                ))}
              </div>
            )}

            {/* Filter bar */}
            <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "1rem", flexWrap: "wrap" }}>
              <input
                type="text"
                value={sbomSearch}
                onChange={e => { setSbomSearch(e.target.value); setSbomOffset(0); }}
                placeholder={t("Search by name, type, license, purl...", "Nach Name, Typ, Lizenz, PURL suchen...")}
                style={{
                  padding: "0 0.75rem",
                  borderRadius: "6px",
                  border: "1px solid rgba(255,255,255,0.15)",
                  background: "rgba(255,255,255,0.05)",
                  color: "#fff",
                  fontSize: "0.8125rem",
                  flex: "1 1 200px",
                  maxWidth: "400px",
                  minWidth: 0,
                  outline: "none",
                  height: "32px",
                  boxSizing: "border-box" as const,
                }}
              />
              <select
                value={sbomType || ""}
                onChange={e => { setSbomType(e.target.value || null); setSbomOffset(0); }}
                style={{
                  padding: "0 0.625rem",
                  borderRadius: "6px",
                  border: "1px solid rgba(255,255,255,0.12)",
                  background: "rgba(255,255,255,0.05)",
                  color: sbomType ? "#ffd43b" : "rgba(255,255,255,0.5)",
                  fontSize: "0.8125rem",
                  outline: "none",
                  cursor: "pointer",
                  minWidth: "120px",
                  height: "32px",
                  boxSizing: "border-box" as const,
                }}
              >
                <option value="">{t("All types", "Alle Typen")}</option>
                {["library", "application", "framework", "container", "firmware", "file", "operating-system"].map(tp => (
                  <option key={tp} value={tp}>{tp}</option>
                ))}
              </select>
              <select
                value={sbomTargetId || ""}
                onChange={e => { setSbomTargetId(e.target.value || null); setSbomOffset(0); }}
                style={{
                  padding: "0 0.625rem",
                  borderRadius: "6px",
                  border: "1px solid rgba(255,255,255,0.12)",
                  background: "rgba(255,255,255,0.05)",
                  color: sbomTargetId ? "#ffd43b" : "rgba(255,255,255,0.5)",
                  fontSize: "0.8125rem",
                  outline: "none",
                  cursor: "pointer",
                  minWidth: "140px",
                  maxWidth: "280px",
                  height: "32px",
                  boxSizing: "border-box" as const,
                }}
              >
                <option value="">{t("All targets", "Alle Ziele")}</option>
                {targets.map(tgt => (
                  <option key={tgt.id} value={tgt.id}>{tgt.name}</option>
                ))}
              </select>
              <select
                value={sbomFilterProvenance || ""}
                onChange={e => setSbomFilterProvenance(e.target.value || null)}
                style={{
                  padding: "0 0.625rem",
                  borderRadius: "6px",
                  border: "1px solid rgba(255,255,255,0.12)",
                  background: "rgba(255,255,255,0.05)",
                  color: sbomFilterProvenance ? "#ffd43b" : "rgba(255,255,255,0.5)",
                  fontSize: "0.8125rem",
                  outline: "none",
                  cursor: "pointer",
                  minWidth: "120px",
                  height: "32px",
                  boxSizing: "border-box" as const,
                }}
              >
                <option value="">{t("All Provenance", "Alle Provenienz")}</option>
                <option value="verified">{t("Verified", "Verifiziert")}</option>
                <option value="unverified">{t("Unverified", "Nicht verifiziert")}</option>
                <option value="unknown">{t("Unknown", "Unbekannt")}</option>
              </select>
              <span style={{ color: "rgba(255,255,255,0.35)", fontSize: "0.75rem", marginLeft: "auto" }}>
                {filteredSortedSbom.length !== sbomComponents.length
                  ? `${filteredSortedSbom.length} / ${sbomTotal.toLocaleString()}`
                  : sbomTotal.toLocaleString()}{" "}
                {t("components", "Komponenten")}
              </span>
            </div>

            {sbomLoading ? (
              <div style={{ overflowX: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr style={{ borderBottom: "1px solid rgba(255,255,255,0.08)" }}>
                      {[t("Component", "Komponente"), t("Version", "Version"), t("Type", "Typ"), t("Provenance", "Herkunft"), t("Licenses", "Lizenzen"), t("Targets", "Ziele")].map(label => (
                        <th key={label} style={thStyle}>{label}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {Array.from({ length: 10 }).map((_, i) => (
                      <tr key={i} style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                        {Array.from({ length: 6 }).map((_, j) => (
                          <td key={j} style={tdStyle}>
                            <SkeletonBlock height={16} width={j === 0 ? "80%" : j === 3 ? "30px" : j === 5 ? "30px" : "60%"} radius={4} />
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : sbomComponents.length === 0 ? (
              <p className="muted" style={{ textAlign: "center", padding: "2rem 0" }}>
                {sbomSearch || sbomType || sbomTargetId
                  ? t("No components match your filters.", "Keine Komponenten entsprechen Ihren Filtern.")
                  : t("No SBOM components from latest scans.", "Keine SBOM-Komponenten aus den letzten Scans.")}
              </p>
            ) : (
              <>
                <div style={{ overflowX: "auto" }}>
                  <table style={{ width: "100%", borderCollapse: "collapse" }}>
                    <thead>
                      <tr style={{ borderBottom: "1px solid rgba(255,255,255,0.08)" }}>
                        {([
                          { col: "name", label: t("Component", "Komponente") },
                          { col: "version", label: t("Version", "Version") },
                          { col: "type", label: t("Type", "Typ") },
                          { col: "provenance", label: t("Provenance", "Herkunft") },
                          { col: "licenses", label: t("Licenses", "Lizenzen") },
                          { col: "targets", label: t("Targets", "Ziele") },
                        ] as const).map(h => (
                          <th key={h.col} style={{ ...thStyle, cursor: "pointer", userSelect: "none" }}
                            onClick={() => setSbomSort(prev => ({ col: h.col, dir: prev.col === h.col && prev.dir === "asc" ? "desc" : "asc" }))}>
                            {h.label} {sbomSort.col === h.col ? (sbomSort.dir === "asc" ? "▲" : "▼") : ""}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {filteredSortedSbom.map(c => {
                        const typeColors: Record<string, string> = { library: "#69db7c", application: "#ffd43b", framework: "#748ffc", container: "#ff922b" };
                        const typeColor = typeColors[c.type] || "rgba(255,255,255,0.4)";
                        const rowKey = `${c.name}|${c.version}`;
                        const isExpanded = expandedSboms.has(rowKey);
                        return (
                          <React.Fragment key={rowKey}>
                            <tr
                              onClick={() => setExpandedSboms(prev => { const next = new Set(prev); if (next.has(rowKey)) next.delete(rowKey); else next.add(rowKey); return next; })}
                              style={{ borderBottom: isExpanded ? "none" : "1px solid rgba(255,255,255,0.04)", cursor: "pointer", transition: "background 0.1s" }}
                              onMouseEnter={e => { (e.currentTarget as HTMLTableRowElement).style.background = "rgba(255,255,255,0.03)"; }}
                              onMouseLeave={e => { (e.currentTarget as HTMLTableRowElement).style.background = ""; }}
                            >
                              <td style={tdStyle}>
                                <div style={{ fontSize: "0.8125rem", fontWeight: 500 }}>{c.name}</div>
                                {c.purl && (
                                  <div style={{ fontSize: "0.6875rem", color: "rgba(255,255,255,0.3)", fontFamily: "monospace", wordBreak: "break-all" }}>{c.purl}</div>
                                )}
                              </td>
                              <td style={{ ...tdStyle, fontSize: "0.8125rem", fontFamily: "monospace", color: "rgba(255,255,255,0.6)" }}>{c.version || "—"}</td>
                              <td style={tdStyle}>
                                <span style={{
                                  display: "inline-block",
                                  padding: "0.125rem 0.5rem",
                                  borderRadius: "4px",
                                  fontSize: "0.6875rem",
                                  fontWeight: 500,
                                  background: `${typeColor}18`,
                                  color: typeColor,
                                }}>
                                  {c.type}
                                </span>
                              </td>
                              <td style={tdStyle}>
                                {c.provenanceVerified === true && <span style={{ color: "#69db7c", fontSize: "0.8125rem" }}>✓</span>}
                                {c.provenanceVerified === false && <span style={{ color: "#fcc419", fontSize: "0.8125rem" }}>⚠</span>}
                                {c.provenanceVerified == null && <span style={{ color: "rgba(255,255,255,0.2)", fontSize: "0.8125rem" }}>—</span>}
                              </td>
                              <td style={{ ...tdStyle, fontSize: "0.75rem", color: "rgba(255,255,255,0.4)" }}>
                                {c.licenses.length > 0 ? c.licenses.join(", ") : "—"}
                              </td>
                              <td style={{ ...tdStyle, fontSize: "0.75rem", color: "rgba(255,255,255,0.4)" }}>
                                {c.targets.length}
                              </td>
                            </tr>
                            {isExpanded && (
                              <tr>
                                <td colSpan={6} style={{ padding: "0 0.75rem 0.75rem 1.5rem", background: "rgba(255,255,255,0.02)", borderBottom: "1px solid rgba(255,255,255,0.06)", textAlign: "left" }}>
                                  <div style={{ fontSize: "0.75rem", color: "rgba(255,255,255,0.5)", marginTop: "0.5rem", marginBottom: "0.375rem", fontWeight: 500, textAlign: "left" }}>
                                    {t("Found in targets:", "Gefunden in Zielen:")}
                                  </div>
                                  <div style={{ display: "flex", flexDirection: "column", gap: "0.25rem", alignItems: "flex-start" }}>
                                    {c.targets.map(tgt => {
                                      const tgtName = targets.find(tt => tt.id === tgt.targetId)?.name || tgt.targetId;
                                      return (
                                        <Link
                                          key={`${tgt.targetId}-${tgt.scanId}`}
                                          to={`/scans/${encodeURIComponent(tgt.scanId)}`}
                                          onClick={e => e.stopPropagation()}
                                          style={{ color: "#ffd43b", textDecoration: "none", fontSize: "0.8125rem", display: "inline-flex", alignItems: "center", gap: "0.375rem" }}
                                        >
                                          <span style={{ color: "rgba(255,255,255,0.6)" }}>{tgtName}</span>
                                        </Link>
                                      );
                                    })}
                                  </div>
                                </td>
                              </tr>
                            )}
                          </React.Fragment>
                        );
                      })}
                    </tbody>
                  </table>
                </div>

                {/* Pagination */}
                {sbomTotal > sbomLimit && (
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: "0.75rem", marginTop: "1rem", fontSize: "0.8125rem" }}>
                    <button
                      type="button"
                      disabled={sbomOffset === 0}
                      onClick={() => setSbomOffset(Math.max(0, sbomOffset - sbomLimit))}
                      style={{
                        padding: "0.3rem 0.75rem", borderRadius: "4px",
                        border: "1px solid rgba(255,255,255,0.1)",
                        background: sbomOffset === 0 ? "transparent" : "rgba(255,255,255,0.05)",
                        color: sbomOffset === 0 ? "rgba(255,255,255,0.2)" : "rgba(255,255,255,0.6)",
                        cursor: sbomOffset === 0 ? "default" : "pointer",
                        fontSize: "0.8125rem",
                      }}
                    >
                      ← {t("Previous", "Zurück")}
                    </button>
                    <span style={{ color: "rgba(255,255,255,0.4)" }}>
                      {Math.floor(sbomOffset / sbomLimit) + 1} / {Math.ceil(sbomTotal / sbomLimit)}
                    </span>
                    <button
                      type="button"
                      disabled={sbomOffset + sbomLimit >= sbomTotal}
                      onClick={() => setSbomOffset(sbomOffset + sbomLimit)}
                      style={{
                        padding: "0.3rem 0.75rem", borderRadius: "4px",
                        border: "1px solid rgba(255,255,255,0.1)",
                        background: sbomOffset + sbomLimit >= sbomTotal ? "transparent" : "rgba(255,255,255,0.05)",
                        color: sbomOffset + sbomLimit >= sbomTotal ? "rgba(255,255,255,0.2)" : "rgba(255,255,255,0.6)",
                        cursor: sbomOffset + sbomLimit >= sbomTotal ? "default" : "pointer",
                        fontSize: "0.8125rem",
                      }}
                    >
                      {t("Next", "Weiter")} →
                    </button>
                  </div>
                )}
              </>
            )}
          </div>
        )}

        {/* Manual scan tab */}
        {tab === "manual" && (
          <div>
            <form onSubmit={handleSubmitScan} style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
              <div>
                <label style={labelStyle}>{t("Type", "Typ")}</label>
                <div style={{ display: "flex", gap: "0.75rem" }}>
                  <label style={{ display: "flex", alignItems: "center", gap: "0.375rem", cursor: "pointer", color: "rgba(255,255,255,0.8)" }}>
                    <input
                      type="radio"
                      name="scanType"
                      value="container_image"
                      checked={scanType === "container_image"}
                      onChange={() => {
                        setScanType("container_image");
                        setScanners(["trivy", "grype", "syft", "dockle", "dive"]);
                        setSourceRepoInputMode("url");
                        setSourceArchiveFile(null);
                        setSourceArchiveTargetName("");
                      }}
                    />
                    Container Image
                  </label>
                  <label style={{ display: "flex", alignItems: "center", gap: "0.375rem", cursor: "pointer", color: "rgba(255,255,255,0.8)" }}>
                    <input
                      type="radio"
                      name="scanType"
                      value="source_repo"
                      checked={scanType === "source_repo"}
                      onChange={() => {
                        setScanType("source_repo");
                        setScanners(["trivy", "grype", "syft", "osv-scanner", "hecate", "semgrep", "trufflehog"]);
                      }}
                    />
                    Source Repository
                  </label>
                </div>
              </div>

              {scanType === "source_repo" && (
                <div>
                  <label style={labelStyle}>{t("Source Input", "Quell-Input")}</label>
                  <div style={{ display: "flex", gap: "0.75rem", flexWrap: "wrap" }}>
                    <label style={{ display: "flex", alignItems: "center", gap: "0.375rem", cursor: "pointer", color: "rgba(255,255,255,0.8)" }}>
                      <input
                        type="radio"
                        name="sourceRepoInputMode"
                        value="url"
                        checked={sourceRepoInputMode === "url"}
                        onChange={() => setSourceRepoInputMode("url")}
                      />
                      {t("Repository URL", "Repository-URL")}
                    </label>
                    <label style={{ display: "flex", alignItems: "center", gap: "0.375rem", cursor: "pointer", color: "rgba(255,255,255,0.8)" }}>
                      <input
                        type="radio"
                        name="sourceRepoInputMode"
                        value="zip"
                        checked={sourceRepoInputMode === "zip"}
                        onChange={() => {
                          setSourceRepoInputMode("zip");
                          setScanTarget("");
                        }}
                      />
                      {t("Upload ZIP (one-time)", "ZIP hochladen (einmalig)")}
                    </label>
                  </div>
                </div>
              )}

              {(scanType === "container_image" || (scanType === "source_repo" && sourceRepoInputMode === "url")) && (
                <div>
                  <label style={labelStyle}>
                    {scanType === "container_image"
                      ? t("Image Reference", "Image-Referenz")
                      : t("Repository URL", "Repository-URL")}
                  </label>
                  <input
                    type="text"
                    value={scanTarget}
                    onChange={e => setScanTarget(e.target.value)}
                    placeholder={scanType === "container_image" ? "github.com/hecate/hecate-backend:latest" : "https://github.com/org/repo"}
                    style={inputStyle}
                    required={scanType === "container_image" || sourceRepoInputMode === "url"}
                  />
                </div>
              )}

              {scanType === "source_repo" && sourceRepoInputMode === "zip" && (
                <>
                  <div>
                    <label style={labelStyle}>{t("Repository ZIP", "Repository-ZIP")}</label>
                    <input
                      type="file"
                      accept=".zip,application/zip"
                      onChange={e => setSourceArchiveFile(e.target.files?.[0] || null)}
                      style={inputStyle}
                      required
                    />
                    <p style={{ margin: "0.375rem 0 0", fontSize: "0.75rem", color: "rgba(255,255,255,0.45)" }}>
                      {t(
                        "Uploads a source archive for a one-time scan.",
                        "Lädt ein Quellcode-Archiv für einen einmaligen Scan hoch."
                      )}
                    </p>
                  </div>
                  <div>
                    <label style={labelStyle}>{t("Scan Name (optional)", "Scan-Name (optional)")}</label>
                    <input
                      type="text"
                      value={sourceArchiveTargetName}
                      onChange={e => setSourceArchiveTargetName(e.target.value)}
                      placeholder={t("Derived from filename", "Wird aus Dateinamen abgeleitet")}
                      style={inputStyle}
                    />
                  </div>
                </>
              )}

              <div>
                <label style={labelStyle}>{t("Scanners", "Scanner")}</label>
                <div style={{ display: "flex", gap: "0.75rem", flexWrap: "wrap" }}>
                  {(scanType === "container_image"
                    ? ["trivy", "grype", "syft", "dockle", "dive"]
                    : ["trivy", "grype", "syft", "osv-scanner", "hecate", "semgrep", "trufflehog"]
                  ).map(name => (
                    <label key={name} style={{ display: "flex", alignItems: "center", gap: "0.375rem", cursor: "pointer", color: "rgba(255,255,255,0.8)" }}>
                      <input
                        type="checkbox"
                        checked={scanners.includes(name)}
                        onChange={() => handleScannerToggle(name)}
                      />
                      {name}
                    </label>
                  ))}
                </div>
              </div>

              <div style={{ display: "flex", justifyContent: "flex-end" }}>
                <button
                  type="submit"
                  disabled={isSubmitDisabled}
                  style={{
                    padding: "0.625rem 1.5rem",
                    borderRadius: "6px",
                    border: "1px solid rgba(255,193,7,0.5)",
                    background: scanning ? "rgba(255,193,7,0.15)" : "rgba(255,193,7,0.3)",
                    color: "#ffd43b",
                    cursor: scanning ? "wait" : "pointer",
                    fontSize: "0.875rem",
                    fontWeight: 600,
                  }}
                >
                  {scanning ? t("Scanning...", "Scannt...") : t("Start Scan", "Scan starten")}
                </button>
              </div>
            </form>

            {scanError && (
              <div style={{ marginTop: "1rem", padding: "0.75rem 1rem", background: "rgba(255,107,107,0.1)", border: "1px solid rgba(255,107,107,0.3)", borderRadius: "6px", color: "#ff6b6b" }}>
                {scanError}
              </div>
            )}

            {scanResult && (
              <div style={{ marginTop: "1.5rem" }}>
                <h3 style={{ marginBottom: "0.75rem" }}>{t("Scan Result", "Scan-Ergebnis")}</h3>
                <div style={{ display: "grid", gap: "0.75rem", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))" }}>
                  <StatBox label="Status" value={scanResult.status} />
                  <StatBox label={t("Findings", "Ergebnisse")} value={(scanResult.summary.total || scanResult.findingsCount).toString()} />
                  <StatBox label={t("SBOM Components", "SBOM-Komponenten")} value={scanResult.sbomComponentCount.toString()} />
                </div>
                <SeverityBadges summary={scanResult.summary} style={{ marginTop: "0.75rem" }} />
                {scanResult.error && (
                  <p style={{ marginTop: "0.5rem", color: "#ff922b", fontSize: "0.8125rem" }}>{scanResult.error}</p>
                )}
                <Link
                  to={`/scans/${scanResult.scanId}`}
                  style={{ display: "inline-block", marginTop: "0.75rem", color: "#ffd43b", textDecoration: "none", fontSize: "0.875rem" }}
                >
                  {t("View scan details", "Scan-Details anzeigen")} →
                </Link>
              </div>
            )}

          </div>
        )}
        {/* Scanner tab */}
        {/* Licenses tab */}
        {tab === "licenses" && (
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "1rem" }}>
              <input
                type="text"
                value={licenseSearch}
                onChange={e => setLicenseSearch(e.target.value)}
                placeholder={t("Search licenses...", "Lizenzen suchen...")}
                style={{
                  padding: "0.375rem 0.75rem",
                  borderRadius: "6px",
                  border: "1px solid rgba(255,255,255,0.15)",
                  background: "rgba(255,255,255,0.05)",
                  color: "#fff",
                  fontSize: "0.8125rem",
                  flex: "1 1 200px",
                  maxWidth: "400px",
                  minWidth: 0,
                  outline: "none",
                }}
              />
              <span style={{ color: "rgba(255,255,255,0.35)", fontSize: "0.75rem", marginLeft: "auto" }}>
                {licenseOverviewTotal} {t("licenses", "Lizenzen")}
              </span>
            </div>

            {licensesLoading ? (
              <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
                {Array.from({ length: 8 }).map((_, i) => (
                  <SkeletonBlock key={i} height={40} radius={6} />
                ))}
              </div>
            ) : licenseOverview.length === 0 ? (
              <p className="muted" style={{ textAlign: "center", padding: "2rem 0" }}>
                {t("No license data available. Run a scan with SBOM generation first.", "Keine Lizenzdaten verfügbar. Führen Sie zuerst einen Scan mit SBOM-Generierung durch.")}
              </p>
            ) : (
              <div style={{ overflowX: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr style={{ borderBottom: "1px solid rgba(255,255,255,0.08)" }}>
                      <th style={thStyle}>{t("License", "Lizenz")}</th>
                      <th style={thStyle}>{t("Components", "Komponenten")}</th>
                      <th style={thStyle}>{t("Used By", "Verwendet von")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {licenseOverview
                      .filter(item => !licenseSearch || item.licenseId.toLowerCase().includes(licenseSearch.toLowerCase()))
                      .map(item => (
                        <tr key={item.licenseId} style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                          <td style={tdStyle}>
                            <span style={{ fontWeight: 500, color: "#fff", fontSize: "0.8125rem" }}>{item.licenseId}</span>
                          </td>
                          <td style={tdStyle}>
                            <span style={{
                              padding: "0.125rem 0.5rem",
                              borderRadius: "4px",
                              fontSize: "0.75rem",
                              fontWeight: 600,
                              background: "rgba(92,132,255,0.15)",
                              color: "#5c84ff",
                            }}>
                              {item.componentCount}
                            </span>
                          </td>
                          <td style={{ ...tdStyle, maxWidth: "500px" }}>
                            <div style={{ display: "flex", flexWrap: "wrap", gap: "0.25rem" }}>
                              {item.components.slice(0, 8).map((c, i) => (
                                <span key={i} style={{
                                  padding: "0.0625rem 0.375rem",
                                  borderRadius: "4px",
                                  fontSize: "0.6875rem",
                                  background: "rgba(255,255,255,0.06)",
                                  color: "rgba(255,255,255,0.6)",
                                }}>
                                  {c.name}@{c.version}
                                </span>
                              ))}
                              {item.componentCount > 8 && (
                                <span style={{ fontSize: "0.6875rem", color: "rgba(255,255,255,0.35)" }}>
                                  +{item.componentCount - 8} {t("more", "weitere")}
                                </span>
                              )}
                            </div>
                          </td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {tab === "scanner" && (
          <div>
            {loading && <SkeletonBlock height={200} radius={8} />}
            {!loading && !scannerStats && (
              <p className="muted">{t("Could not reach scanner.", "Scanner nicht erreichbar.")}</p>
            )}
            {!loading && scannerStats && !scannerStats.error && (
              <div style={{ display: "flex", flexDirection: "column", gap: "1.25rem" }}>
                {/* Active scans indicator */}
                <div style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "1rem",
                  padding: "1rem 1.25rem",
                  border: scannerStats.activeScans > 0 ? "1px solid rgba(92,132,255,0.25)" : "1px solid rgba(255,255,255,0.08)",
                  borderRadius: "8px",
                  background: scannerStats.activeScans > 0 ? "rgba(92,132,255,0.04)" : "rgba(255,255,255,0.02)",
                }}>
                  <div style={{
                    width: "48px", height: "48px", borderRadius: "12px",
                    display: "flex", alignItems: "center", justifyContent: "center",
                    background: scannerStats.activeScans > 0 ? "rgba(92,132,255,0.15)" : "rgba(255,255,255,0.05)",
                    fontSize: "1.5rem", fontWeight: 700,
                    color: scannerStats.activeScans > 0 ? "#5c84ff" : "rgba(255,255,255,0.4)",
                  }}>
                    {scannerStats.activeScans}
                  </div>
                  <div>
                    <div style={{ fontSize: "0.9375rem", fontWeight: 600 }}>
                      {scannerStats.activeScans > 0
                        ? t(`${scannerStats.activeScans} scanner process${scannerStats.activeScans > 1 ? "es" : ""} running`, `${scannerStats.activeScans} Scanner-Prozess${scannerStats.activeScans > 1 ? "e" : ""} aktiv`)
                        : t("Scanner idle", "Scanner inaktiv")}
                    </div>
                    <div style={{ fontSize: "0.75rem", color: "rgba(255,255,255,0.4)", marginTop: "0.125rem" }}>
                      {t("Each target scan runs multiple scanner processes (trivy, grype, syft, ...)", "Jeder Ziel-Scan startet mehrere Scanner-Prozesse (trivy, grype, syft, ...)")}
                    </div>
                  </div>
                </div>

                {/* Time range selector */}
                <div style={{ display: "flex", gap: "0.375rem", alignItems: "center" }}>
                  <span style={{ fontSize: "0.75rem", color: "rgba(255,255,255,0.35)", marginRight: "0.25rem" }}>
                    {t("Range", "Zeitraum")}:
                  </span>
                  {[5, 15, 30, 60].map(m => (
                    <button
                      key={m}
                      type="button"
                      onClick={() => setChartMinutes(m)}
                      style={{
                        padding: "0.2rem 0.5rem",
                        borderRadius: "4px",
                        fontSize: "0.6875rem",
                        fontWeight: chartMinutes === m ? 600 : 400,
                        border: chartMinutes === m ? "1px solid rgba(255,193,7,0.4)" : "1px solid rgba(255,255,255,0.1)",
                        background: chartMinutes === m ? "rgba(255,193,7,0.12)" : "transparent",
                        color: chartMinutes === m ? "#ffd43b" : "rgba(255,255,255,0.45)",
                        cursor: "pointer",
                      }}
                    >
                      {m} min
                    </button>
                  ))}
                </div>

                {/* Live resource charts — full width, stacked */}
                <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
                  <LiveChart
                    label={t("Container Memory", "Container-Speicher")}
                    data={memHistory}
                    max={scannerStats.memoryLimitBytes}
                    current={scannerStats.memoryUsedBytes}
                    color="#5c84ff"
                    minutes={chartMinutes}
                  />
                  <LiveChart
                    label={t("Temp Disk (/tmp)", "Temp-Datenträger (/tmp)")}
                    data={diskHistory}
                    max={scannerStats.tmpDiskTotalBytes}
                    current={scannerStats.tmpDiskUsedBytes}
                    color="#fcc419"
                    minutes={chartMinutes}
                  />
                </div>
              </div>
            )}
            {!loading && scannerStats?.error && (
              <div style={{ padding: "0.75rem 1rem", background: "rgba(255,107,107,0.1)", border: "1px solid rgba(255,107,107,0.3)", borderRadius: "6px", color: "#ff6b6b", fontSize: "0.875rem" }}>
                {scannerStats.error}
              </div>
            )}
          </div>
        )}
      </section>

      {/* Confirmation modal */}
      {confirmModal && (
        <div
          style={{
            position: "fixed", inset: 0, zIndex: 9999,
            display: "flex", alignItems: "center", justifyContent: "center",
            background: "rgba(0,0,0,0.6)", backdropFilter: "blur(4px)",
          }}
          onClick={() => setConfirmModal(null)}
        >
          <div
            style={{
              background: "#1a1d23", border: "1px solid rgba(255,255,255,0.1)",
              borderRadius: "10px", padding: "1.5rem", minWidth: "340px", maxWidth: "440px",
              boxShadow: "0 8px 32px rgba(0,0,0,0.5)",
            }}
            onClick={e => e.stopPropagation()}
          >
            <h3 style={{ margin: "0 0 0.75rem", fontSize: "1rem", fontWeight: 600 }}>{confirmModal.title}</h3>
            <p style={{ margin: "0 0 1.25rem", fontSize: "0.875rem", color: "rgba(255,255,255,0.6)", lineHeight: 1.5 }}>
              {confirmModal.message}
            </p>
            <div style={{ display: "flex", justifyContent: "flex-end", gap: "0.5rem" }}>
              <button
                type="button"
                onClick={() => setConfirmModal(null)}
                style={{
                  padding: "0.4rem 1rem", borderRadius: "6px", fontSize: "0.8125rem", fontWeight: 500, cursor: "pointer",
                  background: "rgba(255,255,255,0.06)", border: "1px solid rgba(255,255,255,0.12)", color: "rgba(255,255,255,0.7)",
                }}
              >
                {t("Cancel", "Abbrechen")}
              </button>
              <button
                type="button"
                onClick={confirmModal.onConfirm}
                style={{
                  padding: "0.4rem 1rem", borderRadius: "6px", fontSize: "0.8125rem", fontWeight: 500, cursor: "pointer",
                  background: "rgba(255,107,107,0.15)", border: "1px solid rgba(255,107,107,0.35)", color: "#ff6b6b",
                }}
              >
                {t("Delete", "Löschen")}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

// --- Sub-components ---

const TargetCard = ({ target, groupSuggestions = [], onDelete, onRescan, onToggleAutoScan, onUpdateScanners, onUpdateGroup, onFilterScans, onCancelScan }: { target: ScanTarget; groupSuggestions?: string[]; onDelete: (id: string) => void; onRescan: (target: ScanTarget) => void; onToggleAutoScan: (target: ScanTarget) => void; onUpdateScanners: (targetId: string, scanners: string[]) => void; onUpdateGroup?: (targetId: string, group: string | null) => void; onFilterScans: (id: string, name: string) => void; onCancelScan?: (scanId: string) => void }) => {
  const { t } = useI18n();
  const isRunning = !!target.hasRunningScan;
  const isPending = target.runningScanStatus === "pending";
  const autoScan = target.autoScan !== false; // default true
  const [editingScanners, setEditingScanners] = useState(false);
  const [selectedScanners, setSelectedScanners] = useState<string[]>([]);
  const [editingGroup, setEditingGroup] = useState(false);
  const [groupDraft, setGroupDraft] = useState<string>(target.group || "");
  const datalistId = `group-suggestions-${target.id.replace(/[^a-zA-Z0-9]/g, "-")}`;
  const isSbomImport = target.type === "sbom-import";

  const startEditingGroup = () => {
    setGroupDraft(target.group || "");
    setEditingGroup(true);
  };
  const saveGroup = () => {
    if (onUpdateGroup) onUpdateGroup(target.id, groupDraft);
    setEditingGroup(false);
  };
  const cancelEditGroup = () => {
    setGroupDraft(target.group || "");
    setEditingGroup(false);
  };

  const availableScanners = target.type === "container_image"
    ? ["trivy", "grype", "syft", "dockle", "dive"]
    : ["trivy", "grype", "syft", "osv-scanner", "hecate", "semgrep", "trufflehog"];

  const startEditing = () => {
    setSelectedScanners(target.scanners?.length ? [...target.scanners] : []);
    setEditingScanners(true);
  };

  const saveScanners = () => {
    if (selectedScanners.length > 0) {
      onUpdateScanners(target.id, selectedScanners);
      setEditingScanners(false);
    }
  };

  return (
    <div style={{
      padding: "1rem 1.25rem",
      border: isRunning ? `1px solid ${isPending ? "rgba(240,160,48,0.3)" : "rgba(92,132,255,0.3)"}` : "1px solid rgba(255,255,255,0.08)",
      borderRadius: "8px",
      background: isRunning ? (isPending ? "rgba(240,160,48,0.04)" : "rgba(92,132,255,0.04)") : "rgba(255,255,255,0.02)",
      display: "flex",
      flexDirection: "column",
      boxSizing: "border-box",
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "0.5rem", flexWrap: "wrap", gap: "0.25rem" }}>
        <div style={{ minWidth: 0, flex: "1 1 200px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <span style={{ display: "block", fontSize: "0.75rem", color: "rgba(255,255,255,0.4)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
              {target.type === "container_image" ? "Container" : "Source"}
            </span>
            {isRunning && <ScanningBadge status={target.runningScanStatus} />}
          </div>
          {target.latestScanId ? (
            <Link to={`/scans/${target.latestScanId}`} style={{ textDecoration: "none" }}>
              <h3 style={{ margin: "0.25rem 0 0", fontSize: "1rem", fontWeight: 600, color: "#ffd43b", wordBreak: "break-word" }}>{target.name}</h3>
            </Link>
          ) : (
            <h3 style={{ margin: "0.25rem 0 0", fontSize: "1rem", fontWeight: 600, wordBreak: "break-word" }}>{target.name}</h3>
          )}
        </div>
        <button
          type="button"
          onClick={() => onDelete(target.id)}
          title={t("Delete", "Löschen")}
          style={{ background: "none", border: "none", color: "rgba(255,255,255,0.3)", cursor: "pointer", fontSize: "1rem", padding: "0.25rem", flexShrink: 0 }}
        >
          ×
        </button>
      </div>
      <p style={{ fontSize: "0.8125rem", color: "rgba(255,255,255,0.5)", margin: "0 0 0.5rem", wordBreak: "break-all" }}>
        {target.id}
      </p>
      {!isSbomImport && onUpdateGroup && (
        <div style={{ display: "flex", alignItems: "center", gap: "0.375rem", marginBottom: "0.625rem", flexWrap: "wrap" }}>
          {editingGroup ? (
            <>
              <input
                list={datalistId}
                value={groupDraft}
                onChange={e => setGroupDraft(e.target.value)}
                onKeyDown={e => {
                  if (e.key === "Enter") { e.preventDefault(); saveGroup(); }
                  else if (e.key === "Escape") { e.preventDefault(); cancelEditGroup(); }
                }}
                placeholder={t("Application name", "Anwendungsname")}
                autoFocus
                style={{
                  flex: "1 1 140px",
                  padding: "0.2rem 0.5rem",
                  borderRadius: "4px",
                  border: "1px solid rgba(255,255,255,0.15)",
                  background: "rgba(0,0,0,0.2)",
                  color: "rgba(255,255,255,0.9)",
                  fontSize: "0.75rem",
                  outline: "none",
                  minWidth: 0,
                }}
              />
              <datalist id={datalistId}>
                {groupSuggestions.map(g => <option key={g} value={g} />)}
              </datalist>
              <button
                type="button"
                onClick={saveGroup}
                style={{ padding: "0.15rem 0.5rem", borderRadius: "4px", fontSize: "0.7rem", fontWeight: 500, cursor: "pointer", background: "rgba(105,219,124,0.15)", border: "1px solid rgba(105,219,124,0.3)", color: "#69db7c" }}
              >
                {t("Save", "Speichern")}
              </button>
              <button
                type="button"
                onClick={cancelEditGroup}
                style={{ padding: "0.15rem 0.5rem", borderRadius: "4px", fontSize: "0.7rem", fontWeight: 500, cursor: "pointer", background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.1)", color: "rgba(255,255,255,0.5)" }}
              >
                {t("Cancel", "Abbrechen")}
              </button>
            </>
          ) : (
            <>
              <span style={{ fontSize: "0.7rem", color: "rgba(255,255,255,0.4)", textTransform: "uppercase", letterSpacing: "0.04em" }}>
                {t("App", "App")}:
              </span>
              {target.group ? (
                <span style={{
                  display: "inline-block",
                  padding: "0.1rem 0.45rem",
                  borderRadius: "4px",
                  fontSize: "0.7rem",
                  background: "rgba(255,193,7,0.1)",
                  border: "1px solid rgba(255,193,7,0.25)",
                  color: "#ffd43b",
                }}>{target.group}</span>
              ) : (
                <span style={{ fontSize: "0.7rem", color: "rgba(255,255,255,0.35)", fontStyle: "italic" }}>
                  {t("none", "keine")}
                </span>
              )}
              <button
                type="button"
                onClick={startEditingGroup}
                title={t("Edit group", "Gruppe bearbeiten")}
                style={{ background: "none", border: "1px solid rgba(255,255,255,0.1)", borderRadius: "4px", color: "rgba(255,255,255,0.35)", cursor: "pointer", fontSize: "0.65rem", padding: "0.05rem 0.3rem", lineHeight: 1 }}
              >
                ✎
              </button>
            </>
          )}
        </div>
      )}
      {target.latestSummary && <SeverityBadges summary={target.latestSummary} />}

      {/* Scanner pills / editor */}
      <div style={{ marginTop: "0.625rem" }}>
        {editingScanners && !isSbomImport ? (
          <div style={{ padding: "0.5rem 0" }}>
            <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap", marginBottom: "0.5rem" }}>
              {availableScanners.map(name => (
                <label key={name} style={{ display: "flex", alignItems: "center", gap: "0.25rem", cursor: "pointer", fontSize: "0.75rem", color: "rgba(255,255,255,0.8)" }}>
                  <input
                    type="checkbox"
                    checked={selectedScanners.includes(name)}
                    onChange={() => setSelectedScanners(prev => prev.includes(name) ? prev.filter(s => s !== name) : [...prev, name])}
                  />
                  {name}
                </label>
              ))}
            </div>
            <div style={{ display: "flex", gap: "0.375rem" }}>
              <button
                type="button"
                onClick={saveScanners}
                disabled={selectedScanners.length === 0}
                style={{
                  padding: "0.15rem 0.5rem", borderRadius: "4px", fontSize: "0.7rem", fontWeight: 500, cursor: selectedScanners.length === 0 ? "not-allowed" : "pointer",
                  background: "rgba(105,219,124,0.15)", border: "1px solid rgba(105,219,124,0.3)", color: "#69db7c",
                  opacity: selectedScanners.length === 0 ? 0.4 : 1,
                }}
              >
                {t("Save", "Speichern")}
              </button>
              <button
                type="button"
                onClick={() => setEditingScanners(false)}
                style={{
                  padding: "0.15rem 0.5rem", borderRadius: "4px", fontSize: "0.7rem", fontWeight: 500, cursor: "pointer",
                  background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.1)", color: "rgba(255,255,255,0.5)",
                }}
              >
                {t("Cancel", "Abbrechen")}
              </button>
            </div>
          </div>
        ) : (
          <div style={{ display: "flex", alignItems: "center", gap: "0.375rem", flexWrap: "wrap" }}>
            {(target.scanners || []).map(s => (
              <span key={s} style={{
                display: "inline-block", padding: "0.1rem 0.4rem", borderRadius: "4px", fontSize: "0.675rem",
                background: "rgba(92,132,255,0.1)", border: "1px solid rgba(92,132,255,0.2)", color: "rgba(92,132,255,0.8)",
              }}>
                {s}
              </span>
            ))}
            {!isSbomImport && (
              <button
                type="button"
                onClick={startEditing}
                title={t("Edit scanners", "Scanner bearbeiten")}
                style={{
                  background: "none", border: "1px solid rgba(255,255,255,0.1)", borderRadius: "4px", color: "rgba(255,255,255,0.35)",
                  cursor: "pointer", fontSize: "0.675rem", padding: "0.1rem 0.35rem", lineHeight: 1,
                }}
              >
                ✎
              </button>
            )}
          </div>
        )}
      </div>

      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: "auto", paddingTop: "0.75rem", flexWrap: "wrap", gap: "0.5rem" }}>
        <div style={{ display: "flex", gap: "1rem", fontSize: "0.75rem", color: "rgba(255,255,255,0.4)" }}>
          <span
            role="button"
            tabIndex={0}
            onClick={() => onFilterScans(target.id, target.name)}
            onKeyDown={e => e.key === "Enter" && onFilterScans(target.id, target.name)}
            style={{ cursor: "pointer", textDecoration: "underline", textDecorationStyle: "dotted", textUnderlineOffset: "2px" }}
            title={t("Show scans for this target", "Scans für dieses Ziel anzeigen")}
          >
            {target.scanCount} {t("scans", "Scans")}
          </span>
          {target.lastScanAt && <span>{t("Last", "Letzter")}: {formatDateTime(target.lastScanAt)}</span>}
        </div>
        <div style={{ display: "flex", gap: "0.375rem", alignItems: "center", marginLeft: "auto" }}>
          {target.type === "sbom-import" ? null : isRunning && (target.runningScanId || target.latestScanId) && onCancelScan ? (
            <button
              type="button"
              onClick={() => onCancelScan(target.runningScanId || target.latestScanId!)}
              title={t("Stop scan", "Scan stoppen")}
              style={{
                background: "rgba(255,107,107,0.15)",
                border: "1px solid rgba(255,107,107,0.3)",
                color: "#ff6b6b",
                cursor: "pointer",
                fontSize: "0.7rem",
                padding: "0.2rem 0.5rem",
                borderRadius: "4px",
                fontWeight: 500,
              }}
            >
              ■ Stop
            </button>
          ) : (
            <button
              type="button"
              onClick={() => onRescan(target)}
              title={t("Rescan", "Erneut scannen")}
              style={{
                background: "rgba(255,193,7,0.15)",
                border: "1px solid rgba(255,193,7,0.3)",
                color: "#ffd43b",
                cursor: "pointer",
                fontSize: "0.7rem",
                padding: "0.2rem 0.5rem",
                borderRadius: "4px",
                fontWeight: 500,
              }}
            >
              ↻ Scan
            </button>
          )}
          {config.scaFeatures.autoScanEnabled && target.type !== "sbom-import" && (
            <button
              type="button"
              onClick={() => onToggleAutoScan(target)}
              title={autoScan ? t("Disable auto-scan", "Auto-Scan deaktivieren") : t("Enable auto-scan", "Auto-Scan aktivieren")}
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: "0.375rem",
                padding: "0.2rem 0.5rem",
                borderRadius: "4px",
                fontSize: "0.7rem",
                fontWeight: 500,
                border: autoScan ? "1px solid rgba(105,219,124,0.3)" : "1px solid rgba(255,255,255,0.1)",
                background: autoScan ? "rgba(105,219,124,0.1)" : "rgba(255,255,255,0.03)",
                color: autoScan ? "#69db7c" : "rgba(255,255,255,0.35)",
                cursor: "pointer",
              }}
            >
              <span style={{
                display: "inline-block",
                width: "24px",
                height: "14px",
                borderRadius: "7px",
                background: autoScan ? "rgba(105,219,124,0.4)" : "rgba(255,255,255,0.15)",
                position: "relative",
                transition: "background 0.2s",
              }}>
                <span style={{
                  position: "absolute",
                  top: "2px",
                  left: autoScan ? "12px" : "2px",
                  width: "10px",
                  height: "10px",
                  borderRadius: "50%",
                  background: autoScan ? "#69db7c" : "rgba(255,255,255,0.4)",
                  transition: "left 0.2s, background 0.2s",
                }} />
              </span>
              Auto-Scan
            </button>
          )}
        </div>
      </div>
    </div>
  );
};

const SeverityBadges = ({ summary, style }: { summary: ScanSummary; style?: React.CSSProperties }) => {
  if (summary.total === 0) return <span style={{ fontSize: "0.8125rem", color: "rgba(255,255,255,0.4)", ...style }}>—</span>;
  const badges: { label: string; count: number; color: string }[] = [
    { label: "C", count: summary.critical, color: "#ff6b6b" },
    { label: "H", count: summary.high, color: "#ff922b" },
    { label: "M", count: summary.medium, color: "#fcc419" },
    { label: "L", count: summary.low, color: "#69db7c" },
  ];
  return (
    <div style={{ display: "flex", gap: "0.375rem", flexWrap: "wrap", ...style }}>
      {badges.filter(b => b.count > 0).map(b => (
        <span
          key={b.label}
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: "0.25rem",
            padding: "0.125rem 0.5rem",
            borderRadius: "4px",
            fontSize: "0.75rem",
            fontWeight: 600,
            background: `${b.color}20`,
            color: b.color,
          }}
        >
          {b.label}: {b.count}
        </span>
      ))}
    </div>
  );
};

const ScanningBadge = ({ status }: { status?: string | null }) => {
  const isPending = status === "pending";
  const color = isPending ? "#f0a030" : "#5c84ff";
  const label = isPending ? "Queued..." : "Scanning...";
  return (
    <span style={{
      display: "inline-flex",
      alignItems: "center",
      gap: "0.25rem",
      padding: "0.125rem 0.5rem",
      borderRadius: "4px",
      fontSize: "0.675rem",
      fontWeight: 600,
      background: isPending ? "rgba(240,160,48,0.15)" : "rgba(92,132,255,0.15)",
      color,
      animation: "pulse-badge 1.5s ease-in-out infinite",
    }}>
      <span style={{
        width: "6px",
        height: "6px",
        borderRadius: "50%",
        background: color,
        animation: "pulse-dot 1.5s ease-in-out infinite",
      }} />
      {label}
      <style>{`
        @keyframes pulse-badge { 0%,100% { opacity: 1; } 50% { opacity: 0.6; } }
        @keyframes pulse-dot { 0%,100% { transform: scale(1); opacity: 1; } 50% { transform: scale(1.4); opacity: 0.5; } }
      `}</style>
    </span>
  );
};

const SourceBadge = ({ source }: { source: string }) => {
  const labels: Record<string, { text: string; color: string }> = {
    manual: { text: "Manual", color: "rgba(255,255,255,0.5)" },
    ci_cd: { text: "CI/CD", color: "#5c84ff" },
    scheduled: { text: "Auto", color: "#69db7c" },
  };
  const { text, color } = labels[source] || { text: source, color: "rgba(255,255,255,0.4)" };
  return (
    <span style={{
      padding: "0.125rem 0.5rem",
      borderRadius: "4px",
      fontSize: "0.75rem",
      fontWeight: 500,
      background: `${color}15`,
      color,
    }}>
      {text}
    </span>
  );
};

type DataPoint = { time: number; value: number };

const LiveChart = ({ label, data, max, current, color, minutes }: { label: string; data: DataPoint[]; max: number; current: number; color: string; minutes: number }) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [tooltip, setTooltip] = useState<{ x: number; value: number; time: number } | null>(null);
  const CHART_H = 120;

  const fmt = useCallback((bytes: number) => {
    if (bytes >= 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
    if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(0)} MB`;
    return `${(bytes / 1024).toFixed(0)} KB`;
  }, []);

  const pct = max > 0 ? Math.min(100, (current / max) * 100) : 0;
  const windowMs = minutes * 60 * 1000;

  // Filter data to the selected time window
  const now = data.length > 0 ? data[data.length - 1].time : Date.now();
  const windowStart = now - windowMs;
  const visible = data.filter(d => d.time >= windowStart);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || visible.length === 0) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const dpr = window.devicePixelRatio || 1;
    const w = canvas.clientWidth;
    const h = canvas.clientHeight;
    canvas.width = w * dpr;
    canvas.height = h * dpr;
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, w, h);

    const pad = { top: 4, bottom: 2 };
    const chartH = h - pad.top - pad.bottom;

    // Y-axis: auto-scale to data with 20% headroom, minimum = max/5 so flat lines sit mid-chart
    const dataMax = Math.max(...visible.map(d => d.value), 1);
    const yMax = Math.max(dataMax * 1.2, max > 0 ? max * 0.05 : dataMax * 1.5);

    // Grid lines + labels
    const gridLines = 4;
    ctx.textAlign = "right";
    ctx.font = "10px monospace";
    for (let i = 0; i <= gridLines; i++) {
      const y = pad.top + (chartH / gridLines) * i;
      if (i > 0 && i < gridLines) {
        ctx.strokeStyle = "rgba(255,255,255,0.05)";
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(w, y);
        ctx.stroke();
      }
      ctx.fillStyle = "rgba(255,255,255,0.18)";
      const val = yMax * (1 - i / gridLines);
      ctx.fillText(fmt(val), w - 4, y + 12);
    }

    // Limit line (dashed) if limit is within visible range
    if (max > 0 && max <= yMax) {
      const limitY = pad.top + chartH - (max / yMax) * chartH;
      ctx.setLineDash([4, 4]);
      ctx.strokeStyle = "rgba(255,107,107,0.3)";
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(0, limitY);
      ctx.lineTo(w, limitY);
      ctx.stroke();
      ctx.setLineDash([]);
      ctx.fillStyle = "rgba(255,107,107,0.4)";
      ctx.textAlign = "left";
      ctx.fillText("limit", 4, limitY - 3);
      ctx.textAlign = "right";
    }

    // Map data points to canvas coords
    const toX = (t: number) => ((t - windowStart) / windowMs) * w;
    const toY = (v: number) => pad.top + chartH - (v / yMax) * chartH;

    // Build drawing points — extend flat line from first point leftward to fill chart
    const pts: { x: number; y: number }[] = visible.map(d => ({ x: toX(d.time), y: toY(d.value) }));
    // Always extend to right edge at current value
    if (pts.length > 0) {
      const lastPt = pts[pts.length - 1];
      if (lastPt.x < w - 1) {
        pts.push({ x: w, y: lastPt.y });
      }
    }

    // Area fill
    ctx.beginPath();
    ctx.moveTo(pts[0].x, h);
    for (const p of pts) ctx.lineTo(p.x, p.y);
    ctx.lineTo(pts[pts.length - 1].x, h);
    ctx.closePath();
    const grad = ctx.createLinearGradient(0, 0, 0, h);
    grad.addColorStop(0, color + "30");
    grad.addColorStop(1, color + "05");
    ctx.fillStyle = grad;
    ctx.fill();

    // Line
    ctx.beginPath();
    for (let i = 0; i < pts.length; i++) {
      i === 0 ? ctx.moveTo(pts[i].x, pts[i].y) : ctx.lineTo(pts[i].x, pts[i].y);
    }
    ctx.strokeStyle = color;
    ctx.lineWidth = 1.5;
    ctx.stroke();

    // Current value dot
    const last = pts[pts.length - 1];
    ctx.beginPath();
    ctx.arc(last.x, last.y, 3, 0, Math.PI * 2);
    ctx.fillStyle = color;
    ctx.fill();
  }, [visible, max, color, windowMs, windowStart]);

  const handleMouseMove = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas || visible.length === 0) return;
    const rect = canvas.getBoundingClientRect();
    const mouseX = e.clientX - rect.left;
    const w = rect.width;
    const hoverTime = windowStart + (mouseX / w) * windowMs;
    // Find closest data point
    let closest = visible[0];
    let closestDist = Infinity;
    for (const d of visible) {
      const dist = Math.abs(d.time - hoverTime);
      if (dist < closestDist) { closestDist = dist; closest = d; }
    }
    const x = ((closest.time - windowStart) / windowMs) * w;
    setTooltip({ x, value: closest.value, time: closest.time });
  };

  const fmtTime = (ts: number) => {
    const d = new Date(ts);
    return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}:${String(d.getSeconds()).padStart(2, "0")}`;
  };

  return (
    <div
      ref={containerRef}
      style={{
        padding: "1rem 1.25rem",
        border: "1px solid rgba(255,255,255,0.08)",
        borderRadius: "8px",
        background: "rgba(255,255,255,0.02)",
      }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: "0.5rem" }}>
        <span style={{ fontSize: "0.75rem", color: "rgba(255,255,255,0.4)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
          {label}
        </span>
        <span style={{ fontSize: "0.75rem", color: "rgba(255,255,255,0.35)" }}>
          <span style={{ fontWeight: 700, color, fontSize: "1rem" }}>{fmt(current)}</span>
          {" "}/ {fmt(max)} ({pct.toFixed(1)}%)
        </span>
      </div>
      <div style={{ position: "relative" }}>
        <canvas
          ref={canvasRef}
          style={{ width: "100%", height: `${CHART_H}px`, display: "block", borderRadius: "4px", cursor: "crosshair" }}
          onMouseMove={handleMouseMove}
          onMouseLeave={() => setTooltip(null)}
        />
        {tooltip && (
          <>
            <div style={{
              position: "absolute", top: 0, left: tooltip.x, width: "1px", height: `${CHART_H}px`,
              background: "rgba(255,255,255,0.2)", pointerEvents: "none",
            }} />
            <div style={{
              position: "absolute", top: "4px",
              left: Math.min(tooltip.x + 8, (containerRef.current?.clientWidth ?? 300) - 130),
              background: "rgba(20,22,28,0.95)", border: "1px solid rgba(255,255,255,0.15)",
              borderRadius: "6px", padding: "0.375rem 0.625rem", pointerEvents: "none",
              fontSize: "0.75rem", whiteSpace: "nowrap",
              boxShadow: "0 4px 12px rgba(0,0,0,0.4)",
            }}>
              <div style={{ color: "rgba(255,255,255,0.5)", marginBottom: "0.125rem" }}>{fmtTime(tooltip.time)}</div>
              <div style={{ color, fontWeight: 600 }}>{fmt(tooltip.value)}</div>
            </div>
          </>
        )}
      </div>
    </div>
  );
};

const ResourceCard = ({ label, used, total, color }: { label: string; used: number; total: number; color: string }) => {
  const pct = total > 0 ? Math.min(100, (used / total) * 100) : 0;
  const fmt = (bytes: number) => {
    if (bytes >= 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
    if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(0)} MB`;
    return `${(bytes / 1024).toFixed(0)} KB`;
  };
  return (
    <div style={{
      padding: "1rem 1.25rem",
      border: "1px solid rgba(255,255,255,0.08)",
      borderRadius: "8px",
      background: "rgba(255,255,255,0.02)",
    }}>
      <div style={{ fontSize: "0.75rem", color: "rgba(255,255,255,0.4)", marginBottom: "0.5rem", textTransform: "uppercase", letterSpacing: "0.05em" }}>
        {label}
      </div>
      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "0.375rem", fontSize: "0.8125rem" }}>
        <span style={{ fontWeight: 600 }}>{fmt(used)}</span>
        <span style={{ color: "rgba(255,255,255,0.4)" }}>{fmt(total)}</span>
      </div>
      <div style={{ height: "6px", borderRadius: "3px", background: "rgba(255,255,255,0.08)", overflow: "hidden" }}>
        <div style={{
          height: "100%",
          width: `${pct}%`,
          borderRadius: "3px",
          background: pct > 85 ? "#ff6b6b" : color,
          transition: "width 0.3s",
        }} />
      </div>
      <div style={{ fontSize: "0.6875rem", color: "rgba(255,255,255,0.35)", marginTop: "0.25rem", textAlign: "right" }}>
        {pct.toFixed(1)}%
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
    cancelled: "#ff922b",
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

const StatBox = ({ label, value }: { label: string; value: string }) => (
  <div style={{
    padding: "0.75rem",
    background: "rgba(255,255,255,0.03)",
    border: "1px solid rgba(255,255,255,0.06)",
    borderRadius: "6px",
  }}>
    <div style={{ fontSize: "0.75rem", color: "rgba(255,255,255,0.4)", marginBottom: "0.25rem" }}>{label}</div>
    <div style={{ fontSize: "1.125rem", fontWeight: 600 }}>{value}</div>
  </div>
);

// Styles
const thStyle: React.CSSProperties = {
  textAlign: "left",
  padding: "0.5rem 0.75rem",
  color: "rgba(255,255,255,0.5)",
  fontWeight: 500,
  fontSize: "0.8125rem",
};

const tdStyle: React.CSSProperties = {
  padding: "0.625rem 0.75rem",
  verticalAlign: "middle",
};

const labelStyle: React.CSSProperties = {
  display: "block",
  fontSize: "0.8125rem",
  fontWeight: 500,
  color: "rgba(255,255,255,0.6)",
  marginBottom: "0.375rem",
};

const inputStyle: React.CSSProperties = {
  width: "100%",
  padding: "0.5rem 0.75rem",
  borderRadius: "6px",
  border: "1px solid rgba(255,255,255,0.15)",
  background: "rgba(255,255,255,0.05)",
  color: "#fff",
  fontSize: "0.875rem",
  outline: "none",
  boxSizing: "border-box",
};
