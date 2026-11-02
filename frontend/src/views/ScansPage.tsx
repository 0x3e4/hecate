import React, { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { LuArrowDown, LuArrowUp, LuChevronDown, LuExternalLink, LuInfo, LuLock, LuPencil, LuPlus, LuRefreshCw, LuSquare, LuTrash2, LuX } from "react-icons/lu";
import { Link } from "react-router-dom";

import "../screens/scans.css";

import { useServerConfig } from "../server-config/context";
import { getCurrentTimezone } from "../timezone/storage";

import {
  fetchScanTargets,
  fetchScans,
  fetchGlobalFindings,
  fetchGlobalSbom,
  fetchGlobalAlerts,
  fetchBadgeCounts,
  fetchSbomFacets,
  type SbomFacets,
  submitManualScan,
  submitManualSourceArchiveScan,
  deleteScanTarget,
  deleteScan,
  updateScanTarget,
  cancelScan,
  fetchScannerStats,
  importSbomFile,
  triggerTargetCheck,
} from "../api/scans";
import { fetchLicenseOverview } from "../api/licensePolicy";
import { SeverityBadges } from "../components/SeverityBadges";
import { SkeletonBlock } from "../components/Skeleton";
import { useToastContext } from "../components/ToastProvider";
import { usePersistentState } from "../hooks/usePersistentState";
import { useI18n } from "../i18n/context";
import { EmptyState, ErrorState, IconButton, PageHeader, SeverityTag, Stat } from "../ui/primitives";
import { TabPill } from "../ui/TabPill";
import { formatDateTime } from "../utils/dateFormat";
import { safeHref } from "../utils/safeHref";
import {
  TYPE_ALIASES,
  buildDepsDevUrl,
  buildSnykUrl,
  buildRegistryUrl,
  buildSocketUrl,
  buildAikidoUrl,
  buildBundlephobiaUrl,
  buildNpmGraphUrl,
} from "../utils/sbomLinks";
import type {
  ScanTarget,
  Scan,
  ScanSummary,
  ConsolidatedFinding,
  ConsolidatedSbom,
  ConsolidatedAlert,
  ScannerStats,
  SubmitScanResponse,
  LicenseOverviewItem,
} from "../types";

type Tab = "targets" | "scans" | "findings" | "sbom" | "licenses" | "alerts" | "scanner";
type SourceRepoInputMode = "url" | "zip";

interface ConfirmModal {
  title: string;
  message: string;
  onConfirm: () => void;
}

type ScannerCategory = "vulnerability" | "sbom" | "sast" | "secrets" | "malware" | "compliance" | "layer";

interface ScannerMeta {
  id: string;
  category: ScannerCategory;
  noteEn?: string;
  noteDe?: string;
}

const SCANNER_META: ScannerMeta[] = [
  { id: "trivy", category: "vulnerability" },
  { id: "grype", category: "vulnerability" },
  { id: "osv-scanner", category: "vulnerability" },
  { id: "syft", category: "sbom" },
  { id: "semgrep", category: "sast" },
  { id: "devskim", category: "sast", noteEn: ".NET focus", noteDe: ".NET-Fokus" },
  { id: "trufflehog", category: "secrets" },
  { id: "hecate", category: "malware" },
  { id: "dockle", category: "compliance" },
  { id: "dive", category: "layer" },
];

const CATEGORY_ORDER: Array<{ key: ScannerCategory; en: string; de: string }> = [
  { key: "vulnerability", en: "Vulnerability", de: "Schwachstellen" },
  { key: "sbom", en: "SBOM", de: "SBOM" },
  { key: "sast", en: "SAST", de: "SAST" },
  { key: "secrets", en: "Secrets", de: "Secrets" },
  { key: "malware", en: "Malware", de: "Malware" },
  { key: "compliance", en: "Compliance", de: "Compliance" },
  { key: "layer", en: "Layer Analysis", de: "Schichtanalyse" },
];

const SOURCE_REPO_SCANNER_IDS = new Set(["trivy", "grype", "syft", "osv-scanner", "hecate", "semgrep", "trufflehog", "devskim"]);
const CONTAINER_SCANNER_IDS = new Set(["trivy", "grype", "syft", "dockle", "dive"]);

interface ScannerCheckboxGroupProps {
  scanType: "container_image" | "source_repo";
  selected: string[];
  onToggle: (id: string) => void;
  compact?: boolean;
}

const ScannerCheckboxGroup = ({ scanType, selected, onToggle, compact = false }: ScannerCheckboxGroupProps) => {
  const { t } = useI18n();
  const allowed = scanType === "container_image" ? CONTAINER_SCANNER_IDS : SOURCE_REPO_SCANNER_IDS;

  return (
    <div className={`scans-scanners${compact ? " scans-scanners--compact" : ""}`}>
      {CATEGORY_ORDER.map(cat => {
        const items = SCANNER_META.filter(m => m.category === cat.key && allowed.has(m.id));
        if (items.length === 0) return null;
        return (
          <div key={cat.key}>
            <div className="scans-scanners-category">
              {t(cat.en, cat.de)}
            </div>
            <div className="scans-scanners-items">
              {items.map(m => (
                <label key={m.id} className="scans-check">
                  <input
                    type="checkbox"
                    checked={selected.includes(m.id)}
                    onChange={() => onToggle(m.id)}
                  />
                  {m.id}
                  {m.noteEn && (
                    <span className="scans-sub">
                      ({t(m.noteEn, m.noteDe || m.noteEn)})
                    </span>
                  )}
                </label>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
};

export const ScansPage = () => {
  const { t } = useI18n();
  const { showToast } = useToastContext();
  const { scaAutoScanEnabled } = useServerConfig();
  const [tab, setTab] = useState<Tab>("targets");
  const [targets, setTargets] = useState<ScanTarget[]>([]);
  // Client-side name/URL filter for the Targets tab.
  const [targetSearch, setTargetSearch] = useState("");
  const [collapsedGroups, setCollapsedGroups] = usePersistentState<Record<string, boolean>>(
    "hecate.scan.groupCollapsed",
    {},
  );
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirmModal, setConfirmModal] = useState<ConfirmModal | null>(null);
  const [newScanModalOpen, setNewScanModalOpen] = useState(false);

  // Scan filter (from target card click or dropdown)
  const [scanFilterTargetId, setScanFilterTargetId] = useState<string | null>(null);
  const [scanFilterStatus, setScanFilterStatus] = useState<string>("");
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

  // Badge counts (unfiltered, for tab labels)
  const [findingsBadgeTotal, setFindingsBadgeTotal] = useState(0);
  const [sbomBadgeTotal, setSbomBadgeTotal] = useState(0);
  const [alertsBadgeTotal, setAlertsBadgeTotal] = useState(0);

  // Global Security Alerts tab
  const [globalAlerts, setGlobalAlerts] = useState<ConsolidatedAlert[]>([]);
  const [globalAlertsTotal, setGlobalAlertsTotal] = useState(0);
  const [alertsLoading, setAlertsLoading] = useState(false);
  const [alertsSearch, setAlertsSearch] = useState("");
  const [alertsSeverity, setAlertsSeverity] = useState<string | null>(null);
  const [alertsCategory, setAlertsCategory] = useState<string | null>(null);
  const [alertsTargetId, setAlertsTargetId] = useState<string | null>(null);
  const [alertsSortBy, setAlertsSortBy] = useState("severity");
  const [alertsSortOrder, setAlertsSortOrder] = useState<"asc" | "desc">("desc");
  const [alertsOffset, setAlertsOffset] = useState(0);
  const alertsLimit = 50;
  const alertsSearchRef = useRef(alertsSearch);
  alertsSearchRef.current = alertsSearch;

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
  const [sbomFacets, setSbomFacets] = useState<SbomFacets | null>(null);
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
  const [scanError, setScanError] = useState<string | null>(null);

  useEffect(() => {
    document.title = t("Hecate Cyber Defense - Software Composition Analysis", "Hecate Cyber Defense - Software-Kompositionsanalyse");
    return () => { document.title = "Hecate Cyber Defense"; };
  }, [t]);

  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    loadData();
  }, [tab, scanFilterTargetId, scanFilterStatus, scanOffset]);

  // Load unfiltered badge counts once on mount so tab labels are correct
  // regardless of which tab the user lands on.
  useEffect(() => {
    fetchBadgeCounts()
      .then(counts => {
        setFindingsBadgeTotal(counts.findings);
        setSbomBadgeTotal(counts.sbom);
        setLicenseOverviewTotal(counts.licenses);
        setAlertsBadgeTotal(counts.alerts);
      })
      .catch(() => { /* ignore */ });
  }, []);

  // Load global SBOM facets when the SBOM tab is first opened.
  useEffect(() => {
    if (tab !== "sbom" || sbomFacets) return;
    fetchSbomFacets()
      .then(setSbomFacets)
      .catch(() => setSbomFacets({ ecosystems: [], licenses: [], types: [] }));
  }, [tab, sbomFacets]);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      if (tab === "targets") {
        const [targetsRes, scansRes, badgeCounts] = await Promise.all([
          fetchScanTargets({ limit: 100 }),
          fetchScans({ limit: 1 }),
          fetchBadgeCounts().catch(() => ({ findings: 0, sbom: 0, licenses: 0, alerts: 0 })),
        ]);
        setTargets(targetsRes.items);
        setScanTotal(scansRes.total);
        setFindingsBadgeTotal(badgeCounts.findings);
        setSbomBadgeTotal(badgeCounts.sbom);
        setLicenseOverviewTotal(badgeCounts.licenses);
        setAlertsBadgeTotal(badgeCounts.alerts);
      } else if (tab === "scans") {
        // Load targets for filter dropdown if not yet loaded
        if (targets.length === 0) {
          const tRes = await fetchScanTargets({ limit: 100 });
          setTargets(tRes.items);
        }
        const res = await fetchScans({ limit: scanLimit, offset: scanOffset, targetId: scanFilterTargetId || undefined, status: scanFilterStatus || undefined });
        setScans(res.items);
        setScanTotal(res.total);
      } else if (tab === "findings" || tab === "sbom" || tab === "alerts") {
        // Ensure targets loaded for filter dropdown
        if (targets.length === 0) {
          const tRes = await fetchScanTargets({ limit: 100 });
          setTargets(tRes.items);
        }
      } else if (tab === "scanner") {
        try {
          // Targets in parallel: the auto-scan diagnostics table below
          // wants the latest last_check_* fields, and the polling loop for
          // this tab refetches both every 5 s.
          const [stats, targetsRes] = await Promise.all([
            fetchScannerStats(),
            fetchScanTargets({ limit: 100 }),
          ]);
          setScannerStats(stats);
          setTargets(targetsRes.items);
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

  // Debounced fetch for global Security Alerts tab
  useEffect(() => {
    if (tab !== "alerts") return;
    setAlertsLoading(true);
    const timer = setTimeout(async () => {
      try {
        const res = await fetchGlobalAlerts({
          search: alertsSearchRef.current || undefined,
          severity: alertsSeverity || undefined,
          category: alertsCategory || undefined,
          targetId: alertsTargetId || undefined,
          sortBy: alertsSortBy,
          sortOrder: alertsSortOrder,
          limit: alertsLimit,
          offset: alertsOffset,
        });
        setGlobalAlerts(res.items);
        setGlobalAlertsTotal(res.total);
      } catch (err) {
        console.error("Failed to load global alerts", err);
      } finally {
        setAlertsLoading(false);
      }
    }, alertsSearch ? 300 : 0);
    return () => clearTimeout(timer);
  }, [tab, alertsSearch, alertsSeverity, alertsCategory, alertsTargetId, alertsSortBy, alertsSortOrder, alertsOffset]);

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
            const res = await fetchScans({ limit: scanLimit, offset: scanOffset, targetId: scanFilterTargetId || undefined, status: scanFilterStatus || undefined });
            setScans(res.items);
            setScanTotal(res.total);
          } else if (tab === "targets") {
            const res = await fetchScanTargets({ limit: 100 });
            setTargets(res.items);
          } else if (tab === "scanner") {
            // Refetch targets in parallel so the auto-scan diagnostics table
            // below picks up the most recent /check probe results without
            // requiring a tab switch.
            const [stats, targetsRes] = await Promise.all([
              fetchScannerStats(),
              fetchScanTargets({ limit: 100 }),
            ]);
            setScannerStats(stats);
            setTargets(targetsRes.items);
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
      void result;
      setNewScanModalOpen(false);
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
      }, target.id);
      setTab("scans");
      showToast(t("Scan started.", "Scan gestartet."), "success");
    } catch (err) {
      console.error("Rescan failed", err);
      showToast(t("Could not start scan.", "Scan konnte nicht gestartet werden."), "error");
    }
  };

  const handleDeleteTarget = (targetId: string) => {
    setConfirmModal({
      title: t("Delete target", "Ziel löschen"),
      message: t(
        "Delete this target and all its scan data? This action cannot be undone.",
        "Dieses Ziel und alle zugehörigen Scan-Daten löschen? Diese Aktion kann nicht rückgängig gemacht werden."
      ),
      onConfirm: async () => {
        try {
          await deleteScanTarget(targetId);
          setTargets(prev => prev.filter(t => t.id !== targetId));
          showToast(t("Target deleted.", "Ziel gelöscht."), "success");
        } catch (err) {
          console.error("Delete failed", err);
          showToast(t("Could not delete target.", "Ziel konnte nicht gelöscht werden."), "error");
        }
        setConfirmModal(null);
      },
    });
  };

  const handleDeleteScan = (scanId: string, scanName: string) => {
    setConfirmModal({
      title: t("Delete scan", "Scan löschen"),
      message: t(
        `Delete scan "${scanName}"? Findings and SBOM data will be removed.`,
        `Scan „${scanName}" löschen? Ergebnisse und SBOM-Daten werden entfernt.`
      ),
      onConfirm: async () => {
        try {
          await deleteScan(scanId);
          setScans(prev => prev.filter(s => s.id !== scanId));
          showToast(t("Scan deleted.", "Scan gelöscht."), "success");
        } catch (err) {
          console.error("Delete scan failed", err);
          showToast(t("Could not delete scan.", "Scan konnte nicht gelöscht werden."), "error");
        }
        setConfirmModal(null);
      },
    });
  };

  const handleCancelScan = async (scanId: string) => {
    try {
      await cancelScan(scanId);
      loadData();
      showToast(t("Scan cancelled.", "Scan abgebrochen."), "success");
    } catch (err) {
      console.error("Cancel scan failed", err);
      showToast(t("Could not cancel scan.", "Scan konnte nicht abgebrochen werden."), "error");
    }
  };

  const handleToggleAutoScan = async (target: ScanTarget) => {
    const newValue = target.autoScan === false; // toggle; default is true
    try {
      await updateScanTarget(target.id, { autoScan: newValue });
      setTargets(prev => prev.map((tt: ScanTarget) => tt.id === target.id ? { ...tt, autoScan: newValue } : tt));
    } catch (err) {
      console.error("Toggle auto-scan failed", err);
      showToast(t("Could not update auto-scan.", "Auto-Scan konnte nicht geändert werden."), "error");
    }
  };

  const handleUpdateScanners = async (targetId: string, newScanners: string[]) => {
    try {
      await updateScanTarget(targetId, { scanners: newScanners });
      setTargets(prev => prev.map((tt: ScanTarget) => tt.id === targetId ? { ...tt, scanners: newScanners } : tt));
    } catch (err) {
      console.error("Update scanners failed", err);
      showToast(t("Could not update scanners.", "Scanner konnten nicht aktualisiert werden."), "error");
    }
  };

  const handleUpdateGroup = async (targetId: string, group: string | null) => {
    const normalized = group && group.trim() ? group.trim() : null;
    try {
      await updateScanTarget(targetId, { group: normalized });
      setTargets(prev => prev.map((tt: ScanTarget) => tt.id === targetId ? { ...tt, group: normalized } : tt));
    } catch (err) {
      console.error("Update group failed", err);
      showToast(t("Could not update application group.", "Anwendungsgruppe konnte nicht aktualisiert werden."), "error");
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

  // Filter by the name/URL search box before grouping. Matches name,
  // target id (URL/image ref), repository URL, registry, and group.
  const targetQuery = targetSearch.trim().toLowerCase();
  const visibleTargets = targetQuery
    ? targets.filter(tgt =>
        [tgt.name, tgt.id, tgt.repositoryUrl, tgt.registry, tgt.group]
          .some(v => (v || "").toLowerCase().includes(targetQuery)),
      )
    : targets;
  const visibleSummary = sumSummary(visibleTargets);
  const targetColumns = scaAutoScanEnabled ? 7 : 6;

  return (
    <div className="page scans-page">
      <PageHeader
        title={t("Software Composition Analysis", "Software-Kompositionsanalyse")}
        description={t(
          "Scan container images and source repositories for vulnerabilities and generate SBOMs.",
          "Container-Images und Quellcode-Repositories auf Schwachstellen scannen und SBOMs generieren."
        )}
        actions={
          <button type="button" className="btn-primary" onClick={() => setNewScanModalOpen(true)}>
            <LuPlus aria-hidden="true" />
            {t("New scan", "Neuer Scan")}
          </button>
        }
      />

      {/* Tab navigation */}
      <div className="scans-tabs">
        {([
          { key: "targets" as Tab, label: t("Targets", "Ziele"), count: targets.length || undefined },
          { key: "scans" as Tab, label: t("Scans", "Scans"), count: scanTotal || undefined },
          { key: "findings" as Tab, label: t("Findings", "Funde"), count: findingsBadgeTotal || undefined },
          { key: "sbom" as Tab, label: "SBOM", count: sbomBadgeTotal || undefined },
          { key: "alerts" as Tab, label: t("Security alerts", "Sicherheitswarnungen"), count: alertsBadgeTotal || undefined },
          { key: "licenses" as Tab, label: t("Licenses", "Lizenzen"), count: licenseOverviewTotal || undefined },
          { key: "scanner" as Tab, label: t("Scanner", "Scanner") },
        ]).map(({ key, label, count }) => (
          <TabPill
            key={key}
            active={tab === key}
            count={count}
            onClick={() => { setTab(key); if (key === "scans") { setScanOffset(0); } }}
          >
            {label}
          </TabPill>
        ))}
      </div>

      {error && <ErrorState title={error} />}

      {/* Targets tab */}
      {tab === "targets" && (
        <div>
          <div className="scans-lead">
            {!loading && targets.length > 0 && (
              <dl className="stat-row">
                <Stat label={t("Critical", "Kritisch")} value={visibleSummary.critical.toLocaleString()} tone={visibleSummary.critical ? "critical" : undefined} />
                <Stat label={t("High", "Hoch")} value={visibleSummary.high.toLocaleString()} tone={visibleSummary.high ? "high" : undefined} />
                <Stat label={t("Medium", "Mittel")} value={visibleSummary.medium.toLocaleString()} tone={visibleSummary.medium ? "medium" : undefined} />
                <Stat label={t("Low", "Niedrig")} value={visibleSummary.low.toLocaleString()} tone={visibleSummary.low ? "low" : undefined} />
              </dl>
            )}
            <input
              type="text"
              className="scans-lead-search"
              value={targetSearch}
              onChange={e => setTargetSearch(e.target.value)}
              placeholder={t("Search by name or URL…", "Nach Name oder URL suchen…")}
              aria-label={t("Search targets", "Ziele suchen")}
            />
          </div>
          {loading && (
            <div className="scans-skeleton-rows">
              {Array.from({ length: 8 }).map((_, i) => (
                <SkeletonBlock key={i} height={56} radius={4} />
              ))}
            </div>
          )}
          {!loading && targets.length === 0 && (
            <EmptyState title={t("No scan targets registered yet.", "Noch keine Scan-Ziele registriert.")} />
          )}
          {!loading && targets.length > 0 && (() => {
            if (visibleTargets.length === 0) {
              return (
                <EmptyState title={<>{t("No targets match", "Keine Ziele passen zu")} “{targetSearch.trim()}”.</>} />
              );
            }
            // Group targets by their `group` field; ungrouped targets bucket last.
            const UNGROUPED = "__ungrouped__";
            const buckets = new Map<string, ScanTarget[]>();
            for (const tgt of visibleTargets) {
              const key = (tgt.group && tgt.group.trim()) || UNGROUPED;
              if (!buckets.has(key)) buckets.set(key, []);
              buckets.get(key)!.push(tgt);
            }
            const orderedKeys = Array.from(buckets.keys()).sort((a, b) => {
              if (a === UNGROUPED) return 1;
              if (b === UNGROUPED) return -1;
              return a.localeCompare(b);
            });
            // Group autocomplete should list every existing group, not just
            // those surviving the current search filter.
            const allGroupNames = Array.from(
              new Set(targets.map(tg => (tg.group || "").trim()).filter(Boolean)),
            ).sort((a, b) => a.localeCompare(b));
            const onFilterScansFn = (id: string, name: string) => {
              setScanFilterTargetId(id);
              setScanFilterTargetName(name);
              setScanOffset(0);
              setTab("scans");
            };
            return (
              <div className="scans-targets-wrap">
                <table className="scans-table scans-targets">
                  <thead>
                    <tr>
                      <th scope="col">{t("Target", "Ziel")}</th>
                      <th scope="col" className="scans-col-findings">{t("Findings", "Ergebnisse")}</th>
                      <th scope="col" className="scans-col-last">{t("Last scan", "Letzter Scan")}</th>
                      <th scope="col" className="scans-col-app">{t("App", "App")}</th>
                      <th scope="col" className="scans-col-scanners">{t("Scanners", "Scanner")}</th>
                      {scaAutoScanEnabled && <th scope="col" className="scans-col-auto">Auto-Scan</th>}
                      <th scope="col" className="scans-col-actions"><span className="visually-hidden">{t("Actions", "Aktionen")}</span></th>
                    </tr>
                  </thead>
                  {orderedKeys.map(key => {
                    const items = buckets.get(key)!;
                    const isUngrouped = key === UNGROUPED;
                    const collapsed = !!collapsedGroups[key];
                    const rollup = sumSummary(items);
                    const label = isUngrouped ? t("Ungrouped", "Ohne Gruppe") : key;
                    const toggleGroup = () => setCollapsedGroups({ ...collapsedGroups, [key]: !collapsed });
                    return (
                      <tbody key={key}>
                        <tr className="scans-group" onClick={toggleGroup}>
                          <th scope="rowgroup" className="scans-group-name">
                            <button
                              type="button"
                              className={`scans-group-toggle${isUngrouped ? " is-ungrouped" : ""}`}
                              aria-expanded={!collapsed}
                              onClick={e => { e.stopPropagation(); toggleGroup(); }}
                            >
                              <LuChevronDown className={`scans-group-chevron${collapsed ? " is-collapsed" : ""}`} aria-hidden="true" />
                              <span>{label}</span>
                              <span className="scans-group-count">{items.length}</span>
                            </button>
                          </th>
                          <td colSpan={targetColumns - 1} className="scans-group-rollup">
                            <SeverityBadges summary={rollup} />
                          </td>
                        </tr>
                        {!collapsed && items.map(target => (
                          <TargetRow
                            key={target.id}
                            target={target}
                            colSpan={targetColumns}
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
                      </tbody>
                    );
                  })}
                </table>
              </div>
            );
          })()}
        </div>
      )}

      {/* Scans tab */}
      {tab === "scans" && (
        <div>
          {/* Filter bar */}
          <div className="filter-row">
            <select
              className="scans-select"
              aria-label={t("Filter by target", "Nach Ziel filtern")}
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
            >
              <option value="">{t("All targets", "Alle Ziele")}</option>
              {targets.map(tgt => (
                <option key={tgt.id} value={tgt.id}>{tgt.name}</option>
              ))}
            </select>
            <select
              className="scans-select"
              aria-label={t("Filter by status", "Nach Status filtern")}
              value={scanFilterStatus}
              onChange={e => { setScanFilterStatus(e.target.value); setScanOffset(0); }}
            >
              <option value="">{t("All statuses", "Alle Status")}</option>
              <option value="pending">{t("Pending", "Wartend")}</option>
              <option value="running">{t("Running", "Läuft")}</option>
              <option value="completed">{t("Completed", "Abgeschlossen")}</option>
              <option value="failed">{t("Failed", "Fehlgeschlagen")}</option>
              <option value="cancelled">{t("Cancelled", "Abgebrochen")}</option>
            </select>
            {(scanFilterTargetId || scanFilterStatus) && (
              <IconButton
                label={t("Clear filter", "Filter entfernen")}
                onClick={() => { setScanFilterTargetId(null); setScanFilterTargetName(null); setScanFilterStatus(""); setScanOffset(0); }}
              >
                <LuX aria-hidden="true" />
              </IconButton>
            )}
            <span className="scans-count">
              {scanTotal} {t("total", "gesamt")}
            </span>
          </div>

          {loading && (
            <div className="scans-skeleton-rows">
              {Array.from({ length: 6 }).map((_, i) => (
                <SkeletonBlock key={i} height={40} radius={4} />
              ))}
            </div>
          )}
          {!loading && scans.length === 0 && (
            <EmptyState title={t("No scans yet.", "Noch keine Scans.")} />
          )}
          {!loading && scans.length > 0 && (
            <>
              <div className="table-scroll">
                <table className="scans-table scans-table--pin scans-table--pin-end">
                  <thead>
                    <tr>
                      <th scope="col">{t("Target", "Ziel")}</th>
                      <th scope="col">Status</th>
                      <th scope="col">{t("Findings", "Ergebnisse")}</th>
                      <th scope="col">{t("Ref", "Ref")}</th>
                      <th scope="col">{t("Source", "Quelle")}</th>
                      <th scope="col">{t("Date", "Datum")}</th>
                      <th scope="col"><span className="visually-hidden">{t("Actions", "Aktionen")}</span></th>
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
                      const done = scan.status === "completed" || scan.status === "failed" || scan.status === "cancelled";
                      const ts = done ? (scan.finishedAt || scan.startedAt) : scan.startedAt;
                      return (
                        <tr key={scan.id}>
                          <td className="scans-cell-strong">
                            <Link to={`/scans/${scan.id}`} className="row-link">
                              {scan.targetName || scan.targetId}
                            </Link>
                          </td>
                          <td><StatusBadge status={scan.status} /></td>
                          <td><SeverityBadges summary={scan.summary} /></td>
                          <td title={refFull || undefined}>
                            {ref ? (
                              <span className="scans-ref">
                                <span className="muted">{refLabel}:</span>
                                <span className="mono">{ref}</span>
                                {refUrl && (
                                  <a href={safeHref(refUrl)} target="_blank" rel="noopener noreferrer" className="scans-ref-link" title={refUrl} aria-label={refUrl}>
                                    <LuExternalLink aria-hidden="true" />
                                  </a>
                                )}
                              </span>
                            ) : <NotAvailable />}
                          </td>
                          <td><SourceBadge source={scan.source} /></td>
                          <td className="scans-nowrap scans-small">{ts ? formatDateTime(ts) : <NotAvailable />}</td>
                          <td className="scans-cell-action">
                            {(scan.status === "running" || scan.status === "pending") ? (
                              <IconButton className="scans-outline" label={t("Stop scan", "Scan stoppen")} onClick={() => handleCancelScan(scan.id)}>
                                <LuSquare aria-hidden="true" />
                              </IconButton>
                            ) : (
                              <IconButton className="scans-outline" label={t("Delete scan", "Scan löschen")} onClick={() => handleDeleteScan(scan.id, scan.targetName || scan.targetId)}>
                                <LuTrash2 aria-hidden="true" />
                              </IconButton>
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
                <Pager
                  prevDisabled={scanOffset === 0}
                  nextDisabled={scanOffset + scanLimit >= scanTotal}
                  onPrev={() => setScanOffset(Math.max(0, scanOffset - scanLimit))}
                  onNext={() => setScanOffset(scanOffset + scanLimit)}
                >
                  {Math.floor(scanOffset / scanLimit) + 1} / {Math.ceil(scanTotal / scanLimit)}
                </Pager>
              )}
            </>
          )}
        </div>
      )}

      {/* Findings tab */}
      {tab === "findings" && (
        <div>
          {/* Filter bar */}
          <div className="filter-row">
            <input
              type="text"
              className="scans-filter-search"
              value={findingsSearch}
              onChange={e => { setFindingsSearch(e.target.value); setFindingsOffset(0); }}
              placeholder={t("Search by CVE, package, title...", "Suche nach CVE, Paket, Titel...")}
              aria-label={t("Search findings", "Funde suchen")}
            />
            {/* Severity filter buttons */}
            <div className="scans-segments" role="group" aria-label={t("Severity", "Schweregrad")}>
              {([
                { value: null, label: t("All", "Alle") },
                { value: "critical", label: "Critical" },
                { value: "high", label: "High" },
                { value: "medium", label: "Medium" },
                { value: "low", label: "Low" },
              ] as const).map(({ value, label }) => (
                <button
                  key={label}
                  type="button"
                  className={`scans-segment${value ? ` sev-${value}` : ""}`}
                  aria-pressed={findingsSeverity === value}
                  onClick={() => { setFindingsSeverity(value); setFindingsOffset(0); }}
                >
                  {label}
                </button>
              ))}
            </div>
            <select
              className="scans-select"
              aria-label={t("Filter by target", "Nach Ziel filtern")}
              value={findingsTargetId || ""}
              onChange={e => { setFindingsTargetId(e.target.value || null); setFindingsOffset(0); }}
            >
              <option value="">{t("All targets", "Alle Ziele")}</option>
              {targets.map(tgt => (
                <option key={tgt.id} value={tgt.id}>{tgt.name}</option>
              ))}
            </select>
            <span className="scans-count">
              {globalFindingsTotal.toLocaleString()} {t("findings", "Funde")}
            </span>
          </div>

          {findingsLoading ? (
            <div className="table-scroll">
              <table className="scans-table">
                <thead>
                  <tr>
                    {[t("Vulnerability", "Schwachstelle"), t("Severity", "Schweregrad"), "CVSS", t("Package", "Paket"), t("Version", "Version"), t("Fix", "Fix"), t("Scanners", "Scanner"), t("Targets", "Ziele")].map(label => (
                      <th key={label} scope="col">{label}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {Array.from({ length: 10 }).map((_, i) => (
                    <tr key={i}>
                      {Array.from({ length: 8 }).map((_, j) => (
                        <td key={j}>
                          <SkeletonBlock height={16} width={j === 0 ? "80%" : j === 2 ? "40px" : j === 7 ? "30px" : "60%"} radius={4} />
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : globalFindings.length === 0 ? (
            <EmptyState
              title={findingsSearch || findingsSeverity || findingsTargetId
                ? t("No findings match your filters.", "Keine Funde entsprechen Ihren Filtern.")
                : t("No findings from latest scans.", "Keine Funde aus den letzten Scans.")}
            />
          ) : (
            <>
              <div className="table-scroll">
                <table className="scans-table scans-table--pin">
                  <thead>
                    <tr>
                      {([
                        { key: "vulnerability_id", label: t("Vulnerability", "Schwachstelle") },
                        { key: "severity", label: t("Severity", "Schweregrad") },
                        { key: "cvss_score", label: "CVSS", numeric: true },
                        { key: "package_name", label: t("Package", "Paket") },
                        { key: "package_version", label: t("Version", "Version") },
                        { key: "fix_version", label: t("Fix", "Fix") },
                        { key: null, label: t("Scanners", "Scanner") },
                        { key: "targets", label: t("Targets", "Ziele"), numeric: true },
                      ] as { key: string | null; label: string; numeric?: boolean }[]).map(({ key, label, numeric }) => (
                        key ? (
                          <SortableTh
                            key={label}
                            label={label}
                            numeric={numeric}
                            active={findingsSortBy === key}
                            dir={findingsSortOrder}
                            onSort={() => {
                              if (findingsSortBy === key) {
                                setFindingsSortOrder(prev => prev === "asc" ? "desc" : "asc");
                              } else {
                                setFindingsSortBy(key);
                                setFindingsSortOrder(key === "package_name" || key === "vulnerability_id" ? "asc" : "desc");
                              }
                              setFindingsOffset(0);
                            }}
                          />
                        ) : (
                          <th key={label} scope="col">{label}</th>
                        )
                      ))}
                      <th scope="col">{t("Links", "Links")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {globalFindings.map(f => {
                      const sev = (f.severity || "").toLowerCase();
                      const rowKey = `${f.vulnerabilityId || ""}|${f.packageName}|${f.packageVersion}`;
                      const isExpanded = expandedFindings.has(rowKey);
                      const pkgType = f.packageType || "";
                      const packagePathClean = f.packagePath
                        ? f.packagePath.replace(/^\/tmp\/hecate-(?:scan|upload)-[^/]+\//, "")
                        : "";
                      return (
                        <React.Fragment key={rowKey}>
                          <tr
                            className={`scans-row-toggle${isExpanded ? " is-expanded" : ""}`}
                            onClick={() => setExpandedFindings(prev => { const next = new Set(prev); if (next.has(rowKey)) next.delete(rowKey); else next.add(rowKey); return next; })}
                          >
                            <td className="scans-cell-strong scans-nowrap">
                              {f.vulnerabilityId ? (
                                <Link to={`/vulnerability/${encodeURIComponent(f.vulnerabilityId)}`} onClick={e => e.stopPropagation()} className="row-link mono">
                                  {f.vulnerabilityId}
                                </Link>
                              ) : (
                                <span className="muted">{f.title || <NotAvailable />}</span>
                              )}
                            </td>
                            <td><SeverityTag severity={sev || undefined} /></td>
                            <td className="scans-num">
                              {f.cvssScore != null ? f.cvssScore.toFixed(1) : <NotAvailable />}
                            </td>
                            <td className="scans-cell-package">
                              {/* Keyboard route to the row's expansion: the click bubbles to the row. */}
                              <button
                                type="button"
                                className="scans-row-expand mono"
                                aria-expanded={isExpanded}
                                title={t("Click to show details", "Klicken für Details")}
                              >
                                {f.packageName || "n/a"}
                              </button>
                            </td>
                            <td className="mono scans-muted scans-nowrap">{f.packageVersion}</td>
                            <td className="mono">
                              {f.fixVersion ? <span className="scans-truncate" title={f.fixVersion}>{f.fixVersion}</span> : <NotAvailable />}
                            </td>
                            <td className="scans-small scans-muted scans-cell-tools">{f.scanners.join(", ")}</td>
                            <td className="scans-num">{f.targets.length}</td>
                            <td className="scans-cell-links" onClick={e => e.stopPropagation()}>
                              <PackageLinks name={f.packageName} version={f.packageVersion} type={pkgType} />
                            </td>
                          </tr>
                          {isExpanded && (
                            <tr className="scans-detail-row">
                              <td colSpan={9}>
                                <div className="scans-detail">
                                  <dl className="scans-detail-list">
                                    {packagePathClean && (
                                      <>
                                        <dt>{t("Source", "Quelle")}</dt>
                                        <dd className="mono">{packagePathClean}</dd>
                                      </>
                                    )}
                                    {pkgType && (
                                      <>
                                        <dt>{t("Type", "Typ")}</dt>
                                        <dd>{TYPE_ALIASES[pkgType] || pkgType}</dd>
                                      </>
                                    )}
                                    {f.cvssScore != null && (
                                      <>
                                        <dt>CVSS</dt>
                                        <dd>{f.cvssScore.toFixed(1)}</dd>
                                      </>
                                    )}
                                    {f.title && (
                                      <>
                                        <dt>{t("Title", "Titel")}</dt>
                                        <dd>{f.title}</dd>
                                      </>
                                    )}
                                    {(f.urls ?? []).length > 0 && (
                                      <>
                                        <dt>{t("References", "Referenzen")}</dt>
                                        <dd className="link-list">
                                          {(f.urls ?? []).slice(0, 5).map((url, i) => {
                                            let host = url;
                                            try { host = new URL(url).hostname.replace(/^www\./, ""); } catch { /* keep raw */ }
                                            return (
                                              <a key={i} href={safeHref(url)} target="_blank" rel="noopener noreferrer" onClick={e => e.stopPropagation()}>
                                                {host}
                                              </a>
                                            );
                                          })}
                                          {(f.urls ?? []).length > 5 && (
                                            <span className="muted">+{(f.urls ?? []).length - 5}</span>
                                          )}
                                        </dd>
                                      </>
                                    )}
                                  </dl>
                                  <FoundInTargets refs={f.targets} targets={targets} />
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
                <Pager
                  prevDisabled={findingsOffset === 0}
                  nextDisabled={findingsOffset + findingsLimit >= globalFindingsTotal}
                  onPrev={() => setFindingsOffset(Math.max(0, findingsOffset - findingsLimit))}
                  onNext={() => setFindingsOffset(findingsOffset + findingsLimit)}
                >
                  {Math.floor(findingsOffset / findingsLimit) + 1} / {Math.ceil(globalFindingsTotal / findingsLimit)}
                </Pager>
              )}
            </>
          )}
        </div>
      )}

      {/* Global Security Alerts tab */}
      {tab === "alerts" && (
        <div>
          {/* Filters */}
          <div className="filter-row">
            <input
              type="text"
              className="scans-filter-search"
              placeholder={t("Search package, rule, or text…", "Paket, Regel oder Text suchen…")}
              aria-label={t("Search alerts", "Warnungen suchen")}
              value={alertsSearch}
              onChange={e => { setAlertsSearch(e.target.value); setAlertsOffset(0); }}
            />
            <select
              className="scans-select"
              aria-label={t("Filter by severity", "Nach Schweregrad filtern")}
              value={alertsSeverity ?? ""}
              onChange={e => { setAlertsSeverity(e.target.value || null); setAlertsOffset(0); }}
            >
              <option value="">{t("All severities", "Alle Schweregrade")}</option>
              <option value="critical">critical</option>
              <option value="high">high</option>
              <option value="medium">medium</option>
              <option value="low">low</option>
            </select>
            <select
              className="scans-select"
              aria-label={t("Filter by category", "Nach Kategorie filtern")}
              value={alertsCategory ?? ""}
              onChange={e => { setAlertsCategory(e.target.value || null); setAlertsOffset(0); }}
            >
              <option value="">{t("All categories", "Alle Kategorien")}</option>
              {/* Categories from scanner/app/malware_detector/rules.py. Keep in sync
                  when new categories are added. Unknown values still filter correctly
                  via exact data_source match. */}
              {[
                "install_hook",
                "suspicious_api",
                "exfiltration",
                "obfuscation",
                "unicode_obfuscation",
                "typosquatting",
                "pth_backdoor",
                "cicd",
                "persistence",
                "kubernetes",
                "worm",
                "ai_abuse",
                "sandbox_evasion",
                "known_compromised",
              ].map(cat => (
                <option key={cat} value={cat}>{cat.replace(/_/g, " ")}</option>
              ))}
            </select>
            <select
              className="scans-select"
              aria-label={t("Filter by target", "Nach Ziel filtern")}
              value={alertsTargetId ?? ""}
              onChange={e => { setAlertsTargetId(e.target.value || null); setAlertsOffset(0); }}
            >
              <option value="">{t("All targets", "Alle Ziele")}</option>
              {targets.map(tgt => (
                <option key={tgt.id} value={tgt.id}>{tgt.name || tgt.id}</option>
              ))}
            </select>
          </div>

          {alertsLoading ? (
            <div className="scans-skeleton-rows">
              {Array.from({ length: 8 }).map((_, i) => (
                <SkeletonBlock key={i} height={48} radius={4} />
              ))}
            </div>
          ) : globalAlerts.length === 0 ? (
            <EmptyState title={t("No security alerts from current scans.", "Keine Sicherheitswarnungen aus aktuellen Scans.")} />
          ) : (
            <>
              <div className="table-scroll">
                <table className="scans-table scans-table--pin">
                  <thead>
                    <tr>
                      {([
                        { col: "title", label: t("Rule", "Regel") },
                        { col: "severity", label: t("Severity", "Schweregrad") },
                        { col: "package_name", label: t("Package", "Paket") },
                        { col: "category", label: t("Category", "Kategorie") },
                        { col: "targets", label: t("Targets", "Ziele") },
                      ] as const).map(h => (
                        <SortableTh
                          key={h.col}
                          label={h.label}
                          active={alertsSortBy === h.col}
                          dir={alertsSortOrder}
                          onSort={() => {
                            if (alertsSortBy === h.col) {
                              setAlertsSortOrder(prev => prev === "asc" ? "desc" : "asc");
                            } else {
                              setAlertsSortBy(h.col);
                              setAlertsSortOrder("desc");
                            }
                            setAlertsOffset(0);
                          }}
                        />
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {globalAlerts.map((a, idx) => {
                      const sev = (a.severity || "").toLowerCase();
                      return (
                        <tr key={`${a.title}|${a.packageName}|${a.packageVersion}|${idx}`}>
                          <td className="scans-cell-rule">
                            <div className="scans-cell-strong">{a.title || <NotAvailable />}</div>
                            {a.description && (
                              <div className="scans-sub scans-truncate-line">
                                {a.description.split("\n")[0]}
                              </div>
                            )}
                          </td>
                          <td><SeverityTag severity={sev || undefined} /></td>
                          <td>
                            <div className="mono">{a.packageName}</div>
                            {a.packageVersion && (
                              <div className="scans-sub mono">@ {a.packageVersion}</div>
                            )}
                          </td>
                          <td>
                            {a.category ? <span className="tag">{a.category.replace(/_/g, " ")}</span> : <NotAvailable />}
                          </td>
                          <td>
                            <div className="scans-target-links">
                              {a.targets.slice(0, 3).map((t2, i2) => (
                                <Link key={`${t2.scanId}-${i2}`} to={`/scans/${t2.scanId}`} className="row-link">
                                  {targets.find(tt => tt.id === t2.targetId)?.name || t2.targetId}
                                </Link>
                              ))}
                              {a.targets.length > 3 && (
                                <span className="scans-sub">
                                  +{a.targets.length - 3} {t("more", "weitere")}
                                </span>
                              )}
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              {/* Pagination */}
              {globalAlertsTotal > alertsLimit && (
                <Pager
                  prevDisabled={alertsOffset === 0}
                  nextDisabled={alertsOffset + alertsLimit >= globalAlertsTotal}
                  onPrev={() => setAlertsOffset(prev => Math.max(0, prev - alertsLimit))}
                  onNext={() => setAlertsOffset(prev => prev + alertsLimit)}
                >
                  {alertsOffset + 1}-{Math.min(alertsOffset + alertsLimit, globalAlertsTotal)} / {globalAlertsTotal}
                </Pager>
              )}
            </>
          )}
        </div>
      )}

      {/* SBOM tab */}
      {tab === "sbom" && (
        <div>
          {/* SBOM import */}
          {!sbomImportResult ? (
            <div
              className="scans-import"
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
            >
              <div className="scans-import-text">
                <h2 className="scans-import-title">{t("Import SBOM", "SBOM importieren")}</h2>
                {sbomImportFile ? (
                  <div className="scans-import-file">
                    <span className="chip scans-import-filename">{sbomImportFile.name}</span>
                    <IconButton
                      label={t("Remove file", "Datei entfernen")}
                      onClick={() => { setSbomImportFile(null); setSbomImportError(null); }}
                    >
                      <LuX aria-hidden="true" />
                    </IconButton>
                  </div>
                ) : (
                  <label className="scans-import-browse">
                    {t("Drop a CycloneDX / SPDX JSON file here or ", "CycloneDX / SPDX JSON-Datei hierher ziehen oder ")}
                    <span className="scans-import-link">{t("browse", "durchsuchen")}</span>
                    <input
                      type="file"
                      accept=".json,application/json"
                      className="visually-hidden"
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
                  <p className="scans-error" role="alert">{sbomImportError}</p>
                )}
              </div>
              <div className="scans-import-controls">
                <select
                  aria-label={t("SBOM format", "SBOM-Format")}
                  value={sbomImportFormat}
                  onChange={e => setSbomImportFormat(e.target.value)}
                >
                  <option value="">{t("Auto-detect", "Auto")}</option>
                  <option value="cyclonedx-json">CycloneDX</option>
                  <option value="spdx-json">SPDX</option>
                </select>
                <input
                  type="text"
                  className="scans-import-name"
                  aria-label={t("Target name (optional)", "Zielname (opt.)")}
                  value={sbomImportTargetName}
                  onChange={e => setSbomImportTargetName(e.target.value)}
                  placeholder={t("Target name (optional)", "Zielname (opt.)")}
                />
                <button
                  type="button"
                  className="btn"
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
                >
                  {sbomImportLoading ? t("Importing...", "Importiert...") : t("Import", "Importieren")}
                </button>
              </div>
            </div>
          ) : (
            <div className="scans-import scans-import--done">
              <div className="scans-import-summary">
                <span className="scans-outcome--ok scans-import-title">
                  {t("SBOM imported!", "SBOM importiert!")}
                </span>
                <span className="scans-muted">
                  {sbomImportResult.sbomComponentCount} {t("components", "Komponenten")}
                </span>
                <span className="scans-muted">
                  {sbomImportResult.findingsCount} {t("findings", "Funde")}
                </span>
              </div>
              <Link to={`/scans/${sbomImportResult.scanId}`} className="btn">
                {t("View details", "Details")}
              </Link>
              <IconButton
                label={t("Dismiss", "Schließen")}
                onClick={() => { setSbomImportResult(null); setSbomImportFile(null); setSbomImportError(null); }}
              >
                <LuX aria-hidden="true" />
              </IconButton>
            </div>
          )}

          {/* Summary: global facets across all components, not just the loaded page */}
          {sbomFacets && (sbomFacets.ecosystems.length > 0 || sbomFacets.licenses.length > 0 || sbomFacets.types.length > 0) && (
            <div className="scans-facets">
              {[
                { title: t("Ecosystems", "Ökosysteme"), data: sbomFacets.ecosystems },
                { title: t("Licenses", "Lizenzen"), data: sbomFacets.licenses },
                { title: t("Types", "Typen"), data: sbomFacets.types },
              ].map(card => (
                <div key={card.title} className="scans-facet">
                  <h2 className="scans-facet-title">{card.title}</h2>
                  <ul className="scans-facet-list">
                    {card.data.slice(0, 5).map(entry => (
                      <li key={entry.name}>
                        <span className="scans-facet-name">{entry.name}</span>
                        <span className="scans-facet-count">{entry.count}</span>
                      </li>
                    ))}
                  </ul>
                  {card.data.length > 5 && (
                    <p className="scans-sub">
                      +{card.data.length - 5} {t("more", "weitere")}
                    </p>
                  )}
                </div>
              ))}
            </div>
          )}

          {/* Filter bar */}
          <div className="filter-row">
            <input
              type="text"
              className="scans-filter-search"
              value={sbomSearch}
              onChange={e => { setSbomSearch(e.target.value); setSbomOffset(0); }}
              placeholder={t("Search by name, type, license, purl...", "Nach Name, Typ, Lizenz, PURL suchen...")}
              aria-label={t("Search components", "Komponenten suchen")}
            />
            <select
              className="scans-select"
              aria-label={t("Filter by type", "Nach Typ filtern")}
              value={sbomType || ""}
              onChange={e => { setSbomType(e.target.value || null); setSbomOffset(0); }}
            >
              <option value="">{t("All types", "Alle Typen")}</option>
              {(() => {
                // Merge CycloneDX canonical types with whatever ecosystem labels
                // the scanners emitted (pnpm, npm, yarn, gobinary, rust-crate, …),
                // so the filter reflects what's actually in the data.
                const baseline = ["library", "application", "framework", "container", "firmware", "file", "operating-system"];
                const facetTypes = (sbomFacets?.types ?? []).map(f => f.name).filter(Boolean);
                const merged = Array.from(new Set<string>([
                  ...baseline,
                  ...facetTypes,
                  ...(sbomType ? [sbomType] : []),
                ]));
                merged.sort((a, b) => a.localeCompare(b));
                return merged.map(tp => (
                  <option key={tp} value={tp}>{tp}</option>
                ));
              })()}
            </select>
            <select
              className="scans-select"
              aria-label={t("Filter by target", "Nach Ziel filtern")}
              value={sbomTargetId || ""}
              onChange={e => { setSbomTargetId(e.target.value || null); setSbomOffset(0); }}
            >
              <option value="">{t("All targets", "Alle Ziele")}</option>
              {targets.map(tgt => (
                <option key={tgt.id} value={tgt.id}>{tgt.name}</option>
              ))}
            </select>
            <select
              className="scans-select"
              aria-label={t("Filter by provenance", "Nach Herkunft filtern")}
              value={sbomFilterProvenance || ""}
              onChange={e => setSbomFilterProvenance(e.target.value || null)}
            >
              <option value="">{t("All provenance", "Alle Provenienz")}</option>
              <option value="verified">{t("Verified", "Verifiziert")}</option>
              <option value="unverified">{t("Unverified", "Nicht verifiziert")}</option>
              <option value="unknown">{t("Unknown", "Unbekannt")}</option>
            </select>
            <span className="scans-count">
              {filteredSortedSbom.length !== sbomComponents.length
                ? `${filteredSortedSbom.length} / ${sbomTotal.toLocaleString()}`
                : sbomTotal.toLocaleString()}{" "}
              {t("components", "Komponenten")}
            </span>
          </div>

          {sbomLoading ? (
            <div className="table-scroll">
              <table className="scans-table">
                <thead>
                  <tr>
                    {[t("Component", "Komponente"), t("Version", "Version"), t("Type", "Typ"), t("Provenance", "Herkunft"), t("Licenses", "Lizenzen"), t("Targets", "Ziele")].map(label => (
                      <th key={label} scope="col">{label}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {Array.from({ length: 10 }).map((_, i) => (
                    <tr key={i}>
                      {Array.from({ length: 6 }).map((_, j) => (
                        <td key={j}>
                          <SkeletonBlock height={16} width={j === 0 ? "80%" : j === 3 ? "30px" : j === 5 ? "30px" : "60%"} radius={4} />
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : sbomComponents.length === 0 ? (
            <EmptyState
              title={sbomSearch || sbomType || sbomTargetId
                ? t("No components match your filters.", "Keine Komponenten entsprechen Ihren Filtern.")
                : t("No SBOM components from latest scans.", "Keine SBOM-Komponenten aus den letzten Scans.")}
            />
          ) : (
            <>
              <div className="table-scroll">
                <table className="scans-table scans-table--pin">
                  <thead>
                    <tr>
                      {([
                        { col: "name", label: t("Component", "Komponente") },
                        { col: "version", label: t("Version", "Version") },
                        { col: "type", label: t("Type", "Typ") },
                        { col: "provenance", label: t("Provenance", "Herkunft") },
                        { col: "licenses", label: t("Licenses", "Lizenzen") },
                        { col: "targets", label: t("Targets", "Ziele"), numeric: true },
                      ] as { col: string; label: string; numeric?: boolean }[]).map(h => (
                        <SortableTh
                          key={h.col}
                          label={h.label}
                          numeric={h.numeric}
                          active={sbomSort.col === h.col}
                          dir={sbomSort.dir}
                          onSort={() => setSbomSort(prev => ({ col: h.col, dir: prev.col === h.col && prev.dir === "asc" ? "desc" : "asc" }))}
                        />
                      ))}
                      <th scope="col">{t("Links", "Links")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredSortedSbom.map(c => {
                      const rowKey = `${c.name}|${c.version}`;
                      const isExpanded = expandedSboms.has(rowKey);
                      return (
                        <React.Fragment key={rowKey}>
                          <tr
                            className={`scans-row-toggle${isExpanded ? " is-expanded" : ""}`}
                            onClick={() => setExpandedSboms(prev => { const next = new Set(prev); if (next.has(rowKey)) next.delete(rowKey); else next.add(rowKey); return next; })}
                          >
                            <td className="scans-cell-component">
                              {/* Keyboard route to the row's expansion: the click bubbles to the row. */}
                              <button type="button" className="scans-row-expand mono" aria-expanded={isExpanded}>
                                {c.name}
                              </button>
                              {c.purl && (
                                <div className="scans-sub mono scans-purl">{c.purl}</div>
                              )}
                            </td>
                            <td className="mono">{c.version || <NotAvailable />}</td>
                            <td><span className="tag">{c.type}</span></td>
                            <td>
                              {c.provenanceVerified === true && <span className="scans-outcome--ok">{t("Verified", "Verifiziert")}</span>}
                              {c.provenanceVerified === false && <span className="scans-outcome--neutral">{t("Unverified", "Nicht verifiziert")}</span>}
                              {c.provenanceVerified == null && <NotAvailable />}
                            </td>
                            <td className="scans-small scans-muted">
                              {c.licenses.length > 0 ? c.licenses.join(", ") : <NotAvailable />}
                            </td>
                            <td className="scans-num">{c.targets.length}</td>
                            <td className="scans-cell-links" onClick={e => e.stopPropagation()}>
                              <PackageLinks name={c.name} version={c.version} type={c.type} purl={c.purl} />
                            </td>
                          </tr>
                          {isExpanded && (
                            <tr className="scans-detail-row">
                              <td colSpan={7}>
                                <div className="scans-detail">
                                  <FoundInTargets refs={c.targets} targets={targets} />
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
                <Pager
                  prevDisabled={sbomOffset === 0}
                  nextDisabled={sbomOffset + sbomLimit >= sbomTotal}
                  onPrev={() => setSbomOffset(Math.max(0, sbomOffset - sbomLimit))}
                  onNext={() => setSbomOffset(sbomOffset + sbomLimit)}
                >
                  {Math.floor(sbomOffset / sbomLimit) + 1} / {Math.ceil(sbomTotal / sbomLimit)}
                </Pager>
              )}
            </>
          )}
        </div>
      )}

      {/* Manual scan dialog */}
      {newScanModalOpen && (
        <div className="scans-modal scans-modal--top" onClick={() => setNewScanModalOpen(false)}>
          <div
            className="scans-dialog scans-dialog--wide"
            role="dialog"
            aria-modal="true"
            aria-labelledby="scans-new-scan-title"
            onClick={e => e.stopPropagation()}
          >
            <div className="scans-dialog-head">
              <h2 id="scans-new-scan-title">{t("New scan", "Neuer Scan")}</h2>
              <IconButton label={t("Close", "Schließen")} onClick={() => setNewScanModalOpen(false)}>
                <LuX aria-hidden="true" />
              </IconButton>
            </div>
            <form onSubmit={handleSubmitScan} className="scans-form">
              <fieldset className="scans-fieldset">
                <legend className="scans-label">{t("Type", "Typ")}</legend>
                <div className="scans-radios">
                  <label className="scans-check">
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
                    {t("Container image", "Container-Image")}
                  </label>
                  <label className="scans-check">
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
                    {t("Source repository", "Quellcode-Repository")}
                  </label>
                </div>
              </fieldset>

              {scanType === "source_repo" && (
                <fieldset className="scans-fieldset">
                  <legend className="scans-label">{t("Source input", "Quell-Input")}</legend>
                  <div className="scans-radios">
                    <label className="scans-check">
                      <input
                        type="radio"
                        name="sourceRepoInputMode"
                        value="url"
                        checked={sourceRepoInputMode === "url"}
                        onChange={() => setSourceRepoInputMode("url")}
                      />
                      {t("Repository URL", "Repository-URL")}
                    </label>
                    <label className="scans-check">
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
                </fieldset>
              )}

              {(scanType === "container_image" || (scanType === "source_repo" && sourceRepoInputMode === "url")) && (
                <div>
                  <label className="scans-label" htmlFor="scans-new-scan-target">
                    {scanType === "container_image"
                      ? t("Image reference", "Image-Referenz")
                      : t("Repository URL", "Repository-URL")}
                  </label>
                  <input
                    id="scans-new-scan-target"
                    type="text"
                    className="scans-input"
                    value={scanTarget}
                    onChange={e => setScanTarget(e.target.value)}
                    placeholder={scanType === "container_image" ? "github.com/hecate/hecate-backend:latest" : "https://github.com/org/repo"}
                    required={scanType === "container_image" || sourceRepoInputMode === "url"}
                  />
                </div>
              )}

              {scanType === "source_repo" && sourceRepoInputMode === "zip" && (
                <>
                  <div>
                    <label className="scans-label" htmlFor="scans-new-scan-archive">{t("Repository ZIP", "Repository-ZIP")}</label>
                    <input
                      id="scans-new-scan-archive"
                      type="file"
                      className="scans-input"
                      accept=".zip,application/zip"
                      onChange={e => setSourceArchiveFile(e.target.files?.[0] || null)}
                      required
                    />
                    <p className="scans-sub scans-field-hint">
                      {t(
                        "Uploads a source archive for a one-time scan.",
                        "Lädt ein Quellcode-Archiv für einen einmaligen Scan hoch."
                      )}
                    </p>
                  </div>
                  <div>
                    <label className="scans-label" htmlFor="scans-new-scan-name">{t("Scan name (optional)", "Scan-Name (optional)")}</label>
                    <input
                      id="scans-new-scan-name"
                      type="text"
                      className="scans-input"
                      value={sourceArchiveTargetName}
                      onChange={e => setSourceArchiveTargetName(e.target.value)}
                      placeholder={t("Derived from filename", "Wird aus Dateinamen abgeleitet")}
                    />
                  </div>
                </>
              )}

              <fieldset className="scans-fieldset">
                <legend className="scans-label">{t("Scanners", "Scanner")}</legend>
                <ScannerCheckboxGroup
                  scanType={scanType}
                  selected={scanners}
                  onToggle={handleScannerToggle}
                />
              </fieldset>

              <div className="scans-dialog-actions">
                <button type="submit" className="btn-primary" disabled={isSubmitDisabled}>
                  {scanning ? t("Scanning...", "Scannt...") : t("Start scan", "Scan starten")}
                </button>
              </div>
            </form>

            {scanError && (
              <p className="scans-error scans-error--block" role="alert">{scanError}</p>
            )}
          </div>
        </div>
      )}

      {/* Licenses tab */}
      {tab === "licenses" && (
        <div>
          <div className="filter-row">
            <input
              type="text"
              className="scans-filter-search"
              value={licenseSearch}
              onChange={e => setLicenseSearch(e.target.value)}
              placeholder={t("Search licenses...", "Lizenzen suchen...")}
              aria-label={t("Search licenses", "Lizenzen suchen")}
            />
            <span className="scans-count">
              {licenseOverviewTotal} {t("licenses", "Lizenzen")}
            </span>
          </div>

          {licensesLoading ? (
            <div className="scans-skeleton-rows">
              {Array.from({ length: 8 }).map((_, i) => (
                <SkeletonBlock key={i} height={40} radius={4} />
              ))}
            </div>
          ) : licenseOverview.length === 0 ? (
            <EmptyState title={t("No license data available. Run a scan with SBOM generation first.", "Keine Lizenzdaten verfügbar. Führen Sie zuerst einen Scan mit SBOM-Generierung durch.")} />
          ) : (
            <div className="table-scroll">
              <table className="scans-table scans-table--pin">
                <thead>
                  <tr>
                    <th scope="col">{t("License", "Lizenz")}</th>
                    <th scope="col" className="scans-num">{t("Components", "Komponenten")}</th>
                    <th scope="col">{t("Used by", "Verwendet von")}</th>
                  </tr>
                </thead>
                <tbody>
                  {licenseOverview
                    .filter(item => !licenseSearch || item.licenseId.toLowerCase().includes(licenseSearch.toLowerCase()))
                    .map(item => (
                      <tr key={item.licenseId}>
                        <td className="scans-cell-strong scans-cell-license">{item.licenseId}</td>
                        <td className="scans-num">{item.componentCount}</td>
                        <td>
                          <div className="scans-used-by">
                            {item.components.slice(0, 8).map((c, i) => (
                              <span key={i} className="mono">{c.name}@{c.version}</span>
                            ))}
                            {item.componentCount > 8 && (
                              <span className="scans-sub">
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

      {/* Scanner tab */}
      {tab === "scanner" && (
        <div>
          {loading && <SkeletonBlock height={200} radius={4} />}
          {!loading && !scannerStats && (
            <ErrorState title={t("Could not reach scanner.", "Scanner nicht erreichbar.")} />
          )}
          {!loading && scannerStats && !scannerStats.error && (
            <div className="scans-scanner">
              <div className="scans-scanner-head">
                {/* Active scans indicator */}
                <div className="scans-active">
                  <span className={`scans-active-count${scannerStats.activeScans > 0 ? " is-active" : ""}`}>
                    {scannerStats.activeScans}
                  </span>
                  <div>
                    <p className="scans-active-title">
                      {scannerStats.activeScans > 0
                        ? t(`${scannerStats.activeScans} scanner process${scannerStats.activeScans > 1 ? "es" : ""} running`, `${scannerStats.activeScans} Scanner-Prozess${scannerStats.activeScans > 1 ? "e" : ""} aktiv`)
                        : t("Scanner idle", "Scanner inaktiv")}
                    </p>
                    <p className="scans-sub">
                      {t("Each target scan runs multiple scanner processes (trivy, grype, syft, ...)", "Jeder Ziel-Scan startet mehrere Scanner-Prozesse (trivy, grype, syft, ...)")}
                    </p>
                  </div>
                </div>

                {/* Time range selector */}
                <div className="scans-range">
                  <span className="scans-sub" id="scans-range-label">{t("Range", "Zeitraum")}</span>
                  <div className="scans-segments" role="group" aria-labelledby="scans-range-label">
                    {[5, 15, 30, 60].map(m => (
                      <button
                        key={m}
                        type="button"
                        className="scans-segment"
                        aria-pressed={chartMinutes === m}
                        onClick={() => setChartMinutes(m)}
                      >
                        {m} min
                      </button>
                    ))}
                  </div>
                </div>
              </div>

              {/* Live resource charts */}
              {scannerStats.stale && (
                <p className="scans-info">
                  <LuInfo aria-hidden="true" />
                  <span>
                    {t(
                      `Cached values shown: sidecar didn't respond in time (last update ${scannerStats.staleSeconds ?? 0}s ago).`,
                      `Zwischengespeicherte Werte: Sidecar hat nicht rechtzeitig geantwortet (letztes Update vor ${scannerStats.staleSeconds ?? 0}s).`,
                    )}
                  </span>
                </p>
              )}
              <div className="scans-charts">
                <LiveChart
                  label={t("Container Memory", "Container-Speicher")}
                  data={memHistory}
                  max={scannerStats.memoryLimitBytes}
                  current={scannerStats.memoryUsedBytes}
                  color="var(--color-ink-2)"
                  minutes={chartMinutes}
                />
                <LiveChart
                  label={t("Temp Disk (/tmp)", "Temp-Datenträger (/tmp)")}
                  data={diskHistory}
                  max={scannerStats.tmpDiskTotalBytes}
                  current={scannerStats.tmpDiskUsedBytes}
                  color="var(--color-ink-2)"
                  minutes={chartMinutes}
                />
              </div>

              {/* Auto-scan change-detection diagnostics. Helps debug why an
                  auto-scan-enabled target isn't being scanned: each row
                  shows the most recent /check probe: when it ran, what
                  fingerprint the scanner returned, the verdict the
                  scheduler reached, and the error if /check failed.
                  Verdict buttons are clickable to force-rerun the probe. */}
              <AutoScanDiagnosticsTable
                targets={targets}
                onTriggerCheck={async (targetId) => {
                  const refreshed = await triggerTargetCheck(targetId);
                  setTargets(prev => prev.map(t => t.id === targetId ? refreshed : t));
                }}
              />
            </div>
          )}
          {!loading && scannerStats?.error && (
            <ErrorState title={scannerStats.error} />
          )}
        </div>
      )}

      {/* Confirmation modal */}
      {confirmModal && (
        <div className="scans-modal" onClick={() => setConfirmModal(null)}>
          <div
            className="scans-dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="scans-confirm-title"
            onClick={e => e.stopPropagation()}
          >
            <h2 id="scans-confirm-title" className="scans-dialog-title">{confirmModal.title}</h2>
            <p className="scans-dialog-text">{confirmModal.message}</p>
            <div className="scans-dialog-actions">
              <button type="button" className="btn" onClick={() => setConfirmModal(null)}>
                {t("Cancel", "Abbrechen")}
              </button>
              <button type="button" className="btn scans-btn-danger" onClick={confirmModal.onConfirm}>
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

/** The placeholder for a value the data does not have. */
const NotAvailable = () => <span className="scans-na">n/a</span>;

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

const SortableTh = ({ label, active, dir, numeric, onSort }: { label: string; active: boolean; dir: "asc" | "desc"; numeric?: boolean; onSort: () => void }) => (
  <th
    scope="col"
    className={numeric ? "scans-num" : undefined}
    aria-sort={active ? (dir === "asc" ? "ascending" : "descending") : undefined}
  >
    <button type="button" className="scans-sort" onClick={onSort}>
      {label}
      {active && (dir === "asc" ? <LuArrowUp aria-hidden="true" /> : <LuArrowDown aria-hidden="true" />)}
    </button>
  </th>
);

const Pager = ({ prevDisabled, nextDisabled, onPrev, onNext, children }: { prevDisabled: boolean; nextDisabled: boolean; onPrev: () => void; onNext: () => void; children: React.ReactNode }) => {
  const { t } = useI18n();
  return (
    <div className="scans-pager">
      <button type="button" className="btn" disabled={prevDisabled} onClick={onPrev}>
        {t("Previous", "Zurück")}
      </button>
      <span className="scans-pager-position">{children}</span>
      <button type="button" className="btn" disabled={nextDisabled} onClick={onNext}>
        {t("Next", "Weiter")}
      </button>
    </div>
  );
};

const PackageLinks = ({ name, version, type, purl }: { name: string; version: string; type: string; purl?: string | null }) => {
  const depsUrl = buildDepsDevUrl(name, version, type, purl);
  const snykUrl = buildSnykUrl(name, version, type, purl);
  const registryLink = buildRegistryUrl(name, version, type, purl);
  const socketUrl = buildSocketUrl(name, version, type, purl);
  const aikidoUrl = buildAikidoUrl(name, version, type, purl);
  const bundlephobiaUrl = buildBundlephobiaUrl(name, version, type, purl);
  const npmGraphUrl = buildNpmGraphUrl(name, version, type, purl);
  const hasAny = depsUrl || snykUrl || registryLink || socketUrl || aikidoUrl || bundlephobiaUrl || npmGraphUrl;
  if (!hasAny) return null;
  return (
    <div className="link-list">
      {depsUrl && <a href={depsUrl} target="_blank" rel="noopener noreferrer" title="deps.dev">deps.dev</a>}
      {snykUrl && <a href={snykUrl} target="_blank" rel="noopener noreferrer" title="Snyk">Snyk</a>}
      {registryLink && <a href={registryLink.url} target="_blank" rel="noopener noreferrer" title={registryLink.label}>{registryLink.label}</a>}
      {socketUrl && <a href={socketUrl} target="_blank" rel="noopener noreferrer" title="socket.dev">socket.dev</a>}
      {aikidoUrl && <a href={aikidoUrl} target="_blank" rel="noopener noreferrer" title="intel.aikido.dev">aikido</a>}
      {bundlephobiaUrl && <a href={bundlephobiaUrl} target="_blank" rel="noopener noreferrer" title="bundlephobia">bundlephobia</a>}
      {npmGraphUrl && <a href={npmGraphUrl} target="_blank" rel="noopener noreferrer" title="npmgraph">npmgraph</a>}
    </div>
  );
};

const FoundInTargets = ({ refs, targets }: { refs: { targetId: string; scanId: string }[]; targets: ScanTarget[] }) => {
  const { t } = useI18n();
  return (
    <div>
      <p className="scans-detail-heading">{t("Found in targets:", "Gefunden in Zielen:")}</p>
      <div className="scans-target-links">
        {refs.map(tgt => {
          const tgtName = targets.find(tt => tt.id === tgt.targetId)?.name || tgt.targetId;
          return (
            <Link
              key={`${tgt.targetId}-${tgt.scanId}`}
              to={`/scans/${encodeURIComponent(tgt.scanId)}`}
              onClick={e => e.stopPropagation()}
              className="row-link"
            >
              {tgtName}
            </Link>
          );
        })}
      </div>
    </div>
  );
};

const TargetRow = ({ target, colSpan, groupSuggestions = [], onDelete, onRescan, onToggleAutoScan, onUpdateScanners, onUpdateGroup, onFilterScans, onCancelScan }: { target: ScanTarget; colSpan: number; groupSuggestions?: string[]; onDelete: (id: string) => void; onRescan: (target: ScanTarget) => void; onToggleAutoScan: (target: ScanTarget) => void; onUpdateScanners: (targetId: string, scanners: string[]) => void; onUpdateGroup?: (targetId: string, group: string | null) => void; onFilterScans: (id: string, name: string) => void; onCancelScan?: (scanId: string) => void }) => {
  const { t } = useI18n();
  const { scaAutoScanEnabled } = useServerConfig();
  const isRunning = !!target.hasRunningScan;
  const autoScan = target.autoScan !== false; // default true
  const [editingScanners, setEditingScanners] = useState(false);
  const [selectedScanners, setSelectedScanners] = useState<string[]>([]);
  const [editingGroup, setEditingGroup] = useState(false);
  const [groupDraft, setGroupDraft] = useState<string>(target.group || "");
  const datalistId = `group-suggestions-${target.id.replace(/[^a-zA-Z0-9]/g, "-")}`;
  const isSbomImport = target.type === "sbom-import";
  const showGroupEditor = !isSbomImport && !!onUpdateGroup && editingGroup;
  const showScannerEditor = !isSbomImport && editingScanners;

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
    <>
      <tr className="scans-target-row">
        <td className="scans-cell-target">
          <div className="scans-target-title">
            <Link to={`/scans/targets/${encodeURIComponent(target.id)}`} className="row-link scans-target-name">
              {target.writePasswordSet && (
                <span className="scans-target-lock" title={t("Write-protected", "Schreibgeschützt")}>
                  <LuLock role="img" aria-label={t("Write-protected", "Schreibgeschützt")} />
                </span>
              )}
              {target.name}
            </Link>
            {isRunning && <ScanningBadge status={target.runningScanStatus} />}
          </div>
          <div className="scans-sub scans-target-meta">
            <span>{target.type === "container_image" ? "Container" : "Source"}</span>
            <span className="mono scans-target-id" title={target.id}>{target.id}</span>
          </div>
        </td>
        <td className="scans-cell-findings" data-label={t("Findings", "Ergebnisse")}>
          {target.latestSummary && <SeverityBadges summary={target.latestSummary} />}
        </td>
        <td className="scans-cell-last" data-label={t("Last scan", "Letzter Scan")}>
          <button
            type="button"
            className="scans-last"
            onClick={() => onFilterScans(target.id, target.name)}
            title={t("Show scans for this target", "Scans für dieses Ziel anzeigen")}
          >
            {target.lastScanAt && <span className="scans-nowrap">{formatDateTime(target.lastScanAt)}</span>}
            <span className="scans-last-count">{target.scanCount} {t("scans", "Scans")}</span>
          </button>
        </td>
        <td className="scans-cell-app" data-label={t("App", "App")}>
          {!isSbomImport && onUpdateGroup && (
            <div className="scans-inline-value">
              {target.group ? (
                <span>{target.group}</span>
              ) : (
                <span className="scans-muted">{t("none", "keine")}</span>
              )}
              <IconButton
                label={t("Edit group", "Gruppe bearbeiten")}
                aria-expanded={editingGroup}
                onClick={editingGroup ? cancelEditGroup : startEditingGroup}
              >
                <LuPencil aria-hidden="true" />
              </IconButton>
            </div>
          )}
        </td>
        <td className="scans-cell-scanners" data-label={t("Scanners", "Scanner")}>
          <div className="scans-inline-value">
            <span className="scans-scanner-list">{(target.scanners || []).join(", ")}</span>
            {!isSbomImport && (
              <IconButton
                label={t("Edit scanners", "Scanner bearbeiten")}
                aria-expanded={editingScanners}
                onClick={editingScanners ? () => setEditingScanners(false) : startEditing}
              >
                <LuPencil aria-hidden="true" />
              </IconButton>
            )}
          </div>
        </td>
        {scaAutoScanEnabled && (
          <td className="scans-cell-auto" data-label="Auto-Scan">
            {target.type !== "sbom-import" && (
              <button
                type="button"
                role="switch"
                aria-checked={autoScan}
                className="scans-switch"
                onClick={() => onToggleAutoScan(target)}
                title={autoScan ? t("Disable auto-scan", "Auto-Scan deaktivieren") : t("Enable auto-scan", "Auto-Scan aktivieren")}
                aria-label={autoScan ? t("Disable auto-scan", "Auto-Scan deaktivieren") : t("Enable auto-scan", "Auto-Scan aktivieren")}
              >
                <span className="scans-switch-track"><span className="scans-switch-knob" /></span>
              </button>
            )}
          </td>
        )}
        <td className="scans-cell-actions">
          <div className="scans-row-actions">
            {target.type === "sbom-import" ? null : isRunning && (target.runningScanId || target.latestScanId) && onCancelScan ? (
              <button
                type="button"
                className="btn scans-row-action"
                onClick={() => onCancelScan(target.runningScanId || target.latestScanId!)}
                title={t("Stop scan", "Scan stoppen")}
              >
                <LuSquare aria-hidden="true" />
                Stop
              </button>
            ) : (
              <button
                type="button"
                className="btn scans-row-action"
                onClick={() => onRescan(target)}
                title={t("Rescan", "Erneut scannen")}
              >
                <LuRefreshCw aria-hidden="true" />
                Scan
              </button>
            )}
            <IconButton className="scans-outline" label={t("Delete", "Löschen")} onClick={() => onDelete(target.id)}>
              <LuTrash2 aria-hidden="true" />
            </IconButton>
          </div>
        </td>
      </tr>
      {(showGroupEditor || showScannerEditor) && (
        <tr className="scans-editor-row">
          <td colSpan={colSpan}>
            <div className="well scans-editor">
              {showGroupEditor && (
                <div className="scans-editor-group">
                  <input
                    list={datalistId}
                    value={groupDraft}
                    onChange={e => setGroupDraft(e.target.value)}
                    onKeyDown={e => {
                      if (e.key === "Enter") { e.preventDefault(); saveGroup(); }
                      else if (e.key === "Escape") { e.preventDefault(); cancelEditGroup(); }
                    }}
                    placeholder={t("Application name", "Anwendungsname")}
                    aria-label={t("Application name", "Anwendungsname")}
                    autoFocus
                  />
                  <datalist id={datalistId}>
                    {groupSuggestions.map(g => <option key={g} value={g} />)}
                  </datalist>
                  <button type="button" className="btn" onClick={saveGroup}>
                    {t("Save", "Speichern")}
                  </button>
                  <button type="button" className="btn" onClick={cancelEditGroup}>
                    {t("Cancel", "Abbrechen")}
                  </button>
                </div>
              )}
              {showScannerEditor && (
                <div className="scans-editor-scanners">
                  <ScannerCheckboxGroup
                    scanType={target.type === "container_image" ? "container_image" : "source_repo"}
                    selected={selectedScanners}
                    onToggle={(id) => setSelectedScanners(prev => prev.includes(id) ? prev.filter(s => s !== id) : [...prev, id])}
                    compact
                  />
                  <div className="scans-editor-actions">
                    <button type="button" className="btn" onClick={saveScanners} disabled={selectedScanners.length === 0}>
                      {t("Save", "Speichern")}
                    </button>
                    <button type="button" className="btn" onClick={() => setEditingScanners(false)}>
                      {t("Cancel", "Abbrechen")}
                    </button>
                  </div>
                </div>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  );
};

const ScanningBadge = ({ status }: { status?: string | null }) => {
  const isPending = status === "pending";
  const label = isPending ? "Queued..." : "Scanning...";
  return <span className={`scans-running${isPending ? " is-queued" : ""}`}>{label}</span>;
};

const SourceBadge = ({ source }: { source: string }) => {
  const labels: Record<string, string> = {
    manual: "Manual",
    ci_cd: "CI/CD",
    scheduled: "Auto",
  };
  return <span className="tag">{labels[source] || source}</span>;
};

type DataPoint = { time: number; value: number };

type VerdictTone = "success" | "error" | "info" | "muted";

// Per-target auto-scan diagnostics. Renders one row per `autoScan: true`
// target with the result of the most recent `/check` probe so users can
// debug why a target isn't being auto-scanned even with the toggle on.
// Backend persists every probe result via
// ``ScanTargetRepository.update_last_check``. Verdict cells are clickable
// to force-rerun the probe out-of-band: `onTriggerCheck` is async so the
// row can show a loading state during the in-flight call.
const AutoScanDiagnosticsTable = ({
  targets,
  onTriggerCheck,
}: {
  targets: ScanTarget[];
  onTriggerCheck: (targetId: string) => Promise<void>;
}) => {
  const { t } = useI18n();
  const [pending, setPending] = useState<Set<string>>(new Set());
  const [errors, setErrors] = useState<Record<string, string>>({});
  const autoScanTargets = useMemo(
    () => targets.filter(target => target.autoScan !== false),
    [targets],
  );

  const runCheck = useCallback(async (targetId: string) => {
    setPending(prev => {
      const next = new Set(prev);
      next.add(targetId);
      return next;
    });
    setErrors(prev => {
      if (!(targetId in prev)) return prev;
      const next = { ...prev };
      delete next[targetId];
      return next;
    });
    try {
      await onTriggerCheck(targetId);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setErrors(prev => ({ ...prev, [targetId]: msg }));
    } finally {
      setPending(prev => {
        const next = new Set(prev);
        next.delete(targetId);
        return next;
      });
    }
  }, [onTriggerCheck]);

  if (autoScanTargets.length === 0) {
    return (
      <section>
        <h2 className="scans-subhead">
          {t("Auto-scan diagnostics", "Auto-Scan-Diagnose")}
        </h2>
        <EmptyState title={t("No targets with auto-scan enabled.", "Keine Ziele mit aktivem Auto-Scan.")} />
      </section>
    );
  }

  // Newest probe first; targets that were never probed sink to the bottom.
  // Tie-break unprobed targets by last-scan time so scanned-but-unprobed ones
  // sit above targets that have neither been probed nor scanned.
  const sorted = [...autoScanTargets].sort((a, b) => {
    const ta = a.lastCheckAt ? Date.parse(a.lastCheckAt) : 0;
    const tb = b.lastCheckAt ? Date.parse(b.lastCheckAt) : 0;
    if (tb !== ta) return tb - ta;
    const sa = a.lastScanAt ? Date.parse(a.lastScanAt) : 0;
    const sb = b.lastScanAt ? Date.parse(b.lastScanAt) : 0;
    return sb - sa;
  });

  const verdictOf = (target: ScanTarget): { label: string; tone: VerdictTone; tooltip: string } => {
    switch (target.lastCheckVerdict) {
      case "changed":
        return {
          label: t("changed, scan", "geändert, Scan"),
          tone: "success",
          tooltip: t(
            "Current fingerprint differs from the stored one: auto-scan submitted.",
            "Aktueller Fingerprint weicht vom gespeicherten ab: Auto-Scan submitted."
          ),
        };
      case "unchanged":
        return {
          label: t("unchanged, skip", "unverändert, übersprungen"),
          tone: "muted",
          tooltip: t(
            "Current fingerprint matches the stored one: no scan needed.",
            "Aktueller Fingerprint stimmt mit dem gespeicherten überein: kein Scan nötig."
          ),
        };
      case "first_scan":
        return {
          label: t("first scan", "erster Scan"),
          tone: "info",
          tooltip: t(
            "No stored fingerprint yet: auto-scan will run an initial scan.",
            "Noch kein gespeicherter Fingerprint: Auto-Scan startet einen Initial-Scan."
          ),
        };
      case "check_failed_skipped":
        return {
          label: t("check failed, skip", "Check fehlgeschlagen, übersprungen"),
          tone: "error",
          tooltip: t(
            "Scanner /check call failed but a previous fingerprint exists, so the run was skipped to avoid wasted scans. Inspect the error column.",
            "Scanner-/check-Aufruf fehlgeschlagen, aber ein früherer Fingerprint existiert: Run übersprungen, um unnötige Scans zu vermeiden. Fehler in der nächsten Spalte prüfen."
          ),
        };
      case "check_failed_scanned":
        return {
          label: t("check failed, scan", "Check fehlgeschlagen, Scan"),
          tone: "error",
          tooltip: t(
            "Scanner /check failed and there is no previous fingerprint: auto-scan ran a fail-open initial scan.",
            "Scanner-/check fehlgeschlagen und es gibt keinen früheren Fingerprint: Auto-Scan startete einen fail-open Initial-Scan."
          ),
        };
      default: {
        // The change-detection /check probe hasn't run yet, but if the target
        // already carries scan data (stored fingerprint or a last-scan time) it
        // HAS been scanned, so "never probed" would be misleading. Distinguish the
        // two so a freshly-scanned target reads "scanned, probe pending".
        const hasScanData = !!(target.lastImageDigest || target.lastCommitSha || target.lastScanAt);
        if (hasScanData) {
          return {
            label: t("scanned, probe pending", "gescannt, Probe ausstehend"),
            tone: "info",
            tooltip: t(
              "This target has been scanned, but the auto-scan change-detection probe hasn't run on it yet. The next auto-scan tick, or a click here, will populate the Last Check / Current columns.",
              "Dieses Ziel wurde gescannt, aber die Auto-Scan-Änderungsprüfung lief noch nicht. Der nächste Auto-Scan-Lauf oder ein Klick hier füllt die Spalten Letzte Prüfung / Aktuell."
            ),
          };
        }
        return {
          label: t("never probed", "noch nie geprüft"),
          tone: "muted",
          tooltip: t(
            "The auto-scan scheduler has not probed this target yet. The next run will populate this row.",
            "Der Auto-Scan-Scheduler hat dieses Ziel noch nicht geprüft. Der nächste Lauf füllt diese Zeile."
          ),
        };
      }
    }
  };

  const truncate = (value: string | null | undefined, head = 12): string => {
    if (!value) return "n/a";
    if (value.length <= head + 4) return value;
    return `${value.slice(0, head)}…`;
  };

  return (
    <section>
      <h2 className="scans-subhead">
        {t("Auto-scan diagnostics", "Auto-Scan-Diagnose")}
      </h2>
      <p className="scans-sub scans-subhead-text">
        {t(
          "Most recent change-detection probe per auto-scan target. Use this to figure out why a target isn't being scanned automatically.",
          "Letzter Change-Detection-Probe pro Auto-Scan-Ziel. Damit lässt sich nachvollziehen, warum ein Ziel nicht automatisch gescannt wird."
        )}
      </p>
      <div className="table-scroll">
        <table className="scans-table scans-table--pin">
          <thead>
            <tr>
              <th scope="col">{t("Target", "Ziel")}</th>
              <th scope="col">{t("Verdict", "Ergebnis")}</th>
              <th scope="col">{t("Error", "Fehler")}</th>
              <th scope="col">{t("Last check", "Letzter Check")}</th>
              <th scope="col">{t("Current", "Aktuell")}</th>
              <th scope="col">{t("Stored", "Gespeichert")}</th>
              <th scope="col">{t("Type", "Typ")}</th>
            </tr>
          </thead>
          <tbody>
            {sorted.map(target => {
              const verdict = verdictOf(target);
              const stored = target.type === "container_image"
                ? target.lastImageDigest
                : target.lastCommitSha;
              const isPending = pending.has(target.id);
              const tooltip = isPending
                ? t("Running /check probe…", "/check-Probe läuft …")
                : `${verdict.tooltip}\n\n${t("Click to re-run the probe.", "Zum erneuten Ausführen klicken.")}`;
              const checkError = errors[target.id] || target.lastCheckError;
              return (
                <tr key={target.id}>
                  <td className="scans-cell-diag-target">
                    <div className="scans-cell-strong">{target.name}</div>
                    {target.id !== target.name && (
                      <div className="scans-sub mono scans-target-id" title={target.id}>{target.id}</div>
                    )}
                  </td>
                  <td>
                    <button
                      type="button"
                      className={`scans-verdict scans-verdict--${verdict.tone}`}
                      onClick={() => runCheck(target.id)}
                      disabled={isPending}
                      aria-busy={isPending}
                      title={tooltip}
                    >
                      <LuRefreshCw aria-hidden="true" />
                      {verdict.label}
                    </button>
                  </td>
                  <td>
                    {checkError && (
                      <span title={checkError} className="scans-check-error">{checkError}</span>
                    )}
                  </td>
                  <td className="scans-nowrap scans-small" title={target.lastCheckAt || undefined}>
                    {target.lastCheckAt ? formatDateTime(target.lastCheckAt) : <NotAvailable />}
                  </td>
                  <td>
                    <code className="mono" title={target.lastCheckCurrentFingerprint || undefined}>
                      {truncate(target.lastCheckCurrentFingerprint)}
                    </code>
                  </td>
                  <td>
                    <code className="mono" title={stored || undefined}>
                      {truncate(stored)}
                    </code>
                  </td>
                  <td>
                    <span className="tag">
                      {target.type === "container_image" ? t("image", "Image") : t("repo", "Repo")}
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
};

// A canvas cannot read CSS variables, so `var(--token)` is resolved to its computed value.
const cssToken = (value: string): string => {
  const token = /^var\((--[\w-]+)\)$/.exec(value)?.[1];
  return token ? getComputedStyle(document.documentElement).getPropertyValue(token).trim() : value;
};

const LiveChart = ({ label, data, max, current, color, minutes }: { label: string; data: DataPoint[]; max: number; current: number; color: string; minutes: number }) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [tooltip, setTooltip] = useState<{ x: number; value: number; time: number } | null>(null);

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

    const lineColor = cssToken(color);
    const ruleColor = cssToken("var(--color-rule)");
    const mutedColor = cssToken("var(--color-muted)");

    // Y-axis: auto-scale to data with 20% headroom, minimum = max/5 so flat lines sit mid-chart
    const dataMax = Math.max(...visible.map(d => d.value), 1);
    const yMax = Math.max(dataMax * 1.2, max > 0 ? max * 0.05 : dataMax * 1.5);

    // Grid lines + labels
    const gridLines = 4;
    ctx.textAlign = "right";
    ctx.font = `12px ${cssToken("var(--font-body)")}`;
    for (let i = 0; i <= gridLines; i++) {
      const y = pad.top + (chartH / gridLines) * i;
      if (i > 0 && i < gridLines) {
        ctx.strokeStyle = ruleColor;
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(w, y);
        ctx.stroke();
      }
      ctx.fillStyle = mutedColor;
      const val = yMax * (1 - i / gridLines);
      ctx.fillText(fmt(val), w - 4, y + 12);
    }

    // Limit line (dashed) if limit is within visible range
    if (max > 0 && max <= yMax) {
      const limitY = pad.top + chartH - (max / yMax) * chartH;
      ctx.setLineDash([4, 4]);
      ctx.strokeStyle = mutedColor;
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(0, limitY);
      ctx.lineTo(w, limitY);
      ctx.stroke();
      ctx.setLineDash([]);
      ctx.fillStyle = mutedColor;
      ctx.textAlign = "left";
      ctx.fillText("limit", 4, limitY - 3);
      ctx.textAlign = "right";
    }

    // Map data points to canvas coords
    const toX = (t: number) => ((t - windowStart) / windowMs) * w;
    const toY = (v: number) => pad.top + chartH - (v / yMax) * chartH;

    // Build drawing points: extend flat line from first point leftward to fill chart
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
    ctx.globalAlpha = 0.08;
    ctx.fillStyle = lineColor;
    ctx.fill();
    ctx.globalAlpha = 1;

    // Line
    ctx.beginPath();
    for (let i = 0; i < pts.length; i++) {
      if (i === 0) ctx.moveTo(pts[i].x, pts[i].y);
      else ctx.lineTo(pts[i].x, pts[i].y);
    }
    ctx.strokeStyle = lineColor;
    ctx.lineWidth = 1.5;
    ctx.stroke();

    // Current value dot
    const last = pts[pts.length - 1];
    ctx.beginPath();
    ctx.arc(last.x, last.y, 3, 0, Math.PI * 2);
    ctx.fillStyle = lineColor;
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
    return new Date(ts).toLocaleTimeString("en-GB", {
      hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false,
      timeZone: getCurrentTimezone(),
    });
  };

  return (
    <div ref={containerRef} className="scans-chart">
      <div className="scans-chart-head">
        <span className="scans-sub">{label}</span>
        <span className="scans-chart-values">
          <span className="scans-chart-current">{fmt(current)}</span>
          <span className="scans-sub">{fmt(max)}</span>
          <span className="scans-sub">{pct.toFixed(1)}%</span>
        </span>
      </div>
      <div className="scans-chart-plot">
        <canvas
          ref={canvasRef}
          className="scans-chart-canvas"
          aria-label={`${label}: ${fmt(current)} / ${fmt(max)}`}
          role="img"
          onMouseMove={handleMouseMove}
          onMouseLeave={() => setTooltip(null)}
        />
        {tooltip && (
          <>
            <div className="scans-chart-cursor" style={{ left: tooltip.x }} />
            <div
              className="scans-chart-tooltip"
              style={{ left: Math.min(tooltip.x + 8, (containerRef.current?.clientWidth ?? 300) - 130) }}
            >
              <div className="scans-sub">{fmtTime(tooltip.time)}</div>
              <div className="scans-chart-current">{fmt(tooltip.value)}</div>
            </div>
          </>
        )}
      </div>
    </div>
  );
};

const StatusBadge = ({ status }: { status: string }) => (
  <span className={`scans-status scans-status--${status}`}>{status}</span>
);
