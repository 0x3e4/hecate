import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";

import { config } from "../config";

import {
  fetchScanTargets,
  fetchScans,
  submitManualScan,
  submitManualSourceArchiveScan,
  deleteScanTarget,
  deleteScan,
  updateScanTarget,
  cancelScan,
  fetchScannerStats,
} from "../api/scans";
import { SkeletonBlock } from "../components/Skeleton";
import { useI18n } from "../i18n/context";
import { formatDateTime } from "../utils/dateFormat";
import type {
  ScanTarget,
  Scan,
  ScanSummary,
  ScannerStats,
  SubmitScanResponse,
} from "../types";

type Tab = "targets" | "scans" | "manual" | "scanner";
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
        const [targetsRes, scansRes] = await Promise.all([
          fetchScanTargets({ limit: 100 }),
          fetchScans({ limit: 1 }),
        ]);
        setTargets(targetsRes.items);
        setScanTotal(scansRes.total);
      } else if (tab === "scans") {
        // Load targets for filter dropdown if not yet loaded
        if (targets.length === 0) {
          const tRes = await fetchScanTargets({ limit: 100 });
          setTargets(tRes.items);
        }
        const res = await fetchScans({ limit: scanLimit, offset: scanOffset, targetId: scanFilterTargetId || undefined });
        setScans(res.items);
        setScanTotal(res.total);
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
      }
    } catch (err) {
      console.error("Failed to load scan data", err);
      setError(t("Could not load data.", "Daten konnten nicht geladen werden."));
    } finally {
      setLoading(false);
    }
  };

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
    try {
      const fallbackScanners = target.type === "container_image"
        ? ["trivy", "grype", "syft", "dockle", "dive"]
        : ["trivy", "grype", "syft", "osv-scanner", "hecate"];
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
        <div style={{ display: "flex", gap: 0, marginBottom: "1.5rem", marginTop: "1rem", borderBottom: "1px solid rgba(255,255,255,0.08)" }}>
          {([
            { key: "targets" as Tab, label: t("Targets", "Ziele"), count: targets.length || undefined },
            { key: "scans" as Tab, label: t("Scans", "Scans"), count: scanTotal || undefined },
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
            {!loading && targets.length > 0 && (
              <div style={{ display: "grid", gap: "1rem", gridTemplateColumns: "repeat(auto-fill, minmax(min(100%, 420px), 1fr))" }}>
                {targets.map(target => (
                  <TargetCard key={target.id} target={target} onDelete={handleDeleteTarget} onRescan={handleRescan} onToggleAutoScan={handleToggleAutoScan} onCancelScan={handleCancelScan} onFilterScans={(id, name) => { setScanFilterTargetId(id); setScanFilterTargetName(name); setScanOffset(0); setTab("scans"); }} />
                ))}
              </div>
            )}
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
                  padding: "0.375rem 0.625rem",
                  borderRadius: "6px",
                  border: "1px solid rgba(255,255,255,0.12)",
                  background: "rgba(255,255,255,0.05)",
                  color: scanFilterTargetId ? "#ffd43b" : "rgba(255,255,255,0.5)",
                  fontSize: "0.8125rem",
                  outline: "none",
                  cursor: "pointer",
                  minWidth: "180px",
                  maxWidth: "320px",
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
                        return (
                          <tr key={scan.id} style={{ borderBottom: "1px solid rgba(255,255,255,0.05)" }}>
                            <td style={tdStyle}>
                              <Link to={`/scans/${scan.id}`} style={{ color: "#ffd43b", textDecoration: "none" }}>
                                {scan.targetName || scan.targetId}
                              </Link>
                            </td>
                            <td style={{ ...tdStyle, fontFamily: ref ? "monospace" : undefined, fontSize: ref ? "0.75rem" : "0.875rem", color: ref ? "rgba(255,255,255,0.45)" : "rgba(255,255,255,0.25)" }} title={refFull || undefined}>
                              {ref ? <span>{refLabel}: {ref}</span> : "—"}
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
                        setScanners(["trivy", "grype", "syft", "osv-scanner", "hecate"]);
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
                    : ["trivy", "grype", "syft", "osv-scanner", "hecate"]
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

const TargetCard = ({ target, onDelete, onRescan, onToggleAutoScan, onFilterScans, onCancelScan }: { target: ScanTarget; onDelete: (id: string) => void; onRescan: (target: ScanTarget) => void; onToggleAutoScan: (target: ScanTarget) => void; onFilterScans: (id: string, name: string) => void; onCancelScan?: (scanId: string) => void }) => {
  const { t } = useI18n();
  const isRunning = !!target.hasRunningScan;
  const autoScan = target.autoScan !== false; // default true
  return (
    <div style={{
      padding: "1rem 1.25rem",
      border: isRunning ? "1px solid rgba(92,132,255,0.3)" : "1px solid rgba(255,255,255,0.08)",
      borderRadius: "8px",
      background: isRunning ? "rgba(92,132,255,0.04)" : "rgba(255,255,255,0.02)",
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "0.5rem", flexWrap: "wrap", gap: "0.25rem" }}>
        <div style={{ minWidth: 0, flex: "1 1 200px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <span style={{ display: "block", fontSize: "0.75rem", color: "rgba(255,255,255,0.4)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
              {target.type === "container_image" ? "Container" : "Source"}
            </span>
            {isRunning && <ScanningBadge />}
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
      <p style={{ fontSize: "0.8125rem", color: "rgba(255,255,255,0.5)", margin: "0 0 0.75rem", wordBreak: "break-all" }}>
        {target.id}
      </p>
      {target.latestSummary && <SeverityBadges summary={target.latestSummary} />}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: "0.75rem", flexWrap: "wrap", gap: "0.5rem" }}>
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
          {isRunning && target.latestScanId && onCancelScan ? (
            <button
              type="button"
              onClick={() => onCancelScan(target.latestScanId!)}
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
          {config.scaFeatures.autoScanEnabled && (
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

const ScanningBadge = () => (
  <span style={{
    display: "inline-flex",
    alignItems: "center",
    gap: "0.25rem",
    padding: "0.125rem 0.5rem",
    borderRadius: "4px",
    fontSize: "0.675rem",
    fontWeight: 600,
    background: "rgba(92,132,255,0.15)",
    color: "#5c84ff",
    animation: "pulse-badge 1.5s ease-in-out infinite",
  }}>
    <span style={{
      width: "6px",
      height: "6px",
      borderRadius: "50%",
      background: "#5c84ff",
      animation: "pulse-dot 1.5s ease-in-out infinite",
    }} />
    Scanning...
    <style>{`
      @keyframes pulse-badge { 0%,100% { opacity: 1; } 50% { opacity: 0.6; } }
      @keyframes pulse-dot { 0%,100% { transform: scale(1); opacity: 1; } 50% { transform: scale(1.4); opacity: 0.5; } }
    `}</style>
  </span>
);

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
