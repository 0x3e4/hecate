import { useEffect, useRef, useState, type FormEvent } from "react";
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
} from "../api/scans";
import { SkeletonBlock } from "../components/Skeleton";
import { useI18n } from "../i18n/context";
import { formatDateTime } from "../utils/dateFormat";
import type {
  ScanTarget,
  Scan,
  ScanSummary,
  SubmitScanResponse,
} from "../types";

type Tab = "targets" | "scans" | "manual";
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
        const res = await fetchScanTargets({ limit: 100 });
        setTargets(res.items);
      } else if (tab === "scans") {
        // Load targets for filter dropdown if not yet loaded
        if (targets.length === 0) {
          const tRes = await fetchScanTargets({ limit: 100 });
          setTargets(tRes.items);
        }
        const res = await fetchScans({ limit: scanLimit, offset: scanOffset, targetId: scanFilterTargetId || undefined });
        setScans(res.items);
        setScanTotal(res.total);
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
    if (hasRunningScans || hasRunningTargets) {
      pollRef.current = setInterval(async () => {
        try {
          if (tab === "scans") {
            const res = await fetchScans({ limit: scanLimit, offset: scanOffset, targetId: scanFilterTargetId || undefined });
            setScans(res.items);
            setScanTotal(res.total);
          } else if (tab === "targets") {
            const res = await fetchScanTargets({ limit: 100 });
            setTargets(res.items);
          }
        } catch { /* ignore poll errors */ }
      }, 4000);
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
                  <TargetCard key={target.id} target={target} onDelete={handleDeleteTarget} onRescan={handleRescan} onToggleAutoScan={handleToggleAutoScan} onFilterScans={(id, name) => { setScanFilterTargetId(id); setScanFilterTargetName(name); setScanOffset(0); setTab("scans"); }} />
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
                            <td style={tdStyle}>{scan.startedAt ? formatDateTime(scan.startedAt) : "—"}</td>
                            <td style={tdStyle}>
                              <button
                                type="button"
                                onClick={() => handleDeleteScan(scan.id, scan.targetName || scan.targetId)}
                                title={t("Delete scan", "Scan löschen")}
                                style={{ background: "none", border: "none", color: "rgba(255,255,255,0.25)", cursor: "pointer", fontSize: "0.875rem", padding: "0.125rem 0.25rem" }}
                              >
                                ×
                              </button>
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

const TargetCard = ({ target, onDelete, onRescan, onToggleAutoScan, onFilterScans }: { target: ScanTarget; onDelete: (id: string) => void; onRescan: (target: ScanTarget) => void; onToggleAutoScan: (target: ScanTarget) => void; onFilterScans: (id: string, name: string) => void }) => {
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
          <button
            type="button"
            onClick={() => !isRunning && onRescan(target)}
            disabled={isRunning}
            title={isRunning ? t("Scan in progress", "Scan läuft") : t("Rescan", "Erneut scannen")}
            style={{
              background: isRunning ? "rgba(255,255,255,0.05)" : "rgba(255,193,7,0.15)",
              border: isRunning ? "1px solid rgba(255,255,255,0.1)" : "1px solid rgba(255,193,7,0.3)",
              color: isRunning ? "rgba(255,255,255,0.3)" : "#ffd43b",
              cursor: isRunning ? "not-allowed" : "pointer",
              fontSize: "0.7rem",
              padding: "0.2rem 0.5rem",
              borderRadius: "4px",
              fontWeight: 500,
            }}
          >
            ↻ Scan
          </button>
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
