import { useEffect, useMemo, useRef, useState, type ChangeEvent, type CSSProperties } from "react";

import {
  exportSavedSearchesBackup,
  exportVulnerabilityBackup,
  restoreSavedSearchesBackup,
  restoreVulnerabilityBackup,
  type VulnerabilitySource
} from "../api/backup";
import {
  fetchSyncStates,
  triggerEuvdSync,
  triggerNvdSync,
  triggerCpeSync,
  triggerKevSync,
  triggerCweSync,
  triggerCapecSync,
  triggerCirclSync,
} from "../api/sync";
import { useSavedSearches } from "../hooks/useSavedSearches";
import type { SavedSearch, SyncState } from "../types";
import { formatDateTime } from "../utils/dateFormat";

type BackupDataset =
  | { id: "VULNERABILITIES"; label: string; description: string; type: "vuln"; source: VulnerabilitySource }
  | { id: "SAVED_SEARCHES"; label: string; description: string; type: "saved_searches" }

const BACKUP_DATASETS: BackupDataset[] = [
  {
    id: "VULNERABILITIES",
    label: "Vulnerabilities",
    description: "Sicherung aller Vulnerability-Einträge (NVD & EUVD)",
    type: "vuln",
    source: "ALL"
  },
  {
    id: "SAVED_SEARCHES",
    label: "Gespeicherte Suchen",
    description: "Sicherung aller gespeicherten Suchfilter",
    type: "saved_searches"
  }
];

export const SystemPage = () => {
  const [busyId, setBusyId] = useState<string | null>(null);
  const [toast, setToast] = useState<{ message: string; type: "success" | "error" } | null>(null);
  const toastTimeoutRef = useRef<number | null>(null);
  const [deletePendingId, setDeletePendingId] = useState<string | null>(null);
  const fileInputs = useRef<Record<string, HTMLInputElement | null>>({});
  const { savedSearches, loading: savedSearchLoading, removeSavedSearch, refresh: refreshSavedSearches } = useSavedSearches();

  const [syncStates, setSyncStates] = useState<SyncState[]>([]);
  const [syncLoading, setSyncLoading] = useState(true);
  const [syncTriggeringId, setSyncTriggeringId] = useState<string | null>(null);
  const [expandedSyncId, setExpandedSyncId] = useState<string | null>(null);
  const syncIntervalRef = useRef<number | null>(null);

  const handleExport = async (dataset: BackupDataset) => {
    setBusyId(dataset.id);
    try {
      const response =
        dataset.type === "vuln"
          ? await exportVulnerabilityBackup(dataset.source)
          : await exportSavedSearchesBackup();

      const timestamp = new Date().toISOString().replace(/[:]/g, "").replace(/\..+/, "");
      const fallbackName =
        dataset.type === "vuln"
          ? `${dataset.source.toLowerCase()}-backup-${timestamp}.json`
          : `saved-searches-backup-${timestamp}.json`;
      const filename = response.filename ?? fallbackName;

      const url = URL.createObjectURL(response.data);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = filename;
      document.body.appendChild(anchor);
      anchor.click();
      document.body.removeChild(anchor);
      URL.revokeObjectURL(url);

      showToast(`${dataset.label}: Sicherung bereitgestellt (${filename}).`, "success");
    } catch (error) {
      console.error("Backup export failed", error);
      showToast(`Backup für ${dataset.label} konnte nicht erstellt werden.`, "error");
    } finally {
      setBusyId(null);
    }
  };

  const sortedSavedSearches = useMemo<SavedSearch[]>(
    () => [...savedSearches].sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: "base" })),
    [savedSearches]
  );

  const loadSyncStates = async () => {
    try {
      const response = await fetchSyncStates();
      setSyncStates(response.syncs);
      setSyncLoading(false);
    } catch (error) {
      console.error("Failed to load sync states", error);
      setSyncLoading(false);
    }
  };

  useEffect(() => {
    document.title = "Hecate Cyber Defense - System";

    return () => {
      document.title = "Hecate Cyber Defense";
    };
  }, []);

  useEffect(() => {
    void loadSyncStates();
    syncIntervalRef.current = window.setInterval(() => {
      void loadSyncStates();
    }, 5000);

    return () => {
      if (toastTimeoutRef.current !== null) {
        window.clearTimeout(toastTimeoutRef.current);
        toastTimeoutRef.current = null;
      }
      if (syncIntervalRef.current !== null) {
        window.clearInterval(syncIntervalRef.current);
        syncIntervalRef.current = null;
      }
    };
  }, []);

  const handleRestore = async (dataset: BackupDataset, file: File) => {
    setBusyId(dataset.id);
    try {
      const fileContent = await file.text();
      const payload = JSON.parse(fileContent);

      if (!payload || typeof payload !== "object") {
        throw new Error("Ungültiges Backup-Format.");
      }

      if (!("metadata" in payload) || typeof (payload as { metadata?: unknown }).metadata !== "object" || payload.metadata == null) {
        throw new Error("Backup enthält keine Metadaten.");
      }

      let summary;
      if (dataset.type === "vuln") {
        const meta = payload.metadata as { source?: string; dataset?: string };
        if (typeof meta.source !== "string") {
          throw new Error("Backup enthält keine Source-Information.");
        }
        const backupSource = meta.source.toUpperCase();
        if (!["ALL", "NVD", "EUVD"].includes(backupSource)) {
          throw new Error(`Ungültige Backup-Quelle: ${meta.source}.`);
        }
        summary = await restoreVulnerabilityBackup("ALL", payload);
      } else {
        const meta = payload.metadata as { dataset?: string };
        if (meta.dataset !== "saved_searches") {
          throw new Error("Backup enthält keine gespeicherten Suchen.");
        }
        summary = await restoreSavedSearchesBackup(payload);
        void refreshSavedSearches();
      }

      showToast(
        `${dataset.label}: ${summary.inserted} neu, ${summary.updated} aktualisiert, ${summary.skipped} übersprungen.`,
        "success"
      );
    } catch (error) {
      console.error("Backup restore failed", error);
      const message =
        error instanceof Error ? error.message : `Wiederherstellung für ${dataset.label} ist fehlgeschlagen.`;
      showToast(message, "error");
    } finally {
      setBusyId(null);
    }
  };

  const showToast = (message: string, type: "success" | "error") => {
    if (toastTimeoutRef.current !== null) {
      window.clearTimeout(toastTimeoutRef.current);
      toastTimeoutRef.current = null;
    }
    setToast({ message, type });
    toastTimeoutRef.current = window.setTimeout(() => {
      setToast(null);
      toastTimeoutRef.current = null;
    }, 4000);
  };

  const handleDeleteSavedSearch = async (search: SavedSearch) => {
    setDeletePendingId(search.id);
    try {
      await removeSavedSearch(search.id);
      showToast(`Suche "${search.name}" gelöscht.`, "success");
    } catch (error) {
      console.error("Failed to delete saved search", error);
      showToast(`Suche "${search.name}" konnte nicht gelöscht werden.`, "error");
    } finally {
      setDeletePendingId(null);
    }
  };

  const triggerRestoreDialog = (datasetId: string) => {
    const input = fileInputs.current[datasetId];
    input?.click();
  };

  const handleFileSelection = (dataset: BackupDataset, event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      void handleRestore(dataset, file);
    }
    event.target.value = "";
  };

  const handleTriggerSync = async (syncType: "euvd" | "nvd" | "cpe" | "kev" | "cwe" | "capec" | "circl", initial: boolean) => {
    const syncId = `${syncType}_${initial ? "initial" : "normal"}`;
    setSyncTriggeringId(syncId);
    try {
      let response;
      switch (syncType) {
        case "euvd":
          response = await triggerEuvdSync(initial);
          break;
        case "nvd":
          response = await triggerNvdSync(initial);
          break;
        case "cpe":
          response = await triggerCpeSync(initial);
          break;
        case "kev":
          response = await triggerKevSync(initial);
          break;
        case "cwe":
          response = await triggerCweSync(initial);
          break;
        case "capec":
          response = await triggerCapecSync(initial);
          break;
        case "circl":
          response = await triggerCirclSync();
          break;
      }
      showToast(response.message, "success");
      void loadSyncStates();
    } catch (error) {
      console.error("Failed to trigger sync", error);
      showToast(`Sync konnte nicht gestartet werden.`, "error");
    } finally {
      setSyncTriggeringId(null);
    }
  };

  const getStatusColor = (status: string): string => {
    switch (status) {
      case "running":
        return "#ffcc66";
      case "completed":
        return "#8fffb0";
      case "failed":
        return "#ffa3a3";
      case "idle":
        return "#888";
      default:
        return "#888";
    }
  };

  const formatDuration = (seconds?: number | null): string => {
    if (!seconds) return "-";
    if (seconds < 60) return `${Math.round(seconds)}s`;
    if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
    return `${Math.round(seconds / 3600)}h`;
  };

  const displayedSyncStates = useMemo(() => {
    const order = [
      "euvd_ingestion",
      "euvd_initial_sync",
      "nvd_sync",
      "nvd_initial_sync",
      "cpe_sync",
      "cpe_initial_sync",
      "kev_sync",
      "kev_initial_sync",
      "cwe_sync",
      "cwe_initial_sync",
      "capec_sync",
      "capec_initial_sync",
      "circl_sync",
    ];
    return syncStates.sort((a: SyncState, b: SyncState) => order.indexOf(a.jobName) - order.indexOf(b.jobName));
  }, [syncStates]);

  return (
    <div className="page">
      <section className="card">
        <h2>Sync Status</h2>
        <p className="muted">
          Übersicht über alle Datenquellen-Synchronisationen. Automatische Aktualisierung alle 5 Sekunden.
        </p>
        {syncLoading ? (
          <p className="muted" style={{ marginTop: "1rem" }}>
            Lade Sync-Status …
          </p>
        ) : (
          <div style={{ marginTop: "1rem", overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", minWidth: "900px" }}>
              <thead>
                <tr>
                  <th style={syncTableHeaderStyle}>Sync Job</th>
                  <th style={syncTableHeaderStyle}>Status</th>
                  <th style={syncTableHeaderStyle}>Gestartet</th>
                  <th style={syncTableHeaderStyle}>Beendet</th>
                  <th style={syncTableHeaderStyle}>Dauer</th>
                  <th style={syncTableHeaderStyle}>Nächster Lauf</th>
                  <th style={syncTableHeaderStyle}>Aktionen</th>
                </tr>
              </thead>
              <tbody>
                {displayedSyncStates.map((sync: SyncState) => {
                  const syncType = sync.jobName.includes("euvd")
                    ? "euvd"
                    : sync.jobName.includes("nvd")
                    ? "nvd"
                    : sync.jobName.includes("cpe")
                    ? "cpe"
                    : sync.jobName.includes("kev")
                    ? "kev"
                    : sync.jobName.includes("capec")
                    ? "capec"
                    : sync.jobName.includes("circl")
                    ? "circl"
                    : "cwe";
                  const isInitial = sync.jobName.includes("initial");
                  const syncId = `${syncType}_${isInitial ? "initial" : "normal"}`;
                  const isBusy = syncTriggeringId === syncId || sync.status === "running";
                  const isExpanded = expandedSyncId === sync.jobName;
                  const hasDetails = sync.lastResult || sync.error;

                  return (
                    <>
                      <tr
                        key={sync.jobName}
                        onClick={() => hasDetails && setExpandedSyncId(isExpanded ? null : sync.jobName)}
                        style={{
                          cursor: hasDetails ? "pointer" : "default",
                          background: isExpanded ? "rgba(255, 255, 255, 0.02)" : undefined,
                        }}
                      >
                        <td style={syncTableCellStyle}>
                          <strong>{sync.label}</strong>
                          {hasDetails && (
                            <span style={{ marginLeft: "0.5rem", fontSize: "0.75rem", opacity: 0.6 }}>
                              {isExpanded ? "▼" : "▶"}
                            </span>
                          )}
                        </td>
                        <td style={syncTableCellStyle}>
                          <span
                            style={{
                              display: "inline-block",
                              padding: "0.25rem 0.5rem",
                              borderRadius: "0.35rem",
                              fontSize: "0.85rem",
                              fontWeight: 600,
                              background: `${getStatusColor(sync.status)}22`,
                              color: getStatusColor(sync.status),
                              border: `1px solid ${getStatusColor(sync.status)}44`,
                            }}
                          >
                            {sync.status === "running"
                              ? "Läuft"
                              : sync.status === "completed"
                              ? "Abgeschlossen"
                              : sync.status === "failed"
                              ? "Fehlgeschlagen"
                              : "Inaktiv"}
                          </span>
                        </td>
                        <td style={syncTableCellStyle}>
                          {sync.startedAt ? formatDateTime(sync.startedAt) : "-"}
                        </td>
                        <td style={syncTableCellStyle}>
                          {sync.finishedAt ? formatDateTime(sync.finishedAt) : "-"}
                        </td>
                        <td style={syncTableCellStyle}>{formatDuration(sync.durationSeconds)}</td>
                        <td style={syncTableCellStyle}>
                          {sync.nextRun ? (
                            formatDateTime(sync.nextRun)
                          ) : isInitial ? (
                            <span className="muted" style={{ fontSize: "0.85rem" }}>
                              Nur bei Start
                            </span>
                          ) : (
                            "-"
                          )}
                        </td>
                        <td style={syncTableCellStyle}>
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              void handleTriggerSync(syncType, isInitial);
                            }}
                            disabled={isBusy}
                            style={{ minWidth: "120px", fontSize: "0.85rem" }}
                          >
                            {isBusy ? "Wird gestartet…" : "Manuell starten"}
                          </button>
                        </td>
                      </tr>
                      {isExpanded && hasDetails && (
                        <tr key={`${sync.jobName}-details`}>
                          <td colSpan={7} style={{ ...syncTableCellStyle, background: "rgba(255, 255, 255, 0.02)", padding: "1rem" }}>
                            {sync.error ? (
                              <div>
                                <strong style={{ color: "#ffa3a3" }}>Fehler:</strong>
                                <pre style={{ marginTop: "0.5rem", whiteSpace: "pre-wrap", color: "#ffa3a3", fontSize: "0.85rem" }}>
                                  {sync.error}
                                </pre>
                              </div>
                            ) : sync.lastResult ? (
                              <div>
                                <strong>Letztes Ergebnis:</strong>
                                <pre style={{ marginTop: "0.5rem", whiteSpace: "pre-wrap", fontSize: "0.85rem", background: "rgba(255, 255, 255, 0.06)", padding: "0.75rem", borderRadius: "0.35rem" }}>
                                  {JSON.stringify(sync.lastResult, null, 2)}
                                </pre>
                              </div>
                            ) : null}
                          </td>
                        </tr>
                      )}
                    </>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="card">
        <h2>Backup & Restore</h2>
        <p className="muted">
          Lade Sicherungen der Datenquellen herunter oder spiele zuvor exportierte Backups wieder ein.
        </p>

        <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem", marginTop: "1rem" }}>
          {BACKUP_DATASETS.map((dataset) => (
            <div
              key={dataset.id}
              style={{
                display: "flex",
                flexWrap: "wrap",
                alignItems: "center",
                justifyContent: "space-between",
                gap: "0.75rem",
                padding: "0.75rem",
                borderRadius: "0.5rem",
                background: "rgba(255, 255, 255, 0.02)",
                border: "1px solid rgba(255, 255, 255, 0.06)"
              }}
            >
              <div style={{ flex: "1 1 auto", minWidth: "200px" }}>
                <strong>{dataset.label}</strong>
                <p className="muted" style={{ margin: "0.25rem 0 0" }}>
                  {dataset.description}
                </p>
              </div>
              <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
                <button type="button" onClick={() => void handleExport(dataset)} disabled={busyId === dataset.id}>
                  {busyId === dataset.id ? "Bitte warten…" : "Backup herunterladen"}
                </button>
                <button type="button" onClick={() => triggerRestoreDialog(dataset.id)} disabled={busyId === dataset.id}>
                  Wiederherstellen…
                </button>
                <input
                  type="file"
                  accept="application/json"
                  style={{ display: "none" }}
                  ref={(element) => {
                    fileInputs.current[dataset.id] = element;
                  }}
                  onChange={(event) => handleFileSelection(dataset, event)}
                />
              </div>
            </div>
          ))}
        </div>
      </section>

      <section className="card">
        <h2>Gespeicherte Suchen</h2>
        <p className="muted">
          Verwalte gespeicherte Filter für die Vulnerability-Ansicht. Gesamt: {sortedSavedSearches.length}.
        </p>
        {savedSearchLoading && sortedSavedSearches.length === 0 ? (
          <p className="muted" style={{ marginTop: "1rem" }}>
            Lade gespeicherte Suchen …
          </p>
        ) : sortedSavedSearches.length === 0 ? (
          <p className="muted" style={{ marginTop: "1rem" }}>
            Es sind keine gespeicherten Suchen vorhanden.
          </p>
        ) : (
          <div style={{ marginTop: "1rem", overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", minWidth: "640px" }}>
              <thead>
                <tr>
                  <th style={savedSearchHeaderStyle}>Name</th>
                  <th style={savedSearchHeaderStyle}>Suchparameter</th>
                  <th style={savedSearchHeaderStyle}>DQL Query</th>
                  <th style={savedSearchHeaderStyle}>Erstellt</th>
                  <th style={savedSearchHeaderStyle}>Aktionen</th>
                </tr>
              </thead>
              <tbody>
                {sortedSavedSearches.map((search) => (
                  <tr key={search.id}>
                    <td style={savedSearchCellStyle}>
                      <strong>{search.name}</strong>
                    </td>
                    <td style={{ ...savedSearchCellStyle, maxWidth: "260px" }}>
                      {search.queryParams ? (
                        <code style={savedSearchCodeStyle}>{search.queryParams}</code>
                      ) : (
                        <span className="muted">-</span>
                      )}
                    </td>
                    <td style={{ ...savedSearchCellStyle, maxWidth: "260px" }}>
                      {search.dqlQuery ? (
                        <code style={savedSearchCodeStyle}>{search.dqlQuery}</code>
                      ) : (
                        <span className="muted">-</span>
                      )}
                    </td>
                    <td style={savedSearchCellStyle}>
                      {formatDateTime(search.createdAt)}
                    </td>
                    <td style={savedSearchCellStyle}>
                      <button
                        type="button"
                        onClick={() => void handleDeleteSavedSearch(search)}
                        disabled={deletePendingId === search.id}
                        style={{ minWidth: "140px" }}
                      >
                        {deletePendingId === search.id ? "Löschen…" : "Suche löschen"}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      {toast && (
        <div style={toastContainerStyle}>
          <div
            role="status"
            aria-live="polite"
            style={{
              ...toastStyle,
              ...(toast.type === "success" ? toastSuccessStyle : toastErrorStyle),
            }}
          >
            {toast.message}
          </div>
        </div>
      )}
    </div>
  );
};

const savedSearchHeaderStyle: CSSProperties = {
  textAlign: "left",
  padding: "0.5rem 0.75rem",
  borderBottom: "1px solid rgba(255, 255, 255, 0.08)",
  fontWeight: 600,
  fontSize: "0.9rem",
};

const savedSearchCellStyle: CSSProperties = {
  padding: "0.65rem 0.75rem",
  borderBottom: "1px solid rgba(255, 255, 255, 0.06)",
  verticalAlign: "top",
  fontSize: "0.9rem",
};

const savedSearchCodeStyle: CSSProperties = {
  display: "inline-block",
  padding: "0.25rem 0.4rem",
  background: "rgba(255, 255, 255, 0.06)",
  borderRadius: "0.35rem",
  fontSize: "0.85rem",
  whiteSpace: "pre-wrap",
  wordBreak: "break-word",
};

const toastContainerStyle: CSSProperties = {
  position: "fixed",
  bottom: "2rem",
  right: "2rem",
  zIndex: 2100,
};

const toastStyle: CSSProperties = {
  background: "rgba(15, 18, 30, 0.92)",
  borderRadius: "10px",
  padding: "0.75rem 1rem",
  color: "#f5f7fa",
  fontWeight: 600,
  boxShadow: "0 18px 40px rgba(0, 0, 0, 0.38)",
  border: "1px solid rgba(255, 255, 255, 0.18)",
  minWidth: "240px",
};

const toastSuccessStyle: CSSProperties = {
  borderColor: "rgba(92, 132, 255, 0.6)",
  color: "#d6e4ff",
};

const toastErrorStyle: CSSProperties = {
  borderColor: "rgba(252, 92, 101, 0.65)",
  color: "#ffb4b6",
};

const syncTableHeaderStyle: CSSProperties = {
  textAlign: "left",
  padding: "0.5rem 0.75rem",
  borderBottom: "1px solid rgba(255, 255, 255, 0.08)",
  fontWeight: 600,
  fontSize: "0.9rem",
};

const syncTableCellStyle: CSSProperties = {
  padding: "0.65rem 0.75rem",
  borderBottom: "1px solid rgba(255, 255, 255, 0.06)",
  verticalAlign: "top",
  fontSize: "0.9rem",
};
