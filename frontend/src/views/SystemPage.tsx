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
  triggerGhsaSync,
} from "../api/sync";
import { useSavedSearches } from "../hooks/useSavedSearches";
import { useI18n, type TranslateFn } from "../i18n/context";
import type { AppLanguage } from "../i18n/language";
import type { SavedSearch, SyncState } from "../types";
import { formatDateTime } from "../utils/dateFormat";

type BackupDataset =
  | { id: "VULNERABILITIES"; label: string; description: string; type: "vuln"; source: VulnerabilitySource }
  | { id: "SAVED_SEARCHES"; label: string; description: string; type: "saved_searches" }

const createBackupDatasets = (t: TranslateFn): BackupDataset[] => [
  {
    id: "VULNERABILITIES",
    label: t("Vulnerabilities", "Schwachstellen"),
    description: t(
      "Backup of all vulnerability entries (NVD & EUVD)",
      "Sicherung aller Vulnerability-Einträge (NVD & EUVD)"
    ),
    type: "vuln",
    source: "ALL"
  },
  {
    id: "SAVED_SEARCHES",
    label: t("Saved Searches", "Gespeicherte Suchen"),
    description: t("Backup of all saved search filters", "Sicherung aller gespeicherten Suchfilter"),
    type: "saved_searches"
  }
];

export const SystemPage = () => {
  const { language, locale, setLanguage, t } = useI18n();
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
  const backupDatasets = useMemo<BackupDataset[]>(() => createBackupDatasets(t), [t]);

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

      showToast(
        t(
          `${dataset.label}: Backup is ready (${filename}).`,
          `${dataset.label}: Sicherung bereitgestellt (${filename}).`
        ),
        "success"
      );
    } catch (error) {
      console.error("Backup export failed", error);
      showToast(
        t(
          `Could not create backup for ${dataset.label}.`,
          `Backup für ${dataset.label} konnte nicht erstellt werden.`
        ),
        "error"
      );
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
    document.title = `${t("Hecate Cyber Defense - System", "Hecate Cyber Defense - System")}`;

    return () => {
      document.title = "Hecate Cyber Defense";
    };
  }, [t]);

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
        throw new Error(t("Invalid backup format.", "Ungültiges Backup-Format."));
      }

      if (!("metadata" in payload) || typeof (payload as { metadata?: unknown }).metadata !== "object" || payload.metadata == null) {
        throw new Error(t("Backup does not contain metadata.", "Backup enthält keine Metadaten."));
      }

      let summary;
      if (dataset.type === "vuln") {
        const meta = payload.metadata as { source?: string; dataset?: string };
        if (typeof meta.source !== "string") {
          throw new Error(t("Backup does not contain source information.", "Backup enthält keine Source-Information."));
        }
        const backupSource = meta.source.toUpperCase();
        if (!["ALL", "NVD", "EUVD"].includes(backupSource)) {
          throw new Error(t(`Invalid backup source: ${meta.source}.`, `Ungültige Backup-Quelle: ${meta.source}.`));
        }
        summary = await restoreVulnerabilityBackup("ALL", payload);
      } else {
        const meta = payload.metadata as { dataset?: string };
        if (meta.dataset !== "saved_searches") {
          throw new Error(t("Backup does not contain saved searches.", "Backup enthält keine gespeicherten Suchen."));
        }
        summary = await restoreSavedSearchesBackup(payload);
        void refreshSavedSearches();
      }

      showToast(
        t(
          `${dataset.label}: ${summary.inserted} inserted, ${summary.updated} updated, ${summary.skipped} skipped.`,
          `${dataset.label}: ${summary.inserted} neu, ${summary.updated} aktualisiert, ${summary.skipped} übersprungen.`
        ),
        "success"
      );
    } catch (error) {
      console.error("Backup restore failed", error);
      const message =
        error instanceof Error
          ? error.message
          : t(
              `Restore for ${dataset.label} failed.`,
              `Wiederherstellung für ${dataset.label} ist fehlgeschlagen.`
            );
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
      showToast(t(`Search "${search.name}" deleted.`, `Suche "${search.name}" gelöscht.`), "success");
    } catch (error) {
      console.error("Failed to delete saved search", error);
      showToast(
        t(`Search "${search.name}" could not be deleted.`, `Suche "${search.name}" konnte nicht gelöscht werden.`),
        "error"
      );
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

  const handleTriggerSync = async (syncType: "euvd" | "nvd" | "cpe" | "kev" | "cwe" | "capec" | "circl" | "ghsa", initial: boolean) => {
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
        case "ghsa":
          response = await triggerGhsaSync(initial);
          break;
      }
      showToast(response.message, "success");
      void loadSyncStates();
    } catch (error) {
      console.error("Failed to trigger sync", error);
      showToast(t("Could not start sync.", "Sync konnte nicht gestartet werden."), "error");
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

  const getStatusLabel = (status: string): string => {
    switch (status) {
      case "running":
        return t("Running", "Läuft");
      case "completed":
        return t("Completed", "Abgeschlossen");
      case "failed":
        return t("Failed", "Fehlgeschlagen");
      default:
        return t("Idle", "Inaktiv");
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
      "ghsa_sync",
      "ghsa_initial_sync",
    ];
    return syncStates.sort((a: SyncState, b: SyncState) => order.indexOf(a.jobName) - order.indexOf(b.jobName));
  }, [syncStates]);

  return (
    <div className="page">
      <section className="card">
        <h2>{t("Language", "Sprache")}</h2>
        <p className="muted">
          {t(
            "The initial default follows your browser language. Set a fixed language here.",
            "Die initiale Standardsprache folgt der Browser-Sprache. Hier kannst du eine feste Sprache setzen."
          )}
        </p>
        <div style={{ marginTop: "1rem", display: "flex", alignItems: "center", gap: "0.75rem", flexWrap: "wrap" }}>
          <label htmlFor="system-language-select" style={{ fontWeight: 600 }}>
            {t("Interface language", "Oberflächensprache")}
          </label>
          <select
            id="system-language-select"
            value={language}
            onChange={(event) => setLanguage(event.target.value as AppLanguage)}
            style={{ minWidth: "180px", padding: "0.5rem 0.75rem" }}
          >
            <option value="en">🇺🇸 English</option>
            <option value="de">🇩🇪 Deutsch</option>
          </select>
        </div>
      </section>

      <section className="card">
        <h2>{t("Sync Status", "Sync-Status")}</h2>
        <p className="muted">
          {t(
            "Overview of all data source synchronizations. Auto-refresh every 5 seconds.",
            "Übersicht über alle Datenquellen-Synchronisationen. Automatische Aktualisierung alle 5 Sekunden."
          )}
        </p>
        {syncLoading ? (
          <p className="muted" style={{ marginTop: "1rem" }}>
            {t("Loading sync status ...", "Lade Sync-Status …")}
          </p>
        ) : (
          <div style={{ marginTop: "1rem", overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", minWidth: "900px" }}>
              <thead>
                <tr>
                  <th style={syncTableHeaderStyle}>{t("Sync Job", "Sync-Job")}</th>
                  <th style={syncTableHeaderStyle}>{t("Status", "Status")}</th>
                  <th style={syncTableHeaderStyle}>{t("Started", "Gestartet")}</th>
                  <th style={syncTableHeaderStyle}>{t("Finished", "Beendet")}</th>
                  <th style={syncTableHeaderStyle}>{t("Duration", "Dauer")}</th>
                  <th style={syncTableHeaderStyle}>{t("Next Run", "Nächster Lauf")}</th>
                  <th style={syncTableHeaderStyle}>{t("Actions", "Aktionen")}</th>
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
                    : sync.jobName.includes("ghsa")
                    ? "ghsa"
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
                            {getStatusLabel(sync.status)}
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
                              {t("Only on startup", "Nur bei Start")}
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
                            {isBusy ? t("Starting...", "Wird gestartet…") : t("Start manually", "Manuell starten")}
                          </button>
                        </td>
                      </tr>
                      {isExpanded && hasDetails && (
                        <tr key={`${sync.jobName}-details`}>
                          <td colSpan={7} style={{ ...syncTableCellStyle, background: "rgba(255, 255, 255, 0.02)", padding: "1rem" }}>
                            {sync.error ? (
                              <div>
                                <strong style={{ color: "#ffa3a3" }}>{t("Error:", "Fehler:")}</strong>
                                <pre style={{ marginTop: "0.5rem", whiteSpace: "pre-wrap", color: "#ffa3a3", fontSize: "0.85rem" }}>
                                  {sync.error}
                                </pre>
                              </div>
                            ) : sync.lastResult ? (
                              <div>
                                <strong>{t("Last result:", "Letztes Ergebnis:")}</strong>
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
        <h2>{t("Backup & Restore", "Backup & Restore")}</h2>
        <p className="muted">
          {t(
            "Download source backups or restore previously exported backup files.",
            "Lade Sicherungen der Datenquellen herunter oder spiele zuvor exportierte Backups wieder ein."
          )}
        </p>

        <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem", marginTop: "1rem" }}>
          {backupDatasets.map((dataset) => (
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
                  {busyId === dataset.id ? t("Please wait...", "Bitte warten…") : t("Download backup", "Backup herunterladen")}
                </button>
                <button type="button" onClick={() => triggerRestoreDialog(dataset.id)} disabled={busyId === dataset.id}>
                  {t("Restore...", "Wiederherstellen…")}
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
        <h2>{t("Saved Searches", "Gespeicherte Suchen")}</h2>
        <p className="muted">
          {t("Manage saved filters for the vulnerabilities view.", "Verwalte gespeicherte Filter für die Vulnerability-Ansicht.")}{" "}
          {t("Total:", "Gesamt:")} {sortedSavedSearches.length.toLocaleString(locale)}.
        </p>
        {savedSearchLoading && sortedSavedSearches.length === 0 ? (
          <p className="muted" style={{ marginTop: "1rem" }}>
            {t("Loading saved searches ...", "Lade gespeicherte Suchen …")}
          </p>
        ) : sortedSavedSearches.length === 0 ? (
          <p className="muted" style={{ marginTop: "1rem" }}>
            {t("No saved searches available.", "Es sind keine gespeicherten Suchen vorhanden.")}
          </p>
        ) : (
          <div style={{ marginTop: "1rem", overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", minWidth: "640px" }}>
              <thead>
                <tr>
                  <th style={savedSearchHeaderStyle}>{t("Name", "Name")}</th>
                  <th style={savedSearchHeaderStyle}>{t("Query Params", "Suchparameter")}</th>
                  <th style={savedSearchHeaderStyle}>{t("DQL Query", "DQL Query")}</th>
                  <th style={savedSearchHeaderStyle}>{t("Created", "Erstellt")}</th>
                  <th style={savedSearchHeaderStyle}>{t("Actions", "Aktionen")}</th>
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
                        {deletePendingId === search.id ? t("Deleting...", "Löschen…") : t("Delete search", "Suche löschen")}
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
