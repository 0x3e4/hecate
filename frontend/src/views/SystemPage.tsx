import { useEffect, useMemo, useRef, useState, type ChangeEvent, type CSSProperties } from "react";

import {
  exportCpeBackup,
  exportVulnerabilityBackup,
  restoreCpeBackup,
  restoreVulnerabilityBackup,
  type VulnerabilitySource
} from "../api/backup";
import { useSavedSearches } from "../hooks/useSavedSearches";
import type { SavedSearch } from "../types";
import { formatDateTime } from "../utils/dateFormat";

type BackupDataset =
  | { id: "VULNERABILITIES" | "CPE"; label: string; description: string; type: "vuln" | "cpe"; source?: VulnerabilitySource }

const BACKUP_DATASETS: BackupDataset[] = [
  {
    id: "VULNERABILITIES",
    label: "Vulnerabilities",
    description: "Sicherung aller Vulnerability-Einträge (NVD & EUVD)",
    type: "vuln",
    source: "ALL"
  },
  {
    id: "CPE",
    label: "CPE",
    description: "Sicherung aller NVD CPE Einträge",
    type: "cpe"
  }
];

export const SystemPage = () => {
  const [busyId, setBusyId] = useState<string | null>(null);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [toast, setToast] = useState<{ message: string; type: "success" | "error" } | null>(null);
  const toastTimeoutRef = useRef<number | null>(null);
  const [deletePendingId, setDeletePendingId] = useState<string | null>(null);
  const fileInputs = useRef<Record<string, HTMLInputElement | null>>({});
  const { savedSearches, loading: savedSearchLoading, removeSavedSearch } = useSavedSearches();

  const beginAction = (datasetId: string) => {
    setBusyId(datasetId);
    setStatusMessage(null);
    setErrorMessage(null);
  };

  const finishAction = () => {
    setBusyId(null);
  };

  const handleExport = async (dataset: BackupDataset) => {
    beginAction(dataset.id);
    try {
      const response =
        dataset.type === "vuln"
          ? await exportVulnerabilityBackup(dataset.source)
          : await exportCpeBackup();

      const timestamp = new Date().toISOString().replace(/[:]/g, "").replace(/\..+/, "");
      const fallbackName =
        dataset.type === "vuln"
          ? `${dataset.source.toLowerCase()}-backup-${timestamp}.json`
          : `cpe-backup-${timestamp}.json`;
      const filename = response.filename ?? fallbackName;

      const url = URL.createObjectURL(response.data);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = filename;
      document.body.appendChild(anchor);
      anchor.click();
      document.body.removeChild(anchor);
      URL.revokeObjectURL(url);

      setStatusMessage(`${dataset.label}: Sicherung bereitgestellt (${filename}).`);
    } catch (error) {
      console.error("Backup export failed", error);
      setErrorMessage(`Backup für ${dataset.label} konnte nicht erstellt werden.`);
    } finally {
      finishAction();
    }
  };

  const sortedSavedSearches = useMemo<SavedSearch[]>(
    () => [...savedSearches].sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: "base" })),
    [savedSearches]
  );

  useEffect(() => {
    return () => {
      if (toastTimeoutRef.current !== null) {
        window.clearTimeout(toastTimeoutRef.current);
        toastTimeoutRef.current = null;
      }
    };
  }, []);

  const handleRestore = async (dataset: BackupDataset, file: File) => {
    beginAction(dataset.id);
    try {
      setStatusMessage(`${dataset.label}: Wiederherstellung gestartet …`);
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
        // Accept ALL, NVD, or EUVD backups for the unified vulnerabilities restore
        const backupSource = meta.source.toUpperCase();
        if (!["ALL", "NVD", "EUVD"].includes(backupSource)) {
          throw new Error(`Ungültige Backup-Quelle: ${meta.source}.`);
        }
        // Always restore to "ALL" endpoint to accept any vulnerability backup
        summary = await restoreVulnerabilityBackup("ALL", payload);
      } else {
        const meta = payload.metadata as { dataset?: string };
        if (meta.dataset?.toLowerCase() !== "cpe") {
          throw new Error("Backup enthält keine CPE-Daten.");
        }
        summary = await restoreCpeBackup(payload);
      }

      setStatusMessage(
        `${dataset.label}: ${summary.inserted} neu, ${summary.updated} aktualisiert, ${summary.skipped} übersprungen.`
      );
    } catch (error) {
      console.error("Backup restore failed", error);
      const message =
        error instanceof Error ? error.message : `Wiederherstellung für ${dataset.label} ist fehlgeschlagen.`;
      setErrorMessage(message);
    } finally {
      finishAction();
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

  return (
    <div className="page">
      <section className="card">
        <h2>Backup & Restore</h2>
        <p className="muted">
          Lade Sicherungen der Datenquellen herunter oder spiele zuvor exportierte Backups wieder ein.
        </p>
        {statusMessage && (
          <p style={{ marginTop: "0.5rem", color: "#8fffb0", fontWeight: 500 }}>{statusMessage}</p>
        )}
        {errorMessage && (
          <p style={{ marginTop: "0.5rem", color: "#ffa3a3", fontWeight: 500 }}>{errorMessage}</p>
        )}

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
