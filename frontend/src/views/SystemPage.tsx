import { useRef, useState, type ChangeEvent } from "react";

import {
  exportCpeBackup,
  exportVulnerabilityBackup,
  restoreCpeBackup,
  restoreVulnerabilityBackup,
  type VulnerabilitySource
} from "../api/backup";

type BackupDataset =
  | { id: "NVD" | "EUVD"; label: string; description: string; type: "vuln"; source: VulnerabilitySource }
  | { id: "CPE"; label: string; description: string; type: "cpe" };

const BACKUP_DATASETS: BackupDataset[] = [
  {
    id: "NVD",
    label: "NVD",
    description: "Sicherung aller NVD CVE Einträge.",
    type: "vuln",
    source: "NVD"
  },
  {
    id: "EUVD",
    label: "EUVD",
    description: "Sicherung aller EUVD Einträge.",
    type: "vuln",
    source: "EUVD"
  },
  {
    id: "CPE",
    label: "CPE",
    description: "Sicherung aller NVD CPE Einträge.",
    type: "cpe"
  }
];

export const SystemPage = () => {
  const [busyId, setBusyId] = useState<string | null>(null);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const fileInputs = useRef<Record<string, HTMLInputElement | null>>({});

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
        if (meta.source.toUpperCase() !== dataset.source) {
          throw new Error(`Backup gehört zu ${meta.source}, erwartet ${dataset.source}.`);
        }
        summary = await restoreVulnerabilityBackup(dataset.source, payload);
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
        <h2>System & Backups</h2>
        <p className="muted">
          Lade Sicherungen der Datenquellen herunter oder spiele zuvor exportierte Backups wieder ein,
          um nach einem Datenbank-Reset schnell den alten Stand herzustellen.
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
    </div>
  );
};
