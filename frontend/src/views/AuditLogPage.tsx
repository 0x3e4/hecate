import { useEffect, useMemo, useState, type ReactNode } from "react";

import { fetchIngestionLogs } from "../api/audit";
import { IngestionLogEntry } from "../types";
import { SkeletonBlock } from "../components/Skeleton";

const JOB_LABELS: Record<string, string> = {
  euvd_ingestion: "EUVD Sync",
  euvd_initial_sync: "EUVD Initial Sync",
  cpe_sync: "CPE Sync",
  cpe_initial_sync: "CPE Initial Sync",
  nvd_sync: "NVD Sync",
  nvd_initial_sync: "NVD Initial Sync",
  manual_refresh: "Manueller Refresh",
};

const STATUS_COLOR: Record<string, string> = {
  completed: "#8fffb0",
  running: "#8286ffff",
  failed: "#ffa3a3",
  timeout: "#fcd34d",
  overdue: "#fcd34d",
  cancelled: "#9ca3af",
};

export const AuditLogPage = () => {
  const [logs, setLogs] = useState<IngestionLogEntry[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [loading, setLoading] = useState<boolean>(false);
  const [jobFilter, setJobFilter] = useState<string>("");

  useEffect(() => {
    const load = async () => {
      try {
        setLoading(true);
        const response = await fetchIngestionLogs({ job: jobFilter || undefined, limit: 50 });
        setLogs(response.items);
        setTotal(response.total);
      } catch (error) {
        console.error("Failed to load ingestion logs", error);
      }
      setLoading(false);
    };

    load();
  }, [jobFilter]);

  const rows = useMemo(
    () =>
      logs.map((entry) => {
        const duration = entry.durationSeconds != null ? `${entry.durationSeconds.toFixed(1)}s` : "-";
        const finished = entry.finishedAt ? new Date(entry.finishedAt).toLocaleString() : "-";
        const started = new Date(entry.startedAt).toLocaleString();
        const isOverdue = entry.overdue === true;
        const statusKey = isOverdue ? "overdue" : entry.status;
        const statusColor = STATUS_COLOR[statusKey] ?? "#d1d5db";
        const statusLabel =
          isOverdue && entry.status === "running" ? "running (overdue)" : entry.status;
        const cancelledNote = entry.status === "cancelled" && entry.error != null ? entry.error : undefined;
        const errorText = entry.error != null && entry.status !== "cancelled" ? entry.error : undefined;
        const hintText = entry.overdueReason ?? (cancelledNote ? `Job abgebrochen: ${cancelledNote}` : undefined);
        const progressJson = entry.progress ? JSON.stringify(entry.progress, null, 2) : undefined;
        const resultJson = entry.result ? JSON.stringify(entry.result, null, 2) : undefined;

        let detailNode: ReactNode = "-";
        if (errorText) {
          detailNode = `Fehler: ${errorText}`;
        } else if (hintText) {
          detailNode = `Hinweis: ${hintText}`;
        } else if (progressJson) {
          detailNode = (
            <details>
              <summary style={{ cursor: "pointer" }}>Fortschritt anzeigen</summary>
              <pre style={{ margin: "0.25rem 0", whiteSpace: "pre-wrap" }}>{progressJson}</pre>
            </details>
          );
        } else if (resultJson) {
          detailNode = (
            <details>
              <summary style={{ cursor: "pointer" }}>Details anzeigen</summary>
              <pre style={{ margin: "0.25rem 0", whiteSpace: "pre-wrap" }}>{resultJson}</pre>
            </details>
          );
        }

        const metadata = (entry.metadata ?? {}) as { label?: unknown };
        const metaLabel =
          typeof metadata.label === "string" && metadata.label.trim().length > 0 ? metadata.label : undefined;
        const jobLabel = metaLabel ?? JOB_LABELS[entry.jobName] ?? entry.jobName;

        return (
          <tr key={entry.id}>
            <td>{jobLabel}</td>
            <td>
              <span style={{ color: statusColor, fontWeight: 600 }}>{statusLabel}</span>
            </td>
            <td>{started}</td>
            <td>{finished}</td>
            <td>{duration}</td>
            <td className="muted" style={{ fontSize: "0.85rem" }}>
              {detailNode}
            </td>
          </tr>
        );
      }),
    [logs]
  );

  const showSkeleton = loading && logs.length === 0;
  const isEmptyState = !loading && logs.length === 0;

  return (
    <div className="page">
      <section className="card">
        <h2>Audit Log</h2>
        <p className="muted">
          Verfolge die letzten automatischen und manuellen Datenimporte. Gesamt: {total} Einträge.
        </p>

        <div style={{ margin: "1rem 0", display: "flex", gap: "1rem", alignItems: "center" }}>
          <label style={{ display: "flex", flexDirection: "column", minWidth: "220px" }}>
            <span className="meta-label" style={{ marginBottom: "0.35rem" }}>
              Job-Filter
            </span>
            <select value={jobFilter} onChange={(event) => setJobFilter(event.target.value)}>
              <option value="">Alle Jobs</option>
              <option value="euvd_ingestion">EUVD Sync</option>
              <option value="euvd_initial_sync">EUVD Initial Sync</option>
              <option value="cpe_sync">CPE Sync</option>
              <option value="cpe_initial_sync">CPE Initial Sync</option>
              <option value="nvd_sync">NVD Sync</option>
              <option value="nvd_initial_sync">NVD Initial Sync</option>
              <option value="manual_refresh">Manueller Refresh</option>
            </select>
          </label>
        </div>

        <div style={{ overflowX: "auto" }}>
          <table style={tableStyle}>
            <thead>
              <tr>
                <th>Job</th>
                <th>Status</th>
                <th>Gestartet</th>
                <th>Beendet</th>
                <th>Dauer</th>
                <th>Ergebnis / Fehler</th>
              </tr>
            </thead>
            <tbody>
              {showSkeleton && <AuditSkeletonRows rows={6} />}
              {!showSkeleton && rows}
              {isEmptyState && (
                <tr>
                  <td colSpan={6} style={{ padding: "1.5rem 0", textAlign: "center", color: "rgba(255,255,255,0.45)" }}>
                    Keine Einträge vorhanden.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
};

const AuditSkeletonRows = ({ rows }: { rows: number }) => (
  <>
    {Array.from({ length: rows }).map((_, index) => (
      <tr key={`audit-skeleton-${index}`}>
        <td>
          <SkeletonBlock height="0.85rem" width="75%" />
        </td>
        <td>
          <SkeletonBlock height="1.1rem" width="80px" radius={999} />
        </td>
        <td>
          <SkeletonBlock height="0.85rem" width="80%" />
        </td>
        <td>
          <SkeletonBlock height="0.85rem" width="70%" />
        </td>
        <td>
          <SkeletonBlock height="0.85rem" width="60px" />
        </td>
        <td>
          <SkeletonBlock height="0.85rem" />
        </td>
      </tr>
    ))}
  </>
);

const tableStyle: React.CSSProperties = {
  width: "100%",
  borderCollapse: "collapse",
};
