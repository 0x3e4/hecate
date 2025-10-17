import { useEffect, useMemo, useState } from "react";

import { fetchIngestionLogs } from "../api/audit";
import { IngestionLogEntry } from "../types";

const JOB_LABELS: Record<string, string> = {
  euvd_ingestion: "EUVD/NVD Ingestion",
  cpe_sync: "CPE Sync",
};

const STATUS_COLOR: Record<string, string> = {
  completed: "#8fffb0",
  running: "#ffd08f",
  failed: "#ffa3a3",
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
        const statusColor = STATUS_COLOR[entry.status] ?? "#d1d5db";

        return (
          <tr key={entry.id}>
            <td>{JOB_LABELS[entry.jobName] ?? entry.jobName}</td>
            <td>
              <span style={{ color: statusColor, fontWeight: 600 }}>{entry.status}</span>
            </td>
            <td>{started}</td>
            <td>{finished}</td>
            <td>{duration}</td>
            <td className="muted" style={{ fontSize: "0.85rem" }}>
              {entry.error ? `Fehler: ${entry.error}` : JSON.stringify(entry.result ?? {}, null, 0) || "-"}
            </td>
          </tr>
        );
      }),
    [logs]
  );

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
              <option value="euvd_ingestion">EUVD/NVD Ingestion</option>
              <option value="cpe_sync">CPE Sync</option>
            </select>
          </label>
          {loading && <span className="muted">Aktualisiere Daten…</span>}
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
            <tbody>{rows}</tbody>
          </table>
        </div>
      </section>
    </div>
  );
};

const tableStyle: React.CSSProperties = {
  width: "100%",
  borderCollapse: "collapse",
};
