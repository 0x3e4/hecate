import { useEffect, useMemo, useState, type ReactNode } from "react";

import { fetchIngestionLogs } from "../api/audit";
import { IngestionLogEntry } from "../types";
import { SkeletonBlock } from "../components/Skeleton";
import { formatDateTime } from "../utils/dateFormat";

const JOB_LABELS: Record<string, string> = {
  euvd_ingestion: "EUVD Sync",
  euvd_initial_sync: "EUVD Initial Sync",
  cpe_sync: "CPE Sync",
  cpe_initial_sync: "CPE Initial Sync",
  nvd_sync: "NVD Sync",
  nvd_initial_sync: "NVD Initial Sync",
  kev_sync: "CISA KEV Sync",
  kev_initial_sync: "CISA KEV Initial Sync",
  cwe_sync: "CWE Cache Refresh",
  cwe_initial_sync: "CWE Initial Cache Prefetch",
  manual_refresh: "Manueller Refresh",
  saved_search_created: "Gespeicherte Suche erstellt",
  saved_search_deleted: "Gespeicherte Suche gelöscht",
  ai_investigation: "AI-Analyse",
};

const STATUS_COLOR: Record<string, string> = {
  completed: "#8fffb0",
  running: "#ffcc66",
  failed: "#ffa3a3",
  timeout: "#fcd34d",
  overdue: "#fcd34d",
  cancelled: "#9ca3af",
};

const STATUS_LABELS: Record<string, string> = {
  completed: "Abgeschlossen",
  running: "Läuft",
  failed: "Fehlgeschlagen",
  cancelled: "Abgebrochen",
};

const PAGE_SIZE = 50;

export const AuditLogPage = () => {
  const [logs, setLogs] = useState<IngestionLogEntry[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [loading, setLoading] = useState<boolean>(false);
  const [jobFilter, setJobFilter] = useState<string>("");
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [page, setPage] = useState<number>(0);

  useEffect(() => {
    if (page === 0) {
      return;
    }
    const maxPage = Math.max(0, Math.ceil(total / PAGE_SIZE) - 1);
    if (page > maxPage) {
      setPage(maxPage);
    }
  }, [total, page]);

  useEffect(() => {
    const load = async () => {
      try {
        setLoading(true);
        const response = await fetchIngestionLogs({
          job: jobFilter || undefined,
          status: statusFilter || undefined,
          limit: PAGE_SIZE,
          offset: page * PAGE_SIZE,
        });
        setLogs(response.items);
        setTotal(response.total);
      } catch (error) {
        console.error("Failed to load ingestion logs", error);
      }
      setLoading(false);
    };

    load();
  }, [jobFilter, statusFilter, page]);

  const rows = useMemo(
    () =>
      logs.map((entry) => {
        const duration = entry.durationSeconds != null ? `${entry.durationSeconds.toFixed(1)}s` : "-";
        const finished = entry.finishedAt ? formatDateTime(entry.finishedAt) : "-";
        const started = formatDateTime(entry.startedAt);
        const isOverdue = entry.overdue === true;
        const statusKey = isOverdue ? "overdue" : entry.status;
        const statusColor = STATUS_COLOR[statusKey] ?? "#d1d5db";
        const statusLabel =
          isOverdue && entry.status === "running"
            ? "Läuft (Überfällig)"
            : STATUS_LABELS[entry.status] ?? entry.status;
        const cancelledNote = entry.status === "cancelled" && entry.error != null ? entry.error : undefined;
        const errorText = entry.error != null && entry.status !== "cancelled" ? entry.error : undefined;
        const hintText = entry.overdueReason ?? (cancelledNote ? `Job abgebrochen: ${cancelledNote}` : undefined);
        const progressJson = entry.progress ? JSON.stringify(entry.progress, null, 2) : undefined;
        const resultJson = entry.result ? JSON.stringify(entry.result, null, 2) : undefined;
        const metadata = (entry.metadata ?? {}) as { label?: unknown; clientIp?: unknown };
        const metaClientIp =
          typeof metadata.clientIp === "string" && metadata.clientIp.trim().length > 0
            ? (metadata.clientIp as string)
            : undefined;
        const metaLabel =
          typeof metadata.label === "string" && metadata.label.trim().length > 0 ? (metadata.label as string) : undefined;

        const detailElements: ReactNode[] = [];
        if (metaClientIp) {
          detailElements.push(<span key="ip">Client IP: {metaClientIp}</span>);
        }
        let detailNode: ReactNode | null = null;
        if (errorText) {
          detailElements.push(`Fehler: ${errorText}`);
        } else if (hintText) {
          detailElements.push(`Hinweis: ${hintText}`);
        } else if (progressJson) {
          detailElements.push(
            <details>
              <summary style={{ cursor: "pointer" }}>Fortschritt anzeigen</summary>
              <pre style={{ margin: "0.25rem 0", whiteSpace: "pre-wrap" }}>{progressJson}</pre>
            </details>,
          );
        } else if (resultJson) {
          detailElements.push(
            <details>
              <summary style={{ cursor: "pointer" }}>Details anzeigen</summary>
              <pre style={{ margin: "0.25rem 0", whiteSpace: "pre-wrap" }}>{resultJson}</pre>
            </details>,
          );
        }
        if (detailElements.length === 0) {
          detailNode = "-";
        } else if (detailElements.length === 1) {
          detailNode = detailElements[0];
        } else {
          detailNode = (
            <div style={{ display: "flex", flexDirection: "column", gap: "0.35rem" }}>
              {detailElements.map((element, index) => (
                <div key={`detail-${entry.id}-${index}`}>{element}</div>
              ))}
            </div>
          );
        }

        const jobLabel = metaLabel ?? JOB_LABELS[entry.jobName] ?? entry.jobName;

        return (
          <tr key={entry.id}>
            <td>{jobLabel}</td>
            <td>
              <span
                style={{
                  display: "inline-block",
                  padding: "0.25rem 0.5rem",
                  borderRadius: "0.35rem",
                  fontSize: "0.85rem",
                  fontWeight: 600,
                  background: `${statusColor}22`,
                  color: statusColor,
                  border: `1px solid ${statusColor}44`,
                }}
              >
                {statusLabel}
              </span>
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
  const hasPreviousPage = page > 0;
  const hasNextPage = (page + 1) * PAGE_SIZE < total;
  const pageStartIndexRaw = total === 0 ? 0 : page * PAGE_SIZE + 1;
  const pageEndIndexRaw =
    total === 0
      ? 0
      : logs.length > 0
        ? page * PAGE_SIZE + logs.length
        : Math.min(total, (page + 1) * PAGE_SIZE);
  const pageStartIndex = total === 0 ? 0 : Math.min(pageStartIndexRaw, total);
  const pageEndIndex = total === 0 ? 0 : Math.min(pageEndIndexRaw, total);

  return (
    <div className="page">
      <section className="card">
        <h2>Audit Log</h2>
        <p className="muted">
          Logs werden bei bestimmten Ereignissen generiert, die von Interesse sein könnten. Gesamt: {total} Einträge.
        </p>

        <div style={{ margin: "1rem 0", display: "flex", gap: "1rem", alignItems: "center", flexWrap: "wrap" }}>
          <label style={{ display: "flex", flexDirection: "column", minWidth: "220px" }}>
            <span className="meta-label" style={{ marginBottom: "0.35rem" }}>
              Job-Filter
            </span>
            <select
              value={jobFilter}
              onChange={(event) => {
                setJobFilter(event.target.value);
                setPage(0);
              }}
            >
              <option value="">Alle Jobs</option>
              <option value="euvd_ingestion">EUVD Sync</option>
              <option value="euvd_initial_sync">EUVD Initial Sync</option>
              <option value="cpe_sync">CPE Sync</option>
              <option value="cpe_initial_sync">CPE Initial Sync</option>
              <option value="nvd_sync">NVD Sync</option>
              <option value="nvd_initial_sync">NVD Initial Sync</option>
              <option value="kev_sync">CISA KEV Sync</option>
              <option value="kev_initial_sync">CISA KEV Initial Sync</option>
              <option value="cwe_sync">CWE Cache Refresh</option>
              <option value="cwe_initial_sync">CWE Initial Cache Prefetch</option>
              <option value="manual_refresh">Manueller Refresh</option>
              <option value="saved_search_created">Gespeicherte Suche erstellt</option>
              <option value="saved_search_deleted">Gespeicherte Suche gelöscht</option>
              <option value="ai_investigation">AI-Analyse</option>
            </select>
          </label>
          <label style={{ display: "flex", flexDirection: "column", minWidth: "180px" }}>
            <span className="meta-label" style={{ marginBottom: "0.35rem" }}>
              Status-Filter
            </span>
            <select
              value={statusFilter}
              onChange={(event) => {
                setStatusFilter(event.target.value);
                setPage(0);
              }}
            >
              <option value="">Alle Status</option>
              <option value="running">Läuft</option>
              <option value="completed">Abgeschlossen</option>
              <option value="failed">Fehlgeschlagen</option>
              <option value="cancelled">Abgebrochen</option>
            </select>
          </label>
          <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: "0.75rem", flexWrap: "wrap" }}>
            <span className="muted" style={{ fontSize: "0.85rem" }}>
              Zeige {total === 0 ? 0 : pageStartIndex}–{pageEndIndex} von {total}
            </span>
            <div style={{ display: "flex", gap: "0.5rem" }}>
              <button type="button" onClick={() => setPage((current) => Math.max(0, current - 1))} disabled={!hasPreviousPage || loading}>
                Zurück
              </button>
              <button
                type="button"
                onClick={() => setPage((current) => current + 1)}
                disabled={!hasNextPage || loading}
              >
                Weiter
              </button>
            </div>
          </div>
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
