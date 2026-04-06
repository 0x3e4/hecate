import { useEffect, useMemo, useState, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";

import { fetchIngestionLogs } from "../api/audit";
import { api } from "../api/client";
import { IngestionLogEntry } from "../types";
import { SkeletonBlock } from "../components/Skeleton";
import { useI18n } from "../i18n/context";
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
  capec_sync: "CAPEC Cache Refresh",
  capec_initial_sync: "CAPEC Initial Cache Prefetch",
  circl_sync: "CIRCL Enrichment Sync",
  ghsa_sync: "GHSA Sync",
  ghsa_initial_sync: "GHSA Initial Sync",
  manual_refresh: "Manual Refresh",
  saved_search_created: "Saved search created",
  saved_search_deleted: "Saved search deleted",
  ai_investigation: "AI analysis",
  ai_batch_investigation: "AI batch analysis",
  "sca-scan": "SCA Scan",
  osv_sync: "OSV Sync",
  osv_initial_sync: "OSV Initial Sync",
  mcp: "MCP",
};

const STATUS_COLOR: Record<string, string> = {
  completed: "#8fffb0",
  running: "#ffcc66",
  failed: "#ffa3a3",
  timeout: "#fcd34d",
  overdue: "#fcd34d",
  cancelled: "#9ca3af",
};

const PAGE_SIZE = 50;

export const AuditLogPage = () => {
  const { t, locale } = useI18n();
  const navigate = useNavigate();

  // --- System password gate ---
  const [authRequired, setAuthRequired] = useState<boolean | null>(null);
  const [authOk, setAuthOk] = useState(false);
  const [authPassword, setAuthPassword] = useState("");
  const [authError, setAuthError] = useState("");
  const [authChecking, setAuthChecking] = useState(false);

  useEffect(() => {
    api.get<{ required: boolean }>("/v1/status/system-auth").then((r) => {
      setAuthRequired(r.data.required);
      if (!r.data.required) setAuthOk(true);
    }).catch(() => {
      setAuthRequired(false);
      setAuthOk(true);
    });
  }, []);

  const handleAuthSubmit = async () => {
    setAuthChecking(true);
    setAuthError("");
    try {
      const r = await api.post<{ authenticated: boolean }>("/v1/status/system-auth", { password: authPassword });
      if (r.data.authenticated) {
        setAuthOk(true);
      }
    } catch {
      setAuthError(t("Invalid password.", "Falsches Passwort."));
    } finally {
      setAuthChecking(false);
    }
  };

  const [logs, setLogs] = useState<IngestionLogEntry[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [loading, setLoading] = useState<boolean>(false);
  const [jobFilter, setJobFilter] = useState<string>("");
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [page, setPage] = useState<number>(0);

  useEffect(() => {
    document.title = t("Hecate Cyber Defense - Audit Log", "Hecate Cyber Defense - Audit-Log");

    return () => {
      document.title = "Hecate Cyber Defense";
    };
  }, [t]);

  const localizeJobLabel = (jobName: string, fallbackLabel: string) => {
    switch (jobName) {
      case "manual_refresh":
        return t("Manual Refresh", "Manueller Refresh");
      case "saved_search_created":
        return t("Saved search created", "Gespeicherte Suche erstellt");
      case "saved_search_deleted":
        return t("Saved search deleted", "Gespeicherte Suche gelöscht");
      case "ai_investigation":
        return t("AI analysis", "AI-Analyse");
      case "ai_batch_investigation":
        return t("AI batch analysis", "AI Batch-Analyse");
      default:
        return fallbackLabel;
    }
  };

  const localizeStatus = (status: string) => {
    switch (status) {
      case "running":
        return t("Running", "Läuft");
      case "completed":
        return t("Completed", "Abgeschlossen");
      case "failed":
        return t("Failed", "Fehlgeschlagen");
      case "cancelled":
        return t("Cancelled", "Abgebrochen");
      default:
        return status;
    }
  };

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
            ? t("Running (Overdue)", "Läuft (Überfällig)")
            : localizeStatus(entry.status);
        const cancelledNote = entry.status === "cancelled" && entry.error != null ? entry.error : undefined;
        const errorText = entry.error != null && entry.status !== "cancelled" ? entry.error : undefined;
        const hintText =
          entry.overdueReason ?? (cancelledNote ? t(`Job cancelled: ${cancelledNote}`, `Job abgebrochen: ${cancelledNote}`) : undefined);
        const progressJson = entry.progress ? JSON.stringify(entry.progress, null, 2) : undefined;
        const resultJson = entry.result ? JSON.stringify(entry.result, null, 2) : undefined;
        const metadata = (entry.metadata ?? {}) as { label?: unknown; clientIp?: unknown };
        const metaClientIp =
          typeof metadata.clientIp === "string" && metadata.clientIp.trim().length > 0
            ? (metadata.clientIp as string)
            : undefined;
        const metaLabel =
          typeof metadata.label === "string" && metadata.label.trim().length > 0 ? (metadata.label as string) : undefined;

        const isAiJob = entry.jobName === "ai_investigation" || entry.jobName === "ai_batch_investigation";
        const tokenUsage =
          isAiJob && entry.result != null && typeof entry.result === "object"
            ? (entry.result as Record<string, unknown>).tokenUsage
            : undefined;
        const tokenUsageTyped =
          tokenUsage != null &&
          typeof tokenUsage === "object" &&
          "inputTokens" in tokenUsage &&
          "outputTokens" in tokenUsage
            ? (tokenUsage as { inputTokens: number; outputTokens: number })
            : undefined;

        const detailElements: ReactNode[] = [];
        if (metaClientIp) {
          detailElements.push(<span key="ip">Client IP: {metaClientIp}</span>);
        }
        if (tokenUsageTyped != null) {
          detailElements.push(
            <span key="tokens" style={{ fontFamily: "monospace", fontSize: "0.85rem" }}>
              {t("Tokens", "Tokens")}: {tokenUsageTyped.inputTokens.toLocaleString(locale)} {t("in", "in")} / {tokenUsageTyped.outputTokens.toLocaleString(locale)} {t("out", "out")}
            </span>,
          );
        }
        let detailNode: ReactNode | null = null;
        const ERROR_TRUNCATE_LEN = 120;
        if (errorText) {
          const prefix = t("Error: ", "Fehler: ");
          if (errorText.length > ERROR_TRUNCATE_LEN) {
            detailElements.push(
              <details key="error">
                <summary style={{ cursor: "pointer" }}>
                  {prefix}{errorText.slice(0, ERROR_TRUNCATE_LEN)}…
                </summary>
                <pre style={{ margin: "0.25rem 0", whiteSpace: "pre-wrap", fontSize: "0.8rem" }}>{errorText}</pre>
              </details>,
            );
          } else {
            detailElements.push(prefix + errorText);
          }
        } else if (hintText) {
          const prefix = t("Hint: ", "Hinweis: ");
          if (hintText.length > ERROR_TRUNCATE_LEN) {
            detailElements.push(
              <details key="hint">
                <summary style={{ cursor: "pointer" }}>
                  {prefix}{hintText.slice(0, ERROR_TRUNCATE_LEN)}…
                </summary>
                <pre style={{ margin: "0.25rem 0", whiteSpace: "pre-wrap", fontSize: "0.8rem" }}>{hintText}</pre>
              </details>,
            );
          } else {
            detailElements.push(prefix + hintText);
          }
        } else if (progressJson) {
          detailElements.push(
            <details>
              <summary style={{ cursor: "pointer" }}>{t("Show progress", "Fortschritt anzeigen")}</summary>
              <pre style={{ margin: "0.25rem 0", whiteSpace: "pre-wrap" }}>{progressJson}</pre>
            </details>,
          );
        } else if (resultJson) {
          detailElements.push(
            <details>
              <summary style={{ cursor: "pointer" }}>{t("Show details", "Details anzeigen")}</summary>
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

        const jobLabel = metaLabel ?? localizeJobLabel(entry.jobName, JOB_LABELS[entry.jobName] ?? entry.jobName);

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
    [logs, t]
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
    <>
    {authRequired && !authOk ? (
      <div className="dialog-overlay" style={{ backdropFilter: "none", WebkitBackdropFilter: "none" }} onClick={() => navigate(-1)}>
        <div className="dialog" onClick={(e) => e.stopPropagation()}>
          <h3>{t("System Password", "System-Passwort")}</h3>
          <p>{t("Enter the password to access this page.", "Passwort eingeben, um auf diese Seite zuzugreifen.")}</p>
          <input
            type="password"
            value={authPassword}
            onChange={(e) => setAuthPassword(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter") void handleAuthSubmit(); else if (e.key === "Escape") navigate(-1); }}
            placeholder={t("Password", "Passwort")}
            autoFocus
          />
          {authError && <p style={{ color: "#ffa3a3", fontSize: "0.85rem", margin: "0.5rem 0 0" }}>{authError}</p>}
          <div className="dialog-actions">
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => navigate(-1)}
            >
              {t("Cancel", "Abbrechen")}
            </button>
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => void handleAuthSubmit()}
              disabled={authChecking || !authPassword}
            >
              {authChecking ? t("Checking...", "Prüfe…") : t("Unlock", "Entsperren")}
            </button>
          </div>
        </div>
      </div>
    ) : authRequired === null ? (
      <div className="dialog-overlay" style={{ backdropFilter: "none", WebkitBackdropFilter: "none" }}>
        <div className="dialog">
          <p className="muted">{t("Loading...", "Laden…")}</p>
        </div>
      </div>
    ) : (
    <div className="page">
      <section className="card">
        <h2>Audit Log</h2>
        <p className="muted">
          {t(
            "Logs are generated for selected events that may be relevant. Total:",
            "Logs werden bei bestimmten Ereignissen generiert, die von Interesse sein könnten. Gesamt:"
          )}{" "}
          {total.toLocaleString(locale)} {t("entries.", "Einträge.")}
        </p>

        <div style={{ margin: "1rem 0", display: "flex", gap: "1rem", alignItems: "center", flexWrap: "wrap" }}>
          <label style={{ display: "flex", flexDirection: "column", minWidth: "220px" }}>
            <span className="meta-label" style={{ marginBottom: "0.35rem" }}>
              {t("Job Filter", "Job-Filter")}
            </span>
            <select
              value={jobFilter}
              onChange={(event) => {
                setJobFilter(event.target.value);
                setPage(0);
              }}
            >
              <option value="">{t("All jobs", "Alle Jobs")}</option>
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
              <option value="capec_sync">CAPEC Cache Refresh</option>
              <option value="capec_initial_sync">CAPEC Initial Cache Prefetch</option>
              <option value="circl_sync">CIRCL Enrichment Sync</option>
              <option value="ghsa_sync">GHSA Sync</option>
              <option value="ghsa_initial_sync">GHSA Initial Sync</option>
              <option value="manual_refresh">{t("Manual Refresh", "Manueller Refresh")}</option>
              <option value="saved_search_created">{t("Saved search created", "Gespeicherte Suche erstellt")}</option>
              <option value="saved_search_deleted">{t("Saved search deleted", "Gespeicherte Suche gelöscht")}</option>
              <option value="ai_investigation">{t("AI analysis", "AI-Analyse")}</option>
              <option value="ai_batch_investigation">{t("AI batch analysis", "AI Batch-Analyse")}</option>
              <option value="sca-scan">SCA Scan</option>
              <option value="osv_sync">OSV Sync</option>
              <option value="osv_initial_sync">OSV Initial Sync</option>
              <option value="mcp">MCP</option>
            </select>
          </label>
          <label style={{ display: "flex", flexDirection: "column", minWidth: "180px" }}>
            <span className="meta-label" style={{ marginBottom: "0.35rem" }}>
              {t("Status Filter", "Status-Filter")}
            </span>
            <select
              value={statusFilter}
              onChange={(event) => {
                setStatusFilter(event.target.value);
                setPage(0);
              }}
            >
              <option value="">{t("All statuses", "Alle Status")}</option>
              <option value="running">{t("Running", "Läuft")}</option>
              <option value="completed">{t("Completed", "Abgeschlossen")}</option>
              <option value="failed">{t("Failed", "Fehlgeschlagen")}</option>
              <option value="cancelled">{t("Cancelled", "Abgebrochen")}</option>
            </select>
          </label>
          <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: "0.75rem", flexWrap: "wrap" }}>
            <span className="muted" style={{ fontSize: "0.85rem" }}>
              {t("Showing", "Zeige")} {total === 0 ? 0 : pageStartIndex}–{pageEndIndex} {t("of", "von")} {total.toLocaleString(locale)}
            </span>
            <div style={{ display: "flex", gap: "0.5rem" }}>
              <button type="button" onClick={() => setPage((current) => Math.max(0, current - 1))} disabled={!hasPreviousPage || loading}>
                {t("Previous", "Zurück")}
              </button>
              <button
                type="button"
                onClick={() => setPage((current) => current + 1)}
                disabled={!hasNextPage || loading}
              >
                {t("Next", "Weiter")}
              </button>
            </div>
          </div>
        </div>

        <div style={{ overflowX: "auto" }}>
          <table style={tableStyle}>
            <thead>
              <tr>
                <th>{t("Job", "Job")}</th>
                <th>{t("Status", "Status")}</th>
                <th>{t("Started", "Gestartet")}</th>
                <th>{t("Finished", "Beendet")}</th>
                <th>{t("Duration", "Dauer")}</th>
                <th>{t("Result / Error", "Ergebnis / Fehler")}</th>
              </tr>
            </thead>
            <tbody>
              {showSkeleton && <AuditSkeletonRows rows={6} />}
              {!showSkeleton && rows}
              {isEmptyState && (
                <tr>
                  <td colSpan={6} style={{ padding: "1.5rem 0", textAlign: "center", color: "rgba(255,255,255,0.45)" }}>
                    {t("No entries available.", "Keine Einträge vorhanden.")}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
    )}
    </>
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
