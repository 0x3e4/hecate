import { useEffect, useMemo, useState, type ReactNode } from "react";

import { fetchIngestionLogs } from "../api/audit";
import { IngestionLogEntry } from "../types";
import { SkeletonBlock } from "../components/Skeleton";
import { AdminGate } from "../components/AdminGate";
import { useI18n } from "../i18n/context";
import { formatDateTime } from "../utils/dateFormat";
import { describeAuditActor } from "../utils/auditActor";
import { EmptyState, PageHeader } from "../ui/primitives";
import "../screens/audit.css";

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
  cert_feeds_sync: "Advisory Feed Sync",
  nuclei_templates_sync: "Nuclei Templates Sync",
  vulncheck_kev_sync: "VulnCheck KEV Sync",
  advisory_feed_added: "Advisory feed added",
  advisory_feed_updated: "Advisory feed updated",
  advisory_feed_removed: "Advisory feed removed",
  inventory_list_pulled: "Server list fetched",
  inventory_list_source_added: "Server list added",
  inventory_list_source_updated: "Server list updated",
  inventory_list_source_removed: "Server list removed",
  ghsa_sync: "GHSA Sync",
  ghsa_initial_sync: "GHSA Initial Sync",
  manual_refresh: "Manual Refresh",
  saved_search_created: "Saved search created",
  saved_search_updated: "Saved search updated",
  saved_search_deleted: "Saved search deleted",
  api_token_created: "API token created",
  api_token_revoked: "API token revoked",
  attack_path_analysis: "Attack Path narrative",
  ai_investigation: "AI analysis",
  ai_batch_investigation: "AI batch analysis",
  "sca-scan": "SCA Scan",
  osv_sync: "OSV Sync",
  osv_initial_sync: "OSV Initial Sync",
  mal_enrichment_backfill: "MAL-* deps.dev Enrichment",
  mcp: "MCP",
  mcp_oauth: "MCP",
  api_request: "API write",
  auth_login: "Sign-in",
  auth_logout: "Sign-out",
  auth_password_check: "Password check",
};

/** An outcome wears its outcome colour; everything else is neutral state. Never a severity colour. */
const STATUS_TONE: Record<string, string> = {
  completed: "success",
  running: "info",
  failed: "error",
  timeout: "info",
  overdue: "info",
  cancelled: "muted",
};

const PAGE_SIZE = 50;

const AuditLog = () => {
  const { t, locale } = useI18n();

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
      case "saved_search_updated":
        return t("Saved search updated", "Gespeicherte Suche aktualisiert");
      case "saved_search_deleted":
        return t("Saved search deleted", "Gespeicherte Suche gelöscht");
      case "api_token_created":
        return t("API token created", "API-Token erstellt");
      case "api_token_revoked":
        return t("API token revoked", "API-Token widerrufen");
      case "advisory_feed_added":
        return t("Advisory feed added", "Meldungs-Feed hinzugefügt");
      case "advisory_feed_updated":
        return t("Advisory feed updated", "Meldungs-Feed geändert");
      case "advisory_feed_removed":
        return t("Advisory feed removed", "Meldungs-Feed entfernt");
      case "inventory_list_pulled":
        return t("Server list fetched", "Serverliste abgerufen");
      case "inventory_list_source_added":
        return t("Server list added", "Serverliste hinzugefügt");
      case "inventory_list_source_updated":
        return t("Server list updated", "Serverliste geändert");
      case "inventory_list_source_removed":
        return t("Server list removed", "Serverliste entfernt");
      case "attack_path_analysis":
        return t("Attack Path narrative", "Attack-Path-Szenario");
      case "ai_investigation":
        return t("AI analysis", "AI-Analyse");
      case "ai_batch_investigation":
        return t("AI batch analysis", "AI Batch-Analyse");
      case "auth_login":
        return t("Sign-in", "Anmeldung");
      case "auth_logout":
        return t("Sign-out", "Abmeldung");
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
        const duration = entry.durationSeconds != null ? `${entry.durationSeconds.toFixed(1)}s` : "";
        const finished = entry.finishedAt ? formatDateTime(entry.finishedAt) : "";
        const started = formatDateTime(entry.startedAt);
        const isOverdue = entry.overdue === true;
        const statusKey = isOverdue ? "overdue" : entry.status;
        const statusTone = STATUS_TONE[statusKey];
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
        const metadata = (entry.metadata ?? {}) as Record<string, unknown>;
        const metaClientIp =
          typeof metadata.clientIp === "string" && metadata.clientIp.trim().length > 0
            ? (metadata.clientIp as string)
            : undefined;
        const metaLabel =
          typeof metadata.label === "string" && metadata.label.trim().length > 0 ? (metadata.label as string) : undefined;
        const isMcpJob = entry.jobName === "mcp" || entry.jobName === "mcp_oauth";
        // Request and sign-in events carry their facts in metadata: show it whole.
        const isJsonDetailJob = isMcpJob || entry.jobName === "api_request" || entry.jobName.startsWith("auth_");
        const actorView = describeAuditActor(metadata, t);

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
        if (isJsonDetailJob) {
          // Render MCP rows like every other audit job: a single JSON blob
          // under a "Show details" expander. Merges metadata and result so
          // both tool inputs and the returned shape are visible.
          const mcpBlob: Record<string, unknown> = { ...metadata };
          if (entry.result != null) {
            mcpBlob.result = entry.result;
          }
          detailElements.push(
            <details key="meta-details" className="audit-details">
              <summary>{t("Show details", "Details anzeigen")}</summary>
              <pre className="audit-pre">{JSON.stringify(mcpBlob, null, 2)}</pre>
            </details>,
          );
        } else if (metaClientIp) {
          detailElements.push(
            <span key="ip">
              Client IP: <span className="mono">{metaClientIp}</span>
            </span>,
          );
        }
        if (tokenUsageTyped != null) {
          detailElements.push(
            <span key="tokens">
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
              <details key="error" className="audit-details">
                <summary>
                  {prefix}{errorText.slice(0, ERROR_TRUNCATE_LEN)}…
                </summary>
                <pre className="audit-pre">{errorText}</pre>
              </details>,
            );
          } else {
            detailElements.push(prefix + errorText);
          }
        } else if (hintText) {
          const prefix = t("Hint: ", "Hinweis: ");
          if (hintText.length > ERROR_TRUNCATE_LEN) {
            detailElements.push(
              <details key="hint" className="audit-details">
                <summary>
                  {prefix}{hintText.slice(0, ERROR_TRUNCATE_LEN)}…
                </summary>
                <pre className="audit-pre">{hintText}</pre>
              </details>,
            );
          } else {
            detailElements.push(prefix + hintText);
          }
        } else if (progressJson) {
          detailElements.push(
            <details className="audit-details">
              <summary>{t("Show progress", "Fortschritt anzeigen")}</summary>
              <pre className="audit-pre">{progressJson}</pre>
            </details>,
          );
        } else if (resultJson && !isJsonDetailJob) {
          detailElements.push(
            <details className="audit-details">
              <summary>{t("Show details", "Details anzeigen")}</summary>
              <pre className="audit-pre">{resultJson}</pre>
            </details>,
          );
        }
        if (detailElements.length === 1) {
          detailNode = detailElements[0];
        } else if (detailElements.length > 1) {
          detailNode = (
            <div className="audit-detail-stack">
              {detailElements.map((element, index) => (
                <div key={`detail-${entry.id}-${index}`}>{element}</div>
              ))}
            </div>
          );
        }

        const jobLabel = localizeJobLabel(entry.jobName, metaLabel ?? JOB_LABELS[entry.jobName] ?? entry.jobName);

        return (
          <tr key={entry.id}>
            <td className="audit-cell-time" data-label={t("Started", "Gestartet")}>{started}</td>
            <td className="audit-cell-job">{jobLabel}</td>
            <td className="audit-cell-actor" data-label={t("Actor", "Akteur")}>
              {actorView ? (
                <span className={`audit-actor audit-actor--${actorView.kind}`} title={actorView.title}>
                  {actorView.label}
                </span>
              ) : null}
            </td>
            <td className="audit-cell-status">
              <span className={`audit-status${statusTone ? ` audit-status--${statusTone}` : ""}`}>{statusLabel}</span>
            </td>
            <td className="audit-cell-time" data-label={t("Finished", "Beendet")}>{finished}</td>
            <td className="audit-cell-duration" data-label={t("Duration", "Dauer")}>{duration}</td>
            <td className="audit-cell-detail">{detailNode}</td>
          </tr>
        );
      }),
    [logs, t]
  );

  const showSkeleton = loading && logs.length === 0;
  const isEmptyState = !loading && logs.length === 0;
  const isRefreshing = loading && logs.length > 0;
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
    <div className="page audit-page">
      <PageHeader
        title={t("Audit log", "Audit-Log")}
        description={
          <>
            {t(
              "Logs are generated for selected events that may be relevant. Total:",
              "Logs werden bei bestimmten Ereignissen generiert, die von Interesse sein könnten. Gesamt:"
            )}{" "}
            <span className="audit-figure">{total.toLocaleString(locale)}</span> {t("entries.", "Einträge.")}
          </>
        }
      />

      <div className="filter-row">
        <label className="audit-filter">
          <span>{t("Job Filter", "Job-Filter")}</span>
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
            <option value="cert_feeds_sync">Advisory Feed Sync</option>
            <option value="nuclei_templates_sync">Nuclei Templates Sync</option>
            <option value="vulncheck_kev_sync">VulnCheck KEV Sync</option>
            <option value="ghsa_sync">GHSA Sync</option>
            <option value="ghsa_initial_sync">GHSA Initial Sync</option>
            <option value="manual_refresh">{t("Manual Refresh", "Manueller Refresh")}</option>
            <option value="saved_search_created">{t("Saved search created", "Gespeicherte Suche erstellt")}</option>
            <option value="saved_search_deleted">{t("Saved search deleted", "Gespeicherte Suche gelöscht")}</option>
            <option value="api_token_created">{t("API token created", "API-Token erstellt")}</option>
            <option value="api_token_revoked">{t("API token revoked", "API-Token widerrufen")}</option>
            <option value="advisory_feed_added">{t("Advisory feed added", "Meldungs-Feed hinzugefügt")}</option>
            <option value="advisory_feed_updated">{t("Advisory feed updated", "Meldungs-Feed geändert")}</option>
            <option value="advisory_feed_removed">{t("Advisory feed removed", "Meldungs-Feed entfernt")}</option>
            <option value="inventory_list_pulled">{t("Server list fetched", "Serverliste abgerufen")}</option>
            <option value="inventory_list_source_added">{t("Server list added", "Serverliste hinzugefügt")}</option>
            <option value="inventory_list_source_updated">{t("Server list updated", "Serverliste geändert")}</option>
            <option value="inventory_list_source_removed">{t("Server list removed", "Serverliste entfernt")}</option>
            <option value="ai_investigation">{t("AI analysis", "AI-Analyse")}</option>
            <option value="ai_batch_investigation">{t("AI batch analysis", "AI Batch-Analyse")}</option>
            <option value="sca-scan">SCA Scan</option>
            <option value="osv_sync">OSV Sync</option>
            <option value="osv_initial_sync">OSV Initial Sync</option>
            <option value="mal_enrichment_backfill">MAL-* deps.dev Enrichment</option>
            <option value="mcp">MCP</option>
            <option value="api_request">{t("API write", "API-Schreibzugriff")}</option>
            <option value="auth_login">{t("Sign-in", "Anmeldung")}</option>
            <option value="auth_logout">{t("Sign-out", "Abmeldung")}</option>
            <option value="auth_password_check">{t("Password check", "Passwortprüfung")}</option>
          </select>
        </label>
        <label className="audit-filter">
          <span>{t("Status Filter", "Status-Filter")}</span>
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
        <div className="audit-pager">
          <span className="audit-range">
            {t("Showing", "Zeige")} {total === 0 ? 0 : pageStartIndex}-{pageEndIndex} {t("of", "von")} {total.toLocaleString(locale)}
          </span>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => setPage((current) => Math.max(0, current - 1))}
            disabled={!hasPreviousPage || loading}
          >
            {t("Previous", "Zurück")}
          </button>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => setPage((current) => current + 1)}
            disabled={!hasNextPage || loading}
          >
            {t("Next", "Weiter")}
          </button>
        </div>
      </div>

      <div className="table-scroll">
        <table
          className={`audit-table${isRefreshing ? " is-refreshing" : ""}`}
          aria-busy={loading || undefined}
        >
          <thead>
            <tr>
              <th>{t("Started", "Gestartet")}</th>
              <th>{t("Job", "Job")}</th>
              <th>{t("Actor", "Akteur")}</th>
              <th>{t("Status", "Status")}</th>
              <th>{t("Finished", "Beendet")}</th>
              <th className="audit-head-duration">{t("Duration", "Dauer")}</th>
              <th>{t("Result / Error", "Ergebnis / Fehler")}</th>
            </tr>
          </thead>
          <tbody>
            {showSkeleton && <AuditSkeletonRows rows={6} />}
            {!showSkeleton && rows}
            {isEmptyState && (
              <tr>
                <td colSpan={7} className="audit-cell-empty">
                  <EmptyState title={t("No entries available.", "Keine Einträge vorhanden.")} />
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

// Admins only, like the System page: nothing in AuditLog mounts, and so nothing
// is fetched, until a signed-in admin or the system password opens the page.
export const AuditLogPage = () => (
  <AdminGate overlayClassName="audit-gate" dialogClassName="audit-gate-dialog" titleClassName="audit-gate-title">
    <AuditLog />
  </AdminGate>
);

const AuditSkeletonRows = ({ rows }: { rows: number }) => (
  <>
    {Array.from({ length: rows }).map((_, index) => (
      <tr key={`audit-skeleton-${index}`} className="loading-appear" aria-hidden="true">
        <td className="audit-cell-time">
          <SkeletonBlock height="0.85rem" width="80%" radius={4} />
        </td>
        <td className="audit-cell-job">
          <SkeletonBlock height="0.85rem" width="75%" radius={4} />
        </td>
        <td className="audit-cell-actor">
          <SkeletonBlock height="0.85rem" width="60%" radius={4} />
        </td>
        <td className="audit-cell-status">
          <SkeletonBlock height="0.85rem" width="72px" radius={4} />
        </td>
        <td className="audit-cell-time">
          <SkeletonBlock height="0.85rem" width="70%" radius={4} />
        </td>
        <td className="audit-cell-duration">
          <SkeletonBlock height="0.85rem" width="48px" radius={4} />
        </td>
        <td className="audit-cell-detail">
          <SkeletonBlock height="0.85rem" radius={4} />
        </td>
      </tr>
    ))}
  </>
);
