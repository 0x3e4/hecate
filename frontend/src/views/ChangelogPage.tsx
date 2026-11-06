import { useEffect, useRef, useState } from "react";
import { LuChevronRight } from "react-icons/lu";
import { Link } from "react-router-dom";
import { ChangelogEntry, ChangelogResponse, fetchChangelog } from "../api/changelog";
import { SkeletonBlock } from "../components/Skeleton";
import { useSSE } from "../hooks/useSSE";
import { useI18n, type TranslateFn } from "../i18n/context";
import { formatDateTime } from "../utils/dateFormat";
import { EmptyState, ErrorState, IconButton, PageHeader, SeverityTag, severityLevel } from "../ui/primitives";
import "../screens/changelog.css";

const PAGE_SIZE = 50;

export const ChangelogPage = () => {
  const { t, locale } = useI18n();
  const [data, setData] = useState<ChangelogResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [errorCause, setErrorCause] = useState<unknown>(null);
  const [retryKey, setRetryKey] = useState(0);
  const [page, setPage] = useState(0);
  const [fromDate, setFromDate] = useState("");
  const [toDate, setToDate] = useState(() => new Date().toISOString().slice(0, 10));
  const [sourceFilter, setSourceFilter] = useState("");
  const showSkeleton = loading && !data;

  // SSE: refresh changelog when ingestion jobs complete
  const { jobs: sseJobs } = useSSE();
  const lastFinishedAt = useRef("");
  const [sseRefreshKey, setSseRefreshKey] = useState(0);

  useEffect(() => {
    let latest = "";
    for (const [, ev] of sseJobs) {
      if (ev.eventType === "job_completed" && ev.finishedAt && ev.finishedAt > latest) {
        latest = ev.finishedAt;
      }
    }
    if (latest && latest !== lastFinishedAt.current) {
      lastFinishedAt.current = latest;
      setSseRefreshKey((k) => k + 1);
    }
  }, [sseJobs]);

  // Polling fallback: SSE may be interrupted by proxies (e.g. Cloudflare)
  useEffect(() => {
    const interval = setInterval(() => setSseRefreshKey((k) => k + 1), 60_000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    document.title = t("Hecate Cyber Defense - Changelog", "Hecate Cyber Defense - Changelog");

    return () => {
      document.title = "Hecate Cyber Defense";
    };
  }, [t]);

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      setError(null);
      try {
        // Convert date (YYYY-MM-DD) to ISO datetime for API
        const fromISO = fromDate ? `${fromDate}T00:00:00` : undefined;
        const toISO = toDate ? `${toDate}T23:59:59` : undefined;
        const response = await fetchChangelog(
          PAGE_SIZE,
          page * PAGE_SIZE,
          fromISO,
          toISO,
          sourceFilter || undefined,
        );
        setData(response);
      } catch (err) {
        console.error("Failed to load changelog", err);
        setErrorCause(err);
        setError(t("Failed to load changelog.", "Changelog konnte nicht geladen werden."));
      } finally {
        setLoading(false);
      }
    };

    load();
  }, [t, page, fromDate, toDate, sourceFilter, sseRefreshKey, retryKey]);

  const totalPages = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1;

  const handleFilterReset = () => {
    setFromDate("");
    setToDate(new Date().toISOString().slice(0, 10));
    setSourceFilter("");
    setPage(0);
  };

  return (
    <div className="page changelog-page">
      <PageHeader
        title="Changelog"
        description={t(
          "Overview of the latest created and updated vulnerabilities.",
          "Übersicht über die neuesten Erstellungen und Aktualisierungen von Schwachstellen."
        )}
      />

      {/* Date filter */}
      <div className="filter-row">
        <label className="changelog-filter">
          <span>{t("From", "Von")}</span>
          <input
            type="date"
            value={fromDate}
            onChange={e => { setFromDate(e.target.value); setPage(0); }}
          />
        </label>
        <label className="changelog-filter">
          <span>{t("To", "Bis")}</span>
          <input
            type="date"
            value={toDate}
            onChange={e => { setToDate(e.target.value); setPage(0); }}
          />
        </label>
        <label className="changelog-filter">
          <span>{t("Job", "Job")}</span>
          <select
            value={sourceFilter}
            onChange={e => { setSourceFilter(e.target.value); setPage(0); }}
          >
            <option value="">{t("All", "Alle")}</option>
            <option value="NVD">NVD</option>
            <option value="EUVD">EUVD</option>
            <option value="GHSA">GHSA</option>
            <option value="KEV">KEV</option>
            <option value="CIRCL">CIRCL</option>
            <option value="OSV">OSV</option>
            <option value="deps_dev">deps.dev</option>
          </select>
        </label>
        {(fromDate || sourceFilter) && (
          <button type="button" className="btn btn-secondary" onClick={handleFilterReset}>
            {t("Reset", "Zurücksetzen")}
          </button>
        )}
        {data && (
          <span className="changelog-count">
            {data.total.toLocaleString(locale)} {t("entries", "Einträge")}
          </span>
        )}
      </div>

      {showSkeleton && <ChangelogSkeleton />}
      {error && !data && <ErrorState title={error} error={errorCause} onRetry={() => setRetryKey((k) => k + 1)} />}

      {!showSkeleton && data && (
        <div className={`changelog-results${loading ? " is-loading" : ""}`}>
          {data.entries.length === 0 && (
            <EmptyState title={t("No changes available.", "Keine Änderungen verfügbar.")} />
          )}
          {data.entries.length > 0 && (
            <div className="table-scroll">
              <table className="changelog-table">
                <thead>
                  <tr>
                    <th className="changelog-cell-toggle">
                      <span className="visually-hidden">{t("Details", "Details")}</span>
                    </th>
                    <th>{t("Time", "Zeit")}</th>
                    <th>{t("Vulnerability", "Schwachstelle")}</th>
                    <th>{t("Severity", "Schweregrad")}</th>
                    <th>{t("Change", "Änderung")}</th>
                    <th>{t("Job", "Job")}</th>
                  </tr>
                </thead>
                <tbody>
                  {data.entries.map((entry) => (
                    <ChangelogEntryRow key={entry.vulnId} entry={entry} t={t} />
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="changelog-pager">
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => setPage(p => Math.max(0, p - 1))}
                disabled={page === 0}
              >
                {t("Previous", "Zurück")}
              </button>
              <span className="changelog-page-count">
                {page + 1} / {totalPages}
              </span>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
                disabled={page >= totalPages - 1}
              >
                {t("Next", "Weiter")}
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

const ChangelogSkeleton = () => (
  <div className="table-scroll" aria-hidden="true">
    <table className="changelog-table">
      <tbody>
        {Array.from({ length: 10 }).map((_, index) => (
          <tr key={index}>
            <td className="changelog-cell-toggle" />
            <td className="changelog-cell-time">
              <SkeletonBlock height="0.85rem" width="9rem" radius={4} />
            </td>
            <td className="changelog-cell-vuln">
              <SkeletonBlock height="0.85rem" width="60%" radius={4} />
            </td>
            <td className="changelog-cell-severity">
              <SkeletonBlock height="0.85rem" width="3.5rem" radius={4} />
            </td>
            <td className="changelog-cell-change">
              <SkeletonBlock height="0.85rem" width="4rem" radius={4} />
            </td>
            <td className="changelog-cell-job">
              <SkeletonBlock height="0.85rem" width="8rem" radius={4} />
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  </div>
);

/** Keyed by severityLevel(): a record with no severity, or an unrecognised one, reads "Unknown". */
const SEVERITY_LABELS: Record<string, [string, string]> = {
  critical: ["Critical", "Kritisch"],
  high: ["High", "Hoch"],
  medium: ["Medium", "Mittel"],
  low: ["Low", "Niedrig"],
  none: ["Unknown", "Unbekannt"],
};

const ChangelogEntryRow = ({ entry, t }: { entry: ChangelogEntry; t: TranslateFn }) => {
  const [isExpanded, setIsExpanded] = useState(false);
  // Use latestChange.changeType for the badge, as it represents the actual change in this entry
  const actualChangeType = entry.latestChange?.changeType ?? entry.changeType;
  const changeTypeLabel = actualChangeType === "insert" ? t("Created", "Erstellt") : t("Updated", "Aktualisiert");
  const severityLabel = SEVERITY_LABELS[severityLevel(entry.severity)];

  const formattedDateTime = formatDateTime(entry.timestamp);
  const [formattedDate, formattedTime] = formattedDateTime.split(', ');

  const renderChangeValue = (value: unknown) => {
    if (value === null) {
      return <span className="muted">n/a</span>;
    }
    if (typeof value === "boolean") {
      return value ? t("yes", "ja") : t("no", "nein");
    }
    if (typeof value === "number") {
      return value.toString();
    }
    if (typeof value === "string") {
      const trimmed = value.trim();
      if (!trimmed) {
        return <span className="muted">""</span>;
      }
      return value;
    }
    if (Array.isArray(value) || typeof value === "object") {
      try {
        return (
          <pre className="changelog-json">
            {JSON.stringify(value, null, 2)}
          </pre>
        );
      } catch {
        return String(value);
      }
    }
    return String(value);
  };

  return (
    <>
      <tr
        className={`changelog-row${isExpanded ? " is-expanded" : ""}`}
        onClick={() => setIsExpanded(!isExpanded)}
      >
        <td className="changelog-cell-toggle">
          {entry.latestChange && (
            <IconButton
              label={isExpanded ? t("Hide changes", "Änderungen ausblenden") : t("Show changes", "Änderungen anzeigen")}
              aria-expanded={isExpanded}
              className="changelog-toggle"
            >
              <LuChevronRight aria-hidden="true" />
            </IconButton>
          )}
        </td>
        <td className="changelog-cell-time">
          {formattedDate} {formattedTime}
        </td>
        <td className="changelog-cell-vuln">
          <Link
            to={`/vulnerability/${entry.vulnId}`}
            onClick={(e) => e.stopPropagation()}
            className="row-link"
          >
            <span className="mono">{entry.vulnId}</span>
            {entry.title !== entry.vulnId && <span className="changelog-title">{entry.title}</span>}
          </Link>
        </td>
        <td className="changelog-cell-severity">
          <SeverityTag severity={entry.severity}>{t(severityLabel[0], severityLabel[1])}</SeverityTag>
        </td>
        <td className="changelog-cell-change">
          <span className="tag">{changeTypeLabel}</span>
        </td>
        <td className="changelog-cell-job">
          {entry.latestChange?.jobLabel ?? entry.latestChange?.jobName ?? entry.source}
        </td>
      </tr>

      {/* Expandable change details */}
      {isExpanded && entry.latestChange && (
        <tr className="changelog-detail-row">
          <td colSpan={6}>
            <details className="changelog-change" open>
              <summary className="changelog-change-summary">
                <LuChevronRight className="changelog-change-chevron" aria-hidden="true" />
                <span className="changelog-change-time">
                  {formatDateTime(entry.latestChange.changedAt)}
                </span>
                <span>
                  {entry.latestChange.jobLabel ?? entry.latestChange.jobName}
                </span>
                <span>
                  {entry.latestChange.changeType === "insert" ? t("Created", "Erstellt") : t("Updated", "Aktualisiert")}
                </span>
                <span className="changelog-change-fields">
                  {entry.latestChange.fields.length === 0
                    ? t("No field changes", "Keine Feldänderungen")
                    : entry.latestChange.fields.length === 1
                    ? t("1 field changed", "1 Feld geändert")
                    : t(`${entry.latestChange.fields.length} fields changed`, `${entry.latestChange.fields.length} Felder geändert`)}
                </span>
              </summary>
              {entry.latestChange.fields.length > 0 ? (
                <div className="changelog-fields">
                  {entry.latestChange.fields.map((field, index) => (
                    <div
                      key={`${field.name}-${index}`}
                      className="changelog-field"
                    >
                      <div className="changelog-field-name mono">{field.name}</div>
                      <div className="changelog-field-values">
                        <div className="changelog-field-value">
                          <span className="changelog-field-label">{t("Old", "Alt")}</span>
                          {renderChangeValue(field.previous)}
                        </div>
                        <div className="changelog-field-value">
                          <span className="changelog-field-label">{t("New", "Neu")}</span>
                          {renderChangeValue(field.current)}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="muted">{t("No field changes recorded.", "Keine Feldänderungen erfasst.")}</div>
              )}
            </details>
          </td>
        </tr>
      )}
    </>
  );
};
