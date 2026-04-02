import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { ChangelogEntry, ChangelogResponse, fetchChangelog } from "../api/changelog";
import { SkeletonBlock } from "../components/Skeleton";
import { useSSE } from "../hooks/useSSE";
import { useI18n, type TranslateFn } from "../i18n/context";
import { formatDateTime } from "../utils/dateFormat";

const PAGE_SIZE = 50;

export const ChangelogPage = () => {
  const { t } = useI18n();
  const [data, setData] = useState<ChangelogResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
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
        setError(t("Failed to load changelog.", "Changelog konnte nicht geladen werden."));
      } finally {
        setLoading(false);
      }
    };

    load();
  }, [t, page, fromDate, toDate, sourceFilter, sseRefreshKey]);

  const totalPages = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1;

  const handleFilterReset = () => {
    setFromDate("");
    setToDate(new Date().toISOString().slice(0, 10));
    setSourceFilter("");
    setPage(0);
  };

  return (
    <div className="page">
      <section className="card">
        <h2>Changelog</h2>
        <p className="muted">
          {t(
            "Overview of the latest created and updated vulnerabilities.",
            "Übersicht über die neuesten Erstellungen und Aktualisierungen von Schwachstellen."
          )}
        </p>

        {/* Date filter */}
        <div style={{ display: "flex", flexWrap: "wrap", gap: "0.75rem", alignItems: "center", marginBottom: "1rem" }}>
          <label style={{ display: "flex", alignItems: "center", gap: "0.375rem", fontSize: "0.8125rem" }}>
            <span className="muted">{t("From", "Von")}</span>
            <input
              type="date"
              value={fromDate}
              onChange={e => { setFromDate(e.target.value); setPage(0); }}
              style={{
                padding: "0.35rem 0.5rem",
                borderRadius: "6px",
                border: "1px solid rgba(255,255,255,0.15)",
                background: "rgba(255,255,255,0.05)",
                color: "#fff",
                fontSize: "0.8125rem",
              }}
            />
          </label>
          <label style={{ display: "flex", alignItems: "center", gap: "0.375rem", fontSize: "0.8125rem" }}>
            <span className="muted">{t("To", "Bis")}</span>
            <input
              type="date"
              value={toDate}
              onChange={e => { setToDate(e.target.value); setPage(0); }}
              style={{
                padding: "0.35rem 0.5rem",
                borderRadius: "6px",
                border: "1px solid rgba(255,255,255,0.15)",
                background: "rgba(255,255,255,0.05)",
                color: "#fff",
                fontSize: "0.8125rem",
              }}
            />
          </label>
          <label style={{ display: "flex", alignItems: "center", gap: "0.375rem", fontSize: "0.8125rem" }}>
            <span className="muted">{t("Job", "Job")}</span>
            <select
              value={sourceFilter}
              onChange={e => { setSourceFilter(e.target.value); setPage(0); }}
              style={{
                padding: "0.35rem 0.5rem",
                borderRadius: "6px",
                border: "1px solid rgba(255,255,255,0.15)",
                background: "rgba(255,255,255,0.05)",
                color: "#fff",
                fontSize: "0.8125rem",
              }}
            >
              <option value="">{t("All", "Alle")}</option>
              <option value="NVD">NVD</option>
              <option value="EUVD">EUVD</option>
              <option value="GHSA">GHSA</option>
              <option value="KEV">KEV</option>
              <option value="CIRCL">CIRCL</option>
              <option value="OSV">OSV</option>
            </select>
          </label>
          {(fromDate || sourceFilter) && (
            <button
              onClick={handleFilterReset}
              style={{
                padding: "0.35rem 0.75rem",
                borderRadius: "6px",
                border: "1px solid rgba(255,255,255,0.15)",
                background: "rgba(255,255,255,0.05)",
                color: "rgba(255,255,255,0.7)",
                fontSize: "0.8125rem",
                cursor: "pointer",
              }}
            >
              {t("Reset", "Zurücksetzen")}
            </button>
          )}
          {data && (
            <span className="muted" style={{ fontSize: "0.75rem", marginLeft: "auto" }}>
              {data.total} {t("entries", "Einträge")}
            </span>
          )}
        </div>

        {showSkeleton && <ChangelogSkeleton />}
        {error && !data && <p className="muted">{error}</p>}

        {!showSkeleton && data && (
          <div style={{ opacity: loading ? 0.5 : 1, transition: "opacity 0.2s ease", pointerEvents: loading ? "none" : "auto" }}>
            <div style={{ display: "grid", gap: "0.75rem" }}>
              {data.entries.length === 0 && (
                <p className="muted">{t("No changes available.", "Keine Änderungen verfügbar.")}</p>
              )}
              {data.entries.map((entry) => (
                <ChangelogEntryCard key={entry.vulnId} entry={entry} t={t} />
              ))}
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div style={{ display: "flex", justifyContent: "center", alignItems: "center", gap: "1rem", marginTop: "1.25rem" }}>
                <button
                  onClick={() => setPage(p => Math.max(0, p - 1))}
                  disabled={page === 0}
                  style={{
                    padding: "0.4rem 0.85rem",
                    borderRadius: "6px",
                    border: "1px solid rgba(255,255,255,0.15)",
                    background: page === 0 ? "transparent" : "rgba(255,255,255,0.05)",
                    color: page === 0 ? "rgba(255,255,255,0.3)" : "rgba(255,255,255,0.8)",
                    cursor: page === 0 ? "default" : "pointer",
                    fontSize: "0.8125rem",
                  }}
                >
                  {t("Previous", "Zurück")}
                </button>
                <span style={{ fontSize: "0.8125rem", color: "rgba(255,255,255,0.6)" }}>
                  {page + 1} / {totalPages}
                </span>
                <button
                  onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
                  disabled={page >= totalPages - 1}
                  style={{
                    padding: "0.4rem 0.85rem",
                    borderRadius: "6px",
                    border: "1px solid rgba(255,255,255,0.15)",
                    background: page >= totalPages - 1 ? "transparent" : "rgba(255,255,255,0.05)",
                    color: page >= totalPages - 1 ? "rgba(255,255,255,0.3)" : "rgba(255,255,255,0.8)",
                    cursor: page >= totalPages - 1 ? "default" : "pointer",
                    fontSize: "0.8125rem",
                  }}
                >
                  {t("Next", "Weiter")}
                </button>
              </div>
            )}
          </div>
        )}
      </section>
    </div>
  );
};

const ChangelogSkeleton = () => (
  <div style={{ display: "grid", gap: "0.75rem" }}>
    {Array.from({ length: 10 }).map((_, index) => (
      <div
        key={index}
        style={{
          background: "rgba(255,255,255,0.03)",
          borderRadius: "12px",
          padding: "1rem 1.25rem",
          border: "1px solid rgba(255,255,255,0.06)",
          display: "grid",
          gap: "0.5rem",
        }}
      >
        <SkeletonBlock height="1rem" width="60%" />
        <SkeletonBlock height="0.75rem" width="40%" />
        <SkeletonBlock height="0.75rem" width="30%" />
      </div>
    ))}
  </div>
);

const ChangelogEntryCard = ({ entry, t }: { entry: ChangelogEntry; t: TranslateFn }) => {
  const [isExpanded, setIsExpanded] = useState(false);
  // Use latestChange.changeType for the badge, as it represents the actual change in this entry
  const actualChangeType = entry.latestChange?.changeType ?? entry.changeType;
  const changeTypeColor = actualChangeType === "insert" ? "#66d9e8" : "#ffd43b";
  const changeTypeLabel = actualChangeType === "insert" ? t("Created", "Erstellt") : t("Updated", "Aktualisiert");

  const severityColors: Record<string, string> = {
    critical: "#ff6b6b",
    high: "#ff922b",
    medium: "#fcc419",
    low: "#69db7c",
  };

  const severityColor = entry.severity
    ? severityColors[entry.severity.toLowerCase()] ?? "#808080"
    : "#808080";

  const formattedDateTime = formatDateTime(entry.timestamp);
  const [formattedDate, formattedTime] = formattedDateTime.split(', ');

  const renderChangeValue = (value: unknown) => {
    if (value === null) {
      return <span className="muted">—</span>;
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
          <pre className="json-block change-history-json">
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
    <div
      style={{
        background: "rgba(255,255,255,0.03)",
        borderRadius: "12px",
        border: "1px solid rgba(255,255,255,0.06)",
        overflow: "hidden",
        transition: "all 0.2s ease",
      }}
    >
      <div
        onClick={() => setIsExpanded(!isExpanded)}
        style={{
          padding: "1rem 1.25rem",
          position: "relative",
          cursor: "pointer",
        }}
        onMouseEnter={(e) => {
          e.currentTarget.style.background = "rgba(255,255,255,0.05)";
        }}
        onMouseLeave={(e) => {
          e.currentTarget.style.background = "transparent";
        }}
      >
        {/* Severity badge in upper right corner */}
        {entry.severity && (
          <span
            style={{
              position: "absolute",
              top: "1rem",
              right: "1.25rem",
              background: `${severityColor}20`,
              color: severityColor,
              padding: "0.2rem 0.5rem",
              borderRadius: "6px",
              fontSize: "0.75rem",
              fontWeight: 600,
              border: `1px solid ${severityColor}40`,
            }}
          >
            {entry.severity.toUpperCase()}
          </span>
        )}

        <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", flexWrap: "wrap", paddingRight: entry.severity ? "6rem" : "0" }}>
          <strong style={{ fontSize: "1rem" }}>{entry.vulnId}</strong>
          <span
            style={{
              background: `${changeTypeColor}20`,
              color: changeTypeColor,
              padding: "0.2rem 0.5rem",
              borderRadius: "6px",
              fontSize: "0.75rem",
              fontWeight: 600,
              border: `1px solid ${changeTypeColor}40`,
            }}
          >
            {changeTypeLabel}
          </span>
        </div>

        <Link
          to={`/vulnerability/${entry.vulnId}`}
          onClick={(e) => e.stopPropagation()}
          style={{
            fontSize: "0.95rem",
            marginTop: "0.5rem",
            display: "inline-block",
            textDecoration: "none",
            color: "inherit",
            transition: "color 0.2s ease",
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.color = "#ffd43b";
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.color = "inherit";
          }}
        >
          {entry.title}
        </Link>

        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            fontSize: "0.75rem",
            marginTop: "0.5rem",
          }}
        >
          <span className="muted">
            {formattedDate} {formattedTime}
          </span>
          <span className="muted">
            {entry.latestChange?.jobLabel ?? entry.latestChange?.jobName ?? entry.source}
          </span>
        </div>
      </div>

      {/* Expandable change details */}
      {isExpanded && entry.latestChange && (
        <div
          style={{
            padding: "1rem 1.25rem",
            borderTop: "1px solid rgba(255,255,255,0.06)",
            background: "rgba(0,0,0,0.2)",
          }}
        >
          <details className="change-history-entry" open>
            <summary className="change-history-entry__summary">
              <span className="change-history-entry__chevron" aria-hidden="true">
                &gt;
              </span>
              <span className="change-history-entry__timestamp">
                {formatDateTime(entry.latestChange.changedAt)}
              </span>
              <span className="change-history-entry__job">
                {entry.latestChange.jobLabel ?? entry.latestChange.jobName}
              </span>
              <span className="change-history-entry__type">
                {entry.latestChange.changeType === "insert" ? t("Created", "Erstellt") : t("Updated", "Aktualisiert")}
              </span>
              <span className="change-history-entry__fields">
                {entry.latestChange.fields.length === 0
                  ? t("No field changes", "Keine Feldänderungen")
                  : entry.latestChange.fields.length === 1
                  ? t("1 field changed", "1 Feld geändert")
                  : t(`${entry.latestChange.fields.length} fields changed`, `${entry.latestChange.fields.length} Felder geändert`)}
              </span>
            </summary>
            <div className="change-history-entry__body">
              {entry.latestChange.fields.length > 0 ? (
                <div className="change-history-fields">
                  {entry.latestChange.fields.map((field, index) => (
                    <div
                      key={`${field.name}-${index}`}
                      className="change-history-field"
                    >
                      <div className="change-history-field-name">{field.name}</div>
                      <div className="change-history-field-values">
                        <span className="change-history-field-label">{t("Old", "Alt")}</span>
                        <div className="change-history-field-value">
                          {renderChangeValue(field.previous)}
                        </div>
                        <span className="change-history-field-label">{t("New", "Neu")}</span>
                        <div className="change-history-field-value">
                          {renderChangeValue(field.current)}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="muted">{t("No field changes recorded.", "Keine Feldänderungen erfasst.")}</div>
              )}
            </div>
          </details>
        </div>
      )}
    </div>
  );
};
