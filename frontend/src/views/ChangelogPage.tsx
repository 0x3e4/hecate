import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ChangelogEntry, ChangelogResponse, fetchChangelog } from "../api/changelog";
import { SkeletonBlock } from "../components/Skeleton";
import { config } from "../config";

export const ChangelogPage = () => {
  const [data, setData] = useState<ChangelogResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const showSkeleton = loading && !data;

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      setError(null);
      try {
        const response = await fetchChangelog(100, 0);
        setData(response);
      } catch (err) {
        console.error("Failed to load changelog", err);
        setError("Changelog konnte nicht geladen werden.");
      } finally {
        setLoading(false);
      }
    };

    load();
  }, []);

  return (
    <div className="page">
      <section className="card">
        <h2>Changelog</h2>
        <p className="muted">
          Übersicht über die neuesten Erstellungen und Aktualisierungen von Schwachstellen.
        </p>

        {showSkeleton && <ChangelogSkeleton />}
        {error && <p className="muted">{error}</p>}

        {!showSkeleton && data && (
          <div style={{ display: "grid", gap: "0.75rem" }}>
            {data.entries.length === 0 && (
              <p className="muted">Keine Änderungen verfügbar.</p>
            )}
            {data.entries.map((entry) => (
              <ChangelogEntryCard key={entry.vulnId} entry={entry} />
            ))}
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

const ChangelogEntryCard = ({ entry }: { entry: ChangelogEntry }) => {
  const [isExpanded, setIsExpanded] = useState(false);
  // Use latestChange.changeType for the badge, as it represents the actual change in this entry
  const actualChangeType = entry.latestChange?.changeType ?? entry.changeType;
  const changeTypeColor = actualChangeType === "insert" ? "#66d9e8" : "#ffd43b";
  const changeTypeLabel = actualChangeType === "insert" ? "Erstellt" : "Aktualisiert";

  const severityColors: Record<string, string> = {
    critical: "#ff6b6b",
    high: "#ff922b",
    medium: "#fcc419",
    low: "#69db7c",
  };

  const severityColor = entry.severity
    ? severityColors[entry.severity.toLowerCase()] ?? "#748ffc"
    : "#748ffc";

  const timestamp = new Date(entry.timestamp);
  const formattedDate = timestamp.toLocaleDateString("de-DE", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    timeZone: config.timezone,
  });
  const formattedTime = timestamp.toLocaleTimeString("de-DE", {
    hour: "2-digit",
    minute: "2-digit",
    timeZone: config.timezone,
  });

  const formatChangeDate = (dateStr: string) => {
    try {
      const date = new Date(dateStr);
      return date.toLocaleString("de-DE", {
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        timeZone: config.timezone,
      });
    } catch {
      return dateStr;
    }
  };

  const renderChangeValue = (value: unknown) => {
    if (value === null) {
      return <span className="muted">—</span>;
    }
    if (typeof value === "boolean") {
      return value ? "ja" : "nein";
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
            e.currentTarget.style.color = "#748ffc";
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
          <span className="muted">{entry.source}</span>
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
                {formatChangeDate(entry.latestChange.changedAt)}
              </span>
              <span className="change-history-entry__job">
                {entry.latestChange.jobLabel ?? entry.latestChange.jobName}
              </span>
              <span className="change-history-entry__type">
                {entry.latestChange.changeType === "insert" ? "Erstellt" : "Aktualisiert"}
              </span>
              <span className="change-history-entry__fields">
                {entry.latestChange.fields.length === 0
                  ? "Keine Feldänderungen"
                  : entry.latestChange.fields.length === 1
                  ? "1 Feld geändert"
                  : `${entry.latestChange.fields.length} Felder geändert`}
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
                        <span className="change-history-field-label">Alt</span>
                        <div className="change-history-field-value">
                          {renderChangeValue(field.previous)}
                        </div>
                        <span className="change-history-field-label">Neu</span>
                        <div className="change-history-field-value">
                          {renderChangeValue(field.current)}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="muted">Keine Feldänderungen erfasst.</div>
              )}
            </div>
          </details>
        </div>
      )}
    </div>
  );
};
