import { useState, useEffect } from "react";
import type { CAPECInfo } from "../api/capec";
import { getCapecFromCwes } from "../api/capec";
import { useI18n } from "../i18n/context";

const INITIAL_DISPLAY_COUNT = 5;

const SEVERITY_COLORS: Record<string, string> = {
  "Very High": "#ff6b6b",
  High: "#ffa3a3",
  Medium: "#ffcc66",
  Low: "#8fffb0",
};

interface CapecListProps {
  cwes: string[];
  onCountChange?: (count: number) => void;
}

export const CapecList = ({ cwes, onCountChange }: CapecListProps) => {
  const { t } = useI18n();
  const [capecInfo, setCapecInfo] = useState<Record<string, CAPECInfo>>({});
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<boolean>(false);

  useEffect(() => {
    if (!cwes.length) {
      setCapecInfo({});
      onCountChange?.(0);
      return;
    }

    const fetchCapecInfo = async () => {
      try {
        setLoading(true);
        setError(null);
        const response = await getCapecFromCwes(cwes);
        setCapecInfo(response.capecs);
        onCountChange?.(Object.keys(response.capecs).length);
      } catch (err) {
        console.error("Failed to fetch CAPEC information", err);
        setError(t("Failed to load CAPEC information", "CAPEC-Informationen konnten nicht geladen werden"));
      } finally {
        setLoading(false);
      }
    };

    fetchCapecInfo();
  }, [cwes, onCountChange, t]);

  if (!cwes.length) {
    return <span className="muted">{t("No CWEs available, CAPEC mapping not possible.", "Keine CWEs vorhanden, CAPEC-Zuordnung nicht möglich.")}</span>;
  }

  if (loading) {
    return <div className="muted">{t("Loading CAPEC information...", "CAPEC-Informationen werden geladen...")}</div>;
  }

  if (error) {
    return <div className="muted">{error}</div>;
  }

  const entries = Object.entries(capecInfo);

  if (!entries.length) {
    return <span className="muted">{t("No CAPEC mappings found for available CWEs.", "Keine CAPEC-Zuordnungen für die vorhandenen CWEs gefunden.")}</span>;
  }

  const hasMore = entries.length > INITIAL_DISPLAY_COUNT;
  const visibleEntries = expanded ? entries : entries.slice(0, INITIAL_DISPLAY_COUNT);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
      {visibleEntries.map(([capecId, info]) => (
        <div key={capecId} className="cwe-item">
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.25rem", flexWrap: "wrap" }}>
            <a
              href={`https://capec.mitre.org/data/definitions/${capecId}.html`}
              target="_blank"
              rel="noreferrer"
              className="chip"
              style={{ textDecoration: "none" }}
            >
              {info.id}
            </a>
            <span style={{ fontWeight: 600, fontSize: "0.95rem" }}>
              {info.name}
            </span>
            {info.severity && (
              <span
                style={{
                  fontSize: "0.75rem",
                  fontWeight: 600,
                  padding: "0.15rem 0.4rem",
                  borderRadius: "0.25rem",
                  background: `${SEVERITY_COLORS[info.severity] ?? "#d1d5db"}22`,
                  color: SEVERITY_COLORS[info.severity] ?? "#d1d5db",
                  border: `1px solid ${SEVERITY_COLORS[info.severity] ?? "#d1d5db"}44`,
                }}
              >
                {info.severity}
              </span>
            )}
            {info.likelihood && (
              <span className="muted" style={{ fontSize: "0.8rem" }}>
                {t("Likelihood", "Wahrscheinlichkeit")}: {info.likelihood}
              </span>
            )}
          </div>
          {info.description && info.description !== info.name && (
            <div className="muted" style={{ fontSize: "0.9rem", paddingLeft: "0.25rem" }}>
              {info.description}
            </div>
          )}
        </div>
      ))}
      {hasMore && (
        <button
          type="button"
          onClick={() => setExpanded((prev) => !prev)}
          style={{
            background: "none",
            border: "1px solid rgba(255,255,255,0.15)",
            color: "rgba(255,255,255,0.6)",
            cursor: "pointer",
            padding: "0.4rem 0.75rem",
            fontSize: "0.85rem",
            borderRadius: "0.35rem",
            alignSelf: "flex-start",
          }}
        >
          {expanded
            ? t("Show less", "Weniger anzeigen")
            : t(
                `Show all ${entries.length} (${entries.length - INITIAL_DISPLAY_COUNT} more)`,
                `Alle ${entries.length} anzeigen (${entries.length - INITIAL_DISPLAY_COUNT} weitere)`
              )}
        </button>
      )}
    </div>
  );
};
