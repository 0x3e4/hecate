import { useState, useEffect } from "react";
import "../screens/vulnerability-detail.css";
import type { CAPECInfo } from "../api/capec";
import { getCapecFromCwes } from "../api/capec";
import { useI18n } from "../i18n/context";
import { SeverityTag } from "../ui/primitives";
import { SkeletonBlock } from "./Skeleton";

const INITIAL_DISPLAY_COUNT = 5;

/** CAPEC grades severity on its own five-step scale; the top step reads as critical. */
const capecSeverityLevel = (severity: string) => (severity === "Very High" ? "critical" : severity);

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
    return (
      <div role="status">
        <span className="visually-hidden">{t("Loading CAPEC information...", "CAPEC-Informationen werden geladen...")}</span>
        <div className="vulnerability-detail-skeleton-stack">
          {Array.from({ length: 3 }).map((_, index) => (
            <SkeletonBlock key={index} height="3rem" radius={4} />
          ))}
        </div>
      </div>
    );
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
    <div className="vulnerability-detail-capec">
      <ul className="vulnerability-detail-entries">
        {visibleEntries.map(([capecId, info]) => (
          <li key={capecId} className="vulnerability-detail-entry">
            <a
              href={`https://capec.mitre.org/data/definitions/${capecId}.html`}
              target="_blank"
              rel="noreferrer"
              className="vulnerability-detail-entry-id"
            >
              {info.id}
            </a>
            <div className="vulnerability-detail-entry-body">
              <div className="vulnerability-detail-entry-head">
                <span className="vulnerability-detail-entry-name">{info.name}</span>
                {info.severity && (
                  <SeverityTag severity={capecSeverityLevel(info.severity)}>{info.severity}</SeverityTag>
                )}
                {info.likelihood && (
                  <span className="vulnerability-detail-entry-meta">
                    {t("Likelihood", "Wahrscheinlichkeit")}: {info.likelihood}
                  </span>
                )}
              </div>
              {info.description && info.description !== info.name && (
                <p className="vulnerability-detail-entry-text">{info.description}</p>
              )}
            </div>
          </li>
        ))}
      </ul>
      {hasMore && (
        <button
          type="button"
          className="btn btn-secondary"
          onClick={() => setExpanded((prev) => !prev)}
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
