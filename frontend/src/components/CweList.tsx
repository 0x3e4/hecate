import { useEffect, useState } from "react";
import "../screens/vulnerability-detail.css";
import type { CWEInfo } from "../api/cwe";
import { getCweBulk } from "../api/cwe";
import { useI18n } from "../i18n/context";
import { EmptyState } from "../ui/primitives";
import { SkeletonBlock } from "./Skeleton";

interface CweListProps {
  cwes: string[];
}

export const CweList = ({ cwes }: CweListProps) => {
  const { t } = useI18n();
  const [cweInfo, setCweInfo] = useState<Record<string, CWEInfo>>({});
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!cwes.length) {
      setCweInfo({});
      return;
    }

    const fetchCweInfo = async () => {
      try {
        setLoading(true);
        setError(null);
        const response = await getCweBulk(cwes);
        setCweInfo(response.cwes);
      } catch (err) {
        console.error("Failed to fetch CWE information", err);
        setError(t("Failed to load CWE information", "CWE-Informationen konnten nicht geladen werden"));
      } finally {
        setLoading(false);
      }
    };

    fetchCweInfo();
  }, [cwes, t]);

  if (!cwes.length) {
    return <EmptyState title={t("No CWEs listed.", "Keine CWEs hinterlegt.")} />;
  }

  if (loading) {
    return (
      <div role="status">
        <span className="visually-hidden">{t("Loading CWE information...", "CWE-Informationen werden geladen...")}</span>
        <div className="vulnerability-detail-skeleton-stack">
          {cwes.map((cwe) => (
            <SkeletonBlock key={cwe} height="3rem" radius={4} />
          ))}
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="link-list">
        {cwes.map((cwe) => (
          <a
            key={cwe}
            href={`https://cwe.mitre.org/data/definitions/${cwe.replace(/[^0-9]/g, "")}.html`}
            target="_blank"
            rel="noreferrer"
            className="vulnerability-detail-entry-id"
          >
            {cwe}
          </a>
        ))}
      </div>
    );
  }

  return (
    <ul className="vulnerability-detail-entries">
      {cwes.map((cwe) => {
        const normalized = cwe.replace(/[^0-9]/g, "");
        const info = cweInfo[normalized];

        return (
          <li key={cwe} className="vulnerability-detail-entry">
            <a
              href={`https://cwe.mitre.org/data/definitions/${normalized}.html`}
              target="_blank"
              rel="noreferrer"
              className="vulnerability-detail-entry-id"
            >
              {cwe}
            </a>
            <div className="vulnerability-detail-entry-body">
              {info ? (
                <div className="vulnerability-detail-entry-name">{info.name}</div>
              ) : (
                <div className="muted">{t("See CWE database for details", "Siehe CWE-Datenbank für Details")}</div>
              )}
              {info && info.description && info.description !== info.name && (
                <p className="vulnerability-detail-entry-text">{info.description}</p>
              )}
            </div>
          </li>
        );
      })}
    </ul>
  );
};
