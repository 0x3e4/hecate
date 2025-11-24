import { useEffect, useState } from "react";
import type { CWEInfo } from "../api/cwe";
import { getCweBulk } from "../api/cwe";

interface CweListProps {
  cwes: string[];
}

export const CweList = ({ cwes }: CweListProps) => {
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
        setError("CWE-Informationen konnten nicht geladen werden");
      } finally {
        setLoading(false);
      }
    };

    fetchCweInfo();
  }, [cwes]);

  if (!cwes.length) {
    return <span>—</span>;
  }

  if (loading) {
    return <div className="muted">CWE-Informationen werden geladen...</div>;
  }

  if (error) {
    return (
      <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
        {cwes.map((cwe) => (
          <a
            key={cwe}
            href={`https://cwe.mitre.org/data/definitions/${cwe.replace(/[^0-9]/g, "")}.html`}
            target="_blank"
            rel="noreferrer"
            className="chip"
          >
            {cwe}
          </a>
        ))}
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
      {cwes.map((cwe) => {
        const normalized = cwe.replace(/[^0-9]/g, "");
        const info = cweInfo[normalized];

        return (
          <div key={cwe} className="cwe-item">
            <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.25rem" }}>
              <a
                href={`https://cwe.mitre.org/data/definitions/${normalized}.html`}
                target="_blank"
                rel="noreferrer"
                className="chip"
                style={{ textDecoration: "none" }}
              >
                {cwe}
              </a>
              {info ? (
                <span style={{ fontWeight: 600, fontSize: "0.95rem" }}>
                  {info.name}
                </span>
              ) : (
                <span className="muted" style={{ fontSize: "0.9rem" }}>
                  See CWE database for details
                </span>
              )}
            </div>
            {info && info.description && info.description !== info.name && (
              <div className="muted" style={{ fontSize: "0.9rem", paddingLeft: "0.25rem" }}>
                {info.description}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
};
