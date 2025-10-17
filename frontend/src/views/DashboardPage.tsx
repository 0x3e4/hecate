import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";

import { VulnerabilityPreview } from "../types";
import { searchVulnerabilities } from "../api/vulnerabilities";

export const DashboardPage = () => {
  const [vulnerabilities, setVulnerabilities] = useState<VulnerabilityPreview[]>([]);
  const [loading, setLoading] = useState<boolean>(false);

  useEffect(() => {
    const load = async () => {
      try {
        setLoading(true);
        const results = await searchVulnerabilities({
          searchTerm: null,
          limit: 20,
        });
        setVulnerabilities(results);
      } catch (error) {
        console.error("Failed to fetch vulnerabilities", error);
      }
      setLoading(false);
    };

    load();
  }, []);

  return (
    <div className="page">
      <VulnerabilityList vulnerabilities={vulnerabilities} />
      {loading && <p className="muted">Aktualisiere Ergebnisse…</p>}
    </div>
  );
};

interface VulnerabilityListProps {
  vulnerabilities: VulnerabilityPreview[];
}

const VulnerabilityList = ({ vulnerabilities }: VulnerabilityListProps) => {
  const hasResults = vulnerabilities.length > 0;

  const rows = useMemo(
    () =>
      vulnerabilities.map((vuln) => {
        const hasCve = Boolean(vuln.cveId && vuln.cveId.startsWith("CVE-"));
        const hasSource = Boolean(vuln.sourceId && (!hasCve || vuln.sourceId !== vuln.cveId));
        const primaryId = vuln.cveId || vuln.sourceId || "Unbekannte-ID";
        const published = vuln.published ? new Date(vuln.published).toLocaleString() : "unbekannt";
        const cvss = vuln.cvssScore != null ? vuln.cvssScore.toFixed(1) : "n/a";
        const epss = vuln.epssScore != null ? vuln.epssScore.toFixed(2) : "n/a";
        const epssPercentileValue = vuln.epssPercentile ?? null;
        const epssPct =
          epssPercentileValue != null
            ? `${(epssPercentileValue > 1 ? epssPercentileValue : epssPercentileValue * 100).toFixed(1)}%`
            : "n/a";
        const vendors = vuln.vendors?.length ? vuln.vendors.join(", ") : "—";
        const products = vuln.products?.length ? vuln.products.join(", ") : "—";
        const cwes = vuln.cwes?.length ? vuln.cwes.join(", ") : "—";
        const aliases = vuln.aliases?.filter(Boolean) ?? [];
        const ghsaIds = vuln.ghsaIds ?? [];

        return (
          <article key={primaryId} className="vuln-card">
            <header className="vuln-header">
              <div>
                <div className="vuln-id">
                  {hasCve && <span className="chip">{vuln.cveId}</span>}
                  {hasSource && <span className="chip">{vuln.sourceId}</span>}
                </div>
              </div>
              <span className={`tag ${vuln.severity ?? "unknown"}`}>{vuln.severity ?? "n/a"}</span>
            </header>

            <h3 className="vuln-title">
              <Link to={`/vulnerabilities/${primaryId}`}>{vuln.title}</Link>
            </h3>
            <div className="external-links" style={{ marginBottom: "0.5rem" }}>
              {hasCve && (
                <>
                  <a
                    href={`https://www.cve.org/CVERecord?id=${encodeURIComponent(vuln.cveId)}`}
                    target="_blank"
                    rel="noreferrer"
                  >
                    <span role="img" aria-label="CVE">
                      🛡️
                    </span>
                    CVE
                  </a>
                  <a
                    href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(vuln.cveId)}`}
                    target="_blank"
                    rel="noreferrer"
                  >
                    <span role="img" aria-label="NVD">
                      🗂️
                    </span>
                    NVD
                  </a>
                </>
              )}
              {vuln.sourceId && (
                <a
                  href={`https://euvd.enisa.europa.eu/vulnerability/${encodeURIComponent(vuln.sourceId)}`}
                  target="_blank"
                  rel="noreferrer"
                >
                  <span role="img" aria-label="EUVD">
                    🇪🇺
                  </span>
                  EUVD
                </a>
              )}
              {ghsaIds.map((alias) => (
                <a
                  key={alias}
                  href={`https://github.com/advisories/${alias}`}
                  target="_blank"
                  rel="noreferrer"
                >
                  <span role="img" aria-label="GHSA">
                    🔗
                  </span>
                  {alias}
                </a>
              ))}
            </div>

            <div className="vuln-meta">
              <MetaItem label="Quelle" value={vuln.source ?? "EUVD"} />
              <MetaItem label="CVSS" value={cvss} />
              <MetaItem label="EPSS" value={epss} />
              <MetaItem label="EPSS Perzentil" value={epssPct} />
              <MetaItem label="Exploited" value={formatBoolean(vuln.exploited)} />
              <MetaItem label="Assigner" value={vuln.assigner ?? "—"} />
              <MetaItem label="Veröffentlicht" value={published} />
            </div>

            <div className="vuln-meta">
              <MetaItem label="Vendors" value={vendors} />
              <MetaItem label="Produkte" value={products} />
              <MetaItem label="CWE" value={cwes} />
            </div>

            <p className="vuln-summary">{vuln.summary}</p>

            {vuln.aiAssessment ? (
              <div className="vuln-ai">
                <strong>AI-Analyse:</strong>{" "}
                {typeof vuln.aiAssessment.summary === "string"
                  ? vuln.aiAssessment.summary
                  : "Bewertung liegt vor"}
              </div>
            ) : (
              <div className="vuln-ai muted">Keine AI-Einschaetzung verfuegbar.</div>
            )}
          </article>
        );
      }),
    [vulnerabilities]
  );

  return (
    <section className="card">
      <h2>Neueste Treffer</h2>
      {hasResults ? rows : <p>Keine Daten geladen.</p>}
    </section>
  );
};

const formatBoolean = (value?: boolean | null) => {
  if (value == null) {
    return "unbekannt";
  }
  return value ? "ja" : "nein";
};

interface MetaItemProps {
  label: string;
  value: string;
}

const MetaItem = ({ label, value }: MetaItemProps) => (
  <div className="meta-item">
    <span className="meta-label">{label}</span>
    <span className="meta-value">{value}</span>
  </div>
);
