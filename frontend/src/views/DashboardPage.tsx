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
        const hasCve = Boolean(vuln.vulnId && vuln.vulnId.startsWith("CVE-"));
        const hasSource = Boolean(vuln.sourceId && (!hasCve || vuln.sourceId !== vuln.vulnId));
        const primaryId = vuln.vulnId || vuln.sourceId || "Unbekannte-ID";
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
        const versions = vuln.productVersions?.length ? vuln.productVersions.join(", ") : "—";
        const cwes = vuln.cwes?.length ? vuln.cwes.join(", ") : "—";
        const aliases = buildAliasList(vuln.aliases, vuln.vulnId, vuln.sourceId);
        const ghsaIds = vuln.ghsaIds ?? [];
        const malAliases = aliases.filter((alias) => alias.toUpperCase().startsWith("MAL-"));
        const exploitedHighlight = vuln.exploited
          ? {
              background: "linear-gradient(315deg, rgba(255,82,82,0.2), rgba(255,82,82,0.05))",
              borderColor: "rgba(255,82,82,0.35)",
              boxShadow: "0 12px 24px rgba(255,82,82,0.12)",
            }
          : undefined;

        return (
          <article
            key={primaryId}
            className="vuln-card"
            style={exploitedHighlight}
          >
            <header className="vuln-header">
              <div>
                <div className="vuln-id">
                  {hasCve && <span className="chip">{vuln.vulnId}</span>}
                  {hasSource && <span className="chip">{vuln.sourceId}</span>}
                  {aliases.map((alias) => (
                    <span key={alias} className="chip" style={{ background: "rgba(92,132,255,0.2)" }}>
                      {alias}
                    </span>
                  ))}
                </div>
              </div>
              <span className={`tag ${vuln.severity ?? "unknown"}`}>{vuln.severity ?? "n/a"}</span>
            </header>

            <h3 className="vuln-title">
              <Link to={`/vulnerability/${primaryId}`}>{vuln.title}</Link>
            </h3>
            <div className="external-links" style={{ marginBottom: "0.5rem" }}>
              {hasCve && (
                <>
                  <a
                    href={`https://www.cve.org/CVERecord?id=${encodeURIComponent(vuln.vulnId)}`}
                    target="_blank"
                    rel="noreferrer"
                  >
                    <span role="img" aria-label="CVE">
                      🛡️
                    </span>
                    CVE
                  </a>
                  <a
                    href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(vuln.vulnId)}`}
                    target="_blank"
                    rel="noreferrer"
                  >
                    <span role="img" aria-label="NVD">
                      🗂️
                    </span>
                    NVD
                  </a>
                  <a
                    href={`https://cti.wazuh.com/vulnerabilities/cves/${encodeURIComponent(vuln.vulnId)}`}
                    target="_blank"
                    rel="noreferrer"
                  >
                    <span role="img" aria-label="Wazuh">
                      🌐
                    </span>
                    Wazuh
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
              {malAliases.map((alias) => (
                <a
                  key={alias}
                  href={`https://osv.dev/vulnerability/${encodeURIComponent(alias)}`}
                  target="_blank"
                  rel="noreferrer"
                >
                  <span role="img" aria-label="OSV">
                    🧩
                  </span>
                  OSV
                </a>
              ))}
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
              <MetaItem label="Versionen" value={versions} />
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

const normalizeId = (value?: string | null) => (value ?? "").trim().toUpperCase();

const buildAliasList = (aliases: string[] | undefined, vulnId?: string | null, sourceId?: string | null) => {
  const skip = new Set<string>();
  if (vulnId) skip.add(normalizeId(vulnId));
  if (sourceId) skip.add(normalizeId(sourceId));

  const seen = new Set<string>();
  const result: string[] = [];

  (aliases ?? []).forEach((alias) => {
    if (!alias) {
      return;
    }
    const trimmed = alias.trim();
    if (!trimmed) {
      return;
    }
    const normalized = normalizeId(trimmed);
    if (skip.has(normalized) || seen.has(normalized)) {
      return;
    }
    seen.add(normalized);
    result.push(trimmed);
  });

  return result;
};
