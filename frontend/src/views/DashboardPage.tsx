import { useEffect, useMemo, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";

import { VulnerabilityPreview } from "../types";
import { searchVulnerabilities } from "../api/vulnerabilities";
import { SkeletonBlock } from "../components/Skeleton";
import { ReservedBadge } from "../components/ReservedBadge";
import { getPublishedDisplay } from "../utils/published";
import { CvssMetricDisplay } from "../components/CvssMetricDisplay";
import { ExploitationSummary } from "../components/ExploitationSummary";
import { getPreferredCvssMetric } from "../utils/cvss";

export const DashboardPage = () => {
  const [vulnerabilities, setVulnerabilities] = useState<VulnerabilityPreview[]>([]);
  const [loading, setLoading] = useState<boolean>(false);

  useEffect(() => {
    document.title = "Hecate Cyber Defense - Dashboard";

    return () => {
      document.title = "Hecate Cyber Defense";
    };
  }, []);

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
      <VulnerabilityList vulnerabilities={vulnerabilities} loading={loading} />
    </div>
  );
};

interface VulnerabilityListProps {
  vulnerabilities: VulnerabilityPreview[];
  loading: boolean;
}

const VulnerabilityList = ({ vulnerabilities, loading }: VulnerabilityListProps) => {
  const hasResults = vulnerabilities.length > 0;
  const showSkeleton = loading && !hasResults;

  const rows = useMemo(
    () =>
      vulnerabilities.map((vuln) => {
        const hasCve = Boolean(vuln.vulnId && vuln.vulnId.startsWith("CVE-"));
        const hasSource = Boolean(vuln.sourceId && (!hasCve || vuln.sourceId !== vuln.vulnId));
        const primaryId = vuln.vulnId || vuln.sourceId || "Unbekannte-ID";
        const { text: published, isReserved: isPublishedReserved } = getPublishedDisplay(
          vuln.published,
          "datetime"
        );
        const cvss = vuln.cvssScore != null ? vuln.cvssScore.toFixed(1) : "n/a";
        const epss =
          vuln.epssScore != null ? `${vuln.epssScore.toFixed(2)}%` : "n/a";
        const vendors = vuln.vendors?.length ? vuln.vendors.join(", ") : "—";
        const products = vuln.products?.length ? vuln.products.join(", ") : "—";
        const versions = vuln.productVersions?.length ? vuln.productVersions.join(", ") : "—";
        const cweList = vuln.cwes ?? [];
        const cwes = cweList.length ? cweList.join(", ") : "—";
        const aliases = buildAliasList(vuln.aliases, vuln.vulnId, vuln.sourceId);
        const ghsaAliases = aliases.filter((alias) => alias.toUpperCase().startsWith("GHSA-"));
        const preferredCvss = getPreferredCvssMetric(vuln.cvssMetrics ?? null);
        const malAliases = aliases.filter((alias) => alias.toUpperCase().startsWith("MAL-"));
        const pysecAliases = aliases.filter((alias) => alias.toUpperCase().startsWith("PYSEC-"));
        const remainingAliases = aliases.filter((alias) => {
          const upper = alias.toUpperCase();
          return !upper.startsWith("GHSA-") && !upper.startsWith("MAL-") && !upper.startsWith("PYSEC-");
        });
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
                  {ghsaAliases.map((alias) => (
                    <span key={alias} className="chip" style={{ background: "rgba(92,132,255,0.2)" }}>
                      {alias}
                    </span>
                  ))}
                  {malAliases.map((alias) => (
                    <span key={alias} className="chip" style={{ background: "rgba(92,132,255,0.2)" }}>
                      {alias}
                    </span>
                  ))}
                  {pysecAliases.map((alias) => (
                    <span key={alias} className="chip" style={{ background: "rgba(92,132,255,0.2)" }}>
                      {alias}
                    </span>
                  ))}
                  {remainingAliases.map((alias) => (
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
                    href={`https://cve.circl.lu/vuln/${encodeURIComponent(vuln.vulnId)}`}
                    target="_blank"
                    rel="noreferrer"
                  >
                    <span role="img" aria-label="CIRCL">
                      🌐
                    </span>
                    CIRCL
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
              {pysecAliases.map((alias) => (
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
              {ghsaAliases.map((alias) => (
                <a
                  key={alias}
                  href={`https://github.com/advisories/${alias}`}
                  target="_blank"
                  rel="noreferrer"
                >
                  <span role="img" aria-label="GHSA">
                    🔗
                  </span>
                  GHSA
                </a>
              ))}
            </div>

            <div className="vuln-meta">
              <MetaItem label="Quelle" value={vuln.source ?? "EUVD"} />
              <MetaItem label="CVSS" value={cvss} />
              <MetaItem label="EPSS" value={epss} />
              <MetaItem
                label="Exploited"
                value={<ExploitationSummary exploited={vuln.exploited} exploitation={vuln.exploitation} />}
              />
              <MetaItem label="Assigner" value={vuln.assigner ?? "—"} />
              <MetaItem
                label="Veröffentlicht"
                value={isPublishedReserved ? <ReservedBadge /> : published}
              />
            </div>

            <div className="vuln-meta">
              <MetaItem label="Vendors" value={vendors} />
              <MetaItem label="Produkte" value={products} />
              <MetaItem label="Versionen" value={versions} />
            </div>

            <div className={`vuln-summary ${preferredCvss ? "cvss-summary" : ""}`}>
              {preferredCvss ? (
                <CvssMetricDisplay
                  metric={preferredCvss}
                  showVector={false}
                  showScores={false}
                />
              ) : (
                <p>{vuln.summary}</p>
              )}
              {cweList.length > 0 && (
                <div className="cvss-summary-cwes">
                  {cweList.map((cwe) => (
                    <span key={cwe} className="chip cwe-chip">
                      {cwe}
                    </span>
                  ))}
                </div>
              )}
            </div>
          </article>
        );
      }),
    [vulnerabilities]
  );

  return (
    <section className="card">
      <h2>Neueste Treffer</h2>
      {showSkeleton ? (
        <DashboardSkeleton />
      ) : hasResults ? (
        rows
      ) : (
        <p>Keine Daten geladen.</p>
      )}
      {loading && hasResults && (
        <p className="muted" style={{ marginTop: "0.75rem" }}>
          Aktualisiere Ergebnisse…
        </p>
      )}
    </section>
  );
};

const DashboardSkeleton = () => (
  <div style={{ display: "grid", gap: "1rem" }}>
    {Array.from({ length: 3 }).map((_, index) => (
      <article
        key={index}
        className="vuln-card"
        style={{ borderColor: "rgba(255,255,255,0.08)", background: "rgba(8,10,18,0.6)" }}
      >
        <div className="vuln-header" style={{ alignItems: "center" }}>
          <div style={{ flex: 1 }}>
            <SkeletonBlock height="0.85rem" width="80%" />
            <div style={{ display: "flex", gap: "0.5rem", marginTop: "0.75rem", flexWrap: "wrap" }}>
              {Array.from({ length: 3 }).map((_, chipIndex) => (
                <SkeletonBlock key={chipIndex} height="1.25rem" width="90px" radius={999} />
              ))}
            </div>
          </div>
          <SkeletonBlock height="1.2rem" width="70px" radius={999} />
        </div>

        <SkeletonBlock height="1.4rem" width="65%" style={{ margin: "1.25rem 0 0.75rem" }} />

        <div style={{ display: "grid", gap: "0.65rem", marginBottom: "0.75rem" }}>
          {Array.from({ length: 2 }).map((_, metaRow) => (
            <div key={metaRow} style={{ display: "flex", flexWrap: "wrap", gap: "1rem" }}>
              {Array.from({ length: 4 }).map((_, metaIndex) => (
                <SkeletonBlock key={metaIndex} height="1.2rem" width="140px" />
              ))}
            </div>
          ))}
        </div>

        <SkeletonBlock height="4.5rem" />
      </article>
    ))}
  </div>
);

interface MetaItemProps {
  label: string;
  value: ReactNode;
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
