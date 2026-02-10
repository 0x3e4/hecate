import React, { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import { Link, useNavigate } from "react-router-dom";

import { VulnerabilityPreview } from "../types";
import { searchVulnerabilities, getVulnerability, triggerVulnerabilityRefresh } from "../api/vulnerabilities";
import { SkeletonBlock } from "../components/Skeleton";
import { ReservedBadge } from "../components/ReservedBadge";
import { getPublishedDisplay } from "../utils/published";
import { CvssMetricDisplay } from "../components/CvssMetricDisplay";
import { ExploitationSummary } from "../components/ExploitationSummary";
import { getPreferredCvssMetric } from "../utils/cvss";

export const DashboardPage = () => {
  const navigate = useNavigate();
  const [vulnerabilities, setVulnerabilities] = useState<VulnerabilityPreview[]>([]);
  const [loading, setLoading] = useState<boolean>(false);

  // Single vulnerability query state
  const [queryInput, setQueryInput] = useState<string>("");
  const [queryLoading, setQueryLoading] = useState<boolean>(false);
  const [queryNotFound, setQueryNotFound] = useState<string | null>(null);
  const [syncLoading, setSyncLoading] = useState<boolean>(false);
  const [toast, setToast] = useState<{ message: string; type: "success" | "error" } | null>(null);

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

  // Auto-dismiss toast after 5 seconds
  useEffect(() => {
    if (!toast) return;
    const timer = setTimeout(() => setToast(null), 5000);
    return () => clearTimeout(timer);
  }, [toast]);

  const handleQuerySearch = useCallback(async () => {
    const trimmed = queryInput.trim().toUpperCase();
    if (!trimmed) return;

    setQueryLoading(true);
    setQueryNotFound(null);
    setToast(null);

    try {
      const vuln = await getVulnerability(trimmed);
      const vulnIdForRoute = vuln.vulnId || vuln.sourceId || trimmed;
      navigate(`/vulnerability/${encodeURIComponent(vulnIdForRoute)}`);
    } catch (error: unknown) {
      const axiosError = error as { response?: { status?: number } };
      if (axiosError.response?.status === 404) {
        setQueryNotFound(trimmed);
      } else {
        setToast({ type: "error", message: `Fehler beim Abrufen: ${trimmed}` });
      }
    } finally {
      setQueryLoading(false);
    }
  }, [queryInput, navigate]);

  const handleManualSync = useCallback(async () => {
    if (!queryNotFound) return;

    setSyncLoading(true);
    setToast(null);

    const isCve = queryNotFound.toUpperCase().startsWith("CVE-");
    const payload = isCve
      ? { vulnIds: [queryNotFound] }
      : { sourceIds: [queryNotFound] };

    try {
      const response = await triggerVulnerabilityRefresh(payload);

      const hasInsertedOrUpdated = response.results.some(
        (r) => r.status === "inserted" || r.status === "updated"
      );
      const errors = response.results.filter((r) => r.status === "error");

      if (hasInsertedOrUpdated) {
        setQueryNotFound(null);
        setQueryInput("");
        navigate(`/vulnerability/${encodeURIComponent(queryNotFound)}`);
      } else if (errors.length > 0) {
        const errorMessages = errors.map((e) => e.message || "Unbekannter Fehler").join("; ");
        setToast({
          type: "error",
          message: `Schwachstelle nicht in NVD/EUVD gefunden: ${errorMessages}`,
        });
      } else {
        setToast({
          type: "error",
          message: `Schwachstelle "${queryNotFound}" konnte nicht synchronisiert werden. Nicht in NVD oder EUVD vorhanden.`,
        });
      }
    } catch (error) {
      console.error("Manual sync failed", error);
      setToast({
        type: "error",
        message: `Synchronisation fehlgeschlagen. NVD/EUVD haben diese Schwachstelle möglicherweise nicht.`,
      });
    } finally {
      setSyncLoading(false);
    }
  }, [queryNotFound, navigate]);

  const handleQueryKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLInputElement>) => {
      if (e.key === "Enter" && !queryLoading && !syncLoading) {
        handleQuerySearch();
      }
    },
    [handleQuerySearch, queryLoading, syncLoading]
  );

  const handleClear = useCallback(() => {
    setQueryInput("");
    setQueryNotFound(null);
    setToast(null);
  }, []);

  return (
    <div className="page">
      <SingleVulnQuery
        queryInput={queryInput}
        setQueryInput={setQueryInput}
        queryLoading={queryLoading}
        queryNotFound={queryNotFound}
        syncLoading={syncLoading}
        onSearch={handleQuerySearch}
        onSync={handleManualSync}
        onKeyDown={handleQueryKeyDown}
        onClear={handleClear}
      />
      <VulnerabilityList vulnerabilities={vulnerabilities} loading={loading} />

      {/* Toast notification */}
      {toast && (
        <div
          role="status"
          aria-live="polite"
          style={{
            position: "fixed",
            bottom: "1.5rem",
            right: "1.5rem",
            padding: "1rem 1.5rem",
            borderRadius: "0.5rem",
            background: toast.type === "error" ? "rgba(255,82,82,0.95)" : "rgba(76,175,80,0.95)",
            color: "#fff",
            boxShadow: "0 4px 12px rgba(0,0,0,0.3)",
            zIndex: 9999,
            maxWidth: "400px",
          }}
        >
          {toast.message}
        </div>
      )}
    </div>
  );
};

interface SingleVulnQueryProps {
  queryInput: string;
  setQueryInput: (value: string) => void;
  queryLoading: boolean;
  queryNotFound: string | null;
  syncLoading: boolean;
  onSearch: () => void;
  onSync: () => void;
  onKeyDown: (e: React.KeyboardEvent<HTMLInputElement>) => void;
  onClear: () => void;
}

const SingleVulnQuery = ({
  queryInput,
  setQueryInput,
  queryLoading,
  queryNotFound,
  syncLoading,
  onSync,
  onKeyDown,
  onClear,
}: SingleVulnQueryProps) => {
  const isLoading = queryLoading || syncLoading;
  const showNotFound = queryNotFound && !queryLoading;

  return (
    <section className="card" style={{ marginBottom: "1.5rem" }}>
      <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", marginBottom: "0.5rem" }}>
        <h2 style={{ margin: 0 }}>Schwachstelle abrufen</h2>
        {isLoading && (
          <span
            style={{
              display: "inline-block",
              width: "1rem",
              height: "1rem",
              border: "2px solid rgba(255,255,255,0.2)",
              borderTopColor: "rgba(255,255,255,0.8)",
              borderRadius: "50%",
              animation: "spin 0.8s linear infinite",
            }}
          />
        )}
      </div>

      <div style={{ position: "relative", width: "100%", overflow: "hidden" }}>
        <input
          type="text"
          value={queryInput}
          onChange={(e: React.ChangeEvent<HTMLInputElement>) => {
            setQueryInput(e.target.value);
          }}
          onKeyDown={onKeyDown}
          placeholder="Vulnerability ID eingeben und Enter drücken"
          disabled={isLoading}
          autoComplete="off"
          style={{
            boxSizing: "border-box",
            width: "100%",
            padding: "0.75rem 1rem",
            paddingRight: queryInput ? "2.5rem" : "1rem",
            borderRadius: "8px",
            border: showNotFound
              ? "1px solid rgba(255,193,7,0.5)"
              : "1px solid rgba(255,255,255,0.12)",
            background: showNotFound
              ? "rgba(255,193,7,0.08)"
              : "rgba(15, 18, 30, 0.85)",
            color: "#f5f7fa",
            fontSize: "1rem",
            transition: "border-color 0.2s, background 0.2s",
          }}
        />
        {queryInput && !isLoading && (
          <button
            onClick={onClear}
            style={{
              position: "absolute",
              right: "0.5rem",
              top: "50%",
              transform: "translateY(-50%)",
              background: "transparent",
              border: "none",
              color: "rgba(255,255,255,0.5)",
              cursor: "pointer",
              padding: "0.25rem",
              fontSize: "1.1rem",
              lineHeight: 1,
            }}
            title="Eingabe löschen"
          >
            ×
          </button>
        )}
      </div>

      {/* Status messages */}
      {queryLoading && (
        <p style={{ margin: "0.75rem 0 0", color: "rgba(255,255,255,0.6)", fontSize: "0.9rem" }}>
          Suche in lokaler Datenbank…
        </p>
      )}

      {syncLoading && (
        <p style={{ margin: "0.75rem 0 0", color: "rgba(255,193,7,0.9)", fontSize: "0.9rem" }}>
          Lade von NVD/EUVD…
        </p>
      )}

      {showNotFound && (
        <div
          style={{
            marginTop: "0.75rem",
            padding: "1rem",
            borderRadius: "0.5rem",
            background: "rgba(255,193,7,0.1)",
            border: "1px solid rgba(255,193,7,0.25)",
          }}
        >
          <div style={{ display: "flex", alignItems: "flex-start", gap: "0.75rem" }}>
            <span style={{ fontSize: "1.25rem", lineHeight: 1 }}>⚠️</span>
            <div style={{ flex: 1 }}>
              <p style={{ margin: 0, fontWeight: 500 }}>
                „{queryNotFound}" nicht in lokaler Datenbank
              </p>
              <p style={{ margin: "0.5rem 0 0", color: "rgba(255,255,255,0.7)", fontSize: "0.9rem" }}>
                Die Schwachstelle wurde noch nicht synchronisiert. Soll sie von den offiziellen Quellen abgerufen werden?
              </p>
              <div style={{ marginTop: "0.75rem", display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
                <button
                  onClick={onSync}
                  disabled={syncLoading}
                  className="btn"
                  style={{
                    padding: "0.5rem 1rem",
                    background: "rgba(255,193,7,0.3)",
                    border: "1px solid rgba(255,193,7,0.5)",
                    fontWeight: 500,
                  }}
                >
                  Von NVD/EUVD laden
                </button>
                <button
                  onClick={onClear}
                  className="btn"
                  style={{
                    padding: "0.5rem 1rem",
                    background: "transparent",
                    border: "1px solid rgba(255,255,255,0.2)",
                  }}
                >
                  Abbrechen
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* CSS for spinner animation */}
      <style>{`
        @keyframes spin {
          to { transform: rotate(360deg); }
        }
      `}</style>
    </section>
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
        const epss =
          vuln.epssScore != null ? `${vuln.epssScore.toFixed(2)}%` : "n/a";
        const ip = vuln.impactedProducts ?? [];
        let vendors: string;
        let products: string;
        let versions: string;
        if (ip.length > 0) {
          const vn = [...new Set(ip.map((p) => p.vendor?.name).filter(Boolean))];
          const pn = [...new Set(ip.map((p) => p.product?.name).filter(Boolean))];
          const vs = [...new Set(ip.flatMap((p) => p.versions ?? []).filter(Boolean))];
          vendors = vn.length ? vn.join(", ") : "—";
          products = pn.length ? pn.join(", ") : "—";
          versions = vs.length ? vs.join(", ") : "—";
        } else {
          vendors = vuln.vendors?.length ? vuln.vendors.join(", ") : "—";
          products = vuln.products?.length ? vuln.products.join(", ") : "—";
          versions = vuln.productVersions?.length ? vuln.productVersions.join(", ") : "—";
        }
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
            className={`vuln-card ${vuln.severity ?? "unknown"}`}
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
                  <a
                    href={`https://cti.wazuh.com/vulnerabilities/cves/${encodeURIComponent(vuln.vulnId)}`}
                    target="_blank"
                    rel="noreferrer"
                  >
                    <span role="img" aria-label="Wazuh">
                      🔮
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
              {vuln.epssScore != null && (
                <MetaItem label="EPSS" value={epss} />
              )}
              {vuln.exploited != null && (
                <MetaItem
                  label="Exploited"
                  value={<ExploitationSummary exploited={vuln.exploited} exploitation={vuln.exploitation} />}
                />
              )}
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
