import { useEffect, useState } from "react";

import { fetchStatsOverview, StatsResponse } from "../api/stats";

export const StatsPage = () => {
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(false);

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      try {
        const response = await fetchStatsOverview();
        setStats(response);
      } catch (error) {
        console.error("Failed to load stats", error);
      }
      setLoading(false);
    };

    load();
  }, []);

  return (
    <div className="page">
      <section className="card">
        <h2>Statistiken</h2>
        <p className="muted">Überblick über gesammelte Schwachstellen und CPE-Daten.</p>

        {loading && <p className="muted">Lade...</p>}

        {stats && (
          <div style={{ display: "grid", gap: "1.5rem" }}>
            <StatsSection stats={stats} />
          </div>
        )}
      </section>
    </div>
  );
};

const StatsSection = ({ stats }: { stats: StatsResponse }) => (
  <>
    <div>
      <h3>Vulnerabilities</h3>
      <p>
        <strong>{stats.vulnerabilities.total.toLocaleString()}</strong> Einträge
      </p>
      <h4>Quellen</h4>
      {stats.vulnerabilities.by_source.length === 0 ? (
        <p className="muted">Keine Daten vorhanden.</p>
      ) : (
        <ul>
          {stats.vulnerabilities.by_source.map((bucket) => (
            <li key={bucket.key || "unknown"}>
              {bucket.key || "unbekannt"}: {bucket.doc_count.toLocaleString()}
            </li>
          ))}
        </ul>
      )}

      <div style={{ display: "flex", gap: "2rem" }}>
        <div>
          <h4>Top Vendors</h4>
          {stats.vulnerabilities.top_vendors.length === 0 ? (
            <p className="muted">Keine Daten.</p>
          ) : (
            <ul>
              {stats.vulnerabilities.top_vendors.map((bucket) => (
                <li key={bucket.key}>
                  {bucket.key}: {bucket.doc_count.toLocaleString()}
                </li>
              ))}
            </ul>
          )}
        </div>
        <div>
          <h4>Top Produkte</h4>
          {stats.vulnerabilities.top_products.length === 0 ? (
            <p className="muted">Keine Daten.</p>
          ) : (
            <ul>
              {stats.vulnerabilities.top_products.map((bucket) => (
                <li key={bucket.key}>
                  {bucket.key}: {bucket.doc_count.toLocaleString()}
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>

    <div>
      <h3>CPE Katalog</h3>
      <p>
        <strong>{stats.cpe.total.toLocaleString()}</strong> Einträge
        <br />
        <strong>{stats.cpe.vendors.toLocaleString()}</strong> Vendors
        <br />
        <strong>{stats.cpe.products.toLocaleString()}</strong> Produkte
      </p>
    </div>
  </>
);
