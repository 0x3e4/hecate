import React, { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import { Link, useNavigate } from "react-router-dom";

import { VulnerabilityPreview } from "../types";
import { searchVulnerabilities, getVulnerability, triggerVulnerabilityRefresh } from "../api/vulnerabilities";
import { fetchTodaySummary, type TodaySummaryResponse, type TodayCve } from "../api/stats";
import { SkeletonBlock } from "../components/Skeleton";
import { ReservedBadge } from "../components/ReservedBadge";
import { useI18n, type TranslateFn } from "../i18n/context";
import { getPublishedDisplay } from "../utils/published";
import { CvssMetricDisplay } from "../components/CvssMetricDisplay";
import { ExploitationSummary } from "../components/ExploitationSummary";
import { getPreferredCvssMetric } from "../utils/cvss";

export const DashboardPage = () => {
  const { t, locale } = useI18n();
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
        setToast({ type: "error", message: t(`Failed to fetch: ${trimmed}`, `Fehler beim Abrufen: ${trimmed}`) });
      }
    } finally {
      setQueryLoading(false);
    }
  }, [queryInput, navigate, t]);

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
        const errorMessages = errors.map((e) => e.message || t("Unknown error", "Unbekannter Fehler")).join("; ");
        setToast({
          type: "error",
          message: t(
            `Vulnerability not found in NVD/EUVD: ${errorMessages}`,
            `Schwachstelle nicht in NVD/EUVD gefunden: ${errorMessages}`
          ),
        });
      } else {
        setToast({
          type: "error",
          message: t(
            `Vulnerability "${queryNotFound}" could not be synchronized. Not available in NVD or EUVD.`,
            `Schwachstelle "${queryNotFound}" konnte nicht synchronisiert werden. Nicht in NVD oder EUVD vorhanden.`
          ),
        });
      }
    } catch (error) {
      console.error("Manual sync failed", error);
      setToast({
        type: "error",
        message: t(
          "Synchronization failed. NVD/EUVD may not contain this vulnerability.",
          "Synchronisation fehlgeschlagen. NVD/EUVD haben diese Schwachstelle möglicherweise nicht."
        ),
      });
    } finally {
      setSyncLoading(false);
    }
  }, [queryNotFound, navigate, t]);

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
        t={t}
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
      <TodayStats t={t} locale={locale} />
      <VulnerabilityList vulnerabilities={vulnerabilities} loading={loading} t={t} />

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
  t: TranslateFn;
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
  t,
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
      {isLoading && (
        <div style={{ marginBottom: "0.5rem" }}>
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
        </div>
      )}

      <div style={{ position: "relative", width: "100%", overflow: "hidden" }}>
        <input
          type="text"
          value={queryInput}
          onChange={(e: React.ChangeEvent<HTMLInputElement>) => {
            setQueryInput(e.target.value);
          }}
          onKeyDown={onKeyDown}
          placeholder={t("Enter vulnerability ID and press Enter", "Vulnerability ID eingeben und Enter drücken")}
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
            fontSize: "14px",
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
            title={t("Clear input", "Eingabe löschen")}
          >
            ×
          </button>
        )}
      </div>

      {/* Status messages */}
      {queryLoading && (
        <p style={{ margin: "0.75rem 0 0", color: "rgba(255,255,255,0.6)", fontSize: "0.9rem" }}>
          {t("Searching local database...", "Suche in lokaler Datenbank…")}
        </p>
      )}

      {syncLoading && (
        <p style={{ margin: "0.75rem 0 0", color: "rgba(255,193,7,0.9)", fontSize: "0.9rem" }}>
          {t("Loading from NVD/EUVD...", "Lade von NVD/EUVD…")}
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
                {t(`"${queryNotFound}" not found in local database`, `„${queryNotFound}" nicht in lokaler Datenbank`)}
              </p>
              <p style={{ margin: "0.5rem 0 0", color: "rgba(255,255,255,0.7)", fontSize: "0.9rem" }}>
                {t(
                  "This vulnerability has not been synchronized yet. Load it from official sources?",
                  "Die Schwachstelle wurde noch nicht synchronisiert. Soll sie von den offiziellen Quellen abgerufen werden?"
                )}
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
                  {t("Load from NVD/EUVD", "Von NVD/EUVD laden")}
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
                  {t("Cancel", "Abbrechen")}
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

/* ---------- Today's Vulnerability Statistics ---------- */

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "unknown"];
const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ff6b6b",
  high: "#ff922b",
  medium: "#fcc419",
  low: "#69db7c",
  unknown: "#808080",
};

const TodayStats = ({ t, locale }: { t: TranslateFn; locale: string }) => {
  const [data, setData] = useState<TodaySummaryResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedDate, setSelectedDate] = useState<string>("");

  useEffect(() => {
    const load = async () => {
      try {
        setLoading(true);
        const result = await fetchTodaySummary(selectedDate || undefined);
        setData(result);
      } catch (err) {
        console.error("Failed to load today stats", err);
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [selectedDate]);

  if (loading) return <TodayStatsSkeleton />;

  const datePicker = (
    <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
      {selectedDate && (
        <button
          onClick={() => setSelectedDate("")}
          title={t("Back to today", "Zurück zu heute")}
          style={{
            background: "rgba(255,255,255,0.06)",
            border: "1px solid rgba(255,255,255,0.12)",
            borderRadius: "6px",
            padding: "0.3rem 0.6rem",
            cursor: "pointer",
            color: "rgba(255,255,255,0.7)",
            fontSize: "0.8rem",
          }}
        >
          {t("Today", "Heute")}
        </button>
      )}
      <input
        type="date"
        value={selectedDate}
        max={new Date().toISOString().split("T")[0]}
        onChange={(e) => setSelectedDate(e.target.value)}
        style={{
          background: "rgba(255,255,255,0.06)",
          border: "1px solid rgba(255,255,255,0.12)",
          borderRadius: "6px",
          padding: "0.3rem 0.5rem",
          color: "rgba(255,255,255,0.7)",
          fontSize: "0.8rem",
          cursor: "pointer",
          colorScheme: "dark",
        }}
      />
    </div>
  );

  if (!data || data.total === 0) {
    return (
      <section className="card" style={{ marginBottom: "1.5rem" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <p className="muted" style={{ margin: 0 }}>
            {selectedDate
              ? t(
                  `No vulnerabilities published on ${new Date(selectedDate + "T00:00:00").toLocaleDateString(locale === "de" ? "de-DE" : "en-US")}.`,
                  `Keine Schwachstellen am ${new Date(selectedDate + "T00:00:00").toLocaleDateString("de-DE")} veröffentlicht.`
                )
              : t("No vulnerabilities published yet today.", "Heute wurden noch keine Schwachstellen veröffentlicht.")}
          </p>
          {datePicker}
        </div>
      </section>
    );
  }

  const todayDate = data.todayDate;

  const dqlQuote = (v: string) => `"${v.replace(/\//g, "\\/")}"`;

  const vendorDql = (vendorName: string) => {
    const q = `vendors:${dqlQuote(vendorName)} AND published:>=${todayDate}`;
    return `/vulnerabilities?search=${encodeURIComponent(q)}&mode=dql`;
  };

  const productDql = (vendorName: string, productName: string) => {
    const q = `vendors:${dqlQuote(vendorName)} AND products:${dqlQuote(productName)} AND published:>=${todayDate}`;
    return `/vulnerabilities?search=${encodeURIComponent(q)}&mode=dql`;
  };

  return (
    <section className="card" style={{ marginBottom: "1.5rem" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "1rem" }}>
        <span className="muted" style={{ fontSize: "0.9rem" }}>
          {selectedDate
            ? t(
                `${data.total.toLocaleString(locale)} vulnerabilities on ${new Date(selectedDate + "T00:00:00").toLocaleDateString(locale === "de" ? "de-DE" : "en-US")}`,
                `${data.total.toLocaleString(locale)} Schwachstellen am ${new Date(selectedDate + "T00:00:00").toLocaleDateString("de-DE")}`
              )
            : t(
                `${data.total.toLocaleString(locale)} vulnerabilities today`,
                `${data.total.toLocaleString(locale)} Schwachstellen heute`
              )}
        </span>
        {datePicker}
      </div>

      <div
        style={{
          display: "grid",
          gap: "1rem",
          gridTemplateColumns: "repeat(auto-fit, minmax(min(100%, 280px), 1fr))",
        }}
      >
        <TodayMiniCard title={t("Vendors", "Hersteller")}>
          {data.vendors.length === 0 ? (
            <p className="muted" style={{ fontSize: "0.85rem", margin: 0 }}>
              {t("No vendor data.", "Keine Vendor-Daten.")}
            </p>
          ) : (
            <ul style={{ listStyle: "none", padding: 0, margin: 0, display: "grid", gap: "0.2rem" }}>
              {data.vendors.map((v) => (
                <TodayListItem
                  key={v.slug}
                  to={vendorDql(v.name)}
                  label={v.name}
                  count={v.doc_count}
                />
              ))}
            </ul>
          )}
        </TodayMiniCard>

        <TodayMiniCard title={t("Products", "Produkte")}>
          {data.products.length === 0 ? (
            <p className="muted" style={{ fontSize: "0.85rem", margin: 0 }}>
              {t("No product data.", "Keine Produkt-Daten.")}
            </p>
          ) : (
            <ul style={{ listStyle: "none", padding: 0, margin: 0, display: "grid", gap: "0.2rem" }}>
              {data.products.map((p) => (
                <TodayListItem
                  key={`${p.vendorSlug}:${p.slug}`}
                  to={productDql(p.vendorName, p.name)}
                  label={p.name}
                  sublabel={p.vendorName}
                  count={p.doc_count}
                />
              ))}
            </ul>
          )}
        </TodayMiniCard>

        <TodayMiniCard title={t("CVEs by severity", "CVEs nach Schweregrad")}>
          <TodayCveList cves={data.cves} todayDate={todayDate} />
        </TodayMiniCard>
      </div>
    </section>
  );
};

const TodayMiniCard = ({ title, children }: { title: string; children: ReactNode }) => (
  <div
    style={{
      background: "rgba(255,255,255,0.03)",
      borderRadius: "12px",
      padding: "1rem 1.25rem",
      border: "1px solid rgba(255,255,255,0.06)",
      minWidth: 0,
    }}
  >
    <h3 style={{ fontSize: "0.9rem", margin: "0 0 0.75rem" }}>{title}</h3>
    <div className="today-mini-card-scroll" style={{ maxHeight: "300px", overflowY: "auto", overflowX: "hidden" }}>
      {children}
    </div>
  </div>
);

const TodayListItem = ({ to, label, sublabel, count }: { to: string; label: string; sublabel?: string; count: number }) => {
  const [hovered, setHovered] = useState(false);
  return (
    <li style={{ minWidth: 0, overflow: "hidden" }}>
      <Link
        to={to}
        onMouseEnter={() => setHovered(true)}
        onMouseLeave={() => setHovered(false)}
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          borderRadius: "6px",
          textDecoration: "none",
          color: "#f5f7fa",
          fontSize: "0.85rem",
          transition: "background 0.15s ease",
          background: hovered ? "rgba(255,255,255,0.06)" : "transparent",
          minWidth: 0,
        }}
      >
        <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", minWidth: 0 }}>
          {label}
          {sublabel && (
            <span style={{ color: "rgba(255,255,255,0.35)", fontSize: "0.75rem", marginLeft: "0.4rem" }}>
              {sublabel}
            </span>
          )}
        </span>
        <span
          style={{
            fontSize: "0.75rem",
            color: "rgba(255,255,255,0.5)",
            flexShrink: 0,
            marginLeft: "0.5rem",
          }}
        >
          {count}
        </span>
      </Link>
    </li>
  );
};

const TodayCveList = ({ cves, todayDate }: { cves: TodayCve[]; todayDate: string }) => {
  const grouped = useMemo(() => {
    const groups: Record<string, TodayCve[]> = {};
    for (const cve of cves) {
      const sev = cve.severity || "unknown";
      if (!groups[sev]) groups[sev] = [];
      groups[sev].push(cve);
    }
    return groups;
  }, [cves]);

  const severityDql = (severity: string) => {
    const q = `cvss.severity:${severity} AND published:>=${todayDate}`;
    return `/vulnerabilities?search=${encodeURIComponent(q)}&mode=dql`;
  };

  return (
    <div style={{ display: "grid", gap: "0.75rem" }}>
      {SEVERITY_ORDER.map((severity) => {
        const items = grouped[severity];
        if (!items || items.length === 0) return null;
        const color = SEVERITY_COLORS[severity] ?? "#808080";
        return (
          <div key={severity}>
            <Link
              to={severityDql(severity)}
              className="today-severity-header"
              style={{
                display: "inline-block",
                fontSize: "0.75rem",
                fontWeight: 600,
                color,
                marginBottom: "0.35rem",
                textTransform: "uppercase",
                textDecoration: "none",
                padding: "0.15rem 0.4rem",
                borderRadius: "4px",
                transition: "background 0.15s ease",
              }}
            >
              {severity} ({items.length})
            </Link>
            <ul style={{ listStyle: "none", padding: 0, margin: 0, display: "grid", gap: "0.15rem" }}>
              {items.map((cve) => (
                <TodayCveItem key={cve.vulnId} cve={cve} color={color} />
              ))}
            </ul>
          </div>
        );
      })}
    </div>
  );
};

const TodayCveItem = ({ cve, color }: { cve: TodayCve; color: string }) => {
  const [hovered, setHovered] = useState(false);
  const aliases = (cve.aliases ?? []).filter(
    (a) => a && a.toUpperCase() !== cve.vulnId.toUpperCase()
  );
  return (
    <li>
      <Link
        to={`/vulnerability/${encodeURIComponent(cve.vulnId)}`}
        onMouseEnter={() => setHovered(true)}
        onMouseLeave={() => setHovered(false)}
        style={{
          fontSize: "0.8rem",
          color: "#f5f7fa",
          textDecoration: "none",
          display: "flex",
          gap: "0 0.5rem",
          alignItems: "baseline",
          borderRadius: "6px",
          transition: "background 0.15s ease",
          background: hovered ? "rgba(255,255,255,0.06)" : "transparent",
          flexWrap: "wrap",
        }}
      >
        <span
          style={{
            fontFamily: "monospace",
            fontSize: "0.75rem",
            color,
            flexShrink: 0,
          }}
        >
          {cve.vulnId}
        </span>
        {aliases.map((alias) => (
          <span
            key={alias}
            style={{
              fontFamily: "monospace",
              fontSize: "0.7rem",
              color: "rgba(255,255,255,0.45)",
              flexShrink: 0,
            }}
          >
            {alias}
          </span>
        ))}
      </Link>
    </li>
  );
};

const TodayStatsSkeleton = () => (
  <section className="card" style={{ marginBottom: "1.5rem" }}>
    <SkeletonBlock height="1.2rem" width="200px" style={{ marginBottom: "1rem" }} />
    <div
      style={{
        display: "grid",
        gap: "1rem",
        gridTemplateColumns: "repeat(auto-fit, minmax(min(100%, 280px), 1fr))",
      }}
    >
      {Array.from({ length: 3 }).map((_, i) => (
        <div
          key={i}
          style={{
            background: "rgba(255,255,255,0.03)",
            borderRadius: "12px",
            padding: "1rem 1.25rem",
            border: "1px solid rgba(255,255,255,0.06)",
          }}
        >
          <SkeletonBlock height="0.9rem" width="120px" style={{ marginBottom: "0.75rem" }} />
          <div style={{ display: "grid", gap: "0.5rem" }}>
            {Array.from({ length: 5 }).map((_, j) => (
              <SkeletonBlock key={j} height="1.4rem" />
            ))}
          </div>
        </div>
      ))}
    </div>
  </section>
);

interface VulnerabilityListProps {
  vulnerabilities: VulnerabilityPreview[];
  loading: boolean;
  t: TranslateFn;
}

const VulnerabilityList = ({ vulnerabilities, loading, t }: VulnerabilityListProps) => {
  const hasResults = vulnerabilities.length > 0;
  const showSkeleton = loading && !hasResults;

  const rows = useMemo(
    () =>
      vulnerabilities.map((vuln) => {
        const hasCve = Boolean(vuln.vulnId && vuln.vulnId.startsWith("CVE-"));
        const hasSource = Boolean(vuln.sourceId && (!hasCve || vuln.sourceId !== vuln.vulnId));
        const primaryId = vuln.vulnId || vuln.sourceId || t("Unknown-ID", "Unbekannte-ID");
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
          <DashboardVulnCard
            key={primaryId}
            vuln={vuln}
            primaryId={primaryId}
            hasCve={hasCve}
            hasSource={hasSource}
            ghsaAliases={ghsaAliases}
            malAliases={malAliases}
            pysecAliases={pysecAliases}
            remainingAliases={remainingAliases}
            exploitedHighlight={exploitedHighlight}
            vendors={vendors}
            products={products}
            versions={versions}
            published={published}
            isPublishedReserved={isPublishedReserved}
            epss={epss}
            cweList={cweList}
            preferredCvss={preferredCvss}
            t={t}
          />
        );
      }),
    [vulnerabilities, t]
  );

  return (
    <section className="card">
      <h2>{t("Latest Findings", "Neueste Treffer")}</h2>
      {showSkeleton ? (
        <DashboardSkeleton />
      ) : hasResults ? (
        rows
      ) : (
        <p>{t("No data loaded.", "Keine Daten geladen.")}</p>
      )}
      {loading && hasResults && (
        <p className="muted" style={{ marginTop: "0.75rem" }}>
          {t("Refreshing results...", "Aktualisiere Ergebnisse...")}
        </p>
      )}
    </section>
  );
};

const DashboardVulnCard = ({
  vuln,
  primaryId,
  hasCve,
  hasSource,
  ghsaAliases,
  malAliases,
  pysecAliases,
  remainingAliases,
  exploitedHighlight,
  vendors,
  products,
  versions,
  published,
  isPublishedReserved,
  epss,
  cweList,
  preferredCvss,
  t,
}: {
  vuln: VulnerabilityPreview;
  primaryId: string;
  hasCve: boolean;
  hasSource: boolean;
  ghsaAliases: string[];
  malAliases: string[];
  pysecAliases: string[];
  remainingAliases: string[];
  exploitedHighlight: React.CSSProperties | undefined;
  vendors: string;
  products: string;
  versions: string;
  published: string;
  isPublishedReserved: boolean;
  epss: string;
  cweList: string[];
  preferredCvss: ReturnType<typeof getPreferredCvssMetric>;
  t: TranslateFn;
}) => {
  const [copyFeedback, setCopyFeedback] = useState(false);

  const handleCopyInfo = (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    const ids = [vuln.vulnId, vuln.sourceId].filter(Boolean).join(", ");
    const severity = (vuln.severity ?? "unknown").toUpperCase();

    const lines: string[] = [ids];
    if (severity !== "UNKNOWN") lines.push(`Severity: ${severity}`);
    if (vendors && vendors !== "\u2014") lines.push(`Vendors: ${vendors}`);
    if (products && products !== "\u2014") lines.push(`Products: ${products}`);
    if (versions && versions !== "\u2014") lines.push(`Versions: ${versions}`);
    if (vuln.summary) lines.push(`\n${vuln.summary}`);

    void navigator.clipboard.writeText(lines.join("\n")).then(() => {
      setCopyFeedback(true);
      setTimeout(() => setCopyFeedback(false), 1500);
    });
  };

  return (
          <article
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
              <div style={{ display: "flex", alignItems: "center", gap: "0.4rem" }}>
                <button
                  type="button"
                  onClick={handleCopyInfo}
                  title={t("Copy vulnerability info", "Schwachstellen-Info kopieren")}
                  style={{
                    background: copyFeedback ? "rgba(105, 219, 124, 0.2)" : "rgba(255,255,255,0.06)",
                    border: copyFeedback ? "1px solid rgba(105, 219, 124, 0.4)" : "1px solid rgba(255,255,255,0.12)",
                    borderRadius: "6px",
                    padding: "0.2rem 0.4rem",
                    cursor: "pointer",
                    color: copyFeedback ? "#69db7c" : "rgba(255,255,255,0.55)",
                    display: "flex",
                    alignItems: "center",
                    transition: "all 0.2s ease",
                  }}
                >
                  {copyFeedback ? (
                    <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12" /></svg>
                  ) : (
                    <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2" /><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" /></svg>
                  )}
                </button>
                <span className={`tag ${vuln.severity ?? "unknown"}`}>{vuln.severity ?? "n/a"}</span>
              </div>
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
              <MetaItem label={t("Source", "Quelle")} value={vuln.source ?? "EUVD"} />
              {vuln.epssScore != null && (
                <MetaItem label="EPSS" value={epss} />
              )}
              {vuln.exploited != null && (
                <MetaItem
                  label="Exploited"
                  value={<ExploitationSummary exploited={vuln.exploited} exploitation={vuln.exploitation} />}
                />
              )}
              <MetaItem label={t("Assigner", "Assigner")} value={vuln.assigner ?? "—"} />
              <MetaItem
                label={t("Published", "Veröffentlicht")}
                value={isPublishedReserved ? <ReservedBadge /> : published}
              />
            </div>

            <div className="vuln-meta">
              <MetaItem label={t("Vendors", "Hersteller")} value={vendors} />
              <MetaItem label={t("Products", "Produkte")} value={products} />
              <MetaItem label={t("Versions", "Versionen")} value={versions} />
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
