import "../screens/dashboard.css";

import React, { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Link, useNavigate } from "react-router-dom";
import { LuCheck, LuChevronLeft, LuChevronRight, LuCopy, LuSearch, LuTriangleAlert, LuX } from "react-icons/lu";

import { VulnerabilityPreview, type VulnerabilityRefreshStatus } from "../types";
import { searchVulnerabilities, getVulnerability, triggerVulnerabilityRefresh } from "../api/vulnerabilities";
import {
  fetchAttention,
  fetchTodaySummary,
  type AttentionItem,
  type AttentionResponse,
  type CertMention,
  type TodaySummaryResponse,
  type TodayCve,
  type SlugBucket,
  type ProductBucket,
} from "../api/stats";
import { fetchScanCoverage, type ScanCoverage } from "../api/scans";
import {
  ChipLinks,
  cveMatchesInventory,
  resolveCveScanId,
  scanChip,
  uniqueChips,
  useCveChips,
  type CoverageChip,
} from "../components/CoverageChips";
import { SkeletonBlock } from "../components/Skeleton";
import { ReservedBadge } from "../components/ReservedBadge";
import { useI18n, type TranslateFn } from "../i18n/context";
import { getCurrentTimezone } from "../timezone/storage";
import { useSSE } from "../hooks/useSSE";
import { getPublishedDisplay } from "../utils/published";
import { Toast, useToast } from "../components/Toast";
import { SEVERITY_ORDER, attentionRows, groupCves, productKey, quietFindings, severityLabel, type CveGroup } from "../utils/cveGroups";
import { getPreferredCvssMetric } from "../utils/cvss";
import { formatDateOnly } from "../utils/dateFormat";
import { formatEcosystemName } from "../utils/advisoryText";
import { safeHref } from "../utils/safeHref";
import { EmptyState, IconButton, PageHeader, Section, SeverityTag, Stat, severityLevel } from "../ui/primitives";

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
  const { toast, showToast, dismiss } = useToast();
  // Adapter so existing setToast({type,message}) / setToast(null) call sites keep working.
  const setToast = (next: { message: string; type: "success" | "error" } | null) =>
    next ? showToast(next.message, next.type) : dismiss();
  // Manual-sync is dispatched async (HTTP 202) and the real result lands on
  // the SSE bus as `vulnerability_refresh_<jobId>` — remember both the jobId
  // and the query ID so the matching effect below can navigate / toast.
  const [pendingSyncJob, setPendingSyncJob] = useState<{ jobId: string; query: string } | null>(null);
  const pendingSyncTimeoutRef = useRef<number | null>(null);

  // SSE: refresh dashboard when new vulnerabilities are ingested
  const { jobs: sseJobs } = useSSE();
  const sseNewVulnCount = useRef(0);
  const [sseRefreshKey, setSseRefreshKey] = useState(0);

  useEffect(() => {
    let count = 0;
    for (const [, ev] of sseJobs) {
      if (ev.eventType === "new_vulnerabilities") count++;
    }
    if (count > sseNewVulnCount.current) {
      sseNewVulnCount.current = count;
      setSseRefreshKey((k) => k + 1);
    }
  }, [sseJobs]);

  // SCA scan coverage for the Today widgets (best-effort; empty → no SCA chips).
  const [scanCoverage, setScanCoverage] = useState<ScanCoverage>({
    cveScan: {},
    productScan: {},
    scanTargets: {},
  });
  // Newly KEV-listed CVEs, independent of the selected day (best-effort; none → no panel).
  const [attention, setAttention] = useState<AttentionResponse | null>(null);
  useEffect(() => {
    let cancelled = false;
    fetchAttention(getCurrentTimezone())
      .then((res) => {
        if (!cancelled) setAttention(res);
      })
      .catch(() => {
        /* the panel is optional context for the dashboard */
      });
    return () => {
      cancelled = true;
    };
  }, [sseRefreshKey]);

  useEffect(() => {
    let cancelled = false;
    fetchScanCoverage()
      .then((res) => {
        if (!cancelled) setScanCoverage(res);
      })
      .catch(() => {
        /* scan coverage is optional context for the dashboard */
      });
    return () => {
      cancelled = true;
    };
  }, []);

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
          limit: LATEST_LIMIT,
        });
        setVulnerabilities(results);
      } catch (error) {
        console.error("Failed to fetch vulnerabilities", error);
      }
      setLoading(false);
    };

    load();
  }, [sseRefreshKey]);

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

      // Async path (current backend): remember the jobId and let the SSE
      // effect pick up the final per-ID results when `job_completed` fires.
      if (response.jobId) {
        setPendingSyncJob({ jobId: response.jobId, query: queryNotFound });
        setToast({
          type: "success",
          message: t(
            `Synchronizing "${queryNotFound}" from upstream sources…`,
            `Synchronisiere "${queryNotFound}" von Upstream-Quellen…`
          ),
        });
        if (pendingSyncTimeoutRef.current !== null) {
          window.clearTimeout(pendingSyncTimeoutRef.current);
        }
        pendingSyncTimeoutRef.current = window.setTimeout(() => {
          setPendingSyncJob(null);
          setSyncLoading(false);
          pendingSyncTimeoutRef.current = null;
        }, 300000);
        return;
      }

      // Legacy synchronous path (older backends without async dispatch).
      const hasInsertedOrUpdated = response.results.some(
        (r) => r.status === "inserted" || r.status === "updated"
      );
      const errors = response.results.filter((r) => r.status === "error");

      if (hasInsertedOrUpdated) {
        const successResult = response.results.find(
          (r) => r.status === "inserted" || r.status === "updated"
        );
        const targetId = successResult?.resolvedId || queryNotFound;
        setQueryNotFound(null);
        setQueryInput("");
        navigate(`/vulnerability/${encodeURIComponent(targetId)}`);
      } else if (errors.length > 0) {
        const errorMessages = errors.map((e) => e.message || t("Unknown error", "Unbekannter Fehler")).join("; ");
        setToast({
          type: "error",
          message: t(
            `Vulnerability not found in NVD/EUVD/GHSA: ${errorMessages}`,
            `Schwachstelle nicht in NVD/EUVD/GHSA gefunden: ${errorMessages}`
          ),
        });
      } else {
        setToast({
          type: "error",
          message: t(
            `Vulnerability "${queryNotFound}" could not be synchronized. Not available in NVD, EUVD or GHSA.`,
            `Schwachstelle "${queryNotFound}" konnte nicht synchronisiert werden. Nicht in NVD, EUVD oder GHSA vorhanden.`
          ),
        });
      }
      setSyncLoading(false);
    } catch (error) {
      console.error("Manual sync failed", error);
      setToast({
        type: "error",
        message: t(
          "Synchronization failed. NVD/EUVD/GHSA may not contain this vulnerability.",
          "Synchronisation fehlgeschlagen. NVD/EUVD/GHSA haben diese Schwachstelle möglicherweise nicht."
        ),
      });
      setSyncLoading(false);
    }
  }, [queryNotFound, navigate, t]);

  // Match pending manual-sync jobId against the SSE stream; same contract as
  // the vulnerability-detail page's refresh subscription.
  useEffect(() => {
    if (!pendingSyncJob) return;
    const jobName = `vulnerability_refresh_${pendingSyncJob.jobId}`;
    const event = sseJobs.get(jobName);
    if (!event || (event.eventType !== "job_completed" && event.eventType !== "job_failed")) {
      return;
    }
    if (pendingSyncTimeoutRef.current !== null) {
      window.clearTimeout(pendingSyncTimeoutRef.current);
      pendingSyncTimeoutRef.current = null;
    }
    const query = pendingSyncJob.query;
    setPendingSyncJob(null);
    setSyncLoading(false);

    if (event.eventType === "job_failed") {
      setToast({
        type: "error",
        message: `${t("Synchronization failed.", "Synchronisation fehlgeschlagen.")}${event.error ? ` (${event.error})` : ""}`,
      });
      return;
    }
    const metadata = event.metadata ?? {};
    const results = Array.isArray((metadata as Record<string, unknown>).results)
      ? ((metadata as Record<string, unknown>).results as VulnerabilityRefreshStatus[])
      : [];
    const success = results.find((r) => r.status === "inserted" || r.status === "updated");
    const errors = results.filter((r) => r.status === "error");
    if (success) {
      const targetId = success.resolvedId || query;
      setQueryNotFound(null);
      setQueryInput("");
      navigate(`/vulnerability/${encodeURIComponent(targetId)}`);
    } else if (errors.length > 0) {
      const errorMessages = errors.map((e) => e.message || t("Unknown error", "Unbekannter Fehler")).join("; ");
      setToast({
        type: "error",
        message: t(
          `Vulnerability not found in NVD/EUVD/GHSA: ${errorMessages}`,
          `Schwachstelle nicht in NVD/EUVD/GHSA gefunden: ${errorMessages}`
        ),
      });
    } else {
      setToast({
        type: "error",
        message: t(
          `Vulnerability "${query}" could not be synchronized. Not available in NVD, EUVD or GHSA.`,
          `Schwachstelle "${query}" konnte nicht synchronisiert werden. Nicht in NVD, EUVD oder GHSA vorhanden.`
        ),
      });
    }
  }, [pendingSyncJob, sseJobs, navigate, t]);

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
    <div className="page dashboard">
      <TodayStats
        t={t}
        locale={locale}
        scanCveScan={scanCoverage.cveScan}
        scanProductScan={scanCoverage.productScan}
        scanTargets={scanCoverage.scanTargets}
        refreshKey={sseRefreshKey}
        attention={
          attention && attention.items.length > 0 ? (
            <AttentionPanel
              t={t}
              data={attention}
              scanCveScan={scanCoverage.cveScan}
              scanProductScan={scanCoverage.productScan}
              scanTargets={scanCoverage.scanTargets}
            />
          ) : null
        }
        headerActions={
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
        }
      />
      <VulnerabilityList vulnerabilities={vulnerabilities} loading={loading} t={t} />

      <Toast toast={toast} onDismiss={dismiss} />
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
  const placeholder = t("Enter vulnerability ID and press Enter", "Vulnerability ID eingeben und Enter drücken");

  return (
    <div className="dashboard-search">
      <div className="dashboard-search-field">
        {queryLoading ? (
          <span className="dashboard-spinner dashboard-search-icon" aria-hidden="true" />
        ) : (
          <LuSearch className="dashboard-search-icon" aria-hidden="true" />
        )}
        <input
          type="text"
          className="dashboard-search-input"
          value={queryInput}
          onChange={(e: React.ChangeEvent<HTMLInputElement>) => {
            setQueryInput(e.target.value);
          }}
          onKeyDown={onKeyDown}
          placeholder={placeholder}
          aria-label={placeholder}
          disabled={isLoading}
          autoComplete="off"
        />
        {queryInput && !isLoading && (
          <IconButton
            className="dashboard-search-clear"
            label={t("Clear input", "Eingabe löschen")}
            onClick={onClear}
          >
            <LuX aria-hidden="true" />
          </IconButton>
        )}
      </div>

      {/* Status messages */}
      {queryLoading && (
        <p className="dashboard-search-status">
          {t("Searching local database...", "Suche in lokaler Datenbank…")}
        </p>
      )}

      {showNotFound && (
        <div className="well dashboard-search-notice">
          {syncLoading ? (
            <div className="dashboard-search-notice-row">
              <span className="dashboard-spinner" aria-hidden="true" />
              <p className="dashboard-search-notice-title">
                {t(
                  `Fetching "${queryNotFound}" from upstream sources…`,
                  `„${queryNotFound}" wird von Upstream-Quellen abgerufen…`
                )}
              </p>
            </div>
          ) : (
            <div className="dashboard-search-notice-row">
              <LuTriangleAlert className="dashboard-search-notice-icon" aria-hidden="true" />
              <div className="dashboard-search-notice-body">
                <p className="dashboard-search-notice-title">
                  {t(`"${queryNotFound}" not found in local database`, `„${queryNotFound}" nicht in lokaler Datenbank`)}
                </p>
                <p className="dashboard-search-notice-text">
                  {t(
                    "This vulnerability has not been synchronized yet. Load it from official sources?",
                    "Die Schwachstelle wurde noch nicht synchronisiert. Soll sie von den offiziellen Quellen abgerufen werden?"
                  )}
                </p>
                <div className="dashboard-search-notice-actions">
                  <button type="button" onClick={onSync} className="btn-primary">
                    {t("Load from NVD/EUVD/GHSA", "Von NVD/EUVD/GHSA laden")}
                  </button>
                  <button type="button" onClick={onClear} className="btn">
                    {t("Cancel", "Abbrechen")}
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

/* ---------- Today's Vulnerability Statistics ---------- */

const severityDql = (severity: string, todayDate: string) => {
  const q = `cvss.severity:${severity} AND published:>=${todayDate}`;
  return `/vulnerabilities?search=${encodeURIComponent(q)}&mode=dql`;
};

const dqlQuote = (v: string) => `"${v.replace(/\//g, "\\/")}"`;

// A vendor or product a row names, and what the list filters on when it is clicked.
interface Facet {
  slug: string;
  name: string;
}
type FacetField = "vendorSlugs" | "productSlugs";

const facetHref = (field: FacetField, slug: string) =>
  `/vulnerabilities?search=${encodeURIComponent(`${field}:${dqlQuote(slug)}`)}&mode=dql`;

const FACETS_SHOWN = 3;

// Sits above the row's stretched link, so it opens the filtered list and not the CVE.
const FacetLinks = ({
  t,
  field,
  facets,
  limit,
}: {
  t: TranslateFn;
  field: FacetField;
  facets: Facet[];
  limit?: number;
}) => {
  const shown = facets.slice(0, FACETS_SHOWN);
  const extra = facets.length - shown.length;
  return (
    <>
      {shown.map((facet, index) => (
        <React.Fragment key={facet.slug}>
          {index > 0 && ", "}
          <Link
            to={facetHref(field, facet.slug)}
            className="dashboard-facet"
            title={
              field === "vendorSlugs"
                ? t(`Filter by vendor: ${facet.name}`, `Filter nach Vendor: ${facet.name}`)
                : t(`Filter by product: ${facet.name}`, `Filter nach Produkt: ${facet.name}`)
            }
          >
            {limit ? shortValue(facet.name, limit) : facet.name}
          </Link>
        </React.Fragment>
      ))}
      {extra > 0 && (
        <span className="dashboard-cve-extra" title={facets.map((facet) => facet.name).join(", ")}>
          +{extra}
        </span>
      )}
    </>
  );
};

// What a today-CVE row shows in its product cell. The summary carries slugs on
// the CVE and display names on the vendor/product buckets.
interface CveProductInfo {
  products: Facet[];
  vendors: Facet[];
}
type CveDescriber = (cve: TodayCve) => CveProductInfo;

// Only Critical opens by default, and only while it stays short, so Vendors and
// Products remain near the first screens on a busy day. Matched rows lead anyway.
const OPEN_SEVERITIES = new Set(["critical"]);
const OPEN_GROUP_LIMIT = 12;
// Rows a vendor/product list shows before the rest folds away. Matched rows sort
// first and always stay visible.
const LIST_PREVIEW = 12;
const TRIAGE_PREVIEW = 8;

const CveProduct = ({ t, info }: { t: TranslateFn; info: CveProductInfo }) => {
  if (info.products.length === 0 && info.vendors.length === 0) {
    return <span className="dashboard-missing">n/a</span>;
  }
  return (
    <>
      {info.products.length > 0 && (
        <span className="dashboard-cve-names">
          <FacetLinks t={t} field="productSlugs" facets={info.products} />
        </span>
      )}
      {info.vendors.length > 0 && (
        <span className="dashboard-cve-vendor">
          <FacetLinks t={t} field="vendorSlugs" facets={info.vendors} />
        </span>
      )}
    </>
  );
};

const TodayStats = ({
  t,
  locale,
  scanCveScan,
  scanProductScan,
  scanTargets,
  refreshKey,
  attention,
  headerActions,
}: {
  t: TranslateFn;
  locale: string;
  scanCveScan: Record<string, string>;
  scanProductScan: Record<string, string>;
  scanTargets: Record<string, string>;
  refreshKey: number;
  attention: ReactNode;
  headerActions: ReactNode;
}) => {
  const [data, setData] = useState<TodaySummaryResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [dayOffset, setDayOffset] = useState(0);

  const getDateForOffset = (offset: number) => {
    const tz = getCurrentTimezone();
    const now = new Date(Date.now() - offset * 86_400_000);
    return new Intl.DateTimeFormat("en-CA", {
      timeZone: tz,
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
    }).format(now);
  };

  const selectedDate = getDateForOffset(dayOffset);
  const isToday = dayOffset === 0;

  useEffect(() => {
    const load = async () => {
      try {
        setLoading(true);
        const result = await fetchTodaySummary(selectedDate, getCurrentTimezone());
        setData(result);
      } catch (err) {
        console.error("Failed to load today stats", err);
      } finally {
        setLoading(false);
      }
    };
    load();
    // refreshKey bumps when new vulnerabilities arrive over SSE, so today's
    // widgets pick up freshly-published (and possibly inventory-relevant) CVEs.
  }, [dayOffset, refreshKey]);

  const formatDisplayDate = (offset: number) => {
    const d = new Date();
    d.setDate(d.getDate() - offset);
    return d.toLocaleDateString(locale, {
      weekday: "short", day: "2-digit", month: "2-digit", year: "numeric", timeZone: getCurrentTimezone(),
    });
  };

  const dateNav = (
    <div className="dashboard-date-nav">
      {!isToday && (
        <button
          type="button"
          className="btn"
          onClick={() => setDayOffset(0)}
          title={t("Back to today", "Zurück zu heute")}
        >
          {t("Today", "Heute")}
        </button>
      )}
      <IconButton label={t("Previous day", "Vorheriger Tag")} onClick={() => setDayOffset((o) => o + 1)}>
        <LuChevronLeft aria-hidden="true" />
      </IconButton>
      <IconButton
        label={t("Next day", "Nächster Tag")}
        onClick={() => setDayOffset((o) => Math.max(0, o - 1))}
        disabled={isToday}
      >
        <LuChevronRight aria-hidden="true" />
      </IconButton>
    </div>
  );

  const header = (
    <PageHeader
      title={isToday ? t("Today", "Heute") : formatDisplayDate(dayOffset)}
      actions={
        <>
          {dateNav}
          {headerActions}
        </>
      }
    />
  );

  if (loading) {
    return (
      <>
        {header}
        <TodayStatsSkeleton />
      </>
    );
  }

  if (!data || data.total === 0) {
    return (
      <>
        {header}
        <EmptyState title={t("No vulnerabilities to show for this day.", "Für diesen Tag gibt es keine Schwachstellen anzuzeigen.")} />
        {attention && <div className="dashboard-triage">{attention}</div>}
      </>
    );
  }

  const todayDate = data.todayDate;
  const nextDay = (() => {
    const d = new Date(todayDate + "T00:00:00Z");
    d.setUTCDate(d.getUTCDate() + 1);
    return d.toISOString().slice(0, 10);
  })();

  const vendorDql = (vendorSlug: string) => {
    const q = `vendorSlugs:${dqlQuote(vendorSlug)} AND published:>=${todayDate} AND published:<${nextDay}`;
    return `/vulnerabilities?search=${encodeURIComponent(q)}&mode=dql`;
  };

  const productDql = (vendorSlug: string, productSlug: string) => {
    const q = `vendorSlugs:${dqlQuote(vendorSlug)} AND productSlugs:${dqlQuote(productSlug)} AND published:>=${todayDate} AND published:<${nextDay}`;
    return `/vulnerabilities?search=${encodeURIComponent(q)}&mode=dql`;
  };

  // SCA coverage: derive "scanned" vendor/product/CVE → most-recent scanId from
  // the SBOM-package map (productScan) plus the CVEs whose scans found/contain
  // them. SBOM carries no vendor, so vendor coverage is CVE-derived.
  const hasScanCoverage =
    Object.keys(scanCveScan).length > 0 || Object.keys(scanProductScan).length > 0;
  const scanProductMap = new Map<string, string>(Object.entries(scanProductScan));
  const scanVendorMap = new Map<string, string>();
  const cveToScan = new Map<string, string>();
  if (hasScanCoverage) {
    for (const cve of data.cves) {
      const sid = resolveCveScanId(cve, scanCveScan, scanProductScan);
      if (!sid) continue;
      cveToScan.set(cve.vulnId, sid);
      for (const p of cve.productSlugs ?? []) if (!scanProductMap.has(p)) scanProductMap.set(p, sid);
      for (const v of cve.vendorSlugs ?? []) if (!scanVendorMap.has(v)) scanVendorMap.set(v, sid);
    }
  }

  const invLabel = t("in inventory", "im Inventar");
  const scanFallback = t("SCA scan", "SCA-Scan");
  const vendorChips = (v: SlugBucket): CoverageChip[] => {
    const chips: CoverageChip[] = [];
    if (v.inventoryMatch) chips.push({ label: invLabel, href: "/inventory" });
    const sid = scanVendorMap.get(v.slug);
    if (sid) chips.push(scanChip(sid, scanTargets, scanFallback));
    return chips;
  };
  const productChips = (p: ProductBucket): CoverageChip[] => {
    const chips: CoverageChip[] = [];
    if (p.inventoryMatch) chips.push({ label: invLabel, href: "/inventory" });
    const sid = scanProductMap.get(p.slug);
    if (sid) chips.push(scanChip(sid, scanTargets, scanFallback));
    return chips;
  };

  // Float vendors/products matched by inventory OR scans to the top (stable sort).
  const anyVendorInventoryMatch = data.vendors.some((v) => v.inventoryMatch);
  const anyProductInventoryMatch = data.products.some((p) => p.inventoryMatch);
  const sortedVendors =
    !anyVendorInventoryMatch && scanVendorMap.size === 0
      ? data.vendors
      : [...data.vendors].sort(
          (a, b) => Number(vendorChips(b).length > 0) - Number(vendorChips(a).length > 0),
        );
  const sortedProducts =
    !anyProductInventoryMatch && scanProductMap.size === 0
      ? data.products
      : [...data.products].sort(
          (a, b) => Number(productChips(b).length > 0) - Number(productChips(a).length > 0),
        );
  const invCveCount = data.cves.filter((c) => cveMatchesInventory(c)).length;
  const scanCveCount = cveToScan.size;
  const hasMatchedCves = invCveCount > 0 || scanCveCount > 0;

  const severityCounts = new Map(data.severities.map((s) => [s.key, s.doc_count]));

  const productsBySlug = new Map(data.products.map((p) => [p.slug, p.name]));
  const vendorsBySlug = new Map(data.vendors.map((v) => [v.slug, v.name]));
  const describeCve: CveDescriber = (cve) => ({
    products: (cve.productSlugs ?? []).map((slug) => ({ slug, name: productsBySlug.get(slug) ?? slug })),
    vendors: (cve.vendorSlugs ?? []).map((slug) => ({
      slug,
      name: formatEcosystemName(vendorsBySlug.get(slug) ?? slug),
    })),
  });

  return (
    <>
      {header}

      <dl className="stat-row dashboard-stats">
        {invCveCount > 0 && (
          <Stat
            label={t("Affect your inventory", "Betreffen Ihr Inventar")}
            value={invCveCount.toLocaleString(locale)}
          />
        )}
        {scanCveCount > 0 && (
          <Stat
            label={t("In your SCA scans", "In Ihren SCA-Scans")}
            value={scanCveCount.toLocaleString(locale)}
          />
        )}
        <Stat label={t("Vulnerabilities", "Schwachstellen")} value={data.total.toLocaleString(locale)} />
        {SEVERITY_ORDER.map((severity) => {
          const count = severityCounts.get(severity);
          if (!count) return null;
          return (
            <Stat
              key={severity}
              label={severityLabel(severity, t)}
              tone={severityLevel(severity)}
              value={
                <Link to={severityDql(severity, todayDate)} className="dashboard-stat-link">
                  {count.toLocaleString(locale)}
                </Link>
              }
            />
          );
        })}
      </dl>

      {(attention || hasMatchedCves) && (
        <div className="dashboard-triage">
          {attention}
          {hasMatchedCves && (
            <Section className="dashboard-triage-panel" title={t("In your inventory or scans", "In Inventar oder Scans")}>
              <TodayLeadGroups
                t={t}
                cves={data.cves}
                scanCveScan={scanCveScan}
                scanProductScan={scanProductScan}
                scanTargets={scanTargets}
                invLabel={invLabel}
                scanFallback={scanFallback}
                describeCve={describeCve}
              />
            </Section>
          )}
        </div>
      )}

      <Section title={t("CVEs by severity", "CVEs nach Schweregrad")}>
        <TodayCveList
          t={t}
          cves={data.cves}
          scanCveScan={scanCveScan}
          scanProductScan={scanProductScan}
          scanTargets={scanTargets}
          invLabel={invLabel}
          scanFallback={scanFallback}
          describeCve={describeCve}
        />
      </Section>

      <div className="dashboard-support">
        <TodayMiniCard title={t("Vendors", "Hersteller")}>
          {sortedVendors.length === 0 ? (
            <EmptyState title={t("No vendor data.", "Keine Vendor-Daten.")} />
          ) : (
            <TodayListPreview
              t={t}
              matched={sortedVendors.filter((v) => vendorChips(v).length > 0).length}
              rows={sortedVendors.map((v) => (
                <TodayListItem
                  key={v.slug}
                  to={vendorDql(v.slug)}
                  label={formatEcosystemName(v.name)}
                  count={v.doc_count}
                  chips={vendorChips(v)}
                />
              ))}
            />
          )}
        </TodayMiniCard>

        <TodayMiniCard title={t("Products", "Produkte")}>
          {sortedProducts.length === 0 ? (
            <EmptyState title={t("No product data.", "Keine Produkt-Daten.")} />
          ) : (
            <TodayListPreview
              t={t}
              matched={sortedProducts.filter((p) => productChips(p).length > 0).length}
              rows={sortedProducts.map((p) => (
                <TodayListItem
                  key={`${p.vendorSlug}:${p.slug}`}
                  to={productDql(p.vendorSlug, p.slug)}
                  label={p.name}
                  sublabel={formatEcosystemName(p.vendorName)}
                  count={p.doc_count}
                  chips={productChips(p)}
                />
              ))}
            />
          )}
        </TodayMiniCard>
      </div>
    </>
  );
};

const TodayMiniCard = ({ title, children }: { title: string; children: ReactNode }) => (
  <Section title={title}>{children}</Section>
);

const TodayListPreview = ({
  t,
  rows,
  matched,
  preview = LIST_PREVIEW,
  listClassName = "dashboard-list",
}: {
  t: TranslateFn;
  rows: ReactNode[];
  matched: number;
  preview?: number;
  listClassName?: string;
}) => {
  const shown = Math.max(preview, matched);
  const rest = rows.slice(shown);
  return (
    <>
      <ul className={listClassName}>{rows.slice(0, shown)}</ul>
      {rest.length > 0 && (
        <details className="dashboard-list-more">
          <summary className="dashboard-disclosure">
            <LuChevronRight className="dashboard-disclosure-icon" aria-hidden="true" />
            {t(`${rest.length} more`, `${rest.length} weitere`)}
          </summary>
          <ul className={listClassName}>{rest}</ul>
        </details>
      )}
    </>
  );
};

const TodayListItem = ({
  to,
  label,
  sublabel,
  count,
  chips = [],
}: {
  to: string;
  label: string;
  sublabel?: string;
  count: number;
  chips?: CoverageChip[];
}) => {
  const highlighted = chips.length > 0;
  return (
    <li className={`dashboard-list-item${highlighted ? " dashboard-list-item--match" : ""}`}>
      <Link to={to} className="dashboard-list-link">
        <span className="dashboard-list-label">{label}</span>
        {sublabel && <span className="dashboard-list-sublabel">{sublabel}</span>}
      </Link>
      {highlighted && (
        <span className="dashboard-list-chips">
          <ChipLinks chips={chips} />
        </span>
      )}
      <span className="dashboard-list-count">{count}</span>
    </li>
  );
};

interface TodayCveTableProps {
  t: TranslateFn;
  cves: TodayCve[];
  scanCveScan: Record<string, string>;
  scanProductScan: Record<string, string>;
  scanTargets: Record<string, string>;
  invLabel: string;
  scanFallback: string;
  describeCve: CveDescriber;
}

const SeverityTally = ({ t, group }: { t: TranslateFn; group: CveGroup<TodayCve> }) => (
  <span className="dashboard-tally">
    {group.tally.map(({ severity, count }) => {
      const label = severityLabel(severity, t);
      return (
        <span key={severity} className={`sev-${severityLevel(severity)}`} title={`${count} ${label}`}>
          {count} {label[0]}
        </span>
      );
    })}
  </span>
);

// The day's CVEs that touch the inventory or a scan, one row per product: a team
// patches a package once, however many CVEs that closes.
const TodayLeadGroups = ({
  t,
  cves,
  scanCveScan,
  scanProductScan,
  scanTargets,
  invLabel,
  scanFallback,
  describeCve,
}: TodayCveTableProps) => {
  const chipsByCve = useCveChips(cves, scanCveScan, scanProductScan, scanTargets, invLabel, scanFallback);
  const groups = useMemo(
    () =>
      groupCves(
        cves.filter((cve) => chipsByCve.has(cve.vulnId)),
        (cve) => productKey(cve, cve.productSlugs?.find((slug) => scanProductScan[slug])),
        cveMatchesInventory,
      ),
    [cves, chipsByCve, scanProductScan],
  );

  return (
    <TodayListPreview
      t={t}
      matched={0}
      preview={TRIAGE_PREVIEW}
      listClassName="dashboard-triage-list"
      rows={groups.map((group) => (
        <LeadGroup
          key={group.key}
          t={t}
          group={group}
          chips={uniqueChips(group.cves.flatMap((cve) => chipsByCve.get(cve.vulnId) ?? []))}
          info={describeGroup(group, describeCve)}
        />
      ))}
    />
  );
};

const describeGroup = (group: CveGroup<TodayCve>, describeCve: CveDescriber): CveProductInfo => {
  const infos = group.cves.map(describeCve);
  const products = uniqueFacets(infos.flatMap((info) => info.products));
  const own = products.filter((product) => product.slug === group.key);
  return {
    products: own.length > 0 ? own : products,
    vendors: uniqueFacets(infos.flatMap((info) => info.vendors)),
  };
};

const LeadGroup = ({
  t,
  group,
  chips,
  info,
}: {
  t: TranslateFn;
  group: CveGroup<TodayCve>;
  chips: CoverageChip[];
  info: CveProductInfo;
}) => {
  const [single] = group.cves;
  const severity = <SeverityTag severity={group.worst}>{severityLabel(group.worst, t)}</SeverityTag>;
  const product = (
    <span className="dashboard-triage-main">
      <CveProduct t={t} info={info} />
    </span>
  );
  const side = (detail: ReactNode) => (
    <span className="dashboard-triage-side">
      <span className="dashboard-triage-chips"><ChipLinks chips={chips} /></span>
      {detail}
    </span>
  );

  if (group.cves.length === 1) {
    return (
      <li className="dashboard-triage-row dashboard-triage-row--lead">
        <span />
        {severity}
        {product}
        {side(
          <Link to={`/vulnerability/${encodeURIComponent(single.vulnId)}`} className="row-link mono dashboard-cve-link dashboard-triage-id">
            {single.vulnId}
          </Link>,
        )}
      </li>
    );
  }

  return (
    <li>
      <details>
        <summary className="dashboard-triage-row dashboard-triage-row--lead">
          <LuChevronRight className="dashboard-disclosure-icon" aria-hidden="true" />
          {severity}
          {product}
          {side(<SeverityTally t={t} group={group} />)}
        </summary>
        <ul className="dashboard-group-cves">
          {group.cves.map((cve) => (
            <li key={cve.vulnId} className="dashboard-group-cve">
              <SeverityTag severity={cve.severity}>{severityLabel(cve.severity || "unknown", t)}</SeverityTag>
              <Link to={`/vulnerability/${encodeURIComponent(cve.vulnId)}`} className="row-link mono dashboard-cve-link">
                {cve.vulnId}
              </Link>
              {cve.title && cve.title !== cve.vulnId && (
                <span className="dashboard-group-cve-title" title={cve.title}>{cve.title}</span>
              )}
            </li>
          ))}
        </ul>
      </details>
    </li>
  );
};

// A KEV date has no time, so it is read at noon UTC: midnight would show the day before west of Greenwich.
const kevDate = (value: string) => formatDateOnly(`${value}T12:00:00Z`);

const attentionHref = (since: string) =>
  `/vulnerabilities?search=${encodeURIComponent(`exploitation.dateAdded:>=${since}`)}&mode=dql`;

// What is being exploited or warned about, whatever day the page shows. Anything in
// the user's stack leads; each row says why it is here.
const AttentionPanel = ({
  t,
  data,
  scanCveScan,
  scanProductScan,
  scanTargets,
}: {
  t: TranslateFn;
  data: AttentionResponse;
  scanCveScan: Record<string, string>;
  scanProductScan: Record<string, string>;
  scanTargets: Record<string, string>;
}) => {
  const chipsByCve = useCveChips(
    data.items,
    scanCveScan,
    scanProductScan,
    scanTargets,
    t("in inventory", "im Inventar"),
    t("SCA scan", "SCA-Scan"),
  );
  // A confirmed hit outranks a package that merely shares the product's name.
  const stackRank = useCallback(
    (item: AttentionItem) => (cveMatchesInventory(item) || scanCveScan[item.vulnId] ? 2 : chipsByCve.has(item.vulnId) ? 1 : 0),
    [chipsByCve, scanCveScan],
  );
  const rows = useMemo(() => attentionRows(data.items, stackRank), [data.items, stackRank]);
  const quiet = useMemo(() => {
    const findings = quietFindings(data.items, (item) => Boolean(scanCveScan[item.vulnId]));
    return { total: findings.length, groups: groupCves(findings, (item) => productKey(item)) };
  }, [data.items, scanCveScan]);

  if (rows.length === 0 && quiet.total === 0) return null;

  return (
    <Section
      className="dashboard-triage-panel"
      title={t("Needs attention", "Handlungsbedarf")}
      actions={
        <>
          <Link to={attentionHref(data.since)} className="dashboard-section-link">
            {t("KEV listings", "KEV-Einträge")}
          </Link>
          <Link to="/advisories" className="dashboard-section-link">
            {t("Advisories", "Meldungen")}
          </Link>
        </>
      }
    >
      <p className="dashboard-triage-note">
        {t(
          `Added to CISA's known exploited list or named by several CERTs or vendors in the last ${data.days} days.`,
          `In den letzten ${data.days} Tagen in die CISA-Liste ausgenutzter Schwachstellen aufgenommen oder von mehreren CERTs oder Herstellern genannt.`,
        )}
      </p>
      <TodayListPreview
        t={t}
        matched={0}
        preview={TRIAGE_PREVIEW}
        listClassName="dashboard-triage-list"
        rows={rows.map((item) => (
          <AttentionRow key={item.vulnId} t={t} item={item} chips={chipsByCve.get(item.vulnId) ?? []} />
        ))}
      />
      {quiet.total > 0 && (
        <details className="dashboard-list-more">
          <summary className="dashboard-disclosure">
            <LuChevronRight className="dashboard-disclosure-icon" aria-hidden="true" />
            {t(
              `${quiet.total} more in your scans, named by one source`,
              `${quiet.total} weitere in Ihren Scans, von einer Quelle genannt`,
            )}
          </summary>
          <ul className="dashboard-triage-list">
            {quiet.groups.map((group) => (
              <LeadGroup
                key={group.key}
                t={t}
                group={group}
                chips={uniqueChips(group.cves.flatMap((cve) => chipsByCve.get(cve.vulnId) ?? []))}
                info={attentionGroupInfo(group)}
              />
            ))}
          </ul>
        </details>
      )}
    </Section>
  );
};

const attentionGroupInfo = (group: CveGroup<AttentionItem>): CveProductInfo => {
  const products = uniqueFacets(group.cves.flatMap((cve) => cve.products));
  const own = products.filter((product) => product.slug === group.key);
  return {
    products: own.length > 0 ? own : products,
    vendors: uniqueFacets(group.cves.flatMap((cve) => cve.vendors)),
  };
};

const CERTS_SHOWN = 3;

// Links to the advisory itself, above the row's stretched link. The backend only stores http(s) URLs.
// CERTs and vendors first, so a community post never takes the place of one.
const CertLinks = ({ sources }: { sources: CertMention[] }) => {
  const certs = [...sources.filter((source) => source.kind !== "community"), ...sources.filter((source) => source.kind === "community")];
  return (
    <span className="dashboard-triage-when">
      {certs.slice(0, CERTS_SHOWN).map((cert, index) => (
        <React.Fragment key={cert.name}>
          {index > 0 && ", "}
          {cert.url ? (
            <a href={safeHref(cert.url)} target="_blank" rel="noreferrer" className="dashboard-facet" title={cert.title ?? cert.name}>
              {cert.name}
            </a>
          ) : (
            cert.name
          )}
        </React.Fragment>
      ))}
      {certs.length > CERTS_SHOWN && (
        <span className="dashboard-cve-extra" title={certs.map((cert) => cert.name).join(", ")}>
          +{certs.length - CERTS_SHOWN}
        </span>
      )}
    </span>
  );
};

const AttentionRow = ({ t, item, chips }: { t: TranslateFn; item: AttentionItem; chips: CoverageChip[] }) => (
  <li className="dashboard-triage-row">
    <SeverityTag severity={item.severity}>{severityLabel(item.severity || "unknown", t)}</SeverityTag>
    <span className="dashboard-triage-main">
      <Link to={`/vulnerability/${encodeURIComponent(item.vulnId)}`} className="row-link mono dashboard-cve-link dashboard-triage-id">
        {item.vulnId}
      </Link>
      <span className="dashboard-cve-vendor">
        {item.products.length > 0 ? (
          <FacetLinks t={t} field="productSlugs" facets={item.products} limit={LATEST_PRODUCT_LIMIT} />
        ) : (
          <FacetLinks t={t} field="vendorSlugs" facets={item.vendors} limit={LATEST_VENDOR_LIMIT} />
        )}
      </span>
    </span>
    <span className="dashboard-triage-side">
      {item.sources.length > 0 && <CertLinks sources={item.sources} />}
      {item.kevListed && item.dateAdded && (
        <span
          className="dashboard-triage-when"
          title={item.dueDate ? t(`CISA due date: ${kevDate(item.dueDate)}`, `CISA-Frist: ${kevDate(item.dueDate)}`) : undefined}
        >
          KEV {kevDate(item.dateAdded)}
        </span>
      )}
      {(chips.length > 0 || item.ransomware) && (
        <span className="dashboard-triage-chips">
          {item.ransomware && <span className="chip dashboard-flag">{t("Ransomware", "Ransomware")}</span>}
          <ChipLinks chips={chips} />
        </span>
      )}
    </span>
  </li>
);

const TodayCveList = ({
  t,
  cves,
  scanCveScan,
  scanProductScan,
  scanTargets,
  invLabel,
  scanFallback,
  describeCve,
}: TodayCveTableProps) => {
  const chipsByCve = useCveChips(cves, scanCveScan, scanProductScan, scanTargets, invLabel, scanFallback);

  const grouped = useMemo(() => {
    const groups: Record<string, TodayCve[]> = {};
    for (const cve of cves) {
      const sev = cve.severity || "unknown";
      if (!groups[sev]) groups[sev] = [];
      groups[sev].push(cve);
    }
    // Float matched (inventory or scan) CVEs to the top of each severity group.
    if (chipsByCve.size > 0) {
      for (const sev of Object.keys(groups)) {
        groups[sev] = [...groups[sev]].sort(
          (a, b) => Number(chipsByCve.has(b.vulnId)) - Number(chipsByCve.has(a.vulnId)),
        );
      }
    }
    return groups;
  }, [cves, chipsByCve]);

  return (
    <div className="dashboard-cve-groups">
      {SEVERITY_ORDER.map((severity) => {
        const items = grouped[severity];
        if (!items || items.length === 0) return null;
        return (
          <details key={severity} className="dashboard-cve-group" open={OPEN_SEVERITIES.has(severity) && items.length <= OPEN_GROUP_LIMIT}>
            <summary className="dashboard-disclosure">
              <LuChevronRight className="dashboard-disclosure-icon" aria-hidden="true" />
              <span className={`dashboard-cve-group-name sev-${severityLevel(severity)}`}>
                {severityLabel(severity, t)}
              </span>
              <span className="dashboard-cve-group-count">{items.length}</span>
            </summary>
            <div className="table-scroll">
              <table className="dashboard-cve-table dashboard-cve-table--group">
                <thead className="dashboard-cve-table-head">
                  <tr>
                    <th scope="col"><span className="visually-hidden">ID</span></th>
                    <th scope="col"><span className="visually-hidden">{t("Aliases", "Aliase")}</span></th>
                    <th scope="col"><span className="visually-hidden">{t("Product", "Produkt")}</span></th>
                    <th scope="col"><span className="visually-hidden">{t("Matched in", "Treffer in")}</span></th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((cve) => (
                    <TodayCveItem
                      key={cve.vulnId}
                      t={t}
                      cve={cve}
                      chips={chipsByCve.get(cve.vulnId) ?? []}
                      product={describeCve(cve)}
                    />
                  ))}
                </tbody>
              </table>
            </div>
          </details>
        );
      })}
    </div>
  );
};

const TodayCveItem = ({
  t,
  cve,
  chips = [],
  product,
}: {
  t: TranslateFn;
  cve: TodayCve;
  chips?: CoverageChip[];
  product: CveProductInfo;
}) => {
  const aliases = (cve.aliases ?? []).filter(
    (a) => a && a.toUpperCase() !== cve.vulnId.toUpperCase()
  );
  return (
    <tr className="dashboard-cve-row">
      <td className="dashboard-cve-id">
        <Link to={`/vulnerability/${encodeURIComponent(cve.vulnId)}`} className="row-link mono dashboard-cve-link">
          {cve.vulnId}
        </Link>
      </td>
      <td className="dashboard-cve-aliases">
        {aliases.map((alias) => (
          <span key={alias} className="mono">
            {alias}
          </span>
        ))}
      </td>
      <td className="dashboard-cve-product">
        <CveProduct t={t} info={product} />
      </td>
      <td className="dashboard-cve-chips">
        <ChipLinks chips={chips} />
      </td>
    </tr>
  );
};

const TodayStatsSkeleton = () => (
  <>
    <div className="stat-row dashboard-stats">
      {Array.from({ length: 6 }).map((_, i) => (
        <div key={i} className="dashboard-skeleton-stat">
          <SkeletonBlock height="0.9rem" width="72px" />
          <SkeletonBlock height="1.6rem" width="48px" />
        </div>
      ))}
    </div>
    <div className="dashboard-skeleton-rows">
      {Array.from({ length: 8 }).map((_, i) => (
        <SkeletonBlock key={i} height="1.75rem" />
      ))}
    </div>
    <div className="dashboard-support">
      {Array.from({ length: 2 }).map((_, i) => (
        <div key={i} className="dashboard-skeleton-rows">
          <SkeletonBlock height="1.1rem" width="120px" />
          {Array.from({ length: 5 }).map((_, j) => (
            <SkeletonBlock key={j} height="1.4rem" />
          ))}
        </div>
      ))}
    </div>
  </>
);

interface VulnerabilityListProps {
  vulnerabilities: VulnerabilityPreview[];
  loading: boolean;
  t: TranslateFn;
}

const MISSING_VALUE = "n/a";
const LATEST_LIMIT = 10;
// Vendor/product values are cut for the row; the full value stays in the tooltip,
// in the copied info and on the detail page.
const LATEST_VENDOR_LIMIT = 22;
const LATEST_PRODUCT_LIMIT = 30;
const shortValue = (value: string, limit: number) =>
  value.length > limit ? `${value.slice(0, limit).trimEnd()}…` : value;

// Older documents carry bare names only; the list page derives their slugs the same way.
const nameFacet = (name: string): Facet => ({
  slug: name.toLowerCase().replace(/\s+/g, "-").replace(/[^a-z0-9-]/g, ""),
  name,
});

const uniqueFacets = (facets: Facet[]): Facet[] => [
  ...new Map(facets.filter((facet) => facet.slug).map((facet) => [facet.slug, facet])).values(),
];

const latestFacets = (vuln: VulnerabilityPreview) => {
  const ip = vuln.impactedProducts ?? [];
  if (ip.length > 0) {
    const vendorNames = [...new Set(ip.map((p) => p.vendor?.name).filter((name): name is string => Boolean(name)))];
    const productNames = [...new Set(ip.map((p) => p.product?.name).filter(Boolean))];
    const versionList = [...new Set(ip.flatMap((p) => p.versions ?? []).filter(Boolean))];
    return {
      vendors: vendorNames.length ? vendorNames.map(formatEcosystemName).join(", ") : MISSING_VALUE,
      products: productNames.length ? productNames.join(", ") : MISSING_VALUE,
      versions: versionList.length ? versionList.join(", ") : MISSING_VALUE,
      vendorFacets: uniqueFacets(ip.map((p) => ({ slug: p.vendor?.slug ?? "", name: formatEcosystemName(p.vendor?.name ?? "") }))),
      productFacets: uniqueFacets(ip.map((p) => ({ slug: p.product?.slug ?? "", name: p.product?.name ?? "" }))),
    };
  }
  return {
    vendors: vuln.vendors?.length ? vuln.vendors.map(formatEcosystemName).join(", ") : MISSING_VALUE,
    products: vuln.products?.length ? vuln.products.join(", ") : MISSING_VALUE,
    versions: vuln.productVersions?.length ? vuln.productVersions.join(", ") : MISSING_VALUE,
    vendorFacets: uniqueFacets((vuln.vendors ?? []).map((name) => nameFacet(formatEcosystemName(name)))),
    productFacets: uniqueFacets((vuln.products ?? []).map(nameFacet)),
  };
};

const VulnerabilityList = ({ vulnerabilities, loading, t }: VulnerabilityListProps) => {
  const hasResults = vulnerabilities.length > 0;
  const showSkeleton = loading && !hasResults;

  return (
    <Section
      className="dashboard-latest"
      title={t("Latest findings", "Neueste Treffer")}
      actions={
        <Link to="/vulnerabilities" className="dashboard-section-link">
          {t("All vulnerabilities", "Alle Schwachstellen")}
        </Link>
      }
    >
      {showSkeleton ? (
        <DashboardSkeleton />
      ) : hasResults ? (
        <div className="table-scroll">
          <table className="dashboard-latest-table">
            <thead>
              <tr>
                <th scope="col" className="dashboard-latest-severity">{t("Severity", "Schweregrad")}</th>
                <th scope="col" className="dashboard-latest-id">ID</th>
                <th scope="col">{t("Product", "Produkt")}</th>
                <th scope="col">{t("Vendor", "Hersteller")}</th>
                <th scope="col" className="num dashboard-latest-cvss">CVSS</th>
                <th scope="col" className="num dashboard-latest-epss">EPSS</th>
                <th scope="col" className="dashboard-latest-published">{t("Published", "Veröffentlicht")}</th>
                <th scope="col" className="dashboard-latest-action">
                  <span className="visually-hidden">{t("Copy vulnerability info", "Schwachstellen-Info kopieren")}</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {vulnerabilities.map((vuln) => (
                <LatestRow key={vuln.vulnId || vuln.sourceId} vuln={vuln} t={t} />
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <EmptyState title={t("No data loaded.", "Keine Daten geladen.")} />
      )}
      {loading && hasResults && (
        <p className="dashboard-refreshing">
          {t("Refreshing results...", "Aktualisiere Ergebnisse...")}
        </p>
      )}
    </Section>
  );
};

const LatestRow = ({ vuln, t }: { vuln: VulnerabilityPreview; t: TranslateFn }) => {
  const [copyFeedback, setCopyFeedback] = useState(false);
  const { vendors, products, versions, vendorFacets, productFacets } = latestFacets(vuln);
  const primaryId = vuln.vulnId || vuln.sourceId || t("Unknown-ID", "Unbekannte-ID");
  const { text: published, isReserved } = getPublishedDisplay(vuln.published, "datetime");
  const cvssScore = getPreferredCvssMetric(vuln.cvssMetrics ?? null)?.baseScore;

  const handleCopyInfo = (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    const ids = [vuln.vulnId, vuln.sourceId].filter(Boolean).join(", ");
    const severity = (vuln.severity ?? "unknown").toUpperCase();

    const lines: string[] = [ids];
    if (severity !== "UNKNOWN") lines.push(`Severity: ${severity}`);
    if (vendors && vendors !== MISSING_VALUE) lines.push(`Vendors: ${vendors}`);
    if (products && products !== MISSING_VALUE) lines.push(`Products: ${products}`);
    if (versions && versions !== MISSING_VALUE) lines.push(`Versions: ${versions}`);
    if (vuln.summary) lines.push(`\n${vuln.summary}`);

    void navigator.clipboard.writeText(lines.join("\n")).then(() => {
      setCopyFeedback(true);
      setTimeout(() => setCopyFeedback(false), 1500);
    });
  };

  return (
    <tr className={`dashboard-latest-row${vuln.exploited ? " dashboard-latest-row--exploited" : ""}`}>
      <td className="dashboard-latest-severity">
        <SeverityTag severity={vuln.severity}>{severityLabel(vuln.severity || "unknown", t)}</SeverityTag>
      </td>
      <td className="dashboard-latest-id">
        <Link to={`/vulnerability/${encodeURIComponent(primaryId)}`} className="row-link mono dashboard-cve-link">
          {primaryId}
        </Link>
        {vuln.exploited && <span className="chip dashboard-flag">{t("Exploited", "Ausgenutzt")}</span>}
      </td>
      <td className="dashboard-latest-product" title={products}>
        {productFacets.length > 0 ? (
          <FacetLinks t={t} field="productSlugs" facets={productFacets} limit={LATEST_PRODUCT_LIMIT} />
        ) : (
          shortValue(products, LATEST_PRODUCT_LIMIT)
        )}
      </td>
      <td className="dashboard-latest-vendor" title={vendors}>
        {vendorFacets.length > 0 ? (
          <FacetLinks t={t} field="vendorSlugs" facets={vendorFacets} limit={LATEST_VENDOR_LIMIT} />
        ) : (
          shortValue(vendors, LATEST_VENDOR_LIMIT)
        )}
      </td>
      <td className="num dashboard-latest-score" data-label="CVSS">
        {cvssScore != null ? cvssScore.toFixed(1) : <span className="dashboard-missing">n/a</span>}
      </td>
      <td className="num dashboard-latest-score" data-label="EPSS">
        {vuln.epssScore != null ? `${(vuln.epssScore * 100).toFixed(2)}%` : <span className="dashboard-missing">n/a</span>}
      </td>
      <td className="dashboard-latest-published">{isReserved ? <ReservedBadge /> : published}</td>
      <td className="dashboard-latest-action">
        <IconButton
          className={copyFeedback ? "dashboard-copy dashboard-copy--done" : "dashboard-copy"}
          label={t("Copy vulnerability info", "Schwachstellen-Info kopieren")}
          onClick={handleCopyInfo}
        >
          {copyFeedback ? <LuCheck aria-hidden="true" /> : <LuCopy aria-hidden="true" />}
        </IconButton>
      </td>
    </tr>
  );
};

const DashboardSkeleton = () => (
  <div className="dashboard-skeleton-rows">
    {Array.from({ length: LATEST_LIMIT }).map((_, index) => (
      <SkeletonBlock key={index} height="1.75rem" />
    ))}
  </div>
);
