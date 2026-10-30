import "../screens/dashboard.css";

import React, { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Link, useNavigate } from "react-router-dom";
import { LuBox, LuCheck, LuChevronLeft, LuChevronRight, LuCopy, LuScanLine, LuSearch, LuTriangleAlert, LuX } from "react-icons/lu";

import { VulnerabilityPreview, type VulnerabilityRefreshStatus } from "../types";
import { searchVulnerabilities, getVulnerability, triggerVulnerabilityRefresh } from "../api/vulnerabilities";
import {
  fetchTodaySummary,
  type TodaySummaryResponse,
  type TodayCve,
  type SlugBucket,
  type ProductBucket,
} from "../api/stats";
import { fetchScanCoverage, type ScanCoverage } from "../api/scans";
import { SkeletonBlock } from "../components/Skeleton";
import { ReservedBadge } from "../components/ReservedBadge";
import { useI18n, type TranslateFn } from "../i18n/context";
import { getCurrentTimezone } from "../timezone/storage";
import { useSSE } from "../hooks/useSSE";
import { getPublishedDisplay } from "../utils/published";
import { CvssMetricDisplay } from "../components/CvssMetricDisplay";
import { ExploitationSummary } from "../components/ExploitationSummary";
import { Toast, useToast } from "../components/Toast";
import { getPreferredCvssMetric } from "../utils/cvss";
import { formatEcosystemName } from "../utils/advisoryText";
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
          limit: 20,
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

      <Toast toast={toast} />
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

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "unknown"];
const SEVERITY_LABELS: Record<string, [string, string]> = {
  critical: ["Critical", "Kritisch"],
  high: ["High", "Hoch"],
  medium: ["Medium", "Mittel"],
  low: ["Low", "Niedrig"],
  unknown: ["Unknown", "Unbekannt"],
};
const severityLabel = (severity: string, t: TranslateFn): string => {
  const label = SEVERITY_LABELS[severity];
  return label ? t(label[0], label[1]) : severity;
};
const severityRank = (severity: string): number => {
  const rank = SEVERITY_ORDER.indexOf(severity || "unknown");
  return rank === -1 ? SEVERITY_ORDER.length : rank;
};

const severityDql = (severity: string, todayDate: string) => {
  const q = `cvss.severity:${severity} AND published:>=${todayDate}`;
  return `/vulnerabilities?search=${encodeURIComponent(q)}&mode=dql`;
};

// A today-CVE counts as "in your environment" only when the backend's precise,
// version-aware matcher (`items_for_vuln`, same logic as the Inventory page and
// the vulnerability detail page) confirmed at least one inventory item is
// actually affected by this CVE's version range.
const cveMatchesInventory = (cve: TodayCve): boolean =>
  (cve.inventoryMatchIds?.length ?? 0) > 0;

// Resolve the most-recent scan covering a today-CVE: a finding hit on the CVE id,
// else the first SBOM-package hit on one of its product slugs. Undefined = not scanned.
const resolveCveScanId = (
  cve: TodayCve,
  scanCveScan: Record<string, string>,
  scanProductScan: Record<string, string>,
): string | undefined => {
  if (scanCveScan[cve.vulnId]) return scanCveScan[cve.vulnId];
  for (const p of cve.productSlugs ?? []) {
    if (scanProductScan[p]) return scanProductScan[p];
  }
  return undefined;
};

// A highlight chip on a Today item. Inventory chips link to /inventory; scan
// chips link to the covering scan's detail page.
interface TodayChip {
  label: string;
  href: string;
  title?: string;
  scan?: boolean;
}

// An "in scans" chip labelled with the covering scan's target name (truncated),
// linking to that scan's detail page. Falls back to a generic label.
const scanChip = (
  sid: string,
  scanTargets: Record<string, string>,
  fallbackLabel: string,
): TodayChip => {
  const target = scanTargets[sid];
  const label = target && target.length > 26 ? `${target.slice(0, 25)}…` : target;
  return {
    label: label || fallbackLabel,
    href: `/scans/${sid}`,
    scan: true,
    title: target || fallbackLabel,
  };
};

// Per-CVE chips (inventory and/or scan), keyed by vulnId.
const useCveChips = (
  cves: TodayCve[],
  scanCveScan: Record<string, string>,
  scanProductScan: Record<string, string>,
  scanTargets: Record<string, string>,
  invLabel: string,
  scanFallback: string,
) =>
  useMemo(() => {
    const map = new Map<string, TodayChip[]>();
    const hasScan =
      Object.keys(scanCveScan).length > 0 || Object.keys(scanProductScan).length > 0;
    for (const cve of cves) {
      const chips: TodayChip[] = [];
      if (cveMatchesInventory(cve)) {
        chips.push({ label: invLabel, href: "/inventory" });
      }
      if (hasScan) {
        const sid = resolveCveScanId(cve, scanCveScan, scanProductScan);
        if (sid) chips.push(scanChip(sid, scanTargets, scanFallback));
      }
      if (chips.length) map.set(cve.vulnId, chips);
    }
    return map;
  }, [cves, scanCveScan, scanProductScan, scanTargets, invLabel, scanFallback]);

// Chips are navigable spans so they work inside a row that is itself a link:
// preventDefault on the chip cancels the row navigation so the chip's own link
// wins (no nested <a>).
const ChipLinks = ({ chips }: { chips: TodayChip[] }) => {
  const navigate = useNavigate();
  if (chips.length === 0) return null;
  return (
    <>
      {chips.map((c, i) => (
        <span
          key={`${c.scan ? "s" : "i"}-${i}`}
          className="chip chip-link dashboard-chip"
          role="link"
          tabIndex={0}
          title={c.title}
          onClick={(e) => {
            e.preventDefault();
            e.stopPropagation();
            navigate(c.href);
          }}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              e.stopPropagation();
              navigate(c.href);
            }
          }}
        >
          {c.scan ? <LuScanLine aria-hidden="true" /> : <LuBox aria-hidden="true" />}
          {c.label}
        </span>
      ))}
    </>
  );
};

// What a today-CVE row shows in its product cell. The summary carries slugs on
// the CVE and display names on the vendor/product buckets.
interface CveProductInfo {
  names: string[];
  extra: number;
  vendors: string;
  all: string;
}
type CveDescriber = (cve: TodayCve) => CveProductInfo;

const CVE_PRODUCTS_SHOWN = 3;
// Only Critical opens by default, and only while it stays short, so Vendors and
// Products remain near the first screens on a busy day. Matched rows lead anyway.
const OPEN_SEVERITIES = new Set(["critical"]);
const OPEN_GROUP_LIMIT = 12;
// Rows a vendor/product list shows before the rest folds away. Matched rows sort
// first and always stay visible.
const LIST_PREVIEW = 12;

const CveProduct = ({ info }: { info: CveProductInfo }) => {
  if (info.names.length === 0 && !info.vendors) {
    return <span className="dashboard-missing">n/a</span>;
  }
  return (
    <>
      {info.names.length > 0 && (
        <span className="dashboard-cve-names" title={info.all}>
          {info.names.join(", ")}
          {info.extra > 0 && <span className="dashboard-cve-extra">+{info.extra}</span>}
        </span>
      )}
      {info.vendors && <span className="dashboard-cve-vendor">{info.vendors}</span>}
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
  headerActions,
}: {
  t: TranslateFn;
  locale: string;
  scanCveScan: Record<string, string>;
  scanProductScan: Record<string, string>;
  scanTargets: Record<string, string>;
  refreshKey: number;
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
    return d.toLocaleDateString(locale === "de" ? "de-DE" : "en-US", {
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
      </>
    );
  }

  const todayDate = data.todayDate;
  const nextDay = (() => {
    const d = new Date(todayDate + "T00:00:00Z");
    d.setUTCDate(d.getUTCDate() + 1);
    return d.toISOString().slice(0, 10);
  })();

  const dqlQuote = (v: string) => `"${v.replace(/\//g, "\\/")}"`;

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
  const vendorChips = (v: SlugBucket): TodayChip[] => {
    const chips: TodayChip[] = [];
    if (v.inventoryMatch) chips.push({ label: invLabel, href: "/inventory" });
    const sid = scanVendorMap.get(v.slug);
    if (sid) chips.push(scanChip(sid, scanTargets, scanFallback));
    return chips;
  };
  const productChips = (p: ProductBucket): TodayChip[] => {
    const chips: TodayChip[] = [];
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
  const describeCve: CveDescriber = (cve) => {
    const names = (cve.productSlugs ?? []).map((slug) => productsBySlug.get(slug) ?? slug);
    const vendors = (cve.vendorSlugs ?? []).map((slug) =>
      formatEcosystemName(vendorsBySlug.get(slug) ?? slug),
    );
    return {
      names: names.slice(0, CVE_PRODUCTS_SHOWN),
      extra: Math.max(0, names.length - CVE_PRODUCTS_SHOWN),
      vendors: vendors.join(", "),
      all: names.join(", "),
    };
  };

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

      {hasMatchedCves && (
        <Section className="dashboard-lead" title={t("In your inventory or scans", "In Inventar oder Scans")}>
          <TodayLeadTable
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

const TodayListPreview = ({ t, rows, matched }: { t: TranslateFn; rows: ReactNode[]; matched: number }) => {
  const shown = Math.max(LIST_PREVIEW, matched);
  const rest = rows.slice(shown);
  return (
    <>
      <ul className="dashboard-list">{rows.slice(0, shown)}</ul>
      {rest.length > 0 && (
        <details className="dashboard-list-more">
          <summary className="dashboard-disclosure">
            <LuChevronRight className="dashboard-disclosure-icon" aria-hidden="true" />
            {t(`${rest.length} more`, `${rest.length} weitere`)}
          </summary>
          <ul className="dashboard-list">{rest}</ul>
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
  chips?: TodayChip[];
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

// The day's CVEs that touch the inventory or a scan, worst severity first. An
// inventory hit went through the version-aware matcher, so it wins a tie.
const TodayLeadTable = ({
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
  const matched = useMemo(
    () =>
      cves
        .filter((cve) => chipsByCve.has(cve.vulnId))
        .sort(
          (a, b) =>
            severityRank(a.severity) - severityRank(b.severity) ||
            Number(cveMatchesInventory(b)) - Number(cveMatchesInventory(a)),
        ),
    [cves, chipsByCve],
  );

  return (
    <div className="table-scroll">
      <table className="dashboard-cve-table dashboard-cve-table--lead">
        <thead>
          <tr>
            <th scope="col">{t("Severity", "Schweregrad")}</th>
            <th scope="col">ID</th>
            <th scope="col">{t("Aliases", "Aliase")}</th>
            <th scope="col">{t("Product", "Produkt")}</th>
            <th scope="col">{t("Matched in", "Treffer in")}</th>
          </tr>
        </thead>
        <tbody>
          {matched.map((cve) => (
            <TodayCveItem
              key={cve.vulnId}
              t={t}
              cve={cve}
              chips={chipsByCve.get(cve.vulnId) ?? []}
              product={describeCve(cve)}
              showSeverity
            />
          ))}
        </tbody>
      </table>
    </div>
  );
};

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
  showSeverity = false,
}: {
  t: TranslateFn;
  cve: TodayCve;
  chips?: TodayChip[];
  product: CveProductInfo;
  showSeverity?: boolean;
}) => {
  const aliases = (cve.aliases ?? []).filter(
    (a) => a && a.toUpperCase() !== cve.vulnId.toUpperCase()
  );
  return (
    <tr className="dashboard-cve-row">
      {showSeverity && (
        <td className="dashboard-cve-severity">
          <SeverityTag severity={cve.severity}>{severityLabel(cve.severity || "unknown", t)}</SeverityTag>
        </td>
      )}
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
        <CveProduct info={product} />
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
const LATEST_COLUMN_COUNT = 9;
// Vendor/product/version values are cut for the row; the full value stays in the
// tooltip, in the copied info and on the detail page.
const LATEST_VENDOR_LIMIT = 22;
const LATEST_PRODUCT_LIMIT = 30;
const LATEST_VERSION_LIMIT = 20;
const shortValue = (value: string, limit: number) =>
  value.length > limit ? `${value.slice(0, limit).trimEnd()}…` : value;

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
          vuln.epssScore != null ? `${(vuln.epssScore * 100).toFixed(2)}%` : "n/a";
        const ip = vuln.impactedProducts ?? [];
        let vendors: string;
        let products: string;
        let versions: string;
        if (ip.length > 0) {
          const vn = [...new Set(ip.map((p) => p.vendor?.name).filter((name): name is string => Boolean(name)))];
          const pn = [...new Set(ip.map((p) => p.product?.name).filter(Boolean))];
          const vs = [...new Set(ip.flatMap((p) => p.versions ?? []).filter(Boolean))];
          vendors = vn.length ? vn.map(formatEcosystemName).join(", ") : MISSING_VALUE;
          products = pn.length ? pn.join(", ") : MISSING_VALUE;
          versions = vs.length ? vs.join(", ") : MISSING_VALUE;
        } else {
          vendors = vuln.vendors?.length ? vuln.vendors.map(formatEcosystemName).join(", ") : MISSING_VALUE;
          products = vuln.products?.length ? vuln.products.join(", ") : MISSING_VALUE;
          versions = vuln.productVersions?.length ? vuln.productVersions.join(", ") : MISSING_VALUE;
        }
        const cweList = vuln.cwes ?? [];
        const aliases = buildAliasList(vuln.aliases, vuln.vulnId, vuln.sourceId);
        const ghsaAliases = aliases.filter((alias) => alias.toUpperCase().startsWith("GHSA-"));
        const preferredCvss = getPreferredCvssMetric(vuln.cvssMetrics ?? null);
        const malAliases = aliases.filter((alias) => alias.toUpperCase().startsWith("MAL-"));
        const pysecAliases = aliases.filter((alias) => alias.toUpperCase().startsWith("PYSEC-"));
        const remainingAliases = aliases.filter((alias) => {
          const upper = alias.toUpperCase();
          return !upper.startsWith("GHSA-") && !upper.startsWith("MAL-") && !upper.startsWith("PYSEC-");
        });

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
    <Section className="dashboard-latest" title={t("Latest findings", "Neueste Treffer")}>
      {showSkeleton ? (
        <DashboardSkeleton />
      ) : hasResults ? (
        <div className="table-scroll">
          <table className="dashboard-latest-table">
            <thead>
              <tr>
                <th scope="col">{t("Severity", "Schweregrad")}</th>
                <th scope="col">{t("Vulnerability", "Schwachstelle")}</th>
                <th scope="col">{t("Vendors", "Hersteller")}</th>
                <th scope="col">{t("Products", "Produkte")}</th>
                <th scope="col">{t("Versions", "Versionen")}</th>
                <th scope="col" className="num">CVSS</th>
                <th scope="col" className="num">EPSS</th>
                <th scope="col">{t("Published", "Veröffentlicht")}</th>
                <th scope="col">
                  <span className="visually-hidden">{t("Copy vulnerability info", "Schwachstellen-Info kopieren")}</span>
                </th>
              </tr>
            </thead>
            {rows}
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

const DashboardVulnCard = ({
  vuln,
  primaryId,
  hasCve,
  hasSource,
  ghsaAliases,
  malAliases,
  pysecAliases,
  remainingAliases,
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
    if (vendors && vendors !== MISSING_VALUE) lines.push(`Vendors: ${vendors}`);
    if (products && products !== MISSING_VALUE) lines.push(`Products: ${products}`);
    if (versions && versions !== MISSING_VALUE) lines.push(`Versions: ${versions}`);
    if (vuln.summary) lines.push(`\n${vuln.summary}`);

    void navigator.clipboard.writeText(lines.join("\n")).then(() => {
      setCopyFeedback(true);
      setTimeout(() => setCopyFeedback(false), 1500);
    });
  };

  const cvssScore = preferredCvss?.baseScore != null ? preferredCvss.baseScore.toFixed(1) : null;
  const titleIsId = vuln.title === primaryId;
  const ids = [
    ...(hasCve ? [vuln.vulnId] : []),
    ...(hasSource && vuln.sourceId ? [vuln.sourceId] : []),
    ...ghsaAliases,
    ...malAliases,
    ...pysecAliases,
    ...remainingAliases,
  ].filter((id) => id !== vuln.title);

  return (
    <tbody className={`dashboard-latest-item${vuln.exploited ? " dashboard-latest-item--exploited" : ""}`}>
      <tr className="dashboard-latest-row">
        <td className="dashboard-latest-severity">
          <SeverityTag severity={vuln.severity}>
            {severityLabel(vuln.severity || "unknown", t)}
          </SeverityTag>
        </td>
        <td className="dashboard-latest-main">
          <h3 className={titleIsId ? "dashboard-latest-title mono" : "dashboard-latest-title"}>
            <Link to={`/vulnerability/${primaryId}`} className="row-link">
              {vuln.title}
            </Link>
          </h3>
        </td>
        <td className="dashboard-latest-vendor" data-label={t("Vendors", "Hersteller")}>
          <span className="dashboard-latest-value" title={vendors}>{shortValue(vendors, LATEST_VENDOR_LIMIT)}</span>
        </td>
        <td data-label={t("Products", "Produkte")}>
          <span className="dashboard-latest-value" title={products}>{shortValue(products, LATEST_PRODUCT_LIMIT)}</span>
        </td>
        <td data-label={t("Versions", "Versionen")}>
          <span className="dashboard-latest-value dashboard-latest-version mono" title={versions}>{shortValue(versions, LATEST_VERSION_LIMIT)}</span>
        </td>
        <td className="num dashboard-latest-score" data-label="CVSS">
          {cvssScore ?? <span className="dashboard-missing">n/a</span>}
        </td>
        <td className="num dashboard-latest-score" data-label="EPSS">
          {vuln.epssScore != null ? epss : <span className="dashboard-missing">n/a</span>}
        </td>
        <td className="num dashboard-latest-published" data-label={t("Published", "Veröffentlicht")}>
          {isPublishedReserved ? <ReservedBadge /> : published}
        </td>
        <td className="dashboard-latest-action" rowSpan={2}>
          <IconButton
            className={copyFeedback ? "dashboard-copy dashboard-copy--done" : "dashboard-copy"}
            label={t("Copy vulnerability info", "Schwachstellen-Info kopieren")}
            onClick={handleCopyInfo}
          >
            {copyFeedback ? <LuCheck aria-hidden="true" /> : <LuCopy aria-hidden="true" />}
          </IconButton>
        </td>
      </tr>
      <tr className="dashboard-latest-more">
        <td className="dashboard-latest-more-spacer" />
        <td colSpan={LATEST_COLUMN_COUNT - 2}>
          <div className="dashboard-latest-line">
          {ids.length > 0 && (
            <div className="dashboard-latest-ids">
              {ids.map((id) => (
                <span key={id} className="mono">
                  {id}
                </span>
              ))}
            </div>
          )}
          <div className="dashboard-latest-meta">
            <MetaItem label={t("Source", "Quelle")} value={vuln.source ?? "EUVD"} />
            {vuln.exploited != null && (
              <MetaItem
                label={t("Exploited", "Ausgenutzt")}
                value={<ExploitationSummary exploited={vuln.exploited} exploitation={vuln.exploitation} />}
                wide={Boolean(vuln.exploitation)}
              />
            )}
            <MetaItem
              label={t("Assigner", "Assigner")}
              value={vuln.assigner ? <span className="mono">{vuln.assigner}</span> : "n/a"}
            />
          </div>
          <div className="link-list">
            {hasCve && (
              <>
                <a
                  href={`https://www.cve.org/CVERecord?id=${encodeURIComponent(vuln.vulnId)}`}
                  target="_blank"
                  rel="noreferrer"
                >
                  CVE
                </a>
                <a
                  href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(vuln.vulnId)}`}
                  target="_blank"
                  rel="noreferrer"
                >
                  NVD
                </a>
                <a
                  href={`https://cve.circl.lu/vuln/${encodeURIComponent(vuln.vulnId)}`}
                  target="_blank"
                  rel="noreferrer"
                >
                  CIRCL
                </a>
                {vuln.published && (Date.now() - new Date(vuln.published).getTime()) >= 7 * 24 * 60 * 60 * 1000 && (
                  <a
                    href={`https://cti.wazuh.com/vulnerabilities/cves/${encodeURIComponent(vuln.vulnId)}`}
                    target="_blank"
                    rel="noreferrer"
                  >
                    Wazuh
                  </a>
                )}
              </>
            )}
            {(vuln.sourceId?.startsWith("EUVD-") || vuln.vulnId?.startsWith("CVE-")) && (
              <a
                href={`https://euvd.enisa.europa.eu/vulnerability/${encodeURIComponent(vuln.sourceId?.startsWith("EUVD-") ? vuln.sourceId : vuln.vulnId)}`}
                target="_blank"
                rel="noreferrer"
              >
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
                OSV
              </a>
            ))}
            {malAliases.map((alias) => (
              <a
                key={`deps-${alias}`}
                href={`https://deps.dev/advisory/osv/${encodeURIComponent(alias)}`}
                target="_blank"
                rel="noreferrer"
                title="deps.dev advisory"
              >
                deps.dev
              </a>
            ))}
            {pysecAliases.map((alias) => (
              <a
                key={alias}
                href={`https://osv.dev/vulnerability/${encodeURIComponent(alias)}`}
                target="_blank"
                rel="noreferrer"
              >
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
                GHSA
              </a>
            ))}
            {ghsaAliases.map((alias) => (
              <a
                key={`osv-${alias}`}
                href={`https://osv.dev/vulnerability/${encodeURIComponent(alias)}`}
                target="_blank"
                rel="noreferrer"
              >
                OSV
              </a>
            ))}
          </div>
          {cweList.length > 0 && (
            <div className="dashboard-latest-cwes">
              {cweList.map((cwe) => (
                <span key={cwe} className="chip mono">
                  {cwe}
                </span>
              ))}
            </div>
          )}
          {(preferredCvss || vuln.summary) && (
            <details className="dashboard-latest-details">
              <summary className="dashboard-disclosure">
                <LuChevronRight className="dashboard-disclosure-icon" aria-hidden="true" />
                {preferredCvss ? "CVSS" : t("Summary", "Zusammenfassung")}
              </summary>
              {preferredCvss ? (
                <CvssMetricDisplay
                  metric={preferredCvss}
                  showVector={false}
                  showScores={false}
                />
              ) : (
                <p>{vuln.summary}</p>
              )}
            </details>
          )}
          </div>
        </td>
      </tr>
    </tbody>
  );
};

const DashboardSkeleton = () => (
  <div className="dashboard-skeleton-rows">
    {Array.from({ length: 6 }).map((_, index) => (
      <div key={index} className="dashboard-skeleton-latest">
        <SkeletonBlock height="1rem" width="64px" />
        <div className="dashboard-skeleton-rows">
          <SkeletonBlock height="1.1rem" width="65%" />
          <SkeletonBlock height="0.9rem" width="40%" />
        </div>
        <SkeletonBlock height="1rem" />
        <SkeletonBlock height="1rem" width="80px" />
      </div>
    ))}
  </div>
);

interface MetaItemProps {
  label: string;
  value: ReactNode;
  wide?: boolean;
}

const MetaItem = ({ label, value, wide = false }: MetaItemProps) => (
  <div className={wide ? "dashboard-meta dashboard-meta--wide" : "dashboard-meta"}>
    <span className="dashboard-meta-label">{label}</span>
    <span className="dashboard-meta-value">{value}</span>
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
