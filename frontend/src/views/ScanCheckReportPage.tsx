import { useCallback, useEffect, useMemo, useState } from "react";
import { LuArrowLeft, LuCopy, LuDownload } from "react-icons/lu";
import { Link, useParams } from "react-router-dom";

import "../screens/scan-check.css";

import { exportScanSbom, fetchScan, fetchScanFindings, fetchScanSbom } from "../api/scans";
import { DocsLink } from "../components/DocsLink";
import { LoadingRegion, SkeletonBlock, SkeletonRows } from "../components/Skeleton";
import { Toast, useToast } from "../components/Toast";
import { useI18n } from "../i18n/context";
import type { SbomComponent, Scan, ScanFinding } from "../types";
import { EmptyState, ErrorState, LoadingState, PageHeader, Section, SeverityTag, Stat } from "../ui/primitives";
import {
  OTHER_FINDING_KINDS,
  type OtherFindingKind,
  SEVERITIES,
  checkSubject,
  countBySeverity,
  isCheckRunning,
  sbomOverview,
  splitReportRows,
} from "../utils/checkReport";
import { severityLabel } from "../utils/cveGroups";
import { formatDateTime } from "../utils/dateFormat";
import { downloadBlob, downloadText } from "../utils/download";
import { findingsExportFilename, findingsToCsv, findingsToJson } from "../utils/findingsExport";
import { type MergedFinding, mergeFindings } from "../utils/mergeFindings";

const POLL_MS = 5000;
const FINDINGS_LIMIT = 5000;
const SBOM_LIMIT = 500;
const PREVIEW = 100;

/**
 * The report of a check: a scan without a target. It is in no list, so this
 * page is the only way to it (the link the form opens, or a CI job's scan id),
 * and it is deleted at expiresAt. Read-only: no VEX, history or comparison.
 */
export const ScanCheckReportPage = () => {
  const { scanId = "" } = useParams<{ scanId: string }>();
  const { t } = useI18n();
  const { toast, showToast, dismiss } = useToast();
  const [scan, setScan] = useState<Scan | null>(null);
  const [scanError, setScanError] = useState<unknown>(null);
  const [findings, setFindings] = useState<ScanFinding[] | null>(null);
  const [sbom, setSbom] = useState<{ total: number; items: SbomComponent[] } | null>(null);
  const [resultsError, setResultsError] = useState<unknown>(null);
  const [retryKey, setRetryKey] = useState(0);

  const status = scan?.status;
  const running = isCheckRunning(status);

  // The scan itself, again every few seconds while it runs.
  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const load = async () => {
      try {
        const next = await fetchScan(scanId);
        if (cancelled) return;
        setScan(next);
        setScanError(null);
        if (isCheckRunning(next.status)) timer = setTimeout(load, POLL_MS);
      } catch (err) {
        if (!cancelled) setScanError(err);
      }
    };
    void load();
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, [scanId, retryKey]);

  // Findings and SBOM once it has finished.
  useEffect(() => {
    if (!status || isCheckRunning(status)) return;
    let cancelled = false;
    (async () => {
      try {
        const [f, s] = await Promise.all([
          fetchScanFindings(scanId, { limit: FINDINGS_LIMIT }),
          fetchScanSbom(scanId, { limit: SBOM_LIMIT }),
        ]);
        if (cancelled) return;
        setFindings(f.items);
        setSbom({ total: s.total, items: s.items });
        setResultsError(null);
      } catch (err) {
        if (!cancelled) setResultsError(err);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [scanId, status, retryKey]);

  const rows = useMemo(() => (findings ? mergeFindings(findings) : []), [findings]);
  const { vulnerabilities, other } = useMemo(() => splitReportRows(rows), [rows]);
  const overview = useMemo(() => sbomOverview(sbom?.items ?? []), [sbom]);

  const handleExport = useCallback(
    (format: "json" | "csv") => {
      if (!scan || rows.length === 0) return;
      const filename = findingsExportFilename(scan, format);
      if (format === "csv") downloadText(findingsToCsv(rows), filename, "text/csv;charset=utf-8");
      else downloadText(findingsToJson(rows, scan, "filtered"), filename, "application/json");
    },
    [scan, rows],
  );

  const handleSbomExport = async (format: "cyclonedx-json" | "spdx-json") => {
    try {
      const { data, filename } = await exportScanSbom(scanId, format);
      downloadBlob(data, filename ?? `check-${scanId}.${format === "spdx-json" ? "spdx" : "cdx"}.json`);
    } catch {
      showToast(t("The SBOM could not be exported.", "Die SBOM konnte nicht exportiert werden."), "error");
    }
  };

  const copyLink = () => {
    void navigator.clipboard?.writeText(window.location.href);
    showToast(t("Link copied.", "Link kopiert."), "success");
  };

  const back = (
    <Link to="/scans" className="scan-check-back">
      <LuArrowLeft aria-hidden="true" />
      {t("SCA Scans", "SCA-Scans")}
    </Link>
  );

  if (scanError && !scan) {
    return (
      <div className="page scan-check">
        {back}
        <ErrorState
          title={t("This check could not be loaded.", "Diese Prüfung konnte nicht geladen werden.")}
          error={scanError}
          onRetry={() => setRetryKey((k) => k + 1)}
        >
          {t("Checks are deleted after a few days.", "Prüfungen werden nach einigen Tagen gelöscht.")}
        </ErrorState>
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="page scan-check">
        {back}
        <LoadingRegion label={t("Loading check", "Prüfung wird geladen")}>
          <SkeletonBlock height={64} />
          <SkeletonRows rows={6} height={40} />
        </LoadingRegion>
      </div>
    );
  }

  const subject = checkSubject(scan);
  const subjectLabel =
    subject === "sbom" ? "SBOM" : subject === "container_image" ? t("Container image", "Container-Image") : t("Source code", "Quellcode");
  const label = scan.targetName || scan.imageRef || scan.id;
  const severityCounts = countBySeverity(vulnerabilities);
  const summary = scan.summary;
  const failed = status === "failed" || status === "cancelled";

  return (
    <div className="page scan-check">
      {back}

      <PageHeader
        title={t("Check report", "Prüfbericht")}
        description={
          <span className="scan-check-identity">
            <span className="mono scan-check-label">{label}</span>
            <span className="chip">{subjectLabel}</span>
            {scan.expiresAt && (
              <span className="chip" title={t("Checks are deleted automatically.", "Prüfungen werden automatisch gelöscht.")}>
                {t(`Deleted on ${formatDateTime(scan.expiresAt)}`, `Wird am ${formatDateTime(scan.expiresAt)} gelöscht`)}
              </span>
            )}
            <DocsLink path="sca-scanning/#checks">{t("About checks", "Über Prüfungen")}</DocsLink>
          </span>
        }
        actions={
          <button type="button" className="btn-secondary" onClick={copyLink}>
            <LuCopy aria-hidden="true" />
            {t("Copy link", "Link kopieren")}
          </button>
        }
      />

      {running && (
        <Section>
          <LoadingState
            label={
              status === "pending"
                ? t("Waiting for a free scanner slot…", "Wartet auf einen freien Scanner-Platz …")
                : t(`Running ${scan.scanners.join(", ")}…`, `${scan.scanners.join(", ")} läuft …`)
            }
          />
        </Section>
      )}

      {failed && (
        <ErrorState title={status === "cancelled" ? t("The check was cancelled.", "Die Prüfung wurde abgebrochen.") : t("The check failed.", "Die Prüfung ist fehlgeschlagen.")}>
          {scan.error || undefined}
        </ErrorState>
      )}

      {!running && !failed && scan.error && (
        <p className="scan-check-warning" role="status">
          {t("Some scanners reported errors: ", "Einige Scanner meldeten Fehler: ")}
          {scan.error}
        </p>
      )}

      {!running && (
        <>
          <Section title={t("Vulnerabilities", "Schwachstellen")}>
            <dl className="stat-row scan-check-rollup">
              <Stat label={t("vulnerabilities", "Schwachstellen")} value={summary?.total ?? vulnerabilities.length} />
              {SEVERITIES.filter((sev) => sev !== "negligible" || (summary?.negligible ?? 0) > 0).map((sev) => (
                <Stat key={sev} label={severityLabel(sev, t)} value={summary?.[sev] ?? severityCounts[sev]} tone={sev === "unknown" ? undefined : sev} />
              ))}
              <Stat label={t("components", "Komponenten")} value={sbom?.total ?? scan.sbomComponentCount ?? 0} />
            </dl>
            <p className="muted scan-check-note">
              {t(
                "Counted per vulnerability; the table lists every affected package.",
                "Gezählt je Schwachstelle; die Tabelle nennt jedes betroffene Paket.",
              )}
            </p>
          </Section>

          {resultsError ? (
            <ErrorState
              title={t("The results could not be loaded.", "Die Ergebnisse konnten nicht geladen werden.")}
              error={resultsError}
              onRetry={() => setRetryKey((k) => k + 1)}
            />
          ) : findings === null ? (
            <LoadingRegion label={t("Loading results", "Ergebnisse werden geladen")}>
              <SkeletonRows rows={8} height={36} />
            </LoadingRegion>
          ) : (
            <>
              <Section
                title={t(`Affected packages (${vulnerabilities.length})`, `Betroffene Pakete (${vulnerabilities.length})`)}
                actions={
                  rows.length > 0 ? (
                    <span className="scan-check-actions">
                      <button type="button" className="btn-secondary" onClick={() => handleExport("csv")}>
                        <LuDownload aria-hidden="true" />
                        CSV
                      </button>
                      <button type="button" className="btn-secondary" onClick={() => handleExport("json")}>
                        <LuDownload aria-hidden="true" />
                        JSON
                      </button>
                    </span>
                  ) : undefined
                }
              >
                {vulnerabilities.length === 0 ? (
                  <EmptyState title={t("No vulnerable packages found.", "Keine verwundbaren Pakete gefunden.")} />
                ) : (
                  <VulnerabilityTable rows={vulnerabilities} />
                )}
              </Section>

              {other.length > 0 && (
                <Section title={t(`Other findings (${other.length})`, `Weitere Funde (${other.length})`)}>
                  <OtherFindingsTable rows={other} />
                </Section>
              )}
            </>
          )}

          {sbom && (
            <Section
              title={t(`SBOM (${sbom.total} components)`, `SBOM (${sbom.total} Komponenten)`)}
              actions={
                sbom.total > 0 ? (
                  <span className="scan-check-actions">
                    <button type="button" className="btn-secondary" onClick={() => void handleSbomExport("cyclonedx-json")}>
                      <LuDownload aria-hidden="true" />
                      CycloneDX
                    </button>
                    <button type="button" className="btn-secondary" onClick={() => void handleSbomExport("spdx-json")}>
                      <LuDownload aria-hidden="true" />
                      SPDX
                    </button>
                  </span>
                ) : undefined
              }
            >
              {sbom.total === 0 ? (
                <EmptyState title={t("No components found.", "Keine Komponenten gefunden.")} />
              ) : (
                <>
                  {sbom.total > sbom.items.length && (
                    <p className="muted scan-check-note">
                      {t(
                        `Overview of the first ${sbom.items.length} components; the export holds all ${sbom.total}.`,
                        `Übersicht der ersten ${sbom.items.length} Komponenten; der Export enthält alle ${sbom.total}.`,
                      )}
                    </p>
                  )}
                  <div className="scan-check-facets">
                    <FacetList title={t("Ecosystems", "Ökosysteme")} items={overview.ecosystems} />
                    <FacetList
                      title={t("Licenses", "Lizenzen")}
                      items={overview.licenses}
                      footer={
                        overview.unlicensed > 0
                          ? t(`${overview.unlicensed} without a license`, `${overview.unlicensed} ohne Lizenz`)
                          : undefined
                      }
                    />
                  </div>
                </>
              )}
            </Section>
          )}
        </>
      )}

      <Toast toast={toast} onDismiss={dismiss} />
    </div>
  );
};

const VulnerabilityTable = ({ rows }: { rows: MergedFinding[] }) => {
  const { t } = useI18n();
  const [showAll, setShowAll] = useState(false);
  const shown = showAll ? rows : rows.slice(0, PREVIEW);
  return (
    <>
      <div className="table-scroll">
        <table className="scan-check-table">
          <thead>
            <tr>
              <th scope="col">{t("Severity", "Schweregrad")}</th>
              <th scope="col">{t("Vulnerability", "Schwachstelle")}</th>
              <th scope="col">{t("Package", "Paket")}</th>
              <th scope="col">{t("Fix", "Fix")}</th>
              <th scope="col">{t("Scanners", "Scanner")}</th>
            </tr>
          </thead>
          <tbody>
            {shown.map((row) => (
              <tr key={row.key}>
                <td>
                  <SeverityTag severity={row.severity}>{severityLabel(row.severity || "unknown", t)}</SeverityTag>
                </td>
                <td className="scan-check-id">
                  {row.vulnerabilityId ? (
                    <Link to={`/vulnerability/${encodeURIComponent(row.vulnerabilityId)}`} className="mono">
                      {row.vulnerabilityId}
                    </Link>
                  ) : (
                    <span className="muted">{row.title || "—"}</span>
                  )}
                </td>
                <td className="scan-check-package">
                  <span className="mono">{row.packageName}</span>
                  {row.packageVersion && <span className="mono muted"> {row.packageVersion}</span>}
                </td>
                <td className="mono">{row.fixVersion || <span className="muted">—</span>}</td>
                <td className="muted">{row.scanners.join(", ")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {rows.length > PREVIEW && (
        <button type="button" className="btn-secondary scan-check-more" onClick={() => setShowAll((v) => !v)}>
          {showAll ? t("Show fewer", "Weniger anzeigen") : t(`Show all ${rows.length}`, `Alle ${rows.length} anzeigen`)}
        </button>
      )}
    </>
  );
};

const KIND_LABELS: Record<OtherFindingKind, [string, string]> = {
  "malicious-indicator": ["Malware indicator", "Malware-Hinweis"],
  "secret-finding": ["Secret", "Secret"],
  "sast-finding": ["Code (SAST)", "Code (SAST)"],
  "compliance-check": ["Best practice", "Best Practice"],
};

const OtherFindingsTable = ({ rows }: { rows: MergedFinding[] }) => {
  const { t } = useI18n();
  const order = (kind: string) => OTHER_FINDING_KINDS.indexOf(kind as OtherFindingKind);
  const sorted = [...rows].sort((a, b) => order(a.packageType) - order(b.packageType));
  return (
    <div className="table-scroll">
      <table className="scan-check-table">
        <thead>
          <tr>
            <th scope="col">{t("Severity", "Schweregrad")}</th>
            <th scope="col">{t("Kind", "Art")}</th>
            <th scope="col">{t("Finding", "Fund")}</th>
            <th scope="col">{t("Where", "Wo")}</th>
          </tr>
        </thead>
        <tbody>
          {sorted.map((row) => {
            const [en, de] = KIND_LABELS[row.packageType as OtherFindingKind] ?? [row.packageType, row.packageType];
            return (
              <tr key={row.key}>
                <td>
                  <SeverityTag severity={row.severity}>{severityLabel(row.severity || "unknown", t)}</SeverityTag>
                </td>
                <td>{t(en, de)}</td>
                <td className="scan-check-finding">{row.title || row.vulnerabilityId || "—"}</td>
                <td className="mono scan-check-where">{row.packagePath || row.packageName || "—"}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
};

const FacetList = ({ title, items, footer }: { title: string; items: { name: string; count: number }[]; footer?: string }) => (
  <div className="scan-check-facet">
    <h3>{title}</h3>
    <ul>
      {items.map((item) => (
        <li key={item.name}>
          <span className="scan-check-facet-name">{item.name}</span>
          <span className="scan-check-facet-count">{item.count}</span>
        </li>
      ))}
    </ul>
    {footer && <p className="muted scan-check-note">{footer}</p>}
  </div>
);
