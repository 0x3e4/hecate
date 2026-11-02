import { useCallback, useEffect, useMemo, useState } from "react";
import {
  LuArrowLeft,
  LuArrowRight,
  LuCopy,
  LuExternalLink,
  LuLock,
  LuRefreshCw,
  LuSearchCheck,
  LuTrash2,
} from "react-icons/lu";
import { Link, useNavigate, useParams } from "react-router-dom";

import "../screens/scan-target.css";

import {
  deleteScanTarget,
  fetchGlobalFindings,
  fetchScanTarget,
  fetchTargetHistory,
  fetchTargetSbomDiff,
  submitManualScan,
  triggerTargetCheck,
} from "../api/scans";
import { SeverityBadges } from "../components/SeverityBadges";
import { SkeletonBlock } from "../components/Skeleton";
import { Toast, useToast } from "../components/Toast";
import { useI18n } from "../i18n/context";
import type { ConsolidatedFinding, ScanHistoryEntry, ScanSummary, ScanTarget, TargetSbomDiff } from "../types";
import {
  EmptyState,
  ErrorState,
  PageHeader,
  Section,
  SeverityTag,
  Stat,
  severityLevel,
  severityVar,
} from "../ui/primitives";
import { formatDateTime } from "../utils/dateFormat";
import { safeHref } from "../utils/safeHref";

const HISTORY_PAGE = 25;

// A scheme URL or a host/path reference is an identifier, so the h1 sets it in mono.
const NAME_IS_URL = /^[a-z][a-z\d+.-]*:\/\/|^[\w-]+(\.[\w-]+)+\//i;

// i18n label per target kind, shown in the header type chip.
const TYPE_META: Record<string, { en: string; de: string }> = {
  container_image: { en: "Container image", de: "Container-Image" },
  source_repo: { en: "Source repo", de: "Quell-Repo" },
  "sbom-import": { en: "SBOM import", de: "SBOM-Import" },
};

type Tone = "success" | "error" | "info" | "muted";

// Tone + label per auto-scan /check verdict. The two failure verdicts differ in
// words, not only in colour.
const VERDICT_META: Record<string, { tone: Tone; en: string; de: string }> = {
  changed: { tone: "info", en: "Changed", de: "Geändert" },
  unchanged: { tone: "success", en: "Unchanged", de: "Unverändert" },
  first_scan: { tone: "info", en: "First scan", de: "Erster Scan" },
  check_failed_skipped: { tone: "error", en: "Check failed, skipped", de: "Prüfung fehlgeschlagen, übersprungen" },
  check_failed_scanned: { tone: "error", en: "Check failed, scanned", de: "Prüfung fehlgeschlagen, gescannt" },
};

const STATUS_TONES: Record<string, Tone> = {
  completed: "success",
  failed: "error",
  running: "info",
  pending: "info",
  cancelled: "muted",
  canceled: "muted",
};

// The severity word in both languages, in rollup order.
const SEVERITY_ORDER: { key: keyof ScanSummary; en: string; de: string; optional?: boolean }[] = [
  { key: "critical", en: "Critical", de: "Kritisch" },
  { key: "high", en: "High", de: "Hoch" },
  { key: "medium", en: "Medium", de: "Mittel" },
  { key: "low", en: "Low", de: "Niedrig" },
  { key: "negligible", en: "Negligible", de: "Vernachlässigbar", optional: true },
  { key: "unknown", en: "Unknown", de: "Unbekannt", optional: true },
];

// Compact, language-neutral relative time ("3h", "2d"). The absolute value
// rides along as a title tooltip so the unit suffix needs no translation.
const formatRelative = (iso?: string | null): string => {
  if (!iso) return "n/a";
  const ms = new Date(iso).getTime();
  if (Number.isNaN(ms)) return "n/a";
  const d = Math.max(0, Date.now() - ms) / 1000;
  if (d < 45) return "now";
  if (d < 3600) return `${Math.round(d / 60)}m`;
  if (d < 86400) return `${Math.round(d / 3600)}h`;
  if (d < 604800) return `${Math.round(d / 86400)}d`;
  if (d < 2629800) return `${Math.round(d / 604800)}w`;
  if (d < 31557600) return `${Math.round(d / 2629800)}mo`;
  return `${Math.round(d / 31557600)}y`;
};

const formatDuration = (sec?: number | null): string => {
  if (sec == null) return "n/a";
  if (sec < 60) return `${Math.round(sec)}s`;
  const m = Math.floor(sec / 60);
  const s = Math.round(sec % 60);
  if (m < 60) return s ? `${m}m ${s}s` : `${m}m`;
  return `${Math.floor(m / 60)}h ${m % 60}m`;
};

// Proportional stacked severity bar. The figures above it carry the same data in
// words, so the bar stays out of the accessibility tree.
const SeverityBar = ({ summary }: { summary?: ScanSummary | null }) => {
  if (!summary || summary.total === 0) return null;
  const segs = SEVERITY_ORDER.map((s) => ({ ...s, n: Number(summary[s.key]) || 0 })).filter((s) => s.n > 0);
  if (segs.length === 0) return null;
  return (
    <div className="scan-target-bar" aria-hidden="true">
      {segs.map((s) => (
        <div key={String(s.key)} title={`${String(s.key)}: ${s.n}`} style={{ flexGrow: s.n, background: severityVar(String(s.key)) }} />
      ))}
    </div>
  );
};

const StatusLabel = ({ status }: { status: string }) => {
  const tone = STATUS_TONES[status?.toLowerCase()] ?? "muted";
  return <span className={`scan-target-status scan-target-tone-${tone}`}>{status}</span>;
};

const SbomDiffGroup = ({
  label,
  tone,
  sign,
  entries,
  total,
}: {
  label: string;
  tone: "added" | "updated" | "removed";
  sign?: string;
  entries: { name: string; version: string; previousVersion?: string | null }[];
  total: number;
}) => {
  const { t } = useI18n();
  if (total === 0) return null;
  const shown = entries.slice(0, 12);
  const overflow = total - shown.length;
  return (
    <div className={`scan-target-diff-group scan-target-diff-group--${tone}`}>
      <h3>
        {label} <span className="scan-target-count">{total}</span>
      </h3>
      <ul className="scan-target-diff-list">
        {shown.map((e, i) => (
          <li key={`${e.name}@${e.version}-${i}`}>
            {sign && (
              <span className="scan-target-diff-sign" aria-hidden="true">
                {sign}
              </span>
            )}
            <span className="mono scan-target-diff-name">{e.name}</span>
            <span className="mono scan-target-diff-versions">
              {e.previousVersion ? (
                <>
                  <span>{e.previousVersion}</span>
                  <LuArrowRight aria-hidden="true" />
                  <span className="visually-hidden">{t("to", "auf")}</span>
                  <span>{e.version}</span>
                </>
              ) : (
                <span>{e.version}</span>
              )}
            </span>
          </li>
        ))}
      </ul>
      {overflow > 0 && <p className="scan-target-note">{t(`${overflow} more`, `${overflow} weitere`)}</p>}
    </div>
  );
};

const SbomChangesCard = ({ diff }: { diff: TargetSbomDiff }) => {
  const { t } = useI18n();
  const hasChanges = diff.addedCount + diff.removedCount + diff.updatedCount > 0;
  return (
    <Section
      title={t("SBOM changes", "SBOM-Änderungen")}
      actions={
        <span className="scan-target-meta">
          {diff.changedScanAt && (
            <span title={formatDateTime(diff.changedScanAt)}>
              {t("scanned", "gescannt")} {formatRelative(diff.changedScanAt)}
            </span>
          )}
          {diff.changedCommitSha && diff.changedScanId && (
            <Link className="scan-target-link mono" to={`/scans/${diff.changedScanId}`}>
              {diff.changedCommitSha.slice(0, 7)}
            </Link>
          )}
          <span>{diff.componentTotal} {t("components", "Komponenten")}</span>
        </span>
      }
    >
      {hasChanges && diff.changedScanId !== diff.latestScanId && (
        <p className="scan-target-note scan-target-note--lead">
          {t(
            "No SBOM changes in the latest scan. Showing the last scan that changed dependencies.",
            "Keine SBOM-Änderungen im letzten Scan. Zeigt den letzten Scan mit Abhängigkeitsänderungen.",
          )}
        </p>
      )}
      {!diff.previousScanId ? (
        <EmptyState
          title={t(
            `Baseline scan: ${diff.componentTotal} components, nothing to compare yet.`,
            `Erster Scan: ${diff.componentTotal} Komponenten, noch nichts zu vergleichen.`,
          )}
        />
      ) : !hasChanges ? (
        <EmptyState title={t("No SBOM changes since the previous scan.", "Keine SBOM-Änderungen seit dem letzten Scan.")} />
      ) : (
        <div className="scan-target-diff">
          <SbomDiffGroup label={t("Added", "Hinzugefügt")} tone="added" sign="+" entries={diff.added} total={diff.addedCount} />
          <SbomDiffGroup label={t("Updated", "Aktualisiert")} tone="updated" entries={diff.updated} total={diff.updatedCount} />
          <SbomDiffGroup label={t("Removed", "Entfernt")} tone="removed" sign="-" entries={diff.removed} total={diff.removedCount} />
        </div>
      )}
    </Section>
  );
};

export const ScanTargetDetailPage = () => {
  const { t } = useI18n();
  const navigate = useNavigate();
  const params = useParams();
  const { toast, showToast, dismiss } = useToast();
  // Splat param, NO extra decodeURIComponent: the router already percent-decodes
  // once, and a second decode mangles ids whose stored form contains literal
  // %-sequences (e.g. ".../ANK%C3%96/..." becomes ".../ANKÖ/..."). The backend
  // resolves non-canonical forms (scheme-less / re-encoded) fuzzily anyway.
  const targetId = params["*"] ?? "";

  const [target, setTarget] = useState<ScanTarget | null>(null);
  // history is accumulated newest-first across server pages.
  const [history, setHistory] = useState<ScanHistoryEntry[]>([]);
  const [historyTotal, setHistoryTotal] = useState(0);
  const [historyBusy, setHistoryBusy] = useState(false);
  const [findings, setFindings] = useState<ConsolidatedFinding[]>([]);
  const [sbomDiff, setSbomDiff] = useState<TargetSbomDiff | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!targetId) {
      setError(t("Target not found.", "Ziel nicht gefunden."));
      setLoading(false);
      return;
    }
    setLoading(true);
    setError("");
    try {
      const tg = await fetchScanTarget(targetId);
      setTarget(tg);
      // Pasted non-canonical URLs (scheme-less, differently encoded) resolve
      // server-side; replace the address bar with the canonical encoded form.
      // Both guards make this loop-proof regardless of router param decoding.
      if (targetId !== tg.id && targetId !== encodeURIComponent(tg.id)) {
        navigate(`/scans/targets/${encodeURIComponent(tg.id)}`, { replace: true });
      }
      // Follow-up queries match exactly on the scans' target_id field: use the
      // canonical id from the response, not the raw URL param.
      const [hist, finds, diff] = await Promise.all([
        fetchTargetHistory(tg.id, { limit: HISTORY_PAGE, offset: 0 }).catch(
          () => ({ items: [] as ScanHistoryEntry[], total: 0, targetId: tg.id })
        ),
        fetchGlobalFindings({ targetId: tg.id, limit: 10 }).catch(() => ({ items: [] as ConsolidatedFinding[], total: 0 })),
        fetchTargetSbomDiff(tg.id).catch(() => null),
      ]);
      // Server returns a page oldest-first; reverse to newest-first for the table.
      setHistory([...(hist.items ?? [])].reverse());
      setHistoryTotal(hist.total ?? (hist.items?.length ?? 0));
      setFindings(finds.items ?? []);
      setSbomDiff(diff);
    } catch {
      setError(t("Target not found.", "Ziel nicht gefunden."));
    } finally {
      setLoading(false);
    }
  }, [targetId, t, navigate]);

  // Fetch successive pages from the server, appending newest-first. `pageLimit`
  // is capped at the endpoint's 500 max; "Show all" loops until everything loads.
  const loadMoreHistory = useCallback(
    async (showAll: boolean) => {
      const id = target?.id ?? targetId;
      if (!id) return;
      setHistoryBusy(true);
      try {
        let current = history;
        do {
          const remaining = historyTotal - current.length;
          if (remaining <= 0) break;
          const pageLimit = showAll ? Math.min(500, remaining) : HISTORY_PAGE;
          const res = await fetchTargetHistory(id, { limit: pageLimit, offset: current.length });
          const page = [...(res.items ?? [])].reverse();
          if (page.length === 0) break;
          current = [...current, ...page];
          setHistory(current);
          setHistoryTotal(res.total ?? historyTotal);
        } while (showAll && current.length < historyTotal);
      } catch {
        /* ignore: keep what we have */
      } finally {
        setHistoryBusy(false);
      }
    },
    [target, targetId, history, historyTotal]
  );

  useEffect(() => {
    void load();
  }, [load]);

  const isImport = target?.type === "sbom-import";

  const handleRescan = async () => {
    if (!target || isImport) return;
    setBusy("rescan");
    try {
      const fallback =
        target.type === "container_image"
          ? ["trivy", "grype", "syft", "dockle", "dive"]
          : ["trivy", "grype", "syft", "osv-scanner", "hecate", "semgrep", "trufflehog"];
      await submitManualScan(
        {
          target: target.id,
          type: target.type as "container_image" | "source_repo",
          scanners: target.scanners?.length ? target.scanners : fallback,
        },
        target.id
      );
      showToast(t("Scan started.", "Scan gestartet."), "success");
    } catch {
      showToast(t("Rescan failed.", "Rescan fehlgeschlagen."), "error");
    } finally {
      setBusy(null);
    }
  };

  const handleCheck = async () => {
    if (!target) return;
    setBusy("check");
    try {
      const updated = await triggerTargetCheck(target.id);
      setTarget(updated);
      showToast(t("Check complete.", "Prüfung abgeschlossen."), "success");
    } catch {
      showToast(t("Check failed.", "Prüfung fehlgeschlagen."), "error");
    } finally {
      setBusy(null);
    }
  };

  const handleDelete = async () => {
    if (!target) return;
    if (!window.confirm(t("Delete this target and all its scan data?", "Dieses Ziel und alle Scan-Daten löschen?"))) {
      return;
    }
    setBusy("delete");
    try {
      await deleteScanTarget(target.id);
      navigate("/scans");
    } catch {
      showToast(t("Delete failed.", "Löschen fehlgeschlagen."), "error");
      setBusy(null);
    }
  };

  // Clickable shields.io badge markdown: the gold/grey severity badge image
  // (rendered by shields.io from our JSON endpoint) linked to this target page.
  const badgeMarkdown = useMemo(() => {
    if (!target) return "";
    const origin = window.location.origin;
    const encId = encodeURIComponent(target.id);
    const shieldEndpoint = `${origin}/api/v1/scans/targets/${encId}/shield`;
    const imgUrl = `https://img.shields.io/endpoint?url=${encodeURIComponent(shieldEndpoint)}`;
    const pageUrl = `${origin}/scans/targets/${encId}`;
    return `[![findings](${imgUrl})](${pageUrl})`;
  }, [target]);

  const backLink = (
    <Link to="/scans" className="scan-target-back">
      <LuArrowLeft aria-hidden="true" />
      {t("Scan targets", "Scan-Ziele")}
    </Link>
  );

  if (loading) {
    return (
      <div className="page scan-target">
        {backLink}
        <div className="scan-target-skeleton" aria-busy="true">
          <SkeletonBlock height={30} width="40%" />
          <SkeletonBlock height={18} width="60%" />
          <div className="scan-target-skeleton-figures">
            {[0, 1, 2, 3, 4].map((i) => (
              <SkeletonBlock key={i} height={64} />
            ))}
          </div>
          <SkeletonBlock height={8} />
          <div className="scan-target-skeleton-rows">
            {[0, 1, 2, 3, 4].map((i) => (
              <SkeletonBlock key={i} height={32} />
            ))}
          </div>
        </div>
      </div>
    );
  }

  if (error || !target) {
    return (
      <div className="page scan-target">
        {backLink}
        <ErrorState title={error || t("Target not found.", "Ziel nicht gefunden.")} />
      </div>
    );
  }

  const externalUrl = target.repositoryUrl || null;
  const summary = target.latestSummary;
  const typeMeta = TYPE_META[target.type] ?? { en: target.type, de: target.type };
  const typeLabel = t(typeMeta.en, typeMeta.de);
  const verdict = target.lastCheckVerdict ?? null;
  const verdictMeta = verdict ? VERDICT_META[verdict] : null;
  const verdictTone = verdictMeta?.tone ?? "muted";
  const verdictLabel = verdictMeta ? t(verdictMeta.en, verdictMeta.de) : "n/a";
  // Critical to low always show; negligible and unknown only when something landed there.
  const rollup = SEVERITY_ORDER.map((s) => ({ ...s, n: Number(summary?.[s.key]) || 0 })).filter((s) => !s.optional || s.n > 0);

  return (
    <div className="page scan-target">
      {backLink}

      <PageHeader
        title={<span className={NAME_IS_URL.test(target.name) ? "mono" : undefined}>{target.name}</span>}
        description={
          <span className="scan-target-identity">
            {externalUrl ? (
              <a
                href={safeHref(externalUrl)}
                target="_blank"
                rel="noopener noreferrer"
                className="scan-target-url scan-target-link mono"
                title={externalUrl}
              >
                {externalUrl}
                <LuExternalLink aria-hidden="true" />
              </a>
            ) : (
              <span className="scan-target-url mono">{target.id}</span>
            )}
            {target.writePasswordSet && (
              <span className="chip scan-target-chip-icon">
                <LuLock aria-hidden="true" />
                {t("Write-protected", "Schreibgeschützt")}
              </span>
            )}
            {target.hasRunningScan && (
              <span className="chip scan-target-tone-info">{t("Scan running", "Scan läuft")}</span>
            )}
            <span className="chip">{typeLabel}</span>
            {target.group && <span className="chip">{t("App", "App")}: {target.group}</span>}
            {target.registry && <span className="chip">{target.registry}</span>}
          </span>
        }
        actions={
          !isImport ? (
            <>
              <button type="button" className="btn-primary" disabled={busy === "rescan"} onClick={handleRescan}>
                <LuRefreshCw aria-hidden="true" />
                {busy === "rescan" ? t("Starting…", "Startet…") : t("Rescan", "Neu scannen")}
              </button>
              <button type="button" className="btn-secondary" disabled={busy === "check"} onClick={handleCheck}>
                <LuSearchCheck aria-hidden="true" />
                {busy === "check" ? t("Checking…", "Prüft…") : t("Run check", "Prüfung ausführen")}
              </button>
              <button
                type="button"
                className="btn-secondary"
                onClick={() => {
                  void navigator.clipboard?.writeText(badgeMarkdown);
                  showToast(t("Badge markdown copied.", "Badge-Markdown kopiert."), "success");
                }}
              >
                <LuCopy aria-hidden="true" />
                {t("Copy badge", "Badge kopieren")}
              </button>
              <button
                type="button"
                className="btn-secondary scan-target-delete"
                disabled={busy === "delete"}
                onClick={handleDelete}
              >
                <LuTrash2 aria-hidden="true" />
                {t("Delete target", "Ziel löschen")}
              </button>
            </>
          ) : undefined
        }
      />

      {/* Severity rollup: what the latest scan found, largest thing on the page */}
      <Section
        title={t("Findings", "Findings")}
        actions={
          <span className="scan-target-meta">
            <span>{t("Last scan", "Letzter Scan")}</span>
            {target.lastScanAt ? (
              <>
                <span title={formatDateTime(target.lastScanAt)}>{formatRelative(target.lastScanAt)}</span>
                <span>{formatDateTime(target.lastScanAt)}</span>
              </>
            ) : (
              <span>{t("never", "nie")}</span>
            )}
            {target.latestScanId && (
              <Link className="scan-target-link" to={`/scans/${target.latestScanId}`}>
                {t("View latest scan", "Neuesten Scan ansehen")}
              </Link>
            )}
          </span>
        }
      >
        <dl className="stat-row scan-target-rollup">
          <Stat label={t("in latest scan", "im letzten Scan")} value={summary?.total ?? 0} />
          {rollup.map((s) => (
            <Stat
              key={String(s.key)}
              label={t(s.en, s.de)}
              value={s.n}
              tone={s.n > 0 ? severityLevel(String(s.key)) : undefined}
            />
          ))}
        </dl>
        {summary && summary.total > 0 && <SeverityBar summary={summary} />}
      </Section>

      {findings.length > 0 && (
        <Section
          title={
            <>
              {t("Top findings", "Top-Findings")} <span className="scan-target-count">{findings.length}</span>
            </>
          }
        >
          <div className="table-scroll scan-target-scroll">
            <table className="scan-target-table scan-target-table--name-sticky">
              <thead>
                <tr>
                  <th scope="col">{t("Vulnerability", "Schwachstelle")}</th>
                  <th scope="col">{t("Severity", "Schweregrad")}</th>
                  <th scope="col">CVSS</th>
                  <th scope="col">{t("Package", "Paket")}</th>
                  <th scope="col">{t("Version", "Version")}</th>
                  <th scope="col">{t("Fix", "Fix")}</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((f, i) => {
                  const word = SEVERITY_ORDER.find((s) => s.key === f.severity?.toLowerCase());
                  return (
                    <tr key={`${f.vulnerabilityId ?? f.packageName}-${i}`}>
                      <td className="scan-target-name-cell">
                        {f.vulnerabilityId ? (
                          <Link className="scan-target-link mono" to={`/vulnerability/${f.vulnerabilityId}`}>
                            {f.vulnerabilityId}
                          </Link>
                        ) : (
                          <span>{f.title ?? f.packageName}</span>
                        )}
                      </td>
                      <td>
                        <SeverityTag severity={f.severity}>{word ? t(word.en, word.de) : f.severity}</SeverityTag>
                      </td>
                      <td>{f.cvssScore != null ? f.cvssScore.toFixed(1) : null}</td>
                      <td className="mono">{f.packageName}</td>
                      <td className="mono">{f.packageVersion}</td>
                      <td className="mono">{f.fixVersion}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </Section>
      )}

      {/* SBOM changes */}
      {!isImport && sbomDiff && sbomDiff.latestScanId && <SbomChangesCard diff={sbomDiff} />}

      {/* History */}
      <Section
        title={t("Scan history", "Scan-Verlauf")}
        actions={
          historyTotal > 0 ? (
            <span className="scan-target-meta">
              {t("Showing", "Zeige")} {history.length} / {historyTotal}
            </span>
          ) : undefined
        }
      >
        {history.length === 0 ? (
          <EmptyState title={t("No completed scans yet.", "Noch keine abgeschlossenen Scans.")} />
        ) : (
          <>
            <div className="table-scroll scan-target-scroll">
              <table className="scan-target-table scan-target-table--name-sticky scan-target-table--action-sticky">
                <thead>
                  <tr>
                    <th scope="col">{t("Date", "Datum")}</th>
                    <th scope="col">{t("Status", "Status")}</th>
                    <th scope="col">{t("Findings", "Findings")}</th>
                    <th scope="col">{t("Duration", "Dauer")}</th>
                    <th scope="col">{t("Commit", "Commit")}</th>
                    <th scope="col">{t("Scan", "Scan")}</th>
                  </tr>
                </thead>
                <tbody>
                  {history.map((h) => (
                    <tr key={h.scanId}>
                      <td className="scan-target-nowrap" title={formatDateTime(h.startedAt)}>
                        {formatDateTime(h.startedAt)}
                      </td>
                      <td>
                        <StatusLabel status={h.status} />
                      </td>
                      <td>
                        <SeverityBadges summary={h.summary} />
                      </td>
                      <td className="scan-target-muted">{formatDuration(h.durationSeconds)}</td>
                      <td>
                        {h.commitSha ? (
                          <code className="mono">{h.commitSha.slice(0, 7)}</code>
                        ) : (
                          <span className="scan-target-muted">n/a</span>
                        )}
                      </td>
                      <td>
                        <Link className="scan-target-link mono" to={`/scans/${h.scanId}`}>
                          {h.scanId.slice(0, 8)}
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {history.length < historyTotal && (
              <div className="scan-target-pager">
                <button type="button" className="btn-secondary" disabled={historyBusy} onClick={() => loadMoreHistory(false)}>
                  {historyBusy
                    ? t("Loading…", "Lädt…")
                    : `${t("Load more", "Mehr laden")} (${history.length} / ${historyTotal})`}
                </button>
                <button type="button" className="btn-secondary" disabled={historyBusy} onClick={() => loadMoreHistory(true)}>
                  {t("Show all", "Alle anzeigen")}
                </button>
              </div>
            )}
          </>
        )}
      </Section>

      {/* Diagnostics: how this target is scanned, not what was found */}
      <Section title={t("Diagnostics", "Diagnose")}>
        <dl className="stat-row scan-target-diagnostics">
          <Stat
            label={t("Scans run", "Scans")}
            value={
              <>
                {target.scanCount ?? 0}
                <span className="scan-target-sub">{t("total runs", "Läufe gesamt")}</span>
              </>
            }
          />
          {!isImport && (
            <Stat
              label={t("Auto-scan", "Auto-Scan")}
              value={<span className={target.autoScan ? undefined : "scan-target-tone-muted"}>{target.autoScan ? t("On", "An") : t("Off", "Aus")}</span>}
            />
          )}
          {!isImport && (target.lastCheckAt || target.autoScan) && (
            <Stat
              label={t("Last check", "Letzte Prüfung")}
              value={
                <>
                  <span className={`scan-target-tone-${verdictTone}`}>{verdictLabel}</span>
                  {target.lastCheckError ? (
                    <span className="scan-target-sub scan-target-tone-error" title={target.lastCheckError}>
                      {target.lastCheckError}
                    </span>
                  ) : (
                    <span className="scan-target-sub">
                      {target.lastCheckAt ? formatRelative(target.lastCheckAt) : t("not yet probed", "noch nicht geprüft")}
                    </span>
                  )}
                </>
              }
            />
          )}
          <Stat
            label={t("Scanners", "Scanner")}
            value={
              <>
                {target.scanners?.length ?? 0}
                <span className="scan-target-sub">{t("configured", "konfiguriert")}</span>
              </>
            }
          />
        </dl>
        {target.scanners?.length ? (
          <div className="scan-target-scanners">
            <span className="scan-target-muted">{t("Scanners", "Scanner")}</span>
            {target.scanners.map((s) => (
              <span key={s} className="chip">
                {s}
              </span>
            ))}
          </div>
        ) : null}
      </Section>

      <Toast toast={toast} onDismiss={dismiss} />
    </div>
  );
};
