import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";

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
import { Toast, useToast } from "../components/Toast";
import { useI18n } from "../i18n/context";
import type { ConsolidatedFinding, ScanHistoryEntry, ScanSummary, ScanTarget, TargetSbomDiff } from "../types";
import { formatDateTime } from "../utils/dateFormat";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ff6b6b",
  high: "#ff922b",
  medium: "#fcc419",
  low: "#69db7c",
  negligible: "#8395a7",
  unknown: "#8395a7",
};

const SeverityTag = ({ severity }: { severity: string }) => {
  const color = SEVERITY_COLORS[severity?.toLowerCase()] ?? "#8395a7";
  return (
    <span
      style={{
        display: "inline-block",
        minWidth: 64,
        textAlign: "center",
        padding: "0.125rem 0.5rem",
        borderRadius: 4,
        fontSize: "0.7rem",
        fontWeight: 600,
        textTransform: "capitalize",
        background: `${color}20`,
        color,
      }}
    >
      {severity}
    </span>
  );
};

const Chip = ({ children }: { children: React.ReactNode }) => (
  <span
    style={{
      display: "inline-flex",
      alignItems: "center",
      padding: "0.125rem 0.625rem",
      borderRadius: 6,
      fontSize: "0.75rem",
      background: "rgba(255,255,255,0.06)",
      border: "1px solid rgba(255,255,255,0.1)",
      color: "rgba(255,255,255,0.75)",
    }}
  >
    {children}
  </span>
);

const HISTORY_PAGE = 25;

const backLinkStyle: React.CSSProperties = {
  color: "rgba(255,255,255,0.4)",
  textDecoration: "none",
  fontSize: "0.8125rem",
};

const sectionHeading: React.CSSProperties = {
  margin: "0 0 1rem",
  fontSize: "1.1rem",
  fontWeight: 600,
};

const btn: React.CSSProperties = {
  padding: "0.4rem 0.85rem",
  borderRadius: 6,
  border: "1px solid rgba(255,255,255,0.12)",
  background: "rgba(255,255,255,0.04)",
  color: "rgba(255,255,255,0.85)",
  cursor: "pointer",
  fontSize: "0.8125rem",
};

const btnPrimary: React.CSSProperties = {
  ...btn,
  background: "rgba(255,212,59,0.12)",
  borderColor: "rgba(255,212,59,0.35)",
  color: "#ffd43b",
  fontWeight: 600,
};

const thStyle: React.CSSProperties = {
  padding: "0.55rem 0.75rem",
  fontWeight: 600,
  whiteSpace: "nowrap",
  fontSize: "0.7rem",
  textTransform: "uppercase",
  letterSpacing: "0.5px",
};
const tdStyle: React.CSSProperties = { padding: "0.6rem 0.75rem", whiteSpace: "nowrap" };

// i18n label per target kind, shown in the header type chip.
const TYPE_META: Record<string, { en: string; de: string }> = {
  container_image: { en: "Container image", de: "Container-Image" },
  source_repo: { en: "Source repo", de: "Quell-Repo" },
  "sbom-import": { en: "SBOM import", de: "SBOM-Import" },
};

// Colour + label per auto-scan /check verdict (mirrors the Scanner-tab pills).
const VERDICT_META: Record<string, { color: string; en: string; de: string }> = {
  changed: { color: "#ff922b", en: "Changed", de: "Geändert" },
  unchanged: { color: "#69db7c", en: "Unchanged", de: "Unverändert" },
  first_scan: { color: "#4dabf7", en: "First scan", de: "Erster Scan" },
  check_failed_skipped: { color: "#ff6b6b", en: "Check failed", de: "Prüfung fehlgeschlagen" },
  check_failed_scanned: { color: "#fcc419", en: "Check failed", de: "Prüfung fehlgeschlagen" },
};

const STATUS_COLORS: Record<string, string> = {
  completed: "#69db7c",
  failed: "#ff6b6b",
  running: "#4dabf7",
  pending: "#fcc419",
  cancelled: "#8395a7",
  canceled: "#8395a7",
};

const SEVERITY_BAR_ORDER: { key: keyof ScanSummary; color: string }[] = [
  { key: "critical", color: "#ff6b6b" },
  { key: "high", color: "#ff922b" },
  { key: "medium", color: "#fcc419" },
  { key: "low", color: "#69db7c" },
  { key: "negligible", color: "#5c6b7a" },
  { key: "unknown", color: "#5c6b7a" },
];

const worstSeverity = (s?: ScanSummary | null): string | null => {
  if (!s) return null;
  if (s.critical > 0) return "critical";
  if (s.high > 0) return "high";
  if (s.medium > 0) return "medium";
  if (s.low > 0) return "low";
  if (s.negligible > 0 || s.unknown > 0) return "unknown";
  return null;
};

// Compact, language-neutral relative time ("3h", "2d") — the absolute value
// rides along as a title tooltip so the unit suffix needs no translation.
const formatRelative = (iso?: string | null): string => {
  if (!iso) return "—";
  const ms = new Date(iso).getTime();
  if (Number.isNaN(ms)) return "—";
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
  if (sec == null) return "—";
  if (sec < 60) return `${Math.round(sec)}s`;
  const m = Math.floor(sec / 60);
  const s = Math.round(sec % 60);
  if (m < 60) return s ? `${m}m ${s}s` : `${m}m`;
  return `${Math.floor(m / 60)}h ${m % 60}m`;
};

// Proportional stacked severity bar — instant visual read of the risk mix.
const SeverityBar = ({ summary }: { summary?: ScanSummary | null }) => {
  if (!summary || summary.total === 0) return null;
  const segs = SEVERITY_BAR_ORDER.map((s) => ({ ...s, n: Number(summary[s.key]) || 0 })).filter((s) => s.n > 0);
  if (segs.length === 0) return null;
  return (
    <div
      style={{
        display: "flex",
        height: 8,
        borderRadius: 5,
        overflow: "hidden",
        background: "rgba(255,255,255,0.05)",
      }}
    >
      {segs.map((s) => (
        <div key={String(s.key)} title={`${String(s.key)}: ${s.n}`} style={{ flexGrow: s.n, flexBasis: 0, background: s.color }} />
      ))}
    </div>
  );
};

const StatTile = ({
  label,
  value,
  valueColor,
  sub,
}: {
  label: string;
  value: React.ReactNode;
  valueColor?: string;
  sub?: React.ReactNode;
}) => (
  <div
    style={{
      background: "rgba(255,255,255,0.03)",
      border: "1px solid rgba(255,255,255,0.07)",
      borderRadius: 10,
      padding: "0.8rem 0.95rem",
      minWidth: 0,
    }}
  >
    <div
      style={{
        fontSize: "0.66rem",
        textTransform: "uppercase",
        letterSpacing: "0.6px",
        color: "rgba(255,255,255,0.4)",
        whiteSpace: "nowrap",
        overflow: "hidden",
        textOverflow: "ellipsis",
      }}
    >
      {label}
    </div>
    <div
      style={{
        fontSize: "1.45rem",
        fontWeight: 700,
        lineHeight: 1.15,
        marginTop: "0.35rem",
        color: valueColor ?? "rgba(255,255,255,0.92)",
        display: "flex",
        alignItems: "center",
        gap: "0.4rem",
      }}
    >
      {value}
    </div>
    {sub != null && (
      <div
        style={{
          fontSize: "0.72rem",
          color: "rgba(255,255,255,0.38)",
          marginTop: "0.3rem",
          whiteSpace: "nowrap",
          overflow: "hidden",
          textOverflow: "ellipsis",
        }}
      >
        {sub}
      </div>
    )}
  </div>
);

const StatusPill = ({ status }: { status: string }) => {
  const color = STATUS_COLORS[status?.toLowerCase()] ?? "#8395a7";
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: "0.4rem", fontSize: "0.8rem", color }}>
      <span style={{ width: 7, height: 7, borderRadius: "50%", background: color, display: "inline-block" }} />
      {status}
    </span>
  );
};

const SbomDiffGroup = ({
  label,
  color,
  entries,
  total,
}: {
  label: string;
  color: string;
  entries: { name: string; version: string; previousVersion?: string | null }[];
  total: number;
}) => {
  if (total === 0) return null;
  const shown = entries.slice(0, 12);
  const overflow = total - shown.length;
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "0.4rem", minWidth: 0 }}>
      <div style={{ display: "flex", alignItems: "center", gap: "0.4rem" }}>
        <span style={{ width: 8, height: 8, borderRadius: "50%", background: color }} />
        <span style={{ fontSize: "0.8rem", fontWeight: 600, color }}>{label}</span>
        <span style={{ fontSize: "0.75rem", color: "rgba(255,255,255,0.4)" }}>{total}</span>
      </div>
      <div style={{ display: "flex", gap: "0.35rem", flexWrap: "wrap" }}>
        {shown.map((e, i) => (
          <span
            key={`${e.name}@${e.version}-${i}`}
            style={{
              fontSize: "0.72rem",
              fontFamily: "var(--mono, monospace)",
              background: `${color}14`,
              border: `1px solid ${color}33`,
              borderRadius: 5,
              padding: "0.1rem 0.45rem",
              color: "rgba(255,255,255,0.8)",
              wordBreak: "break-all",
            }}
          >
            {e.name}
            {e.previousVersion ? ` ${e.previousVersion} → ${e.version}` : `@${e.version}`}
          </span>
        ))}
        {overflow > 0 && (
          <span style={{ fontSize: "0.72rem", color: "rgba(255,255,255,0.4)" }}>+{overflow}</span>
        )}
      </div>
    </div>
  );
};

const SbomChangesCard = ({ diff }: { diff: TargetSbomDiff }) => {
  const { t } = useI18n();
  const hasChanges = diff.addedCount + diff.removedCount + diff.updatedCount > 0;
  return (
    <section className="card">
      <div style={{ display: "flex", alignItems: "baseline", gap: "0.6rem", flexWrap: "wrap", marginBottom: "0.85rem" }}>
        <h2 style={{ ...sectionHeading, margin: 0 }}>{t("SBOM changes", "SBOM-Änderungen")}</h2>
        <span style={{ color: "rgba(255,255,255,0.45)", fontSize: "0.8rem", display: "inline-flex", gap: "0.45rem", alignItems: "center", flexWrap: "wrap" }}>
          {diff.changedScanAt && (
            <span title={formatDateTime(diff.changedScanAt)}>
              {t("scanned", "gescannt")} {formatRelative(diff.changedScanAt)}
            </span>
          )}
          {diff.changedCommitSha && diff.changedScanId && (
            <>
              <span>·</span>
              <Link to={`/scans/${diff.changedScanId}`}>
                <code
                  style={{
                    fontSize: "0.72rem",
                    color: "rgba(255,255,255,0.6)",
                    background: "rgba(255,255,255,0.05)",
                    borderRadius: 4,
                    padding: "0.1rem 0.4rem",
                  }}
                >
                  {diff.changedCommitSha.slice(0, 7)}
                </code>
              </Link>
            </>
          )}
          <span>·</span>
          <span>{diff.componentTotal} {t("components", "Komponenten")}</span>
        </span>
      </div>
      {hasChanges && diff.changedScanId !== diff.latestScanId && (
        <p style={{ color: "rgba(255,255,255,0.4)", fontSize: "0.78rem", margin: "0 0 0.85rem" }}>
          {t(
            "No SBOM changes in the latest scan — showing the last scan that changed dependencies.",
            "Keine SBOM-Änderungen im letzten Scan — zeigt den letzten Scan mit Abhängigkeitsänderungen.",
          )}
        </p>
      )}
      {!diff.previousScanId ? (
        <p style={{ color: "rgba(255,255,255,0.45)", fontSize: "0.85rem", margin: 0 }}>
          {t(
            `Baseline scan — ${diff.componentTotal} components, nothing to compare yet.`,
            `Erster Scan — ${diff.componentTotal} Komponenten, noch nichts zu vergleichen.`,
          )}
        </p>
      ) : !hasChanges ? (
        <p style={{ color: "rgba(255,255,255,0.45)", fontSize: "0.85rem", margin: 0 }}>
          {t("No SBOM changes since the previous scan.", "Keine SBOM-Änderungen seit dem letzten Scan.")}
        </p>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
          <SbomDiffGroup label={t("Added", "Hinzugefügt")} color="#69db7c" entries={diff.added} total={diff.addedCount} />
          <SbomDiffGroup label={t("Updated", "Aktualisiert")} color="#fcc419" entries={diff.updated} total={diff.updatedCount} />
          <SbomDiffGroup label={t("Removed", "Entfernt")} color="#ff6b6b" entries={diff.removed} total={diff.removedCount} />
        </div>
      )}
    </section>
  );
};

export const ScanTargetDetailPage = () => {
  const { t } = useI18n();
  const navigate = useNavigate();
  const params = useParams();
  const { toast, showToast } = useToast();
  // Splat param, NO extra decodeURIComponent: the router already percent-decodes
  // once, and a second decode mangles ids whose stored form contains literal
  // %-sequences (e.g. ".../ANK%C3%96/..." → ".../ANKÖ/..."). The backend
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
      // Follow-up queries match exactly on the scans' target_id field — use the
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
        /* ignore — keep what we have */
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

  if (loading) {
    return (
      <div className="page">
        <section className="card" style={{ borderLeft: "3px solid rgba(255,255,255,0.12)" }}>
          <Link to="/scans" style={backLinkStyle}>
            ← {t("Scan targets", "Scan-Ziele")}
          </Link>
          <div style={{ display: "flex", flexDirection: "column", gap: "0.85rem", marginTop: "1rem" }}>
            <div className="skeleton" style={{ width: "45%", height: 26 }} />
            <div className="skeleton" style={{ width: "70%", height: 14 }} />
            <div className="skeleton" style={{ width: "100%", height: 8 }} />
          </div>
        </section>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: "0.85rem", marginBottom: "1.5rem" }}>
          {[0, 1, 2, 3].map((i) => (
            <div key={i} className="skeleton" style={{ height: 78, borderRadius: 10 }} />
          ))}
        </div>
      </div>
    );
  }

  if (error || !target) {
    return (
      <div className="page">
        <section className="card">
          <Link to="/scans" style={backLinkStyle}>
            ← {t("Scan targets", "Scan-Ziele")}
          </Link>
          <p style={{ color: "#ff6b6b", marginTop: "0.75rem" }}>
            {error || t("Target not found.", "Ziel nicht gefunden.")}
          </p>
        </section>
      </div>
    );
  }

  const externalUrl = target.repositoryUrl || null;
  const summary = target.latestSummary;
  const worst = worstSeverity(summary);
  const accent = worst ? SEVERITY_COLORS[worst] : "rgba(255,255,255,0.12)";
  const typeMeta = TYPE_META[target.type] ?? { en: target.type, de: target.type };
  const typeLabel = t(typeMeta.en, typeMeta.de);
  const verdict = target.lastCheckVerdict ?? null;
  const verdictMeta = verdict ? VERDICT_META[verdict] : null;
  const verdictColor = verdictMeta?.color ?? "rgba(255,255,255,0.5)";
  const verdictLabel = verdictMeta ? t(verdictMeta.en, verdictMeta.de) : "—";

  return (
    <div className="page">
      {/* Header — severity-accented, with type icon and live scan state */}
      <section className="card" style={{ overflow: "visible", borderLeft: `3px solid ${accent}` }}>
        <Link to="/scans" style={backLinkStyle}>
          ← {t("Scan targets", "Scan-Ziele")}
        </Link>

        <div style={{ display: "flex", justifyContent: "space-between", gap: "1.25rem", flexWrap: "wrap", marginTop: "0.5rem" }}>
          <div style={{ minWidth: 0, flex: "1 1 320px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "0.6rem", flexWrap: "wrap" }}>
              <h2 style={{ margin: 0, fontSize: "1.5rem", wordBreak: "break-word" }}>
                {target.writePasswordSet && <span title={t("Write-protected", "Schreibgeschützt")}>🔒 </span>}
                {target.name}
              </h2>
              {externalUrl && (
                <a
                  href={externalUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{ color: "#ffd43b", textDecoration: "none", fontSize: "1rem", lineHeight: 1 }}
                  title={externalUrl}
                >
                  ↗
                </a>
              )}
              {target.hasRunningScan && (
                <span
                  style={{
                    display: "inline-flex",
                    alignItems: "center",
                    gap: "0.35rem",
                    fontSize: "0.72rem",
                    color: "#4dabf7",
                    background: "rgba(77,171,247,0.12)",
                    border: "1px solid rgba(77,171,247,0.3)",
                    borderRadius: 999,
                    padding: "0.15rem 0.65rem",
                    animation: "pulse-badge 1.5s ease-in-out infinite",
                  }}
                >
                  <span
                    style={{
                      width: "6px",
                      height: "6px",
                      borderRadius: "50%",
                      background: "#4dabf7",
                      animation: "pulse-dot 1.5s ease-in-out infinite",
                    }}
                  />
                  {t("Scan running", "Scan läuft")}
                </span>
              )}
            </div>

            <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap", marginTop: "0.7rem" }}>
              <Chip>{typeLabel}</Chip>
              {target.group && <Chip>{t("App", "App")}: {target.group}</Chip>}
              {target.registry && <Chip>{target.registry}</Chip>}
            </div>

            <p style={{ marginTop: "0.7rem", color: "rgba(255,255,255,0.4)", fontSize: "0.8rem", wordBreak: "break-all" }}>
              {target.repositoryUrl || target.id}
            </p>
          </div>

          <div style={{ textAlign: "right", marginLeft: "auto", minWidth: 150 }}>
            <SeverityBadges summary={summary} style={{ justifyContent: "flex-end" }} />
            {target.latestScanId && (
              <div style={{ marginTop: "0.6rem" }}>
                <Link to={`/scans/${target.latestScanId}`} style={{ fontSize: "0.85rem" }}>
                  {t("View latest scan", "Neuesten Scan ansehen")} →
                </Link>
              </div>
            )}
          </div>
        </div>

        {summary && summary.total > 0 && (
          <div style={{ marginTop: "1rem" }}>
            <SeverityBar summary={summary} />
          </div>
        )}

        {target.scanners?.length ? (
          <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap", marginTop: "1rem", alignItems: "center" }}>
            <span style={{ fontSize: "0.7rem", textTransform: "uppercase", letterSpacing: "0.5px", color: "rgba(255,255,255,0.35)" }}>
              {t("Scanners", "Scanner")}
            </span>
            {target.scanners.map((s) => (
              <Chip key={s}>{s}</Chip>
            ))}
          </div>
        ) : null}

        {!isImport && (
          <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap", marginTop: "1.25rem" }}>
            <button type="button" style={btnPrimary} disabled={busy === "rescan"} onClick={handleRescan}>
              ↻ {busy === "rescan" ? t("Starting…", "Startet…") : t("Rescan", "Neu scannen")}
            </button>
            <button type="button" style={btn} disabled={busy === "check"} onClick={handleCheck}>
              {busy === "check" ? t("Checking…", "Prüft…") : t("Run check", "Prüfung ausführen")}
            </button>
            <button
              type="button"
              style={btn}
              onClick={() => {
                void navigator.clipboard?.writeText(badgeMarkdown);
                showToast(t("Badge markdown copied.", "Badge-Markdown kopiert."), "success");
              }}
            >
              {t("Copy badge", "Badge kopieren")}
            </button>
            <button
              type="button"
              style={{ ...btn, color: "#ff6b6b", borderColor: "rgba(255,107,107,0.3)" }}
              disabled={busy === "delete"}
              onClick={handleDelete}
            >
              {t("Delete target", "Ziel löschen")}
            </button>
          </div>
        )}
      </section>

      {/* Metrics strip */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))",
          gap: "0.85rem",
          marginBottom: "1.5rem",
        }}
      >
        <StatTile
          label={t("Findings", "Findings")}
          value={summary?.total ?? 0}
          valueColor={worst ? SEVERITY_COLORS[worst] : undefined}
          sub={t("in latest scan", "im letzten Scan")}
        />
        <StatTile label={t("Scans run", "Scans")} value={target.scanCount ?? 0} sub={t("total runs", "Läufe gesamt")} />
        <StatTile
          label={t("Last scan", "Letzter Scan")}
          value={<span title={target.lastScanAt ? formatDateTime(target.lastScanAt) : undefined}>{formatRelative(target.lastScanAt)}</span>}
          sub={target.lastScanAt ? formatDateTime(target.lastScanAt) : t("never", "nie")}
        />
        {!isImport && (
          <StatTile
            label={t("Auto-scan", "Auto-Scan")}
            value={
              <span style={{ display: "inline-flex", alignItems: "center", gap: "0.45rem" }}>
                <span style={{ width: 9, height: 9, borderRadius: "50%", background: target.autoScan ? "#69db7c" : "#8395a7" }} />
                {target.autoScan ? t("On", "An") : t("Off", "Aus")}
              </span>
            }
            valueColor={target.autoScan ? "#69db7c" : "rgba(255,255,255,0.6)"}
          />
        )}
        {!isImport && (target.lastCheckAt || target.autoScan) && (
          <StatTile
            label={t("Last check", "Letzte Prüfung")}
            value={
              <span style={{ display: "inline-flex", alignItems: "center", gap: "0.45rem", fontSize: "1.02rem" }}>
                <span style={{ width: 9, height: 9, borderRadius: "50%", background: verdictColor }} />
                {verdictLabel}
              </span>
            }
            valueColor={verdictColor}
            sub={
              target.lastCheckError ? (
                <span style={{ color: "#ff6b6b" }} title={target.lastCheckError}>
                  {target.lastCheckError}
                </span>
              ) : target.lastCheckAt ? (
                formatRelative(target.lastCheckAt)
              ) : (
                t("not yet probed", "noch nicht geprüft")
              )
            }
          />
        )}
        <StatTile label={t("Scanners", "Scanner")} value={target.scanners?.length ?? 0} sub={t("configured", "konfiguriert")} />
      </div>

      {(findings.length > 0 || (!isImport && sbomDiff && sbomDiff.latestScanId)) && (
        <div className="target-detail-top-row">
          {/* Top findings */}
          {findings.length > 0 && (
            <section className="card">
              <div style={{ display: "flex", alignItems: "baseline", gap: "0.6rem", marginBottom: "1rem" }}>
                <h2 style={{ ...sectionHeading, margin: 0 }}>{t("Top findings", "Top-Findings")}</h2>
                <span style={{ color: "rgba(255,255,255,0.4)", fontSize: "0.8rem" }}>{findings.length}</span>
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: "0.55rem" }}>
                {findings.map((f, i) => {
                  const sevColor = SEVERITY_COLORS[f.severity?.toLowerCase()] ?? "#8395a7";
                  return (
                    <div
                      key={`${f.vulnerabilityId ?? f.packageName}-${i}`}
                      style={{
                        display: "flex",
                        gap: "0.85rem",
                        alignItems: "center",
                        flexWrap: "wrap",
                        padding: "0.65rem 0.85rem",
                        background: "rgba(255,255,255,0.025)",
                        borderRadius: 8,
                        borderLeft: `3px solid ${sevColor}`,
                      }}
                    >
                      <SeverityTag severity={f.severity} />
                      <div style={{ display: "flex", flexDirection: "column", gap: "0.2rem", minWidth: 0, flex: 1 }}>
                        <div style={{ display: "flex", alignItems: "center", gap: "0.6rem", flexWrap: "wrap" }}>
                          {f.vulnerabilityId ? (
                            <Link to={`/vulnerability/${f.vulnerabilityId}`} style={{ fontWeight: 600 }}>
                              {f.vulnerabilityId}
                            </Link>
                          ) : (
                            <span style={{ fontWeight: 600 }}>{f.title ?? f.packageName}</span>
                          )}
                          {f.cvssScore != null && (
                            <span style={{ fontSize: "0.72rem", color: sevColor, fontWeight: 600 }}>
                              CVSS {f.cvssScore.toFixed(1)}
                            </span>
                          )}
                          {f.fixVersion && (
                            <span
                              style={{
                                fontSize: "0.7rem",
                                color: "#69db7c",
                                background: "rgba(105,219,124,0.12)",
                                border: "1px solid rgba(105,219,124,0.25)",
                                borderRadius: 5,
                                padding: "0.05rem 0.4rem",
                              }}
                            >
                              {t("fix", "Fix")}: {f.fixVersion}
                            </span>
                          )}
                        </div>
                        <span
                          style={{
                            color: "rgba(255,255,255,0.45)",
                            fontSize: "0.8rem",
                            fontFamily: "var(--mono, monospace)",
                            wordBreak: "break-all",
                          }}
                        >
                          {f.packageName}@{f.packageVersion}
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </section>
          )}

          {/* SBOM changes */}
          {!isImport && sbomDiff && sbomDiff.latestScanId && <SbomChangesCard diff={sbomDiff} />}
        </div>
      )}

      {/* History */}
      <section className="card">
        <div style={{ display: "flex", alignItems: "baseline", justifyContent: "space-between", gap: "0.5rem" }}>
          <h2 style={sectionHeading}>{t("Scan history", "Scan-Verlauf")}</h2>
          {historyTotal > 0 && (
            <span style={{ color: "rgba(255,255,255,0.4)", fontSize: "0.8rem" }}>
              {t("Showing", "Zeige")} {history.length} / {historyTotal}
            </span>
          )}
        </div>
        {history.length === 0 ? (
          <p style={{ color: "rgba(255,255,255,0.45)" }}>{t("No completed scans yet.", "Noch keine abgeschlossenen Scans.")}</p>
        ) : (
          <>
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.875rem" }}>
                <thead>
                  <tr style={{ textAlign: "left", color: "rgba(255,255,255,0.4)" }}>
                    <th style={thStyle}>{t("Date", "Datum")}</th>
                    <th style={thStyle}>{t("Status", "Status")}</th>
                    <th style={thStyle}>{t("Findings", "Findings")}</th>
                    <th style={thStyle}>{t("Duration", "Dauer")}</th>
                    <th style={thStyle}>{t("Commit", "Commit")}</th>
                    <th style={thStyle}>{t("Scan", "Scan")}</th>
                  </tr>
                </thead>
                <tbody>
                  {history.map((h, i) => (
                    <tr
                      key={h.scanId}
                      style={{
                        borderTop: "1px solid rgba(255,255,255,0.06)",
                        background: i % 2 ? "rgba(255,255,255,0.015)" : "transparent",
                      }}
                    >
                      <td style={tdStyle} title={formatDateTime(h.startedAt)}>
                        {formatDateTime(h.startedAt)}
                      </td>
                      <td style={tdStyle}>
                        <StatusPill status={h.status} />
                      </td>
                      <td style={tdStyle}>
                        <SeverityBadges summary={h.summary} />
                      </td>
                      <td style={{ ...tdStyle, color: "rgba(255,255,255,0.55)" }}>{formatDuration(h.durationSeconds)}</td>
                      <td style={tdStyle}>
                        {h.commitSha ? (
                          <code
                            style={{
                              fontSize: "0.75rem",
                              color: "rgba(255,255,255,0.6)",
                              background: "rgba(255,255,255,0.05)",
                              borderRadius: 4,
                              padding: "0.1rem 0.4rem",
                            }}
                          >
                            {h.commitSha.slice(0, 7)}
                          </code>
                        ) : (
                          <span style={{ color: "rgba(255,255,255,0.25)" }}>—</span>
                        )}
                      </td>
                      <td style={tdStyle}>
                        <Link to={`/scans/${h.scanId}`}>{h.scanId.slice(0, 8)}</Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {history.length < historyTotal && (
              <div style={{ display: "flex", gap: "0.5rem", marginTop: "0.75rem", flexWrap: "wrap" }}>
                <button type="button" style={btn} disabled={historyBusy} onClick={() => loadMoreHistory(false)}>
                  {historyBusy
                    ? t("Loading…", "Lädt…")
                    : `${t("Load more", "Mehr laden")} (${history.length} / ${historyTotal})`}
                </button>
                <button type="button" style={btn} disabled={historyBusy} onClick={() => loadMoreHistory(true)}>
                  {t("Show all", "Alle anzeigen")}
                </button>
              </div>
            )}
          </>
        )}
      </section>

      <Toast toast={toast} />
    </div>
  );
};
