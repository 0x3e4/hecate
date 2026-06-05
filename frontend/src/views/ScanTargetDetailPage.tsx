import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";

import {
  deleteScanTarget,
  fetchGlobalFindings,
  fetchScanTarget,
  fetchTargetHistory,
  submitManualScan,
  triggerTargetCheck,
} from "../api/scans";
import { SeverityBadges } from "../components/SeverityBadges";
import { Toast, useToast } from "../components/Toast";
import { useI18n } from "../i18n/context";
import type { ConsolidatedFinding, ScanHistoryEntry, ScanTarget } from "../types";
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

const thStyle: React.CSSProperties = { padding: "0.5rem 0.75rem", fontWeight: 600, whiteSpace: "nowrap" };
const tdStyle: React.CSSProperties = { padding: "0.5rem 0.75rem", whiteSpace: "nowrap" };

export const ScanTargetDetailPage = () => {
  const { t } = useI18n();
  const navigate = useNavigate();
  const params = useParams();
  const { toast, showToast } = useToast();
  const targetId = useMemo(
    () => (params.targetId ? decodeURIComponent(params.targetId) : ""),
    [params.targetId]
  );

  const [target, setTarget] = useState<ScanTarget | null>(null);
  // history is accumulated newest-first across server pages.
  const [history, setHistory] = useState<ScanHistoryEntry[]>([]);
  const [historyTotal, setHistoryTotal] = useState(0);
  const [historyBusy, setHistoryBusy] = useState(false);
  const [findings, setFindings] = useState<ConsolidatedFinding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!targetId) return;
    setLoading(true);
    setError("");
    try {
      const tg = await fetchScanTarget(targetId);
      setTarget(tg);
      const [hist, finds] = await Promise.all([
        fetchTargetHistory(targetId, { limit: HISTORY_PAGE, offset: 0 }).catch(
          () => ({ items: [] as ScanHistoryEntry[], total: 0, targetId })
        ),
        fetchGlobalFindings({ targetId, limit: 10 }).catch(() => ({ items: [] as ConsolidatedFinding[], total: 0 })),
      ]);
      // Server returns a page oldest-first; reverse to newest-first for the table.
      setHistory([...(hist.items ?? [])].reverse());
      setHistoryTotal(hist.total ?? (hist.items?.length ?? 0));
      setFindings(finds.items ?? []);
    } catch {
      setError(t("Target not found.", "Ziel nicht gefunden."));
    } finally {
      setLoading(false);
    }
  }, [targetId, t]);

  // Fetch successive pages from the server, appending newest-first. `pageLimit`
  // is capped at the endpoint's 500 max; "Show all" loops until everything loads.
  const loadMoreHistory = useCallback(
    async (showAll: boolean) => {
      if (!targetId) return;
      setHistoryBusy(true);
      try {
        let current = history;
        do {
          const remaining = historyTotal - current.length;
          if (remaining <= 0) break;
          const pageLimit = showAll ? Math.min(500, remaining) : HISTORY_PAGE;
          const res = await fetchTargetHistory(targetId, { limit: pageLimit, offset: current.length });
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
    [targetId, history, historyTotal]
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
        <section className="card">
          <Link to="/scans" style={backLinkStyle}>
            ← {t("Scan targets", "Scan-Ziele")}
          </Link>
          <p style={{ color: "rgba(255,255,255,0.5)", marginTop: "0.75rem" }}>
            {t("Loading target…", "Ziel wird geladen…")}
          </p>
        </section>
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

  return (
    <div className="page">
      {/* Header */}
      <section className="card" style={{ overflow: "visible" }}>
        <div style={{ display: "flex", justifyContent: "space-between", gap: "1rem", flexWrap: "wrap" }}>
          <div style={{ minWidth: 0 }}>
            <Link to="/scans" style={backLinkStyle}>
              ← {t("Scan targets", "Scan-Ziele")}
            </Link>
            <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", margin: "0.5rem 0 0.25rem", flexWrap: "wrap" }}>
              <h2 style={{ margin: 0 }}>
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
            </div>
            <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap", marginTop: "0.5rem" }}>
              <Chip>{target.type}</Chip>
              {target.group && <Chip>{t("App", "App")}: {target.group}</Chip>}
              {target.registry && <Chip>{target.registry}</Chip>}
              <Chip>
                {t("Auto-scan", "Auto-Scan")}: {target.autoScan ? t("on", "an") : t("off", "aus")}
              </Chip>
            </div>
            <p style={{ marginTop: "0.75rem", color: "rgba(255,255,255,0.45)", fontSize: "0.85rem", wordBreak: "break-all" }}>
              {target.repositoryUrl || target.id}
            </p>
          </div>
          <div style={{ textAlign: "right", marginLeft: "auto" }}>
            <SeverityBadges summary={target.latestSummary} style={{ justifyContent: "flex-end" }} />
            {target.latestScanId && (
              <div style={{ marginTop: "0.75rem" }}>
                <Link to={`/scans/${target.latestScanId}`} style={{ fontSize: "0.875rem" }}>
                  {t("View latest scan", "Neuesten Scan ansehen")} →
                </Link>
              </div>
            )}
          </div>
        </div>

        {target.scanners?.length ? (
          <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap", marginTop: "1rem" }}>
            {target.scanners.map((s) => (
              <Chip key={s}>{s}</Chip>
            ))}
          </div>
        ) : null}

        {target.lastCheckAt && (
          <p style={{ marginTop: "1rem", color: "rgba(255,255,255,0.45)", fontSize: "0.8rem" }}>
            {t("Last check", "Letzte Prüfung")}: {target.lastCheckVerdict ?? "—"} · {formatDateTime(target.lastCheckAt)}
            {target.lastCheckError ? ` · ${target.lastCheckError}` : ""}
          </p>
        )}

        {!isImport && (
          <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap", marginTop: "1.25rem" }}>
            <button type="button" style={btn} disabled={busy === "rescan"} onClick={handleRescan}>
              ↻ {t("Rescan", "Neu scannen")}
            </button>
            <button type="button" style={btn} disabled={busy === "check"} onClick={handleCheck}>
              {t("Run check", "Prüfung ausführen")}
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

      {/* Top findings */}
      {findings.length > 0 && (
        <section className="card">
          <h2 style={sectionHeading}>{t("Top findings", "Top-Findings")}</h2>
          <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
            {findings.map((f, i) => (
              <div
                key={`${f.vulnerabilityId ?? f.packageName}-${i}`}
                style={{ display: "flex", gap: "0.75rem", alignItems: "center", flexWrap: "wrap" }}
              >
                <SeverityTag severity={f.severity} />
                {f.vulnerabilityId ? (
                  <Link to={`/vulnerability/${f.vulnerabilityId}`}>{f.vulnerabilityId}</Link>
                ) : (
                  <span>{f.title ?? f.packageName}</span>
                )}
                <span style={{ color: "rgba(255,255,255,0.45)", fontSize: "0.85rem" }}>
                  {f.packageName}@{f.packageVersion}
                </span>
              </div>
            ))}
          </div>
        </section>
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
                    <th style={thStyle}>{t("Scan", "Scan")}</th>
                  </tr>
                </thead>
                <tbody>
                  {history.map((h) => (
                    <tr key={h.scanId} style={{ borderTop: "1px solid rgba(255,255,255,0.06)" }}>
                      <td style={tdStyle}>{formatDateTime(h.startedAt)}</td>
                      <td style={{ ...tdStyle, color: "rgba(255,255,255,0.6)" }}>{h.status}</td>
                      <td style={tdStyle}>
                        <SeverityBadges summary={h.summary} />
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
