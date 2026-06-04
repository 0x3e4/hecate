import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";

import {
  clearTargetWritePassword,
  deleteScanTarget,
  fetchGlobalFindings,
  fetchScanTarget,
  fetchTargetHistory,
  setTargetWritePassword,
  submitManualScan,
  triggerTargetCheck,
} from "../api/scans";
import { clearTargetPassword, setTargetPassword } from "../api/writeAuth";
import { useI18n } from "../i18n/context";
import type { ConsolidatedFinding, ScanHistoryEntry, ScanTarget } from "../types";
import { formatDateTime } from "../utils/dateFormat";

const SEVERITIES: { key: keyof ScanSummaryLike; color: string; label: string }[] = [
  { key: "critical", color: "#ff6b6b", label: "C" },
  { key: "high", color: "#ff9f43", label: "H" },
  { key: "medium", color: "#feca57", label: "M" },
  { key: "low", color: "#54a0ff", label: "L" },
  { key: "negligible", color: "#8395a7", label: "N" },
  { key: "unknown", color: "#576574", label: "?" },
];

type ScanSummaryLike = {
  critical: number;
  high: number;
  medium: number;
  low: number;
  negligible: number;
  unknown: number;
  total: number;
};

const SeverityPills = ({ summary }: { summary?: ScanSummaryLike | null }) => {
  if (!summary) return <span className="muted">—</span>;
  const present = SEVERITIES.filter((s) => (summary[s.key] as number) > 0);
  if (present.length === 0) return <span style={{ color: "#1dd1a1" }}>✓ 0 findings</span>;
  return (
    <span style={{ display: "inline-flex", gap: 6, flexWrap: "wrap" }}>
      {present.map((s) => (
        <span
          key={s.key}
          style={{
            background: s.color,
            color: "#0b0b12",
            borderRadius: 6,
            padding: "1px 8px",
            fontWeight: 700,
            fontSize: "0.8rem",
          }}
        >
          {summary[s.key]} {s.label}
        </span>
      ))}
    </span>
  );
};

const Chip = ({ children }: { children: React.ReactNode }) => (
  <span
    style={{
      background: "rgba(255,255,255,0.06)",
      border: "1px solid var(--border, #2a2a3a)",
      borderRadius: 6,
      padding: "2px 10px",
      fontSize: "0.85rem",
    }}
  >
    {children}
  </span>
);

export const ScanTargetDetailPage = () => {
  const { t } = useI18n();
  const navigate = useNavigate();
  const params = useParams();
  const targetId = useMemo(
    () => (params.targetId ? decodeURIComponent(params.targetId) : ""),
    [params.targetId]
  );

  const [target, setTarget] = useState<ScanTarget | null>(null);
  const [history, setHistory] = useState<ScanHistoryEntry[]>([]);
  const [findings, setFindings] = useState<ConsolidatedFinding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [toast, setToast] = useState("");

  const [pwEditing, setPwEditing] = useState(false);
  const [pwValue, setPwValue] = useState("");

  const flash = useCallback((msg: string) => {
    setToast(msg);
    window.setTimeout(() => setToast(""), 3000);
  }, []);

  const load = useCallback(async () => {
    if (!targetId) return;
    setLoading(true);
    setError("");
    try {
      const tg = await fetchScanTarget(targetId);
      setTarget(tg);
      const [hist, finds] = await Promise.all([
        fetchTargetHistory(targetId, { limit: 50 }).catch(() => ({ items: [] as ScanHistoryEntry[] })),
        fetchGlobalFindings({ targetId, limit: 10 }).catch(() => ({ items: [] as ConsolidatedFinding[], total: 0 })),
      ]);
      setHistory(hist.items ?? []);
      setFindings(finds.items ?? []);
    } catch {
      setError(t("Target not found.", "Ziel nicht gefunden."));
    } finally {
      setLoading(false);
    }
  }, [targetId, t]);

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
      flash(t("Scan started.", "Scan gestartet."));
    } catch {
      flash(t("Rescan failed.", "Rescan fehlgeschlagen."));
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
      flash(t("Check complete.", "Prüfung abgeschlossen."));
    } catch {
      flash(t("Check failed.", "Prüfung fehlgeschlagen."));
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
      flash(t("Delete failed.", "Löschen fehlgeschlagen."));
      setBusy(null);
    }
  };

  const handleSetPassword = async () => {
    if (!target || !pwValue.trim()) return;
    setBusy("pw");
    try {
      const updated = await setTargetWritePassword(target.id, pwValue.trim());
      setTargetPassword(target.id, pwValue.trim());
      setTarget(updated);
      setPwEditing(false);
      setPwValue("");
      flash(t("Password set.", "Passwort gesetzt."));
    } catch {
      flash(t("Failed (admin password required).", "Fehlgeschlagen (Admin-Passwort erforderlich)."));
    } finally {
      setBusy(null);
    }
  };

  const handleClearPassword = async () => {
    if (!target) return;
    setBusy("pw");
    try {
      const updated = await clearTargetWritePassword(target.id);
      clearTargetPassword(target.id);
      setTarget(updated);
      flash(t("Password cleared.", "Passwort entfernt."));
    } catch {
      flash(t("Failed (admin password required).", "Fehlgeschlagen (Admin-Passwort erforderlich)."));
    } finally {
      setBusy(null);
    }
  };

  const shieldUrl = useMemo(
    () =>
      target
        ? `${window.location.origin}/api/v1/scans/targets/${encodeURIComponent(target.id)}/shield`
        : "",
    [target]
  );

  if (loading) {
    return (
      <div className="page">
        <p className="muted">{t("Loading target…", "Ziel wird geladen…")}</p>
      </div>
    );
  }

  if (error || !target) {
    return (
      <div className="page">
        <p style={{ color: "#ff6b6b" }}>{error || t("Target not found.", "Ziel nicht gefunden.")}</p>
        <Link to="/scans">← {t("Back to scans", "Zurück zu Scans")}</Link>
      </div>
    );
  }

  return (
    <div className="page">
      <div style={{ marginBottom: 12 }}>
        <Link to="/scans" className="muted">
          ← {t("Scan targets", "Scan-Ziele")}
        </Link>
      </div>

      {toast && (
        <div className="card" style={{ borderColor: "#54a0ff", marginBottom: 12 }}>
          {toast}
        </div>
      )}

      {/* Header */}
      <section className="card">
        <div style={{ display: "flex", justifyContent: "space-between", gap: 12, flexWrap: "wrap" }}>
          <div>
            <h1 style={{ margin: 0 }}>
              {target.writePasswordSet && <span title={t("Write-protected", "Schreibgeschützt")}>🔒 </span>}
              {target.name}
            </h1>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 8 }}>
              <Chip>{target.type}</Chip>
              {target.group && <Chip>{t("App", "App")}: {target.group}</Chip>}
              {target.registry && <Chip>{target.registry}</Chip>}
              <Chip>
                {t("Auto-scan", "Auto-Scan")}: {target.autoScan ? t("on", "an") : t("off", "aus")}
              </Chip>
            </div>
            <p className="muted" style={{ marginTop: 8, wordBreak: "break-all" }}>
              {target.repositoryUrl || target.id}
            </p>
          </div>
          <div style={{ textAlign: "right" }}>
            <SeverityPills summary={target.latestSummary} />
            {target.latestScanId && (
              <div style={{ marginTop: 8 }}>
                <Link to={`/scans/${target.latestScanId}`}>{t("View latest scan", "Neuesten Scan ansehen")} →</Link>
              </div>
            )}
          </div>
        </div>

        {/* Scanners */}
        {target.scanners?.length ? (
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 12 }}>
            {target.scanners.map((s) => (
              <Chip key={s}>{s}</Chip>
            ))}
          </div>
        ) : null}

        {/* Last check diagnostics */}
        {target.lastCheckAt && (
          <p className="muted" style={{ marginTop: 12 }}>
            {t("Last check", "Letzte Prüfung")}: {target.lastCheckVerdict ?? "—"} ·{" "}
            {formatDateTime(target.lastCheckAt)}
            {target.lastCheckError ? ` · ${target.lastCheckError}` : ""}
          </p>
        )}

        {/* Actions */}
        {!isImport && (
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 16 }}>
            <button type="button" className="btn-primary" disabled={busy === "rescan"} onClick={handleRescan}>
              ↻ {t("Rescan", "Neu scannen")}
            </button>
            <button type="button" className="btn-secondary" disabled={busy === "check"} onClick={handleCheck}>
              {t("Run check", "Prüfung ausführen")}
            </button>
            <button
              type="button"
              className="btn-secondary"
              onClick={() => {
                void navigator.clipboard?.writeText(`![findings](${shieldUrl})`);
                flash(t("Shield markdown copied.", "Shield-Markdown kopiert."));
              }}
            >
              {t("Copy badge", "Badge kopieren")}
            </button>
            <button
              type="button"
              className="btn-secondary"
              style={{ color: "#ff6b6b", borderColor: "rgba(255,107,107,0.3)" }}
              disabled={busy === "delete"}
              onClick={handleDelete}
            >
              {t("Delete target", "Ziel löschen")}
            </button>
          </div>
        )}
      </section>

      {/* Target access (write password) */}
      {!isImport && (
        <section className="card">
          <h2>{t("Write protection", "Schreibschutz")}</h2>
          <p className="muted" style={{ marginTop: 4 }}>
            {target.writePasswordSet
              ? t(
                  "This target has its own write password. Holders can manage it without the admin password. Reads stay open.",
                  "Dieses Ziel hat ein eigenes Schreib-Passwort. Inhaber können es ohne Admin-Passwort verwalten. Lesen bleibt offen."
                )
              : t(
                  "No per-target password set. Set one so an owner can manage this target's writes without the admin password.",
                  "Kein Ziel-Passwort gesetzt. Setze eines, damit ein Inhaber die Schreibaktionen dieses Ziels ohne Admin-Passwort verwalten kann."
                )}
          </p>
          {pwEditing ? (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                void handleSetPassword();
              }}
              style={{ display: "flex", gap: 6, marginTop: 8 }}
            >
              <input
                type="password"
                autoFocus
                className="advanced-filter-input"
                value={pwValue}
                onChange={(e) => setPwValue(e.target.value)}
                placeholder={t("New password", "Neues Passwort")}
              />
              <button type="submit" className="btn-primary" disabled={busy === "pw" || !pwValue.trim()}>
                {t("Save", "Speichern")}
              </button>
              <button type="button" className="btn-secondary" onClick={() => { setPwEditing(false); setPwValue(""); }}>
                {t("Cancel", "Abbrechen")}
              </button>
            </form>
          ) : (
            <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
              <button type="button" className="btn-secondary" onClick={() => setPwEditing(true)}>
                {target.writePasswordSet ? t("Change password", "Passwort ändern") : t("Set password", "Passwort setzen")}
              </button>
              {target.writePasswordSet && (
                <button type="button" className="btn-secondary" disabled={busy === "pw"} onClick={handleClearPassword}>
                  {t("Clear", "Entfernen")}
                </button>
              )}
            </div>
          )}
        </section>
      )}

      {/* Top findings */}
      {findings.length > 0 && (
        <section className="card">
          <h2>{t("Top findings", "Top-Findings")}</h2>
          <div style={{ display: "flex", flexDirection: "column", gap: 6, marginTop: 8 }}>
            {findings.map((f, i) => (
              <div
                key={`${f.vulnerabilityId ?? f.packageName}-${i}`}
                style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}
              >
                <span style={{ minWidth: 70 }}>
                  <SeverityPills
                    summary={{
                      critical: f.severity === "critical" ? 1 : 0,
                      high: f.severity === "high" ? 1 : 0,
                      medium: f.severity === "medium" ? 1 : 0,
                      low: f.severity === "low" ? 1 : 0,
                      negligible: f.severity === "negligible" ? 1 : 0,
                      unknown: 0,
                      total: 1,
                    }}
                  />
                </span>
                {f.vulnerabilityId ? (
                  <Link to={`/vulnerability/${f.vulnerabilityId}`}>{f.vulnerabilityId}</Link>
                ) : (
                  <span>{f.title ?? f.packageName}</span>
                )}
                <span className="muted">
                  {f.packageName}@{f.packageVersion}
                </span>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* History */}
      <section className="card">
        <h2>{t("Scan history", "Scan-Verlauf")}</h2>
        {history.length === 0 ? (
          <p className="muted">{t("No completed scans yet.", "Noch keine abgeschlossenen Scans.")}</p>
        ) : (
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ textAlign: "left", color: "var(--muted, #8a8a9a)" }}>
                <th style={{ padding: "6px 8px" }}>{t("Date", "Datum")}</th>
                <th style={{ padding: "6px 8px" }}>{t("Status", "Status")}</th>
                <th style={{ padding: "6px 8px" }}>{t("Findings", "Findings")}</th>
                <th style={{ padding: "6px 8px" }}>{t("Scan", "Scan")}</th>
              </tr>
            </thead>
            <tbody>
              {[...history].reverse().map((h) => (
                <tr key={h.scanId} style={{ borderTop: "1px solid var(--border, #2a2a3a)" }}>
                  <td style={{ padding: "6px 8px" }}>{formatDateTime(h.startedAt)}</td>
                  <td style={{ padding: "6px 8px" }}>{h.status}</td>
                  <td style={{ padding: "6px 8px" }}>
                    <SeverityPills summary={h.summary} />
                  </td>
                  <td style={{ padding: "6px 8px" }}>
                    <Link to={`/scans/${h.scanId}`}>{h.scanId.slice(0, 8)}</Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
};
