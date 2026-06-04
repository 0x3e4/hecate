import { useEffect, useState } from "react";

import {
  clearTargetWritePassword,
  fetchScanTargets,
  setTargetWritePassword,
} from "../api/scans";
import { setTargetPassword, clearTargetPassword } from "../api/writeAuth";
import { useI18n } from "../i18n/context";
import type { ScanTarget } from "../types";

/**
 * Admin "Target Access" manager (System → General). Lists SCA targets and lets
 * an admin set or clear a per-target write password. Setting a password lets a
 * target owner manage that target's writes with their own secret, without the
 * global admin password. Reads are never gated.
 */
export const TargetAccessPanel = () => {
  const { t } = useI18n();
  const [targets, setTargets] = useState<ScanTarget[]>([]);
  const [loading, setLoading] = useState(true);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [pwValue, setPwValue] = useState("");
  const [busyId, setBusyId] = useState<string | null>(null);
  const [error, setError] = useState("");

  const load = async () => {
    setLoading(true);
    try {
      const res = await fetchScanTargets({ limit: 200 });
      setTargets(res.items);
    } catch {
      setError(t("Failed to load targets.", "Ziele konnten nicht geladen werden."));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const handleSet = async (targetId: string) => {
    if (!pwValue.trim()) return;
    setBusyId(targetId);
    setError("");
    try {
      const updated = await setTargetWritePassword(targetId, pwValue.trim());
      // Cache it locally so this admin can immediately act on the target too.
      setTargetPassword(targetId, pwValue.trim());
      setTargets((prev) => prev.map((tg) => (tg.id === targetId ? updated : tg)));
      setEditingId(null);
      setPwValue("");
    } catch {
      setError(t("Failed to set password (admin password required).", "Passwort konnte nicht gesetzt werden (Admin-Passwort erforderlich)."));
    } finally {
      setBusyId(null);
    }
  };

  const handleClear = async (targetId: string) => {
    setBusyId(targetId);
    setError("");
    try {
      const updated = await clearTargetWritePassword(targetId);
      clearTargetPassword(targetId);
      setTargets((prev) => prev.map((tg) => (tg.id === targetId ? updated : tg)));
    } catch {
      setError(t("Failed to clear password (admin password required).", "Passwort konnte nicht entfernt werden (Admin-Passwort erforderlich)."));
    } finally {
      setBusyId(null);
    }
  };

  return (
    <div>
      <h2 style={{ marginTop: 0 }}>{t("Target Access", "Ziel-Zugriff")}</h2>
      <p className="muted" style={{ marginTop: 4 }}>
        {t(
          "Assign a per-target write password so a target owner can manage their target's writes (scans, settings, findings) without the global admin password. Reads stay open for everyone. The global admin password always works as an override.",
          "Vergib ein Schreib-Passwort pro Ziel, damit ein Ziel-Verantwortlicher die Schreibaktionen seines Ziels (Scans, Einstellungen, Findings) ohne globales Admin-Passwort verwalten kann. Lesen bleibt für alle offen. Das globale Admin-Passwort funktioniert immer als Override."
        )}
      </p>
      {error && <p style={{ color: "var(--danger, #f87171)" }}>{error}</p>}
      {loading ? (
        <p className="muted">{t("Loading…", "Lädt…")}</p>
      ) : targets.length === 0 ? (
        <p className="muted">{t("No scan targets yet.", "Noch keine Scan-Ziele.")}</p>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {targets.map((target) => (
            <div
              key={target.id}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 12,
                padding: "8px 12px",
                border: "1px solid var(--border, #2a2a3a)",
                borderRadius: 8,
                flexWrap: "wrap",
              }}
            >
              <span style={{ flex: 1, minWidth: 200 }}>
                {target.writePasswordSet ? "🔒 " : ""}
                <strong>{target.name}</strong>
                <span className="muted" style={{ marginLeft: 8, fontSize: "0.85em" }}>
                  {target.id}
                </span>
              </span>
              {editingId === target.id ? (
                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    handleSet(target.id);
                  }}
                  style={{ display: "flex", gap: 6 }}
                >
                  <input
                    type="password"
                    autoFocus
                    className="advanced-filter-input"
                    value={pwValue}
                    onChange={(e) => setPwValue(e.target.value)}
                    placeholder={t("New password", "Neues Passwort")}
                  />
                  <button type="submit" className="btn-primary" disabled={busyId === target.id || !pwValue.trim()}>
                    {t("Save", "Speichern")}
                  </button>
                  <button
                    type="button"
                    className="btn-secondary"
                    onClick={() => {
                      setEditingId(null);
                      setPwValue("");
                    }}
                  >
                    {t("Cancel", "Abbrechen")}
                  </button>
                </form>
              ) : (
                <div style={{ display: "flex", gap: 6 }}>
                  <button
                    type="button"
                    className="btn-secondary"
                    onClick={() => {
                      setEditingId(target.id);
                      setPwValue("");
                    }}
                  >
                    {target.writePasswordSet
                      ? t("Change password", "Passwort ändern")
                      : t("Set password", "Passwort setzen")}
                  </button>
                  {target.writePasswordSet && (
                    <button
                      type="button"
                      className="btn-secondary"
                      disabled={busyId === target.id}
                      onClick={() => handleClear(target.id)}
                    >
                      {t("Clear", "Entfernen")}
                    </button>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
