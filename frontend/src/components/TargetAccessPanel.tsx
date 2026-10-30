import { useEffect, useState } from "react";
import { LuLock } from "react-icons/lu";

import "../screens/scan-target.css";

import {
  clearTargetWritePassword,
  fetchScanTargets,
  setTargetWritePassword,
} from "../api/scans";
import { setTargetPassword, clearTargetPassword } from "../api/writeAuth";
import { useI18n } from "../i18n/context";
import type { ScanTarget } from "../types";
import { EmptyState, ErrorState } from "../ui/primitives";
import { SkeletonBlock } from "./Skeleton";

/**
 * Admin "Target Access" manager (System, Access Control). Lists SCA targets and lets
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
    <div className="scan-target-access">
      <h2>{t("Target access", "Ziel-Zugriff")}</h2>
      <p className="scan-target-access-intro">
        {t(
          "Assign a per-target write password so a target owner can manage their target's writes (scans, settings, findings) without the global admin password. Reads stay open for everyone. The global admin password always works as an override.",
          "Vergib ein Schreib-Passwort pro Ziel, damit ein Ziel-Verantwortlicher die Schreibaktionen seines Ziels (Scans, Einstellungen, Findings) ohne globales Admin-Passwort verwalten kann. Lesen bleibt für alle offen. Das globale Admin-Passwort funktioniert immer als Override."
        )}
      </p>
      {error && <ErrorState title={error} />}
      {loading ? (
        <div className="scan-target-access-skeleton" aria-busy="true">
          {[0, 1, 2, 3].map((i) => (
            <SkeletonBlock key={i} height={36} />
          ))}
        </div>
      ) : targets.length === 0 ? (
        <EmptyState title={t("No scan targets yet.", "Noch keine Scan-Ziele.")} />
      ) : (
        <div className="table-scroll scan-target-scroll">
          <table className="scan-target-table scan-target-access-table">
            <thead>
              <tr>
                <th scope="col">{t("Target", "Ziel")}</th>
                <th scope="col">{t("ID", "ID")}</th>
                <th scope="col">{t("Write access", "Schreibzugriff")}</th>
                <th scope="col" className="scan-target-access-actions-head">{t("Actions", "Aktionen")}</th>
              </tr>
            </thead>
            <tbody>
              {targets.map((target) => (
                <tr key={target.id}>
                  <td className="scan-target-access-name">{target.name}</td>
                  <td className="mono scan-target-access-id">{target.id}</td>
                  <td>
                    {target.writePasswordSet ? (
                      <span className="scan-target-access-lock">
                        <LuLock aria-hidden="true" />
                        {t("Write-protected", "Schreibgeschützt")}
                      </span>
                    ) : null}
                  </td>
                  <td>
                    {editingId === target.id ? (
                      <form
                        className="scan-target-access-actions"
                        onSubmit={(e) => {
                          e.preventDefault();
                          handleSet(target.id);
                        }}
                      >
                        <input
                          type="password"
                          autoFocus
                          className="scan-target-access-input"
                          value={pwValue}
                          onChange={(e) => setPwValue(e.target.value)}
                          placeholder={t("New password", "Neues Passwort")}
                          aria-label={t("New password", "Neues Passwort")}
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
                      <div className="scan-target-access-actions">
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
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
