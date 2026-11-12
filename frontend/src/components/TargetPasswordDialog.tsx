import { useEffect, useRef, useState } from "react";

import { clearTargetWritePassword, setTargetWritePassword } from "../api/scans";
import { clearTargetPassword, setTargetPassword } from "../api/writeAuth";
import { useI18n } from "../i18n/context";
import type { ScanTarget } from "../types";
import { BusyLabel } from "../ui/primitives";

// The owner of a protected target changes or removes its password here. The
// write is authorized by the current target password (asked for if not stored)
// or by the admin password; setting the first password stays on System → Access Control.
export const TargetPasswordDialog = ({
  target,
  onClose,
  onUpdated,
}: {
  target: ScanTarget;
  onClose: () => void;
  onUpdated: (target: ScanTarget, message: string) => void;
}) => {
  const { t } = useI18n();
  const [value, setValue] = useState("");
  const [pending, setPending] = useState<"save" | "remove" | null>(null);
  const busy = pending !== null;
  const [error, setError] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  const run = async (
    kind: "save" | "remove",
    action: () => Promise<ScanTarget>,
    done: (updated: ScanTarget) => string,
  ) => {
    setPending(kind);
    setError("");
    try {
      const updated = await action();
      onUpdated(updated, done(updated));
    } catch {
      setError(t("The password could not be changed.", "Das Passwort konnte nicht geändert werden."));
      setPending(null);
    }
  };

  const save = () =>
    run(
      "save",
      () => setTargetWritePassword(target.id, value.trim()),
      () => {
        // The next writes on this target go out with the new password.
        setTargetPassword(target.id, value.trim());
        return t("Target password changed.", "Ziel-Passwort geändert.");
      },
    );

  const remove = () =>
    run(
      "remove",
      () => clearTargetWritePassword(target.id),
      () => {
        clearTargetPassword(target.id);
        return t("Write protection removed.", "Schreibschutz entfernt.");
      },
    );

  return (
    <div className="dialog-overlay" role="presentation" onClick={() => !busy && onClose()}>
      <div
        className="dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="target-password-title"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 id="target-password-title">{t("Target password", "Ziel-Passwort")}</h2>
        <p>
          {t(
            "Set a new write password for this target, or remove the protection. Everyone who uses the old password needs the new one.",
            "Setze ein neues Schreib-Passwort für dieses Ziel oder entferne den Schutz. Wer das alte Passwort nutzt, braucht dann das neue.",
          )}
        </p>
        {error && <p role="alert">{error}</p>}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (value.trim()) void save();
          }}
        >
          <input
            ref={inputRef}
            type="password"
            autoComplete="new-password"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder={t("New password", "Neues Passwort")}
            aria-label={t("New password", "Neues Passwort")}
            onKeyDown={(e) => {
              if (e.key === "Escape" && !busy) onClose();
            }}
          />
          <div className="dialog-actions">
            <button type="button" className="btn btn-secondary" disabled={busy} onClick={onClose}>
              {t("Cancel", "Abbrechen")}
            </button>
            <button
              type="button"
              className="btn btn-secondary"
              disabled={busy}
              aria-busy={pending === "remove" || undefined}
              onClick={() => void remove()}
            >
              <BusyLabel busy={pending === "remove"}>{t("Remove protection", "Schutz entfernen")}</BusyLabel>
            </button>
            <button
              type="submit"
              className="btn btn-primary"
              disabled={busy || !value.trim()}
              aria-busy={pending === "save" || undefined}
            >
              <BusyLabel busy={pending === "save"}>{t("Save", "Speichern")}</BusyLabel>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
