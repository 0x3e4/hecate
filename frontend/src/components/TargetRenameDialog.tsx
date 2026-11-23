import { useEffect, useRef, useState } from "react";
import axios from "axios";

import { updateScanTarget } from "../api/scans";
import { useI18n } from "../i18n/context";
import type { ScanTarget } from "../types";
import { BusyLabel } from "../ui/primitives";

/** Mirrors TARGET_NAME_MAX_LENGTH in backend/app/schemas/scan.py. */
export const TARGET_NAME_MAX_LENGTH = 200;

// Renames a scan target. Only the name changes: the id (image reference or
// repository URL) stays, and so do its scans, which take the new name too. The
// next scan keeps it. A target password opens this like every other target write.
export const TargetRenameDialog = ({
  target,
  onClose,
  onRenamed,
}: {
  target: ScanTarget;
  onClose: () => void;
  onRenamed: (target: ScanTarget) => void;
}) => {
  const { t } = useI18n();
  const [value, setValue] = useState(target.name);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    inputRef.current?.select();
  }, []);

  const name = value.trim();
  const unchanged = name === target.name;

  const save = async () => {
    if (!name || unchanged) return;
    setBusy(true);
    setError("");
    try {
      onRenamed(await updateScanTarget(target.id, { name }));
    } catch (err) {
      const detail = axios.isAxiosError(err) ? err.response?.data?.detail : null;
      setError(
        typeof detail === "string" ? detail : t("The target could not be renamed.", "Das Ziel konnte nicht umbenannt werden."),
      );
      setBusy(false);
    }
  };

  return (
    <div className="dialog-overlay" role="presentation" onClick={() => !busy && onClose()}>
      <div
        className="dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="target-rename-title"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 id="target-rename-title">{t("Rename target", "Ziel umbenennen")}</h2>
        <p className="muted mono">{target.id}</p>
        {error && <p role="alert">{error}</p>}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void save();
          }}
        >
          <input
            ref={inputRef}
            value={value}
            maxLength={TARGET_NAME_MAX_LENGTH}
            onChange={(e) => setValue(e.target.value)}
            aria-label={t("Name", "Name")}
            onKeyDown={(e) => {
              if (e.key === "Escape" && !busy) onClose();
            }}
          />
          <div className="dialog-actions">
            <button type="button" className="btn btn-secondary" disabled={busy} onClick={onClose}>
              {t("Cancel", "Abbrechen")}
            </button>
            <button type="submit" className="btn btn-primary" disabled={busy || !name || unchanged} aria-busy={busy || undefined}>
              <BusyLabel busy={busy}>{t("Save", "Speichern")}</BusyLabel>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
