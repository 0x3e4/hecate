import { useEffect, useRef, useState, type ReactNode } from "react";

import { useI18n } from "../i18n/context";

// A destructive action asks here instead of window.confirm: the native prompt
// looks foreign, can be suppressed by the browser and blocks the page.
export const ConfirmDialog = ({
  title,
  message,
  confirmLabel,
  onConfirm,
  onCancel,
}: {
  title: string;
  message: ReactNode;
  confirmLabel: string;
  /** Runs the action; the dialog stays open and disabled until it settles. */
  onConfirm: () => Promise<void> | void;
  onCancel: () => void;
}) => {
  const { t } = useI18n();
  const [busy, setBusy] = useState(false);
  const cancelRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    // Cancel takes focus, so Enter right after opening does not delete.
    cancelRef.current?.focus();
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !busy) onCancel();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [busy, onCancel]);

  const confirm = async () => {
    setBusy(true);
    try {
      await onConfirm();
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="dialog-overlay" role="presentation" onClick={() => !busy && onCancel()}>
      <div
        className="dialog"
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="confirm-dialog-title"
        aria-describedby="confirm-dialog-message"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 id="confirm-dialog-title">{title}</h2>
        <p id="confirm-dialog-message">{message}</p>
        <div className="dialog-actions">
          <button ref={cancelRef} type="button" className="btn" disabled={busy} onClick={onCancel}>
            {t("Cancel", "Abbrechen")}
          </button>
          <button type="button" className="btn dialog-danger" disabled={busy} onClick={() => void confirm()}>
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
};
