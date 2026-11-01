import { useCallback, useEffect, useRef, useState } from "react";
import { LuX } from "react-icons/lu";

import { useI18n } from "../i18n/context";
import { IconButton } from "../ui/primitives";

// Shared bottom-right toast — the single source of truth for transient
// success/error notifications across the app. Use `useToast()` for state +
// auto-dismiss and render `<Toast toast={toast} onDismiss={dismiss} />` near the
// page root.

export type ToastType = "success" | "error";
export type ToastMessage = { message: string; type: ToastType };

export const useToast = (autoDismissMs = 4000) => {
  const [toast, setToast] = useState<ToastMessage | null>(null);
  const timeoutRef = useRef<number | null>(null);

  const clearTimer = useCallback(() => {
    if (timeoutRef.current !== null) {
      window.clearTimeout(timeoutRef.current);
      timeoutRef.current = null;
    }
  }, []);

  const dismiss = useCallback(() => {
    clearTimer();
    setToast(null);
  }, [clearTimer]);

  const showToast = useCallback(
    (message: string, type: ToastType = "success") => {
      clearTimer();
      setToast({ message, type });
      timeoutRef.current = window.setTimeout(() => {
        setToast(null);
        timeoutRef.current = null;
      }, autoDismissMs);
    },
    [autoDismissMs, clearTimer]
  );

  // Clear any pending timer if the host component unmounts.
  useEffect(() => clearTimer, [clearTimer]);

  return { toast, showToast, dismiss };
};

export const Toast = ({ toast, onDismiss }: { toast: ToastMessage | null; onDismiss: () => void }) => {
  const { t } = useI18n();
  if (!toast) return null;
  return (
    <div className="toast-region">
      <div role="status" aria-live="polite" className={`toast toast--${toast.type}`}>
        <span className="toast-message">{toast.message}</span>
        <IconButton className="toast-close" label={t("Dismiss", "Schließen")} onClick={onDismiss}>
          <LuX aria-hidden="true" />
        </IconButton>
      </div>
    </div>
  );
};
