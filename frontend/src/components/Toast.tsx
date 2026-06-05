import { useCallback, useEffect, useRef, useState, type CSSProperties } from "react";

// Shared bottom-right toast — the single source of truth for transient
// success/error notifications across the app. Use `useToast()` for state +
// auto-dismiss and render `<Toast toast={toast} />` near the page root.

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

const containerStyle: CSSProperties = {
  position: "fixed",
  bottom: "2rem",
  right: "2rem",
  zIndex: 2100,
};

const baseStyle: CSSProperties = {
  background: "rgba(15, 18, 30, 0.92)",
  borderRadius: "10px",
  padding: "0.75rem 1rem",
  color: "#f5f7fa",
  fontWeight: 600,
  boxShadow: "0 18px 40px rgba(0, 0, 0, 0.38)",
  border: "1px solid rgba(255, 255, 255, 0.18)",
  minWidth: "240px",
  maxWidth: "min(90vw, 420px)",
};

const successStyle: CSSProperties = {
  borderColor: "rgba(92, 132, 255, 0.6)",
  color: "#d6e4ff",
};

const errorStyle: CSSProperties = {
  borderColor: "rgba(252, 92, 101, 0.65)",
  color: "#ffb4b6",
};

export const Toast = ({ toast }: { toast: ToastMessage | null }) => {
  if (!toast) return null;
  return (
    <div style={containerStyle}>
      <div
        role="status"
        aria-live="polite"
        style={{ ...baseStyle, ...(toast.type === "success" ? successStyle : errorStyle) }}
      >
        {toast.message}
      </div>
    </div>
  );
};
