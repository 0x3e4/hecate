import { createContext, useContext, useEffect, type ReactNode } from "react";

import { Toast, useToast, type ToastType } from "./Toast";
import { registerToast } from "../api/toastBridge";

// App-wide toast surface. Mount once near the root so any view/component can raise
// a transient success/error toast via useToastContext() without wiring its own
// useToast() + <Toast/>. Reuses the existing Toast hook/component.

interface ToastContextValue {
  showToast: (message: string, type?: ToastType) => void;
}

const ToastContext = createContext<ToastContextValue | null>(null);

export const ToastProvider = ({ children }: { children: ReactNode }) => {
  const { toast, showToast } = useToast();

  // Expose showToast to non-React callers (axios interceptor, etc.).
  useEffect(() => {
    registerToast(showToast);
    return () => registerToast(null);
  }, [showToast]);

  return (
    <ToastContext.Provider value={{ showToast }}>
      {children}
      <Toast toast={toast} />
    </ToastContext.Provider>
  );
};

export const useToastContext = (): ToastContextValue => {
  const ctx = useContext(ToastContext);
  if (!ctx) {
    throw new Error("useToastContext must be used within a ToastProvider");
  }
  return ctx;
};
