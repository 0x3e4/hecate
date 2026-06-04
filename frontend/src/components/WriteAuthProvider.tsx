import { useCallback, useEffect, useRef, useState } from "react";

import { useI18n } from "../i18n/context";
import {
  registerWritePrompt,
  type WritePromptContext,
} from "../api/writeAuth";

type PendingPrompt = {
  ctx: WritePromptContext;
  resolve: (password: string | null) => void;
};

/**
 * Bridges the axios 401-on-write handler to a React modal. When a write is
 * rejected for a missing/invalid write password, the response interceptor calls
 * the registered prompt; this provider renders a dialog and resolves it with the
 * entered password (or null on cancel). Mount once near the app root.
 */
export const WriteAuthProvider = ({ children }: { children: React.ReactNode }) => {
  const { t } = useI18n();
  const [pending, setPending] = useState<PendingPrompt | null>(null);
  const [value, setValue] = useState("");
  const inputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    registerWritePrompt(
      (ctx) =>
        new Promise<string | null>((resolve) => {
          setValue("");
          setPending({ ctx, resolve });
        })
    );
    return () => registerWritePrompt(null);
  }, []);

  useEffect(() => {
    if (pending) {
      const id = window.setTimeout(() => inputRef.current?.focus(), 50);
      return () => window.clearTimeout(id);
    }
  }, [pending]);

  const close = useCallback(
    (password: string | null) => {
      pending?.resolve(password);
      setPending(null);
      setValue("");
    },
    [pending]
  );

  return (
    <>
      {children}
      {pending && (
        <div
          className="modal-overlay"
          role="presentation"
          onClick={() => close(null)}
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(0,0,0,0.6)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 2000,
          }}
        >
          <div
            className="card"
            role="dialog"
            aria-modal="true"
            onClick={(e) => e.stopPropagation()}
            style={{ maxWidth: 420, width: "90%" }}
          >
            <h3 style={{ marginTop: 0 }}>
              {t("Write password required", "Schreib-Passwort erforderlich")}
            </h3>
            <p className="muted" style={{ marginTop: 4 }}>
              {pending.ctx.targetId
                ? t(
                    "This action modifies a protected target. Enter the target's write password (or the admin password).",
                    "Diese Aktion ändert ein geschütztes Ziel. Gib das Schreib-Passwort des Ziels (oder das Admin-Passwort) ein."
                  )
                : t(
                    "This action requires the system password.",
                    "Diese Aktion erfordert das System-Passwort."
                  )}
            </p>
            <form
              onSubmit={(e) => {
                e.preventDefault();
                if (value.trim()) close(value.trim());
              }}
            >
              <input
                ref={inputRef}
                type="password"
                className="advanced-filter-input"
                value={value}
                onChange={(e) => setValue(e.target.value)}
                placeholder={t("Password", "Passwort")}
                style={{ width: "100%", marginBottom: 12 }}
                onKeyDown={(e) => {
                  if (e.key === "Escape") close(null);
                }}
              />
              <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
                <button type="button" className="btn-secondary" onClick={() => close(null)}>
                  {t("Cancel", "Abbrechen")}
                </button>
                <button type="submit" className="btn-primary" disabled={!value.trim()}>
                  {t("Unlock", "Entsperren")}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </>
  );
};
