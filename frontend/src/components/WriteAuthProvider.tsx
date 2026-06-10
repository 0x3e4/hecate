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
        <div className="dialog-overlay" role="presentation" onClick={() => close(null)}>
          <div
            className="dialog"
            role="dialog"
            aria-modal="true"
            onClick={(e) => e.stopPropagation()}
          >
            <h3>{t("Password required", "Passwort erforderlich")}</h3>
            <p>
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
                value={value}
                onChange={(e) => setValue(e.target.value)}
                placeholder={t("Password", "Passwort")}
                onKeyDown={(e) => {
                  if (e.key === "Escape") close(null);
                }}
              />
              <div className="dialog-actions">
                <button type="button" className="btn btn-secondary" onClick={() => close(null)}>
                  {t("Cancel", "Abbrechen")}
                </button>
                <button type="submit" className="btn btn-primary" disabled={!value.trim()}>
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
