import { useCallback, useEffect, useRef, useState } from "react";

import { useAuth } from "../auth/context";
import { onSignedInElsewhere, openSignInWindow } from "../auth/signInWindow";
import { useI18n } from "../i18n/context";
import { apiBaseURL } from "../api/client";
import {
  clearWriteSecrets,
  registerWritePrompt,
  type AccessAnswer,
  type AccessPrompt,
} from "../api/writeAuth";
import { BusyLabel } from "../ui/primitives";

type PendingPrompt = {
  prompt: AccessPrompt;
  resolve: (answer: AccessAnswer) => void;
};

/**
 * Bridges the axios 401 handler to a React dialog. A refused request waits
 * here; once the user signed in (in a popup, so this page keeps its state) or
 * entered the password, the interceptor retries it and the action the user
 * started runs on its own. With sign-in configured the dialog leads with it,
 * the password stays an alternative where the backend accepts one; without
 * sign-in it asks for the password only. Mount once near the app root.
 */
export const WriteAuthProvider = ({ children }: { children: React.ReactNode }) => {
  const { t } = useI18n();
  const auth = useAuth();
  const [pending, setPending] = useState<PendingPrompt | null>(null);
  const [value, setValue] = useState("");
  const [usePassword, setUsePassword] = useState(false);
  const [waiting, setWaiting] = useState(false);
  const [blocked, setBlocked] = useState(false);
  const inputRef = useRef<HTMLInputElement | null>(null);
  const signInRef = useRef<HTMLButtonElement | null>(null);

  useEffect(() => {
    registerWritePrompt(
      (prompt) =>
        new Promise<AccessAnswer>((resolve) => {
          setValue("");
          setWaiting(false);
          setBlocked(false);
          setUsePassword(!prompt.signIn);
          setPending({ prompt, resolve });
        })
    );
    return () => registerWritePrompt(null);
  }, []);

  const showPassword = pending !== null && pending.prompt.password && usePassword;

  useEffect(() => {
    if (!pending) return;
    const id = window.setTimeout(() => (showPassword ? inputRef.current : signInRef.current)?.focus(), 50);
    return () => window.clearTimeout(id);
  }, [pending, showPassword]);

  const close = useCallback(
    (answer: AccessAnswer) => {
      pending?.resolve(answer);
      setPending(null);
      setValue("");
      setWaiting(false);
    },
    [pending]
  );

  // Read through refs: refreshing the user re-renders this provider, and the
  // waiting effect below must not restart (and drop its answer) because of it.
  const closeRef = useRef(close);
  closeRef.current = close;
  const refreshRef = useRef(auth.refresh);
  refreshRef.current = auth.refresh;

  // Waiting for the sign-in window: it announces itself, and returning to this
  // window checks too (a provider that cut the window off from its opener, or
  // a sign-in that ended on another page of the popup).
  useEffect(() => {
    if (!waiting) return;
    let done = false;
    const check = async () => {
      const user = await refreshRef.current();
      if (user && !done) {
        done = true;
        // The new account starts without the previous person's write secrets.
        clearWriteSecrets();
        closeRef.current({ kind: "signed-in" });
      }
    };
    const stop = onSignedInElsewhere(() => void check());
    const onFocus = () => void check();
    window.addEventListener("focus", onFocus);
    return () => {
      done = true;
      stop();
      window.removeEventListener("focus", onFocus);
    };
  }, [waiting]);

  const startSignIn = () => {
    if (openSignInWindow(apiBaseURL)) {
      setBlocked(false);
      setWaiting(true);
      return;
    }
    setBlocked(true);
  };

  const prompt = pending?.prompt;

  return (
    <>
      {children}
      {pending && prompt && (
        <div className="dialog-overlay" role="presentation" onClick={() => close(null)}>
          <div
            className="dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="write-auth-title"
            onClick={(e) => e.stopPropagation()}
            onKeyDown={(e) => {
              if (e.key === "Escape") close(null);
            }}
          >
            <h2 id="write-auth-title">
              {showPassword ? t("Password required", "Passwort erforderlich") : t("Sign-in required", "Anmeldung erforderlich")}
            </h2>
            {showPassword ? (
              <p>
                {prompt.targetId
                  ? t(
                      "This action modifies a protected target. Enter the target's write password (or the system password); the action then continues.",
                      "Diese Aktion ändert ein geschütztes Ziel. Gib das Schreib-Passwort des Ziels (oder das System-Passwort) ein; danach läuft die Aktion weiter."
                    )
                  : t(
                      "This action requires the system password. Enter it and the action continues.",
                      "Diese Aktion erfordert das System-Passwort. Nach der Eingabe läuft die Aktion weiter."
                    )}
              </p>
            ) : (
              <p>
                {waiting
                  ? t(
                      `Sign in with ${auth.providerLabel} in the window that opened. The action continues here once you are signed in.`,
                      `Melde dich im geöffneten Fenster mit ${auth.providerLabel} an. Danach läuft die Aktion hier weiter.`
                    )
                  : t(
                      `This action needs you to sign in with ${auth.providerLabel}. It continues once you are signed in.`,
                      `Für diese Aktion musst du dich mit ${auth.providerLabel} anmelden. Danach läuft sie weiter.`
                    )}
              </p>
            )}
            {blocked && !showPassword && (
              <p className="dialog-note" role="alert">
                {t(
                  "The browser blocked the sign-in window. Allow pop-ups for Hecate, or sign in on this page (the action then has to be started again).",
                  "Der Browser hat das Anmeldefenster blockiert. Erlaube Pop-ups für Hecate oder melde dich auf dieser Seite an (die Aktion muss danach neu gestartet werden)."
                )}
              </p>
            )}
            {showPassword ? (
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  if (value.trim()) close({ kind: "password", password: value.trim() });
                }}
              >
                <input
                  ref={inputRef}
                  type="password"
                  value={value}
                  onChange={(e) => setValue(e.target.value)}
                  placeholder={t("Password", "Passwort")}
                  aria-label={t("Password", "Passwort")}
                />
                <div className="dialog-actions">
                  <button type="button" className="btn btn-secondary" onClick={() => close(null)}>
                    {t("Cancel", "Abbrechen")}
                  </button>
                  {prompt.signIn && (
                    <button type="button" className="btn btn-secondary" onClick={() => setUsePassword(false)}>
                      {t("Sign in instead", "Stattdessen anmelden")}
                    </button>
                  )}
                  <button type="submit" className="btn btn-primary" disabled={!value.trim()}>
                    {t("Unlock", "Entsperren")}
                  </button>
                </div>
              </form>
            ) : (
              <div className="dialog-actions">
                <button type="button" className="btn btn-secondary" onClick={() => close(null)}>
                  {t("Cancel", "Abbrechen")}
                </button>
                {prompt.password && (
                  <button type="button" className="btn btn-secondary" onClick={() => setUsePassword(true)}>
                    {t("Use a password", "Passwort verwenden")}
                  </button>
                )}
                {blocked && (
                  <button type="button" className="btn btn-secondary" onClick={() => auth.signIn()}>
                    {t("Sign in on this page", "Auf dieser Seite anmelden")}
                  </button>
                )}
                <button
                  ref={signInRef}
                  type="button"
                  className="btn btn-primary"
                  onClick={startSignIn}
                  aria-busy={waiting || undefined}
                >
                  <BusyLabel busy={waiting}>
                    {waiting ? t("Open the window again", "Fenster erneut öffnen") : t("Sign in", "Anmelden")}
                  </BusyLabel>
                </button>
              </div>
            )}
          </div>
        </div>
      )}
    </>
  );
};
