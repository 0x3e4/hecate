import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { LuLogIn } from "react-icons/lu";

import { api, apiBaseURL } from "../api/client";
import { clearWriteSecrets } from "../api/writeAuth";
import { useI18n } from "../i18n/context";
import { useServerConfig } from "../server-config/context";
import { LoadingState } from "../ui/primitives";
import { currentReturnPath, loginUrl, roleAtLeast, type AuthRole } from "./returnTo";
import { SIGNED_IN_PATH, announceSignedIn, onSignedInElsewhere } from "./signInWindow";
import "../screens/auth.css";

export interface AuthUser {
  name: string;
  email: string | null;
  role: AuthRole;
}

interface AuthContextValue {
  /** OIDC sign-in is configured on the backend. */
  enabled: boolean;
  /** Every page needs a session. */
  required: boolean;
  providerLabel: string;
  user: AuthUser | null;
  /** True when the signed-in user reaches `role`. Without OIDC nobody has a role. */
  hasRole: (role: AuthRole) => boolean;
  signIn: (returnTo?: string) => void;
  signOut: () => Promise<void>;
  /** Asks the backend who is signed in now (after a sign-in in another window). */
  refresh: () => Promise<AuthUser | null>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

const AUTH_ERROR_PARAM = "authError";

const readAuthError = (): string | null => {
  if (typeof window === "undefined") return null;
  return new URLSearchParams(window.location.search).get(AUTH_ERROR_PARAM);
};

const clearAuthErrorFromUrl = (): void => {
  try {
    window.history.replaceState(window.history.state, "", currentReturnPath());
  } catch {
    /* ignore */
  }
};

export const AuthProvider = ({ children }: { children: ReactNode }) => {
  const config = useServerConfig();
  const enabled = config.authEnabled === true;
  const required = enabled && config.authRequired === true;
  const providerLabel = config.authProviderLabel || "Single sign-on";
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loaded, setLoaded] = useState(!enabled);
  const [authError, setAuthError] = useState<string | null>(readAuthError);

  useEffect(() => {
    if (!enabled) return;
    let cancelled = false;
    fetchMe()
      .then((me) => {
        if (!cancelled) setUser(me);
      })
      .finally(() => {
        if (!cancelled) setLoaded(true);
      });
    return () => {
      cancelled = true;
    };
  }, [enabled]);

  const refresh = useCallback(async () => {
    if (!enabled) return null;
    const me = await fetchMe();
    setUser(me);
    return me;
  }, [enabled]);

  // A sign-in finished in another window (the sign-in popup, another tab):
  // the sidebar and role checks here follow without a reload.
  useEffect(() => {
    if (!enabled) return;
    return onSignedInElsewhere(() => void refresh());
  }, [enabled, refresh]);

  const signInLanding = enabled && loaded && typeof window !== "undefined" && window.location.pathname === SIGNED_IN_PATH;
  useEffect(() => {
    if (!signInLanding || !user) return;
    announceSignedIn();
    // Closes the popup; a window the browser won't let close shows the note below.
    const id = window.setTimeout(() => window.close(), 400);
    return () => window.clearTimeout(id);
  }, [signInLanding, user]);

  const signIn = useCallback((returnTo?: string) => {
    // A new account starts without the previous person's write secrets.
    clearWriteSecrets();
    window.location.assign(loginUrl(apiBaseURL, returnTo ?? currentReturnPath()));
  }, []);

  const signOut = useCallback(async () => {
    let target = "/";
    try {
      const res = await api.post<{ logoutUrl: string | null }>("/v1/auth/logout");
      if (res.data.logoutUrl) target = res.data.logoutUrl;
    } catch {
      /* the cookie is gone either way once the backend answered; reload regardless */
    }
    // Signing out ends every credential entered in this browser, not only the
    // session: the next person's writes would carry them otherwise.
    clearWriteSecrets();
    setUser(null);
    window.location.assign(target);
  }, []);

  const hasRole = useCallback((role: AuthRole) => roleAtLeast(user?.role, role), [user]);

  const value = useMemo<AuthContextValue>(
    () => ({ enabled, required, providerLabel, user, hasRole, signIn, signOut, refresh }),
    [enabled, required, providerLabel, user, hasRole, signIn, signOut, refresh],
  );

  if (!loaded) {
    return (
      <div className="auth-splash">
        <LoadingState />
      </div>
    );
  }

  if (signInLanding && !authError) {
    return (
      <AuthContext.Provider value={value}>
        <SignedInScreen user={user} onSignIn={() => signIn(SIGNED_IN_PATH)} />
      </AuthContext.Provider>
    );
  }

  if (enabled && (authError || (required && !user))) {
    return (
      <AuthContext.Provider value={value}>
        <LoginScreen
          providerLabel={providerLabel}
          error={authError}
          onSignIn={() => {
            clearAuthErrorFromUrl();
            signIn(currentReturnPath());
          }}
          onContinue={
            required && !user
              ? undefined
              : () => {
                  clearAuthErrorFromUrl();
                  setAuthError(null);
                }
          }
        />
      </AuthContext.Provider>
    );
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = (): AuthContextValue => {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return ctx;
};

const fetchMe = async (): Promise<AuthUser | null> => {
  try {
    const res = await api.get<{ authenticated: boolean; user: AuthUser | null }>("/v1/auth/me");
    return res.data.authenticated ? res.data.user : null;
  } catch {
    return null;
  }
};

// Where the sign-in window lands: the page that asked for the sign-in is
// still open in the other window and continues on its own.
const SignedInScreen = ({ user, onSignIn }: { user: AuthUser | null; onSignIn: () => void }) => {
  const { t } = useI18n();
  return (
    <main className="auth-screen">
      <div className="auth-card" role="status">
        <img src="/logo.png" alt="" width={48} height={48} />
        <h1 className="auth-title">Hecate Cyber Defense</h1>
        {user ? (
          <p className="auth-lead">
            {t(
              `Signed in as ${user.name}. You can close this window; Hecate continues in the other one.`,
              `Angemeldet als ${user.name}. Du kannst dieses Fenster schließen; Hecate macht im anderen weiter.`,
            )}
          </p>
        ) : (
          <>
            <p className="auth-error">{t("The sign-in did not complete.", "Die Anmeldung wurde nicht abgeschlossen.")}</p>
            <div className="auth-actions">
              <button type="button" className="btn btn-primary" onClick={onSignIn}>
                <LuLogIn aria-hidden="true" />
                {t("Sign in again", "Erneut anmelden")}
              </button>
            </div>
          </>
        )}
      </div>
    </main>
  );
};

const LoginScreen = ({
  providerLabel,
  error,
  onSignIn,
  onContinue,
}: {
  providerLabel: string;
  error: string | null;
  onSignIn: () => void;
  onContinue?: () => void;
}) => {
  const { t } = useI18n();

  const errorText = (code: string): string => {
    switch (code) {
      case "no_role":
        return t(
          "Your account has no role in Hecate. Ask an administrator to add you to one of the groups configured for it.",
          "Dein Konto hat keine Rolle in Hecate. Bitte eine Administratorin oder einen Administrator, dich einer der dafür konfigurierten Gruppen hinzuzufügen.",
        );
      case "invalid_state":
        return t(
          "The sign-in expired or was started in another tab. Please try again.",
          "Die Anmeldung ist abgelaufen oder wurde in einem anderen Tab begonnen. Bitte erneut versuchen.",
        );
      case "invalid_token":
        return t(
          "The identity provider's answer could not be verified. An administrator finds the reason in the audit log.",
          "Die Antwort des Identity Providers ließ sich nicht prüfen. Den Grund finden Administratoren im Audit-Log.",
        );
      case "idp_error":
        return t("The identity provider refused the sign-in.", "Der Identity Provider hat die Anmeldung abgelehnt.");
      case "provider_unavailable":
        return t("The identity provider is not reachable right now.", "Der Identity Provider ist gerade nicht erreichbar.");
      case "provider_misconfigured":
      case "token_exchange_failed":
        return t(
          "Sign-in is not set up correctly. An administrator finds the reason in the audit log.",
          "Die Anmeldung ist nicht richtig eingerichtet. Den Grund finden Administratoren im Audit-Log.",
        );
      default:
        return t("Sign-in failed.", "Anmeldung fehlgeschlagen.");
    }
  };

  return (
    <main className="auth-screen">
      <div className="auth-card" role={error ? "alert" : undefined}>
        <img src="/logo.png" alt="" width={48} height={48} />
        <h1 className="auth-title">Hecate Cyber Defense</h1>
        {error ? (
          <p className="auth-error">{errorText(error)}</p>
        ) : (
          <p className="auth-lead">{t("Sign in to continue.", "Melde dich an, um fortzufahren.")}</p>
        )}
        <div className="auth-actions">
          <button type="button" className="btn btn-primary" onClick={onSignIn}>
            <LuLogIn aria-hidden="true" />
            {t(`Sign in with ${providerLabel}`, `Mit ${providerLabel} anmelden`)}
          </button>
          {onContinue && (
            <button type="button" className="btn btn-secondary" onClick={onContinue}>
              {t("Continue without signing in", "Ohne Anmeldung fortfahren")}
            </button>
          )}
        </div>
      </div>
    </main>
  );
};
