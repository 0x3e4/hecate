import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { LuLogIn } from "react-icons/lu";

import { api, apiBaseURL } from "../api/client";
import { clearWriteSecrets } from "../api/writeAuth";
import { useI18n } from "../i18n/context";
import { useServerConfig } from "../server-config/context";
import { LoadingState } from "../ui/primitives";
import { currentReturnPath, loginUrl, roleAtLeast, type AuthRole } from "./returnTo";
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
    api
      .get<{ authenticated: boolean; user: AuthUser | null }>("/v1/auth/me")
      .then((res) => {
        if (!cancelled) setUser(res.data.authenticated ? res.data.user : null);
      })
      .catch(() => {
        if (!cancelled) setUser(null);
      })
      .finally(() => {
        if (!cancelled) setLoaded(true);
      });
    return () => {
      cancelled = true;
    };
  }, [enabled]);

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
    () => ({ enabled, required, providerLabel, user, hasRole, signIn, signOut }),
    [enabled, required, providerLabel, user, hasRole, signIn, signOut],
  );

  if (!loaded) {
    return (
      <div className="auth-splash">
        <LoadingState />
      </div>
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
