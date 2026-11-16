import { useEffect, useState, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";

import { api } from "../api/client";
import { setAdminPassword } from "../api/writeAuth";
import { useAuth } from "../auth/context";
import { useI18n } from "../i18n/context";
import { BusyLabel, LoadingState } from "../ui/primitives";
import { useToastContext } from "./ToastProvider";

// Gate for the admin-only pages (System, Audit log): their reads are behind the
// backend's require_admin_read. `children` mounts, and so fetches, only once a
// signed-in admin or the system password opens the page. With OIDC and no
// system password only the admin role helps, so the dialog offers a sign-in.
export const AdminGate = ({
  children,
  overlayClassName,
  dialogClassName = "",
  titleClassName,
}: {
  children: ReactNode;
  overlayClassName: string;
  dialogClassName?: string;
  titleClassName: string;
}) => {
  const { t } = useI18n();
  const auth = useAuth();
  const navigate = useNavigate();
  const { showToast } = useToastContext();
  const [authRequired, setAuthRequired] = useState<boolean | null>(null);
  const [authOk, setAuthOk] = useState(false);
  const [passwordAccepted, setPasswordAccepted] = useState(true);
  const [authPassword, setAuthPassword] = useState("");
  const [authChecking, setAuthChecking] = useState(false);

  useEffect(() => {
    api
      .get<{ required: boolean; adminRequired?: boolean | null; passwordAccepted?: boolean | null }>(
        "/v1/status/system-auth",
      )
      .then((r) => {
        const required = r.data.adminRequired ?? r.data.required;
        setPasswordAccepted(r.data.passwordAccepted ?? r.data.required);
        setAuthRequired(required);
        if (!required) setAuthOk(true);
      })
      .catch(() => {
        setAuthRequired(false);
        setAuthOk(true);
      });
  }, []);

  const handleAuthSubmit = async () => {
    setAuthChecking(true);
    try {
      const r = await api.post<{ authenticated: boolean }>("/v1/status/system-auth", { password: authPassword });
      if (r.data.authenticated) {
        setAuthOk(true);
        // Persist so the axios interceptor can attach X-System-Password to write
        // requests from any page (delete target, manage notifications, etc.).
        setAdminPassword(authPassword);
      }
    } catch {
      showToast(t("Invalid password.", "Falsches Passwort."), "error");
    } finally {
      setAuthChecking(false);
    }
  };

  if (authRequired === null) {
    return (
      <div className={`dialog-overlay ${overlayClassName}`}>
        <div className="dialog">
          <LoadingState />
        </div>
      </div>
    );
  }
  if (authRequired && !authOk) {
    if (!passwordAccepted) {
      // OIDC without a system password: only the admin role opens the settings.
      return (
        <div className={`dialog-overlay ${overlayClassName}`} onClick={() => navigate(-1)}>
          <div className={`dialog ${dialogClassName}`} onClick={(e) => e.stopPropagation()}>
            <h1 className={titleClassName}>{t("Admins only", "Nur für Admins")}</h1>
            <p>
              {auth.user
                ? t(
                    "The system settings are visible to the admin role only.",
                    "Die Systemeinstellungen sind nur für die Admin-Rolle sichtbar.",
                  )
                : t(
                    "Sign in as an admin to see the system settings.",
                    "Melde dich als Admin an, um die Systemeinstellungen zu sehen.",
                  )}
            </p>
            <div className="dialog-actions">
              <button type="button" className="btn btn-secondary" onClick={() => navigate(-1)}>
                {t("Back", "Zurück")}
              </button>
              {!auth.user && (
                <button type="button" className="btn btn-primary" onClick={() => auth.signIn()}>
                  {t("Sign in", "Anmelden")}
                </button>
              )}
            </div>
          </div>
        </div>
      );
    }
    return (
      <div className={`dialog-overlay ${overlayClassName}`} onClick={() => navigate(-1)}>
        <div className={`dialog ${dialogClassName}`} onClick={(e) => e.stopPropagation()}>
          <h1 className={titleClassName}>{t("System Password", "System-Passwort")}</h1>
          <p>{t("Enter the password to access this page.", "Passwort eingeben, um auf diese Seite zuzugreifen.")}</p>
          <input
            type="password"
            value={authPassword}
            onChange={(e) => setAuthPassword(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter") void handleAuthSubmit(); else if (e.key === "Escape") navigate(-1); }}
            placeholder={t("Password", "Passwort")}
            aria-label={t("Password", "Passwort")}
            autoFocus
          />
          <div className="dialog-actions">
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => navigate(-1)}
            >
              {t("Cancel", "Abbrechen")}
            </button>
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => void handleAuthSubmit()}
              disabled={authChecking || !authPassword}
              aria-busy={authChecking || undefined}
            >
              <BusyLabel busy={authChecking}>{t("Unlock", "Entsperren")}</BusyLabel>
            </button>
          </div>
        </div>
      </div>
    );
  }
  return <>{children}</>;
};
