import { useEffect, useMemo, useRef, useState } from "react";
import { LuLogIn, LuLogOut } from "react-icons/lu";

import "../ui/preferences.css";
import { useAuth } from "../auth/context";
import { roleLabel } from "../auth/roleLabel";
import { useI18n } from "../i18n/context";
import type { AppLanguage } from "../i18n/language";
import type { PreferencesStore } from "../preferences/context";
import type { UserPreferences } from "../preferences/sync";
import { useTimezone } from "../timezone/context";
import { listSupportedTimezones } from "../timezone/storage";
import { DocsLink } from "./DocsLink";
import { LanguageFlag } from "./LanguageFlag";

const LANGUAGES: { value: AppLanguage; label: string }[] = [
  { value: "en", label: "English" },
  { value: "de", label: "Deutsch" },
];

/**
 * The account panel: who is signed in, the personal preferences as compact
 * rows, and signing in or out. Opened from the sidebar's bottom row (or the
 * dashboard's "Change") as a popover next to its trigger.
 */
export const PreferencesPanel = ({
  dashboardOnlyMyStack,
  update,
  store,
  saveFailed,
  titleId,
}: {
  dashboardOnlyMyStack: boolean;
  update: (patch: Partial<UserPreferences>) => void;
  store: PreferencesStore;
  saveFailed: boolean;
  titleId: string;
}) => {
  const { language, t } = useI18n();
  const { timezone, isBrowserDefault } = useTimezone();
  const auth = useAuth();
  const zones = useMemo(() => listSupportedTimezones(), []);
  const [zoneDraft, setZoneDraft] = useState(isBrowserDefault ? "" : timezone);
  const firstControl = useRef<HTMLInputElement>(null);

  useEffect(() => setZoneDraft(isBrowserDefault ? "" : timezone), [timezone, isBrowserDefault]);
  useEffect(() => firstControl.current?.focus(), []);

  const commitZone = (value: string): boolean => {
    const zone = value.trim();
    if (!zone) {
      update({ timezone: null });
      return true;
    }
    if (!zones.includes(zone)) return false;
    update({ timezone: zone });
    return true;
  };

  const user = auth.user;
  return (
    <>
      {user ? (
        <div className="prefs-identity">
          <p id={titleId} className="prefs-name">{user.name}</p>
          {user.email && <p className="prefs-email">{user.email}</p>}
          <p className="prefs-role">{roleLabel(user.role, t)}</p>
        </div>
      ) : (
        <p id={titleId} className="prefs-title">{t("Preferences", "Einstellungen")}</p>
      )}

      <div className="prefs-rows">
        {/* A radiogroup rather than fieldset + legend: Safari lays a fieldset out
            as a block whatever its display, which stacked the label and
            squeezed the two languages into each other. */}
        <div className="prefs-row">
          <span className="prefs-label" id="prefs-language-label">
            {t("Language", "Sprache")}
          </span>
          <div className="prefs-segments" role="radiogroup" aria-labelledby="prefs-language-label">
            {LANGUAGES.map((option, index) => (
              <label key={option.value} className="prefs-segment">
                <input
                  ref={index === 0 ? firstControl : undefined}
                  type="radio"
                  name="prefs-language"
                  className="visually-hidden"
                  value={option.value}
                  checked={language === option.value}
                  onChange={() => update({ language: option.value })}
                />
                <LanguageFlag language={option.value} />
                <span>{option.label}</span>
              </label>
            ))}
          </div>
        </div>

        <div className="prefs-row">
          <label className="prefs-label" htmlFor="prefs-timezone">
            {t("Time zone", "Zeitzone")}
          </label>
          <div className="prefs-control">
            <input
              id="prefs-timezone"
              className="prefs-input"
              list="prefs-timezone-options"
              value={zoneDraft}
              placeholder={t(`${timezone} (browser)`, `${timezone} (Browser)`)}
              onChange={(event) => {
                setZoneDraft(event.target.value);
                commitZone(event.target.value);
              }}
              onBlur={() => {
                // An unknown zone snaps back to the one in use.
                if (!commitZone(zoneDraft)) setZoneDraft(isBrowserDefault ? "" : timezone);
              }}
            />
            <datalist id="prefs-timezone-options">
              {zones.map((zone) => (
                <option key={zone} value={zone} />
              ))}
            </datalist>
          </div>
        </div>

        <div className="prefs-row">
          <span className="prefs-label" id="prefs-dashboard-label">
            {t("Dashboard", "Dashboard")}
          </span>
          <div className="prefs-control">
            <label className="prefs-switch">
              <input
                type="checkbox"
                role="switch"
                aria-describedby="prefs-dashboard-label"
                checked={dashboardOnlyMyStack}
                onChange={(event) => update({ dashboardOnlyMyStack: event.target.checked })}
              />
              <span>{t("Only my stack", "Nur mein Stack")}</span>
            </label>
          </div>
          {/* Under the whole row, so it reads as the setting's explanation. */}
          <DocsLink path="guide/dashboard/#only-my-stack" className="prefs-hint prefs-row-hint">
            {t("Only CVEs from your inventory and scans", "Nur CVEs aus Inventar und Scans")}
          </DocsLink>
        </div>
      </div>

      <p className="prefs-store" role={saveFailed ? "alert" : undefined}>
        {saveFailed
          ? t("Not saved to your account; kept in this browser.", "Nicht im Konto gespeichert; in diesem Browser behalten.")
          : store === "account"
            ? t("Saved to your account.", "Im Konto gespeichert.")
            : t("Saved in this browser.", "In diesem Browser gespeichert.")}
      </p>

      {auth.enabled && (
        <div className="prefs-actions">
          {user ? (
            <button type="button" className="prefs-action" onClick={() => void auth.signOut()}>
              <LuLogOut aria-hidden="true" />
              {t("Sign out", "Abmelden")}
            </button>
          ) : (
            <button type="button" className="prefs-action" onClick={() => auth.signIn()}>
              <LuLogIn aria-hidden="true" />
              {t("Sign in to keep these on your account", "Anmelden, um sie im Konto zu speichern")}
            </button>
          )}
        </div>
      )}
    </>
  );
};
