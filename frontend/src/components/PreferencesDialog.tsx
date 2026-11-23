import { useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { LuX } from "react-icons/lu";

import { useI18n } from "../i18n/context";
import type { AppLanguage } from "../i18n/language";
import { useTimezone } from "../timezone/context";
import { listSupportedTimezones } from "../timezone/storage";

/**
 * Language and display timezone. Both are stored in this browser only, so
 * everyone can set them: they used to sit on the admin-only System page.
 *
 * Rendered into document.body: it is opened from the sidebar, and on narrow
 * screens the sidebar slides in through a transform, which makes it the
 * containing block of every position: fixed descendant. Inside it the overlay
 * only covered the sidebar.
 */
export const PreferencesDialog = ({ onClose }: { onClose: () => void }) => {
  const { language, setLanguage, t } = useI18n();
  const { timezone, isBrowserDefault, setTimezone } = useTimezone();
  const supportedTimezones = useMemo(() => listSupportedTimezones(), []);
  const [timezoneDraft, setTimezoneDraft] = useState<string>(isBrowserDefault ? "" : timezone);
  const languageRef = useRef<HTMLSelectElement>(null);

  useEffect(() => {
    setTimezoneDraft(isBrowserDefault ? "" : timezone);
  }, [timezone, isBrowserDefault]);

  useEffect(() => {
    languageRef.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const commitTimezone = (value: string) => {
    const trimmed = value.trim();
    if (!trimmed) {
      setTimezone(null);
      return true;
    }
    if (supportedTimezones.includes(trimmed)) {
      setTimezone(trimmed);
      return true;
    }
    return false;
  };

  return createPortal(
    <div className="dialog-overlay" role="presentation" onClick={onClose}>
      <div
        className="dialog preferences-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="preferences-dialog-title"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="dialog-head">
          <h2 id="preferences-dialog-title">{t("Language and time", "Sprache und Zeit")}</h2>
          <button type="button" className="dialog-close" onClick={onClose} aria-label={t("Close", "Schließen")}>
            <LuX aria-hidden="true" />
          </button>
        </div>

        <div className="preferences-field">
          <label htmlFor="preferences-language">{t("Interface language", "Oberflächensprache")}</label>
          <select
            id="preferences-language"
            ref={languageRef}
            className="preferences-input"
            value={language}
            onChange={(event) => setLanguage(event.target.value as AppLanguage)}
          >
            <option value="en">English</option>
            <option value="de">Deutsch</option>
          </select>
        </div>

        <div className="preferences-field">
          <label htmlFor="preferences-timezone">{t("Display timezone", "Anzeige-Zeitzone")}</label>
          <input
            id="preferences-timezone"
            className="preferences-input"
            list="preferences-timezone-options"
            value={timezoneDraft}
            placeholder={t(`Browser default (${timezone})`, `Browser-Standard (${timezone})`)}
            aria-describedby="preferences-timezone-note"
            onChange={(event) => {
              setTimezoneDraft(event.target.value);
              commitTimezone(event.target.value);
            }}
            onBlur={() => {
              // An unknown zone snaps back to the one in use.
              if (!commitTimezone(timezoneDraft)) setTimezoneDraft(isBrowserDefault ? "" : timezone);
            }}
          />
          <datalist id="preferences-timezone-options">
            {supportedTimezones.map((tz) => (
              <option key={tz} value={tz} />
            ))}
          </datalist>
          <p id="preferences-timezone-note" className="muted preferences-note">
            {t(
              `Dates are shown in ${timezone}${isBrowserDefault ? " (browser default)" : ""}.`,
              `Datumsangaben in ${timezone}${isBrowserDefault ? " (Browser-Standard)" : ""}.`,
            )}
          </p>
          {!isBrowserDefault && (
            <button type="button" className="btn btn-secondary" onClick={() => setTimezone(null)}>
              {t("Use browser default", "Browser-Standard verwenden")}
            </button>
          )}
        </div>

        <p className="muted preferences-note">
          {t("Saved in this browser only.", "Nur in diesem Browser gespeichert.")}
        </p>
      </div>
    </div>,
    document.body,
  );
};
