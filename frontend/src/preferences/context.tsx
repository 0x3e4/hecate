import { createContext, useCallback, useContext, useEffect, useId, useMemo, useRef, useState, type ReactNode } from "react";

import { fetchUserPreferences, saveUserPreferences } from "../api/preferences";
import { useAuth } from "../auth/context";
import { PreferencesPanel } from "../components/PreferencesPanel";
import { usePersistentState } from "../hooks/usePersistentState";
import { useI18n } from "../i18n/context";
import type { AppLanguage } from "../i18n/language";
import { useTimezone } from "../timezone/context";
import { placePanel } from "./placement";
import { planSync, samePreferences, type UserPreferences } from "./sync";

/** Where the preferences live right now. */
export type PreferencesStore = "browser" | "account";

interface PreferencesContextValue {
  dashboardOnlyMyStack: boolean;
  update: (patch: Partial<UserPreferences>) => void;
  store: PreferencesStore;
  saveFailed: boolean;
  /**
   * Props for a button that opens the panel next to itself. It is the popover's
   * declared invoker, so clicking it again closes the panel (instead of light
   * dismiss closing and the click reopening it) and focus returns to it.
   */
  triggerProps: () => {
    popoverTarget: string;
    onClick: (event: { currentTarget: HTMLElement }) => void;
    "aria-haspopup": "dialog";
  };
}

const PreferencesContext = createContext<PreferencesContextValue | null>(null);

const SAVE_DELAY_MS = 500;

/**
 * Language, timezone and the dashboard view. Kept in the browser; with OIDC and
 * a signed-in user also on the account (`/auth/me/preferences`), so they follow
 * the user to every browser. Also owns the account panel, a popover the sidebar's
 * bottom row and the dashboard open next to themselves.
 */
export const PreferencesProvider = ({ children }: { children: ReactNode }) => {
  const auth = useAuth();
  const { language, setLanguage } = useI18n();
  const { timezone, isBrowserDefault, setTimezone } = useTimezone();
  const [dashboardOnlyMyStack, setDashboardOnlyMyStack] = usePersistentState("hecate.dashboard.onlyMyStack", false);
  const [open, setOpen] = useState(false);
  const panelRef = useRef<HTMLDivElement>(null);
  const anchorRef = useRef<HTMLElement | null>(null);
  const panelId = useId();
  const titleId = useId();
  const [store, setStore] = useState<PreferencesStore>("browser");
  const [saveFailed, setSaveFailed] = useState(false);

  const current: UserPreferences = useMemo(
    () => ({ language, timezone: isBrowserDefault ? null : timezone, dashboardOnlyMyStack }),
    [language, timezone, isBrowserDefault, dashboardOnlyMyStack],
  );
  const currentRef = useRef(current);
  currentRef.current = current;
  const saveTimer = useRef<number | null>(null);

  const apply = useCallback(
    (prefs: UserPreferences) => {
      if (prefs.language) setLanguage(prefs.language as AppLanguage);
      setTimezone(prefs.timezone);
      setDashboardOnlyMyStack(prefs.dashboardOnlyMyStack);
    },
    [setLanguage, setTimezone, setDashboardOnlyMyStack],
  );

  // On sign-in: the account's saved preferences win; an account without any takes this browser's.
  const userKey = auth.user ? `${auth.user.name}|${auth.user.email ?? ""}` : null;
  useEffect(() => {
    setStore("browser");
    setSaveFailed(false);
    if (!userKey) return;
    let cancelled = false;
    void (async () => {
      try {
        const plan = planSync(await fetchUserPreferences(), currentRef.current);
        if (cancelled) return;
        if (plan.kind === "apply") apply(plan.preferences);
        else await saveUserPreferences(plan.preferences);
        if (!cancelled) setStore("account");
      } catch {
        // The browser copy keeps working; the dialog says where things are saved.
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [userKey, apply]);

  const update = useCallback(
    (patch: Partial<UserPreferences>) => {
      const next = { ...currentRef.current, ...patch };
      if (samePreferences(next, currentRef.current)) return;
      apply(next);
      if (store !== "account") return;
      // Typing a zone or flipping switches sends one request, not one per change.
      if (saveTimer.current !== null) window.clearTimeout(saveTimer.current);
      saveTimer.current = window.setTimeout(() => {
        saveTimer.current = null;
        saveUserPreferences(next).then(
          () => setSaveFailed(false),
          () => setSaveFailed(true),
        );
      }, SAVE_DELAY_MS);
    },
    [apply, store],
  );

  useEffect(
    () => () => {
      if (saveTimer.current !== null) window.clearTimeout(saveTimer.current);
    },
    [],
  );

  const place = useCallback(() => {
    const panel = panelRef.current;
    const anchor = anchorRef.current;
    if (!panel || !anchor || !anchor.isConnected) return;
    const size = panel.getBoundingClientRect();
    const { top, left } = placePanel(anchor.getBoundingClientRect(), size, {
      width: document.documentElement.clientWidth,
      height: window.innerHeight,
    });
    panel.style.top = `${top}px`;
    panel.style.left = `${left}px`;
  }, []);

  const triggerProps = useCallback(
    () => ({
      popoverTarget: panelId,
      // Runs before the browser toggles the popover, so the panel knows where to open.
      onClick: (event: { currentTarget: HTMLElement }) => {
        anchorRef.current = event.currentTarget;
      },
      "aria-haspopup": "dialog" as const,
    }),
    [panelId],
  );

  // The popover closes itself on Escape and on a click outside; this follows it.
  useEffect(() => {
    const panel = panelRef.current;
    if (!panel) return;
    const onToggle = (event: Event) => setOpen((event as ToggleEvent).newState === "open");
    panel.addEventListener("toggle", onToggle);
    return () => panel.removeEventListener("toggle", onToggle);
  }, []);

  // Placed once its content is rendered, and again when the window changes.
  useEffect(() => {
    if (!open) return;
    place();
    window.addEventListener("resize", place);
    return () => window.removeEventListener("resize", place);
  }, [open, place]);

  const value = useMemo<PreferencesContextValue>(
    () => ({ dashboardOnlyMyStack, update, store, saveFailed, triggerProps }),
    [dashboardOnlyMyStack, update, store, saveFailed, triggerProps],
  );

  return (
    <PreferencesContext.Provider value={value}>
      {children}
      <div
        ref={panelRef}
        id={panelId}
        popover="auto"
        role="dialog"
        aria-labelledby={titleId}
        className="prefs-panel"
      >
        {open && (
          <PreferencesPanel
            dashboardOnlyMyStack={dashboardOnlyMyStack}
            update={update}
            store={store}
            saveFailed={saveFailed}
            titleId={titleId}
          />
        )}
      </div>
    </PreferencesContext.Provider>
  );
};

export const usePreferences = (): PreferencesContextValue => {
  const context = useContext(PreferencesContext);
  if (!context) throw new Error("usePreferences must be used within a PreferencesProvider");
  return context;
};
