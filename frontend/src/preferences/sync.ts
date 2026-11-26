/**
 * Personal preferences: what the browser keeps, what a signed-in account keeps,
 * and how the two meet on sign-in. Pure, so the rule is tested.
 */
import type { AppLanguage } from "../i18n/language";

export interface UserPreferences {
  language: AppLanguage | null;
  /** IANA zone; null = the browser's zone. */
  timezone: string | null;
  dashboardOnlyMyStack: boolean;
}

export interface StoredUserPreferences extends UserPreferences {
  /** null while the account has never saved any. */
  updatedAt: string | null;
}

export type SyncPlan = { kind: "apply"; preferences: UserPreferences } | { kind: "upload"; preferences: UserPreferences };

/**
 * On sign-in: an account that has saved preferences wins over this browser;
 * an account without any takes this browser's, so a first sign-in changes nothing on screen.
 */
export const planSync = (account: StoredUserPreferences, browser: UserPreferences): SyncPlan => {
  if (!account.updatedAt) return { kind: "upload", preferences: browser };
  return {
    kind: "apply",
    preferences: {
      // No language saved: keep the one this browser shows.
      language: account.language ?? browser.language,
      timezone: account.timezone,
      dashboardOnlyMyStack: account.dashboardOnlyMyStack,
    },
  };
};

export const samePreferences = (a: UserPreferences, b: UserPreferences): boolean =>
  a.language === b.language && a.timezone === b.timezone && a.dashboardOnlyMyStack === b.dashboardOnlyMyStack;
