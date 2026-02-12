export type AppLanguage = "en" | "de";

export const LANGUAGE_STORAGE_KEY = "hecate.ui_language";

const DEFAULT_LANGUAGE: AppLanguage = "en";
const LANGUAGE_SET = new Set<AppLanguage>(["en", "de"]);

const normalizeLanguage = (value: unknown): AppLanguage | null => {
  if (typeof value !== "string") {
    return null;
  }
  const normalized = value.toLowerCase();
  if (!LANGUAGE_SET.has(normalized as AppLanguage)) {
    return null;
  }
  return normalized as AppLanguage;
};

export const detectBrowserLanguage = (): AppLanguage => {
  if (typeof navigator === "undefined") {
    return DEFAULT_LANGUAGE;
  }
  const candidates = Array.isArray(navigator.languages) && navigator.languages.length > 0
    ? navigator.languages
    : [navigator.language];

  for (const candidate of candidates) {
    const normalized = candidate.toLowerCase();
    if (normalized.startsWith("de")) {
      return "de";
    }
    if (normalized.startsWith("en")) {
      return "en";
    }
  }
  return DEFAULT_LANGUAGE;
};

export const readStoredLanguage = (): AppLanguage | null => {
  if (typeof window === "undefined") {
    return null;
  }
  try {
    const raw = window.localStorage.getItem(LANGUAGE_STORAGE_KEY);
    if (raw == null) {
      return null;
    }
    try {
      const parsed = JSON.parse(raw);
      const normalizedParsed = normalizeLanguage(parsed);
      if (normalizedParsed) {
        return normalizedParsed;
      }
    } catch {
      const normalizedRaw = normalizeLanguage(raw);
      if (normalizedRaw) {
        return normalizedRaw;
      }
    }
    return null;
  } catch (error) {
    console.warn("Failed to read UI language from localStorage", error);
    return null;
  }
};

export const writeStoredLanguage = (language: AppLanguage): void => {
  if (typeof window === "undefined") {
    return;
  }
  try {
    window.localStorage.setItem(LANGUAGE_STORAGE_KEY, JSON.stringify(language));
  } catch (error) {
    console.warn("Failed to write UI language to localStorage", error);
  }
};

export const getCurrentLanguage = (): AppLanguage => {
  return readStoredLanguage() ?? detectBrowserLanguage();
};

export const getLocaleFromLanguage = (language: AppLanguage): string => {
  return language === "de" ? "de-DE" : "en-US";
};

export const getCurrentLocale = (): string => {
  return getLocaleFromLanguage(getCurrentLanguage());
};
