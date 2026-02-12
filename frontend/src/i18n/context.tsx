import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";

import {
  type AppLanguage,
  detectBrowserLanguage,
  getLocaleFromLanguage,
  readStoredLanguage,
  writeStoredLanguage
} from "./language";

type TranslateFn = (english: string, german: string) => string;

interface I18nContextValue {
  language: AppLanguage;
  locale: string;
  setLanguage: (language: AppLanguage) => void;
  t: TranslateFn;
}

const I18nContext = createContext<I18nContextValue | null>(null);

const getInitialLanguage = (): AppLanguage => {
  return readStoredLanguage() ?? detectBrowserLanguage();
};

export const I18nProvider = ({ children }: { children: ReactNode }) => {
  const [language, setLanguageState] = useState<AppLanguage>(getInitialLanguage);

  useEffect(() => {
    writeStoredLanguage(language);
    if (typeof document !== "undefined") {
      document.documentElement.lang = language;
    }
  }, [language]);

  const setLanguage = useCallback((next: AppLanguage) => {
    setLanguageState(next);
  }, []);

  const value = useMemo<I18nContextValue>(() => {
    const t: TranslateFn = (english: string, german: string) => {
      return language === "de" ? german : english;
    };
    return {
      language,
      locale: getLocaleFromLanguage(language),
      setLanguage,
      t,
    };
  }, [language, setLanguage]);

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
};

export const useI18n = (): I18nContextValue => {
  const context = useContext(I18nContext);
  if (!context) {
    throw new Error("useI18n must be used within an I18nProvider");
  }
  return context;
};

export type { TranslateFn };

