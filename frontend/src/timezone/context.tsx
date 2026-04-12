import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";

import {
  detectBrowserTimezone,
  readStoredTimezone,
  writeStoredTimezone,
} from "./storage";

interface TimezoneContextValue {
  timezone: string;
  isBrowserDefault: boolean;
  setTimezone: (timezone: string | null) => void;
}

const TimezoneContext = createContext<TimezoneContextValue | null>(null);

const getInitial = (): { value: string; isDefault: boolean } => {
  const stored = readStoredTimezone();
  if (stored) {
    return { value: stored, isDefault: false };
  }
  return { value: detectBrowserTimezone(), isDefault: true };
};

export const TimezoneProvider = ({ children }: { children: ReactNode }) => {
  const [state, setState] = useState(getInitial);

  useEffect(() => {
    if (state.isDefault) {
      writeStoredTimezone(null);
    } else {
      writeStoredTimezone(state.value);
    }
  }, [state]);

  const setTimezone = useCallback((next: string | null) => {
    if (next == null) {
      setState({ value: detectBrowserTimezone(), isDefault: true });
      return;
    }
    setState({ value: next, isDefault: false });
  }, []);

  const value = useMemo<TimezoneContextValue>(
    () => ({
      timezone: state.value,
      isBrowserDefault: state.isDefault,
      setTimezone,
    }),
    [state, setTimezone]
  );

  return <TimezoneContext.Provider value={value}>{children}</TimezoneContext.Provider>;
};

export const useTimezone = (): TimezoneContextValue => {
  const context = useContext(TimezoneContext);
  if (!context) {
    throw new Error("useTimezone must be used within a TimezoneProvider");
  }
  return context;
};
