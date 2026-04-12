export const TIMEZONE_STORAGE_KEY = "hecate.ui_timezone";

export const detectBrowserTimezone = (): string => {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  } catch {
    return "UTC";
  }
};

const isValidTimezone = (value: string): boolean => {
  try {
    new Intl.DateTimeFormat("en-US", { timeZone: value });
    return true;
  } catch {
    return false;
  }
};

export const readStoredTimezone = (): string | null => {
  if (typeof window === "undefined") {
    return null;
  }
  try {
    const raw = window.localStorage.getItem(TIMEZONE_STORAGE_KEY);
    if (raw == null) {
      return null;
    }
    let candidate: unknown = raw;
    try {
      candidate = JSON.parse(raw);
    } catch {
      candidate = raw;
    }
    if (typeof candidate !== "string" || !candidate) {
      return null;
    }
    return isValidTimezone(candidate) ? candidate : null;
  } catch (error) {
    console.warn("Failed to read UI timezone from localStorage", error);
    return null;
  }
};

export const writeStoredTimezone = (timezone: string | null): void => {
  if (typeof window === "undefined") {
    return;
  }
  try {
    if (timezone == null) {
      window.localStorage.removeItem(TIMEZONE_STORAGE_KEY);
      return;
    }
    window.localStorage.setItem(TIMEZONE_STORAGE_KEY, JSON.stringify(timezone));
  } catch (error) {
    console.warn("Failed to write UI timezone to localStorage", error);
  }
};

export const getCurrentTimezone = (): string => {
  return readStoredTimezone() ?? detectBrowserTimezone();
};

export const listSupportedTimezones = (): string[] => {
  const intl = Intl as unknown as { supportedValuesOf?: (key: string) => string[] };
  if (typeof intl.supportedValuesOf === "function") {
    try {
      return intl.supportedValuesOf("timeZone");
    } catch {
      // fall through
    }
  }
  return ["UTC"];
};
