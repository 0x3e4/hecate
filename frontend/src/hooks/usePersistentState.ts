import { useEffect, useState } from "react";

const SYNC_EVENT = "hecate:persistent-state";

export const usePersistentState = <T>(key: string, defaultValue: T): [T, (value: T) => void] => {
  const [value, setValue] = useState<T>(() => {
    if (typeof window === "undefined") {
      return defaultValue;
    }
    try {
      const stored = window.localStorage.getItem(key);
      if (stored != null) {
        return JSON.parse(stored) as T;
      }
    } catch (error) {
      console.warn("Failed to read persistent state", error);
    }
    return defaultValue;
  });

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }
    try {
      window.localStorage.setItem(key, JSON.stringify(value));
      window.dispatchEvent(new CustomEvent(SYNC_EVENT, { detail: { key } }));
    } catch (error) {
      console.warn("Failed to persist state", error);
    }
  }, [key, value]);

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }
    const resync = () => {
      try {
        const stored = window.localStorage.getItem(key);
        const next = stored != null ? (JSON.parse(stored) as T) : defaultValue;
        setValue((prev) => (JSON.stringify(prev) === JSON.stringify(next) ? prev : next));
      } catch (error) {
        console.warn("Failed to resync persistent state", error);
      }
    };
    const onCustom = (e: Event) => {
      const detail = (e as CustomEvent<{ key: string }>).detail;
      if (detail?.key === key) resync();
    };
    const onStorage = (e: StorageEvent) => {
      if (e.key === key) resync();
    };
    window.addEventListener(SYNC_EVENT, onCustom);
    window.addEventListener("storage", onStorage);
    return () => {
      window.removeEventListener(SYNC_EVENT, onCustom);
      window.removeEventListener("storage", onStorage);
    };
  }, [key, defaultValue]);

  return [value, setValue];
};
