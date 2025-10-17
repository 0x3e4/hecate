import { useEffect, useState } from "react";

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
    } catch (error) {
      console.warn("Failed to persist state", error);
    }
  }, [key, value]);

  return [value, setValue];
};
