import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode
} from "react";

import {
  createSavedSearch as apiCreateSavedSearch,
  deleteSavedSearch as apiDeleteSavedSearch,
  listSavedSearches as apiListSavedSearches,
  updateSavedSearch as apiUpdateSavedSearch,
  type SavedSearchInput
} from "../api/savedSearches";
import type { SavedSearch } from "../types";

interface SavedSearchesContextValue {
  savedSearches: SavedSearch[];
  loading: boolean;
  refresh: () => Promise<void>;
  createSavedSearch: (input: SavedSearchInput) => Promise<SavedSearch>;
  updateSavedSearch: (id: string, input: Partial<SavedSearchInput>) => Promise<SavedSearch>;
  removeSavedSearch: (id: string) => Promise<void>;
}

const SavedSearchesContext = createContext<SavedSearchesContextValue | undefined>(undefined);

export const SavedSearchesProvider = ({ children }: { children: ReactNode }) => {
  const [savedSearches, setSavedSearches] = useState<SavedSearch[]>([]);
  const [loading, setLoading] = useState<boolean>(true);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const data = await apiListSavedSearches();
      data.sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: "base" }));
      setSavedSearches(data);
    } catch (error) {
      console.error("Failed to load saved searches", error);
      setSavedSearches([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const createSavedSearch = useCallback(async (input: SavedSearchInput) => {
    const trimmedName = input.name.trim();
    const trimmedQueryParams = input.queryParams.trim().replace(/^\?/, "");
    const trimmedDql = input.dqlQuery?.trim();
    const created = await apiCreateSavedSearch({
      name: trimmedName,
      queryParams: trimmedQueryParams,
      dqlQuery: trimmedDql && trimmedDql.length > 0 ? trimmedDql : undefined
    });
    setSavedSearches((current) => {
      const next = [...current, created];
      next.sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: "base" }));
      return next;
    });
    return created;
  }, []);

  const updateSavedSearch = useCallback(async (id: string, input: Partial<SavedSearchInput>) => {
    const updated = await apiUpdateSavedSearch(id, input);
    setSavedSearches((current) => {
      const next = current.map((item) => (item.id === id ? updated : item));
      next.sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: "base" }));
      return next;
    });
    return updated;
  }, []);

  const removeSavedSearch = useCallback(async (id: string) => {
    await apiDeleteSavedSearch(id);
    setSavedSearches((current) => current.filter((item) => item.id !== id));
  }, []);

  const value = useMemo(
    () => ({
      savedSearches,
      loading,
      refresh,
      createSavedSearch,
      updateSavedSearch,
      removeSavedSearch
    }),
    [savedSearches, loading, refresh, createSavedSearch, updateSavedSearch, removeSavedSearch]
  );

  return <SavedSearchesContext.Provider value={value}>{children}</SavedSearchesContext.Provider>;
};

export const useSavedSearches = (): SavedSearchesContextValue => {
  const context = useContext(SavedSearchesContext);
  if (!context) {
    throw new Error("useSavedSearches must be used within a SavedSearchesProvider");
  }
  return context;
};
