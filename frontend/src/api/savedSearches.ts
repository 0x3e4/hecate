import type { SavedSearch } from "../types";
import { api } from "./client";

export interface SavedSearchInput {
  name: string;
  queryParams: string;
  dqlQuery?: string | null;
}

export const listSavedSearches = async (): Promise<SavedSearch[]> => {
  const response = await api.get<SavedSearch[]>("/v1/saved-searches");
  return response.data;
};

export const createSavedSearch = async (payload: SavedSearchInput): Promise<SavedSearch> => {
  const response = await api.post<SavedSearch>("/v1/saved-searches", payload);
  return response.data;
};

export const updateSavedSearch = async (id: string, payload: Partial<SavedSearchInput>): Promise<SavedSearch> => {
  const response = await api.put<SavedSearch>(`/v1/saved-searches/${id}`, payload);
  return response.data;
};

export const deleteSavedSearch = async (id: string): Promise<void> => {
  await api.delete(`/v1/saved-searches/${id}`);
};
