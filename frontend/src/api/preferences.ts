import { api } from "./client";
import type { StoredUserPreferences, UserPreferences } from "../preferences/sync";

/** The signed-in user's preferences (OIDC only). */
export async function fetchUserPreferences(): Promise<StoredUserPreferences> {
  const response = await api.get<StoredUserPreferences>("/v1/auth/me/preferences");
  return response.data;
}

export async function saveUserPreferences(preferences: UserPreferences): Promise<StoredUserPreferences> {
  const response = await api.put<StoredUserPreferences>("/v1/auth/me/preferences", preferences);
  return response.data;
}
