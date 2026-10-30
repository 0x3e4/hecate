import type { ApiToken, ApiTokenCreated, ApiTokenScope } from "../types";

import { api } from "./client";
import { getAdminPassword } from "./writeAuth";

// The token list is the one read behind the admin password, and the request
// interceptor attaches that password to writes only.
const adminHeaders = () => {
  const password = getAdminPassword();
  return password ? { "X-System-Password": password } : undefined;
};

export const fetchApiTokens = async (): Promise<ApiToken[]> => {
  const response = await api.get<{ items: ApiToken[] }>("/v1/api-tokens", { headers: adminHeaders() });
  return response.data.items;
};

export const createApiToken = async (payload: {
  name: string;
  scopes: ApiTokenScope[];
  expiresInDays: number | null;
}): Promise<ApiTokenCreated> => {
  const response = await api.post<ApiTokenCreated>("/v1/api-tokens", payload);
  return response.data;
};

export const revokeApiToken = async (tokenId: string): Promise<void> => {
  await api.delete(`/v1/api-tokens/${encodeURIComponent(tokenId)}`);
};
