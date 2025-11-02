import { api } from "./client";
import {
  AIInvestigationResponse,
  AIProviderId,
  AIProviderInfo,
  PagedVulnerabilityResponse,
  VulnerabilityDetail,
  VulnerabilityPreview,
  VulnerabilityQuery,
} from "../types";

export const searchVulnerabilities = async (
  query: VulnerabilityQuery
): Promise<VulnerabilityPreview[]> => {
  const response = await api.post<VulnerabilityPreview[]>("/v1/vulnerabilities/search", query);
  return response.data;
};

export const getVulnerability = async (identifier: string): Promise<VulnerabilityDetail> => {
  const response = await api.get<VulnerabilityDetail>(`/v1/vulnerabilities/${encodeURIComponent(identifier)}`);
  return response.data;
};

export const listVulnerabilities = async (
  params: Partial<VulnerabilityQuery> & { limit?: number; offset?: number }
): Promise<PagedVulnerabilityResponse> => {
  const searchParams = new URLSearchParams();

  Object.entries(params).forEach(([key, value]) => {
    if (value === undefined || value === null) {
      return;
    }
    if (Array.isArray(value)) {
      value.forEach((item) => {
        if (item !== undefined && item !== null && item !== "") {
          const paramKey = key === "searchTerm" ? "search" : key;
          searchParams.append(paramKey, String(item));
        }
      });
      return;
    }
    if (typeof value === "boolean") {
      if (value) {
        const paramKey = key === "searchTerm" ? "search" : key;
        searchParams.set(paramKey, "true");
      }
      return;
    }
    if (value === "") {
      return;
    }
    const paramKey = key === "searchTerm" ? "search" : key;
    searchParams.set(paramKey, String(value));
  });

  const response = await api.get<PagedVulnerabilityResponse>("/v1/vulnerabilities", { params: searchParams });
  return response.data;
};

export const getAiProviders = async (): Promise<AIProviderInfo[]> => {
  const response = await api.get<AIProviderInfo[]>("/v1/vulnerabilities/ai/providers");
  return response.data;
};

export const requestAiInvestigation = async (
  identifier: string,
  provider: AIProviderId,
  language?: string | null
): Promise<AIInvestigationResponse> => {
  const payload: { provider: AIProviderId; language?: string | null } = { provider };
  if (language) {
    payload.language = language;
  }
  const response = await api.post<AIInvestigationResponse>(
    `/v1/vulnerabilities/${encodeURIComponent(identifier)}/ai-investigation`,
    payload
  );
  return response.data;
};
