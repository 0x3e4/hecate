import { api } from "./client";
import {
  AIBatchInvestigationRequest,
  AIBatchInvestigationResponse,
  AIBatchInvestigationSubmitResponse,
  AIInvestigationResponse,
  AIInvestigationSubmitResponse,
  AIProviderId,
  AIProviderInfo,
  BatchAnalysisListResponse,
  DQLFieldAggregation,
  PagedVulnerabilityResponse,
  VulnerabilityDetail,
  VulnerabilityPreview,
  VulnerabilityQuery,
  VulnerabilityRefreshRequest,
  VulnerabilityRefreshResponse,
} from "../types";

const getAiAnalysisHeaders = (
  aiAnalysisPassword?: string | null
): Record<string, string> | undefined => {
  const password = aiAnalysisPassword?.trim();
  if (!password) {
    return undefined;
  }
  return { "X-AI-Analysis-Password": password };
};

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

export const getAiProviders = async (
  aiAnalysisPassword?: string | null
): Promise<AIProviderInfo[]> => {
  const response = await api.get<AIProviderInfo[]>("/v1/vulnerabilities/ai/providers", {
    headers: getAiAnalysisHeaders(aiAnalysisPassword),
  });
  return response.data;
};

export const requestAiInvestigation = async (
  identifier: string,
  provider: AIProviderId,
  language?: string | null,
  additionalContext?: string | null,
  aiAnalysisPassword?: string | null
): Promise<AIInvestigationSubmitResponse> => {
  const payload: { provider: AIProviderId; language?: string | null; additionalContext?: string | null } = { provider };
  if (language) {
    payload.language = language;
  }
  if (additionalContext) {
    payload.additionalContext = additionalContext;
  }
  const response = await api.post<AIInvestigationSubmitResponse>(
    `/v1/vulnerabilities/${encodeURIComponent(identifier)}/ai-investigation`,
    payload,
    {
      headers: getAiAnalysisHeaders(aiAnalysisPassword),
    }
  );
  return response.data;
};

export const requestBatchAiInvestigation = async (
  request: AIBatchInvestigationRequest,
  aiAnalysisPassword?: string | null
): Promise<AIBatchInvestigationSubmitResponse> => {
  const response = await api.post<AIBatchInvestigationSubmitResponse>(
    "/v1/vulnerabilities/ai-investigation/batch",
    request,
    {
      headers: getAiAnalysisHeaders(aiAnalysisPassword),
    }
  );
  return response.data;
};

export const listBatchAnalyses = async (
  params?: { limit?: number; offset?: number },
  aiAnalysisPassword?: string | null
): Promise<BatchAnalysisListResponse> => {
  const response = await api.get<BatchAnalysisListResponse>(
    "/v1/vulnerabilities/ai-investigation/batch",
    {
      params,
      headers: getAiAnalysisHeaders(aiAnalysisPassword),
    }
  );
  return response.data;
};

export interface SingleAnalysisItem {
  type: "single";
  vulnerability_id: string;
  title: string;
  provider: string;
  language: string;
  summary: string;
  timestamp: string;
  token_usage?: { inputTokens: number; outputTokens: number } | null;
}

export interface SingleAnalysisListResponse {
  items: SingleAnalysisItem[];
  total: number;
  limit: number;
  offset: number;
}

export const getBatchAnalysis = async (
  batchId: string,
  aiAnalysisPassword?: string | null
): Promise<AIBatchInvestigationResponse> => {
  const response = await api.get<AIBatchInvestigationResponse>(
    `/v1/vulnerabilities/ai-investigation/batch/${encodeURIComponent(batchId)}`,
    {
      headers: getAiAnalysisHeaders(aiAnalysisPassword),
    }
  );
  return response.data;
};

export const listSingleAiAnalyses = async (
  params?: { limit?: number; offset?: number },
  aiAnalysisPassword?: string | null
): Promise<SingleAnalysisListResponse> => {
  const response = await api.get<SingleAnalysisListResponse>(
    "/v1/vulnerabilities/ai-investigation/single",
    {
      params,
      headers: getAiAnalysisHeaders(aiAnalysisPassword),
    }
  );
  return response.data;
};

export const triggerVulnerabilityRefresh = async (
  payload: VulnerabilityRefreshRequest
): Promise<VulnerabilityRefreshResponse> => {
  const response = await api.post<VulnerabilityRefreshResponse>("/v1/vulnerabilities/refresh", payload);
  return response.data;
};

export const getFieldAggregation = async (
  fieldName: string,
  size: number = 10
): Promise<DQLFieldAggregation> => {
  const response = await api.get<DQLFieldAggregation>(
    `/v1/vulnerabilities/dql/fields/${encodeURIComponent(fieldName)}/aggregation`,
    { params: { size } }
  );
  return response.data;
};
