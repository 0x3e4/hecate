import { api } from "./client";
import { VulnerabilityDetail, VulnerabilityPreview, VulnerabilityQuery } from "../types";

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
