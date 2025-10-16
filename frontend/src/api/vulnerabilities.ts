import { api } from "./client";
import { VulnerabilityPreview, VulnerabilityQuery } from "../types";

export const searchVulnerabilities = async (
  query: VulnerabilityQuery
): Promise<VulnerabilityPreview[]> => {
  const response = await api.post<VulnerabilityPreview[]>("/v1/vulnerabilities/search", query);
  return response.data;
};
