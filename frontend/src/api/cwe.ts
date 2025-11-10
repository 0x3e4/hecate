import { api } from "./client";

export interface CWEInfo {
  id: string;
  name: string;
  description: string;
}

export interface CWEBulkResponse {
  cwes: Record<string, CWEInfo>;
}

export const getCweBulk = async (cweIds: string[]): Promise<CWEBulkResponse> => {
  const response = await api.post<CWEBulkResponse>("/v1/cwe/bulk", {
    cweIds,
  });
  return response.data;
};

export const getCwe = async (cweId: string): Promise<CWEInfo> => {
  const response = await api.get<CWEInfo>(`/v1/cwe/${cweId}`);
  return response.data;
};
