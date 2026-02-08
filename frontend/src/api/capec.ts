import { api } from "./client";

export interface CAPECInfo {
  id: string;
  name: string;
  description: string;
  severity: string | null;
  likelihood: string | null;
  abstraction: string | null;
}

export interface CAPECFromCWEsResponse {
  capecs: Record<string, CAPECInfo>;
}

export interface CAPECBulkResponse {
  capecs: Record<string, CAPECInfo>;
}

export const getCapecFromCwes = async (cweIds: string[]): Promise<CAPECFromCWEsResponse> => {
  const response = await api.post<CAPECFromCWEsResponse>("/v1/capec/from-cwes", {
    cweIds,
  });
  return response.data;
};

export const getCapecBulk = async (capecIds: string[]): Promise<CAPECBulkResponse> => {
  const response = await api.post<CAPECBulkResponse>("/v1/capec/bulk", {
    capecIds,
  });
  return response.data;
};

export const getCapec = async (capecId: string): Promise<CAPECInfo> => {
  const response = await api.get<CAPECInfo>(`/v1/capec/${capecId}`);
  return response.data;
};
