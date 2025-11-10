import { api } from "./client";
import { IngestionLogResponse } from "../types";

export interface FetchAuditParams {
  job?: string;
  status?: string;
  limit?: number;
  offset?: number;
}

export const fetchIngestionLogs = async (params: FetchAuditParams = {}): Promise<IngestionLogResponse> => {
  const response = await api.get<IngestionLogResponse>("/v1/audit/ingestion", { params });
  return response.data;
};
