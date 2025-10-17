import { api } from "./client";

export interface StatsResponse {
  vulnerabilities: {
    total: number;
    by_source: Array<{ key: string; doc_count: number }>;
    top_vendors: Array<{ key: string; doc_count: number }>;
    top_products: Array<{ key: string; doc_count: number }>;
  };
  cpe: {
    total: number;
    vendors: number;
    products: number;
  };
}

export const fetchStatsOverview = async (): Promise<StatsResponse> => {
  const response = await api.get<StatsResponse>("/v1/stats/overview");
  return response.data;
};
