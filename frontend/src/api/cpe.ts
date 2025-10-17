import { api } from "./client";
import { CpeQueryResponse, CpeValueListResponse } from "../types";

export interface FetchCpeParams {
  keyword?: string | null;
  vendor?: string | null;
  product?: string | null;
  limit?: number;
  offset?: number;
}

export const fetchCpeEntries = async (params: FetchCpeParams = {}): Promise<CpeQueryResponse> => {
  const sanitized: Record<string, unknown> = {};
  Object.entries(params).forEach(([key, value]) => {
    if (value === undefined || value === null || value === "") {
      return;
    }
    sanitized[key] = value;
  });

  const response = await api.get<CpeQueryResponse>("/v1/cpe/entries", { params: sanitized });
  return response.data;
};

export const fetchCpeVendors = async (
  keyword: string | null,
  limit = 25
): Promise<CpeValueListResponse> => {
  const params: Record<string, unknown> = { limit };
  if (keyword) {
    params.keyword = keyword;
  }
  const response = await api.get<CpeValueListResponse>("/v1/cpe/vendors", { params });
  return response.data;
};

export const fetchCpeProducts = async (
  vendors: string[],
  keyword: string | null,
  limit = 25
): Promise<CpeValueListResponse> => {
  const params = new URLSearchParams();
  params.set("limit", String(limit));
  vendors.forEach((vendor) => params.append("vendors", vendor));
  if (keyword) {
    params.set("keyword", keyword);
  }
  const response = await api.get<CpeValueListResponse>("/v1/cpe/products", { params });
  return response.data;
};
