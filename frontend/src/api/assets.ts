import { api } from "./client";
import {
  CatalogProductListResponse,
  CatalogVendorListResponse,
  CatalogVersionListResponse,
} from "../types";

export const fetchVendors = async (
  keyword: string | null,
  limit = 25,
): Promise<CatalogVendorListResponse> => {
  const params: Record<string, unknown> = { limit };
  if (keyword) {
    params.keyword = keyword;
  }
  const response = await api.get<CatalogVendorListResponse>("/v1/assets/vendors", { params });
  return response.data;
};

export const fetchProducts = async (
  vendorSlugs: string[],
  keyword: string | null,
  limit = 25,
): Promise<CatalogProductListResponse> => {
  const params = new URLSearchParams();
  params.set("limit", String(limit));
  vendorSlugs.forEach((slug) => params.append("vendorSlugs", slug));
  if (keyword) {
    params.set("keyword", keyword);
  }
  const response = await api.get<CatalogProductListResponse>("/v1/assets/products", { params });
  return response.data;
};

export const fetchVersions = async (
  productSlug: string,
  keyword: string | null,
  limit = 25,
): Promise<CatalogVersionListResponse> => {
  const params = new URLSearchParams();
  params.set("productSlug", productSlug);
  params.set("limit", String(limit));
  if (keyword) {
    params.set("keyword", keyword);
  }
  const response = await api.get<CatalogVersionListResponse>("/v1/assets/versions", { params });
  return response.data;
};
