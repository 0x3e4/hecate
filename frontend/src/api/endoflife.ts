import { api } from "./client";
import type { EolProductListResponse, EolStatus } from "../types";

/** Fetch the endoflife.date product catalog (optionally filtered) for the link picker. */
export async function fetchEolProducts(search?: string): Promise<EolProductListResponse> {
  const response = await api.get<EolProductListResponse>("/v1/inventory/eol/products", {
    params: search ? { search } : undefined,
  });
  return response.data;
}

/** Fetch the resolved endoflife.date support/EOL status for an inventory item. */
export async function fetchInventoryEol(itemId: string): Promise<EolStatus> {
  const response = await api.get<EolStatus>(`/v1/inventory/${itemId}/eol`);
  return response.data;
}
