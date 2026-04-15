import { api } from "./client";
import type {
  AffectedVulnerabilitiesResponse,
  InventoryDeployment,
  InventoryEnvironment,
  InventoryItem,
  InventoryItemListResponse,
} from "../types";

export interface InventoryItemCreateInput {
  name: string;
  vendorSlug: string;
  productSlug: string;
  vendorName?: string | null;
  productName?: string | null;
  version: string;
  deployment: InventoryDeployment;
  environment: InventoryEnvironment;
  instanceCount: number;
  owner?: string | null;
  notes?: string | null;
}

export type InventoryItemUpdateInput = Partial<InventoryItemCreateInput>;

export async function fetchInventoryItems(): Promise<InventoryItemListResponse> {
  const response = await api.get<InventoryItemListResponse>("/v1/inventory");
  return response.data;
}

export async function fetchInventoryItem(itemId: string): Promise<InventoryItem> {
  const response = await api.get<InventoryItem>(`/v1/inventory/${itemId}`);
  return response.data;
}

export async function createInventoryItem(
  payload: InventoryItemCreateInput,
): Promise<InventoryItem> {
  const response = await api.post<InventoryItem>("/v1/inventory", payload);
  return response.data;
}

export async function updateInventoryItem(
  itemId: string,
  payload: InventoryItemUpdateInput,
): Promise<InventoryItem> {
  const response = await api.put<InventoryItem>(`/v1/inventory/${itemId}`, payload);
  return response.data;
}

export async function deleteInventoryItem(itemId: string): Promise<void> {
  await api.delete(`/v1/inventory/${itemId}`);
}

export async function fetchInventoryAffectedVulnerabilities(
  itemId: string,
  limit = 200,
): Promise<AffectedVulnerabilitiesResponse> {
  const response = await api.get<AffectedVulnerabilitiesResponse>(
    `/v1/inventory/${itemId}/affected-vulnerabilities`,
    { params: { limit } },
  );
  return response.data;
}
