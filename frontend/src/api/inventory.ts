import { api } from "./client";
import type {
  AffectedVulnerabilitiesResponse,
  InventoryDeployment,
  InventoryEnvironment,
  InventoryHistoryResponse,
  InventoryItem,
  InventoryItemListResponse,
  InventorySystem,
  InventorySystemListResponse,
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
  eolProduct?: string | null;
  /** Inventory systems it runs on; unknown ids are dropped by the backend. */
  systemIds?: string[];
  /** Why it changed (ticket, server); stored in the history entry, not on the item. */
  changeNote?: string | null;
}

export type InventoryItemUpdateInput = Partial<InventoryItemCreateInput>;

export interface InventorySystemInput {
  name: string;
  kind?: InventorySystem["kind"];
  exposure?: InventorySystem["exposure"];
  environment?: string | null;
  owner?: string | null;
  notes?: string | null;
  groups?: string[];
}

export async function fetchInventorySystems(): Promise<InventorySystemListResponse> {
  const response = await api.get<InventorySystemListResponse>("/v1/inventory/systems");
  return response.data;
}

export async function createInventorySystem(payload: InventorySystemInput): Promise<InventorySystem> {
  const response = await api.post<InventorySystem>("/v1/inventory/systems", payload);
  return response.data;
}

/** Partial; null clears kind, exposure, environment, owner and notes. */
export async function updateInventorySystem(
  systemId: string,
  payload: Partial<InventorySystemInput>,
): Promise<InventorySystem> {
  const response = await api.put<InventorySystem>(`/v1/inventory/systems/${encodeURIComponent(systemId)}`, payload);
  return response.data;
}

export async function deleteInventorySystem(systemId: string): Promise<void> {
  await api.delete(`/v1/inventory/systems/${encodeURIComponent(systemId)}`);
}

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

export async function fetchInventoryHistory(limit = 20): Promise<InventoryHistoryResponse> {
  const response = await api.get<InventoryHistoryResponse>("/v1/inventory/history", {
    params: { limit },
  });
  return response.data;
}

export async function fetchInventoryItemHistory(
  itemId: string,
  limit = 50,
): Promise<InventoryHistoryResponse> {
  const response = await api.get<InventoryHistoryResponse>(`/v1/inventory/${itemId}/history`, {
    params: { limit },
  });
  return response.data;
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
