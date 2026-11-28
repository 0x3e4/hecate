import { api } from "./client";
import type {
  AffectedVulnerabilitiesResponse,
  InventoryDeployment,
  InventoryEnvironment,
  InventoryHistoryEntry,
  InventoryHistoryResponse,
  InventoryItem,
  InventoryItemListResponse,
  InventoryListSource,
  InventoryListSourceInput,
  InventoryListSourcePullResult,
  InventorySystem,
  InventorySystemImportResult,
  InventorySystemListFormat,
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

/** Apply a server list (docs/guide/inventory.md#server-lists); dryRun only reports. */
export async function importInventorySystemList(payload: {
  content: string;
  format?: InventorySystemListFormat | null;
  source: string;
  mode: "merge" | "replace";
  dryRun?: boolean;
  force?: boolean;
}): Promise<InventorySystemImportResult> {
  const response = await api.post<InventorySystemImportResult>("/v1/inventory/systems/import", payload);
  return response.data;
}

/** Server lists Hecate fetches itself; admin only (System → Data). */
export async function fetchInventoryListSources(): Promise<{ items: InventoryListSource[]; allowPrivateHosts: boolean }> {
  const response = await api.get<{ items: InventoryListSource[]; allowPrivateHosts: boolean }>("/v1/inventory/systems/sources");
  return response.data;
}

export async function createInventoryListSource(payload: InventoryListSourceInput): Promise<InventoryListSource> {
  const response = await api.post<InventoryListSource>("/v1/inventory/systems/sources", payload);
  return response.data;
}

export async function updateInventoryListSource(id: string, payload: InventoryListSourceInput): Promise<InventoryListSource> {
  const response = await api.put<InventoryListSource>(`/v1/inventory/systems/sources/${encodeURIComponent(id)}`, payload);
  return response.data;
}

export async function deleteInventoryListSource(id: string): Promise<void> {
  await api.delete(`/v1/inventory/systems/sources/${encodeURIComponent(id)}`);
}

/** Fetch now; dryRun only reports. A failed fetch resolves with ok: false. */
export async function pullInventoryListSource(
  id: string,
  options: { dryRun?: boolean; force?: boolean } = {},
): Promise<InventoryListSourcePullResult> {
  const response = await api.post<InventoryListSourcePullResult>(
    `/v1/inventory/systems/sources/${encodeURIComponent(id)}/pull`,
    { dryRun: options.dryRun ?? false, force: options.force ?? false },
  );
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

/** Correct the note of a history entry ("" removes it); the recorded changes stay. */
export async function updateInventoryHistoryNote(
  entryId: string,
  note: string | null,
): Promise<InventoryHistoryEntry> {
  const response = await api.patch<InventoryHistoryEntry>(
    `/v1/inventory/history/${encodeURIComponent(entryId)}`,
    { note },
  );
  return response.data;
}

export async function deleteInventoryHistoryEntry(entryId: string): Promise<void> {
  await api.delete(`/v1/inventory/history/${encodeURIComponent(entryId)}`);
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
