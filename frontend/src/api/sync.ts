import { api } from "./client";
import type { SyncStatesResponse, TriggerSyncRequest, TriggerSyncResponse } from "../types";

export const fetchSyncStates = async (): Promise<SyncStatesResponse> => {
  const response = await api.get<SyncStatesResponse>("/v1/sync/states");
  return response.data;
};

export const triggerEuvdSync = async (initial: boolean = false): Promise<TriggerSyncResponse> => {
  const response = await api.post<TriggerSyncResponse>("/v1/sync/trigger/euvd", { initial } as TriggerSyncRequest);
  return response.data;
};

export const triggerNvdSync = async (initial: boolean = false): Promise<TriggerSyncResponse> => {
  const response = await api.post<TriggerSyncResponse>("/v1/sync/trigger/nvd", { initial } as TriggerSyncRequest);
  return response.data;
};

export const triggerCpeSync = async (initial: boolean = false): Promise<TriggerSyncResponse> => {
  const response = await api.post<TriggerSyncResponse>("/v1/sync/trigger/cpe", { initial } as TriggerSyncRequest);
  return response.data;
};

export const triggerKevSync = async (initial: boolean = false): Promise<TriggerSyncResponse> => {
  const response = await api.post<TriggerSyncResponse>("/v1/sync/trigger/kev", { initial } as TriggerSyncRequest);
  return response.data;
};

export const triggerCweSync = async (initial: boolean = false): Promise<TriggerSyncResponse> => {
  const response = await api.post<TriggerSyncResponse>("/v1/sync/trigger/cwe", { initial } as TriggerSyncRequest);
  return response.data;
};
