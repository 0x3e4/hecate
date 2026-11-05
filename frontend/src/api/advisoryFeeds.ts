import type { FeedKind } from "./cert";
import { api } from "./client";

export interface AdvisoryFeed {
  /** `null` for a feed from `.env`, which the UI cannot change. */
  id: string | null;
  name: string;
  /** Credentials in the URL come back masked as `***`. */
  url: string;
  kind: FeedKind;
  origin: "env" | "ui";
  enabled: boolean;
  createdAt: string | null;
  updatedAt: string | null;
}

export interface AdvisoryFeedList {
  items: AdvisoryFeed[];
  syncEnabled: boolean;
}

export interface AdvisoryFeedInput {
  name?: string;
  url?: string;
  kind?: FeedKind;
  enabled?: boolean;
}

export const fetchAdvisoryFeeds = async (): Promise<AdvisoryFeedList> => {
  const response = await api.get<AdvisoryFeedList>("/v1/advisory-feeds");
  return response.data;
};

export const createAdvisoryFeed = async (payload: Required<Pick<AdvisoryFeedInput, "name" | "url" | "kind">>): Promise<AdvisoryFeed> => {
  const response = await api.post<AdvisoryFeed>("/v1/advisory-feeds", payload);
  return response.data;
};

export const updateAdvisoryFeed = async (id: string, payload: AdvisoryFeedInput): Promise<AdvisoryFeed> => {
  const response = await api.put<AdvisoryFeed>(`/v1/advisory-feeds/${encodeURIComponent(id)}`, payload);
  return response.data;
};

export const deleteAdvisoryFeed = async (id: string): Promise<void> => {
  await api.delete(`/v1/advisory-feeds/${encodeURIComponent(id)}`);
};
