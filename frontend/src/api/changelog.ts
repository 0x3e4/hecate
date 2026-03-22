import { api } from "./client";

export interface ChangeHistoryField {
  name: string;
  previous: any;
  current: any;
}

export interface LatestChange {
  changedAt: string;
  changeType: string;
  jobName: string;
  jobLabel: string | null;
  fields: ChangeHistoryField[];
}

export interface ChangelogEntry {
  vulnId: string;
  title: string;
  source: string;
  changeType: "created" | "updated";
  timestamp: string;
  cvssScore?: number;
  severity?: string;
  latestChange?: LatestChange;
}

export interface ChangelogResponse {
  entries: ChangelogEntry[];
  total: number;
}

export const fetchChangelog = async (
  limit: number = 50,
  offset: number = 0,
  fromDate?: string,
  toDate?: string,
  source?: string,
): Promise<ChangelogResponse> => {
  const params: Record<string, string | number> = { limit, offset };
  if (fromDate) params.fromDate = fromDate;
  if (toDate) params.toDate = toDate;
  if (source) params.source = source;
  const response = await api.get<ChangelogResponse>("/v1/changelog", { params });
  return response.data;
};
