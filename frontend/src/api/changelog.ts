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

export const fetchChangelog = async (limit: number = 50, offset: number = 0): Promise<ChangelogResponse> => {
  const response = await api.get<ChangelogResponse>("/v1/changelog", {
    params: { limit, offset },
  });
  return response.data;
};
