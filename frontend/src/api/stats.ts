import { api } from "./client";

export interface TermsBucket {
  key: string;
  doc_count: number;
}

export interface TimelinePoint {
  key: string;
  count: number;
  timestamp: number;
}

export interface CatalogSample {
  slug: string;
  name: string;
  aliases: string[];
}

export interface StatsResponse {
  vulnerabilities: {
    total: number;
    sources: TermsBucket[];
    severities: TermsBucket[];
    topVendors: TermsBucket[];
    topProducts: TermsBucket[];
    topCwes: TermsBucket[];
    epssRanges: TermsBucket[];
    timeline: TimelinePoint[];
    timelineSummary: TimelinePoint[];
    topAssigners: TermsBucket[];
    exploitedCount: number;
    referenceDomains: TermsBucket[];
  };
  assets: {
    vendorTotal: number;
    productTotal: number;
    versionTotal: number;
    sampleVendors: CatalogSample[];
    sampleProducts: CatalogSample[];
  };
}

export const fetchStatsOverview = async (): Promise<StatsResponse> => {
  const response = await api.get<StatsResponse>("/v1/stats/overview");
  return response.data;
};

export interface SlugBucket {
  slug: string;
  name: string;
  doc_count: number;
}

export interface TodayCve {
  vulnId: string;
  title: string;
  severity: string;
}

export interface TodaySummaryResponse {
  total: number;
  topVendors: SlugBucket[];
  topProducts: SlugBucket[];
  severities: TermsBucket[];
  cves: TodayCve[];
}

export const fetchTodaySummary = async (): Promise<TodaySummaryResponse> => {
  const response = await api.get<TodaySummaryResponse>("/v1/stats/today");
  return response.data;
};
