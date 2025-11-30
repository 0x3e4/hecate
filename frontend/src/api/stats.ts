import { api } from "./client";

export interface TermsBucket {
  key: string;
  doc_count: number;
}

export interface TimelinePoint {
  key: string;
  count: number;
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
