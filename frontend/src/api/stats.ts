import { api } from "./client";
import type { FeedKind } from "./cert";
import type { TimelineInterval, TimelineRange, TimelineSeries } from "../utils/timelineRange";

export interface TermsBucket {
  key: string;
  doc_count: number;
}

export interface TimelinePoint {
  key: string;
  count: number;
  timestamp: number;
}

/** A catalogue vendor among those most vulnerabilities name (`vendorSlugs`). */
export interface CatalogRankedVendor {
  slug: string;
  name: string;
  aliases: string[];
  vulnerabilityCount: number;
  /** Catalogue products listing this vendor; null when the lookup failed. */
  productCount: number | null;
  inCatalog: boolean;
}

/** A catalogue product among those most vulnerabilities name (`productSlugs`). */
export interface CatalogRankedProduct {
  slug: string;
  name: string;
  aliases: string[];
  vulnerabilityCount: number;
  /** Known versions in the catalogue; null when the lookup failed. */
  versionCount: number | null;
  vendor: { slug: string; name: string } | null;
  inCatalog: boolean;
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
    topVendors: CatalogRankedVendor[];
    topProducts: CatalogRankedProduct[];
  };
}

export const fetchStatsOverview = async (): Promise<StatsResponse> => {
  const response = await api.get<StatsResponse>("/v1/stats/overview");
  return response.data;
};

/**
 * Publications per bucket (GET /v1/stats/timeline). Buckets follow `tz`; `interval`
 * defaults to `auto` (day up to 120 days, week up to ~3 years, else month).
 */
export const fetchTimeline = async (
  range: TimelineRange,
  tz: string,
  { interval = "auto", signal }: { interval?: TimelineInterval | "auto"; signal?: AbortSignal } = {}
): Promise<TimelineSeries> => {
  const params: Record<string, string> = { interval, tz };
  if (range.from) params.from = range.from;
  if (range.to) params.to = range.to;
  const response = await api.get<TimelineSeries>("/v1/stats/timeline", { params, signal });
  return response.data;
};

export interface SlugBucket {
  slug: string;
  name: string;
  doc_count: number;
  inventoryMatch?: boolean;
}

export interface ProductBucket extends SlugBucket {
  vendorSlug: string;
  vendorName: string;
}

export interface TodayCve {
  vulnId: string;
  title: string;
  severity: string;
  aliases: string[];
  vendorSlugs?: string[];
  productSlugs?: string[];
  inventoryMatchIds?: string[];
  /** Latest scan whose SBOM ships a package at a version this CVE affects (backend-checked). */
  sbomScanId?: string | null;
}

export interface TodaySummaryResponse {
  total: number;
  todayDate: string;
  vendors: SlugBucket[];
  products: ProductBucket[];
  severities: TermsBucket[];
  cves: TodayCve[];
}

export interface NamedSlug {
  slug: string;
  name: string;
}

export interface CertMention {
  name: string;
  kind: FeedKind;
  title: string | null;
  url: string | null;
}

export interface AttentionItem extends TodayCve {
  kevListed: boolean;
  sources: CertMention[];
  cvssScore: number | null;
  epssScore: number | null;
  dateAdded: string | null;
  dueDate: string | null;
  ransomware: boolean;
  vendors: NamedSlug[];
  products: NamedSlug[];
}

export interface AttentionResponse {
  since: string;
  days: number;
  total: number;
  items: AttentionItem[];
}

export const fetchAttention = async (tz?: string): Promise<AttentionResponse> => {
  const response = await api.get<AttentionResponse>("/v1/stats/attention", { params: tz ? { tz } : {} });
  return response.data;
};

export const fetchTodaySummary = async (date?: string, tz?: string): Promise<TodaySummaryResponse> => {
  const params: Record<string, string> = {};
  if (date) params.date = date;
  if (tz) params.tz = tz;
  const response = await api.get<TodaySummaryResponse>("/v1/stats/today", { params });
  return response.data;
};
