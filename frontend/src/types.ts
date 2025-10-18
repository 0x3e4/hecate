export interface VulnerabilityPreview {
  cveId: string;
  sourceId?: string | null;
  source?: string | null;
  title: string;
  summary: string;
  severity?: string | null;
  cvssScore?: number | null;
  epssScore?: number | null;
  epssPercentile?: number | null;
  vendors?: string[];
  products?: string[];
  assigner?: string | null;
  exploited?: boolean | null;
  published?: string | null;
  aliases?: string[];
  ghsaIds?: string[];
  cwes?: string[];
  aiAssessment?: Record<string, unknown> | null;
}

export interface VulnerabilityQuery {
  searchTerm: string | null;
  cpeFilters?: string[];
  vendorFilters?: string[];
  productFilters?: string[];
  severity?: string[];
  limit?: number;
}

export interface CpeEntry {
  cpeName: string;
  title?: string | null;
  vendor?: string | null;
  product?: string | null;
  version?: string | null;
  deprecated?: boolean;
}

export interface CpeQueryResponse {
  total: number;
  items: CpeEntry[];
}

export interface CpeValueListResponse {
  total: number;
  items: string[];
}

export interface IngestionLogEntry {
  id: string;
  jobName: string;
  status: string;
  startedAt: string;
  finishedAt?: string | null;
  durationSeconds?: number | null;
  metadata?: Record<string, unknown> | null;
  result?: Record<string, unknown> | null;
  error?: string | null;
  overdue?: boolean;
  overdueReason?: string | null;
}

export interface IngestionLogResponse {
  total: number;
  items: IngestionLogEntry[];
}

export interface VulnerabilityDetail extends VulnerabilityPreview {
  references?: string[];
  cwes?: string[];
  cpes?: string[];
  modified?: string | null;
  ingestedAt?: string | null;
  rawDocument?: Record<string, unknown> | null;
}

export interface PagedVulnerabilityResponse {
  total: number;
  items: VulnerabilityPreview[];
}
