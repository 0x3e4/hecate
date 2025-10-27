export interface CvssVectorData {
  version?: string | null;
  vectorString?: string | null;
  baseScore?: number | null;
  baseSeverity?: string | null;
  attackVector?: string | null;
  attackComplexity?: string | null;
  privilegesRequired?: string | null;
  userInteraction?: string | null;
  scope?: string | null;
  confidentialityImpact?: string | null;
  integrityImpact?: string | null;
  availabilityImpact?: string | null;
  [key: string]: unknown;
}

export interface CvssMetric {
  source?: string | null;
  type?: string | null;
  exploitabilityScore?: number | null;
  impactScore?: number | null;
  baseSeverity?: string | null;
  baseScore?: number | null;
  vectorString?: string | null;
  cvssData?: CvssVectorData | null;
  data?: CvssVectorData | null;
  version?: string | null;
  [key: string]: unknown;
}

export type CvssMetrics = Record<string, CvssMetric[]>;

export interface VulnerabilityChangeField {
  name: string;
  previous?: unknown | null;
  current?: unknown | null;
}

export interface VulnerabilityChangeEntry {
  changedAt: string;
  jobName: string;
  jobLabel?: string | null;
  changeType: "insert" | "update";
  fields: VulnerabilityChangeField[];
  snapshot?: Record<string, unknown> | null;
  metadata?: Record<string, unknown> | null;
}

export interface VulnerabilityPreview {
  vulnId: string;
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
  productVersions?: string[];
  rejected?: boolean;
  assigner?: string | null;
  exploited?: boolean | null;
  published?: string | null;
  aliases?: string[];
  ghsaIds?: string[];
  cwes?: string[];
  aiAssessment?: Record<string, unknown> | null;
  cvssMetrics?: CvssMetrics | null;
}

export interface VulnerabilityQuery {
  searchTerm: string | null;
  dqlQuery?: string | null;
  cpeFilters?: string[];
  vendorFilters?: string[];
  productFilters?: string[];
  vendorSlugs?: string[];
  productSlugs?: string[];
  versionFilters?: string[];
  severity?: string[];
  includeRejected?: boolean;
  limit?: number;
}

export interface IngestionLogEntry {
  id: string;
  jobName: string;
  status: string;
  startedAt: string;
  finishedAt?: string | null;
  durationSeconds?: number | null;
  metadata?: Record<string, unknown> | null;
  progress?: Record<string, unknown> | null;
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
  productVersionIds?: string[];
  changeHistory?: VulnerabilityChangeEntry[];
}

export interface PagedVulnerabilityResponse {
  total: number;
  items: VulnerabilityPreview[];
}

export interface CatalogVendor {
  slug: string;
  name: string;
  aliases: string[];
}

export interface CatalogVendorListResponse {
  total: number;
  items: CatalogVendor[];
}

export interface CatalogProduct {
  slug: string;
  name: string;
  vendorSlugs: string[];
  aliases: string[];
}

export interface CatalogProductListResponse {
  total: number;
  items: CatalogProduct[];
}

export interface CatalogVersion {
  id: string;
  value: string;
  productSlug: string;
}

export interface CatalogVersionListResponse {
  total: number;
  items: CatalogVersion[];
}

export interface BackupRestoreSummary {
  dataset: "vulnerabilities" | "cpe";
  source?: string | null;
  inserted: number;
  updated: number;
  skipped: number;
  total: number;
}
