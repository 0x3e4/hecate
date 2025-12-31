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

export type AIProviderId = "openai" | "anthropic" | "gemini";

export interface AIProviderInfo {
  id: AIProviderId;
  label: string;
}

export interface AIInvestigationResponse {
  provider: AIProviderId;
  language: string;
  summary: string;
  generatedAt: string;
}

export interface AIAssessment {
  summary?: string;
  provider?: string;
  language?: string;
  generatedAt?: string;
  [key: string]: unknown;
}

export interface KnownExploitation {
  source?: string | null;
  vendorProject?: string | null;
  product?: string | null;
  vulnerabilityName?: string | null;
  dateAdded?: string | null;
  shortDescription?: string | null;
  requiredAction?: string | null;
  dueDate?: string | null;
  knownRansomwareCampaignUse?: string | null;
  notes?: string | null;
  catalogVersion?: string | null;
  dateReleased?: string | null;
}

export interface CpeMatch {
  criteria?: string | null;
  matchCriteriaId?: string | null;
  cpeName?: string | null;
  vulnerable?: boolean;
  part?: string | null;
  vendor?: string | null;
  vendorRaw?: string | null;
  product?: string | null;
  productRaw?: string | null;
  targetSw?: string | null;
  targetHw?: string | null;
  version?: string | null;
  versionStartIncluding?: string | null;
  versionStartExcluding?: string | null;
  versionEndIncluding?: string | null;
  versionEndExcluding?: string | null;
  versionTokens?: string[];
}

export interface CpeNode {
  operator?: string | null;
  negate?: boolean;
  matches?: CpeMatch[];
  nodes?: CpeNode[];
}

export interface CpeConfiguration {
  nodes: CpeNode[];
}

export interface ImpactedEntity {
  name: string;
  slug?: string | null;
}

export interface ImpactedProduct {
  vendor: ImpactedEntity;
  product: ImpactedEntity;
  versions: string[];
  vulnerable?: boolean | null;
  environments?: string[];
}

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
  vendors?: string[];
  products?: string[];
  productVersions?: string[];
  rejected?: boolean;
  assigner?: string | null;
  exploited?: boolean | null;
  exploitation?: KnownExploitation | null;
  published?: string | null;
  aliases?: string[];
  cwes?: string[];
  aiAssessment?: AIAssessment | null;
  cvssMetrics?: CvssMetrics | null;
  impactedProducts?: ImpactedProduct[];
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
  includeReserved?: boolean;
  exploitedOnly?: boolean;
  aiAnalysedOnly?: boolean;
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

export interface SourceEntry {
  source: string;
  url: string;
  ingested_at: string;
  raw?: Record<string, unknown> | null;
}

export interface VulnerabilityDetail extends VulnerabilityPreview {
  references?: string[];
  cwes?: string[];
  cpes?: string[];
  cpeConfigurations?: CpeConfiguration[];
  cpeVersionTokens?: string[];
  impactedProducts?: ImpactedProduct[];
  modified?: string | null;
  ingestedAt?: string | null;
  rawDocument?: Record<string, unknown> | null;
  productVersionIds?: string[];
  changeHistory?: VulnerabilityChangeEntry[];
  sources?: SourceEntry[];
}

export interface VulnerabilityRefreshRequest {
  vulnIds?: string[];
  sourceIds?: string[];
}

export type VulnerabilityRefreshStatus = {
  identifier: string;
  provider?: string | null;
  status: "inserted" | "updated" | "skipped" | "error";
  message?: string | null;
  changedFields?: number | null;
};

export interface VulnerabilityRefreshResponse {
  requested: string[];
  results: VulnerabilityRefreshStatus[];
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

export interface SavedSearch {
  id: string;
  name: string;
  queryParams: string;
  dqlQuery?: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface BackupRestoreSummary {
  dataset: "vulnerabilities" | "cpe";
  source?: string | null;
  inserted: number;
  updated: number;
  skipped: number;
  total: number;
}

export interface DQLFieldValueBucket {
  value: string;
  count: number;
}

export interface DQLFieldAggregation {
  field: string;
  totalDocs: number;
  buckets: DQLFieldValueBucket[];
}

export interface SyncState {
  jobName: string;
  label: string;
  status: string; // running, completed, failed, cancelled, idle
  startedAt?: string | null;
  finishedAt?: string | null;
  durationSeconds?: number | null;
  nextRun?: string | null;
  lastResult?: Record<string, unknown> | null;
  error?: string | null;
}

export interface SyncStatesResponse {
  syncs: SyncState[];
}

export interface TriggerSyncRequest {
  initial?: boolean;
}

export interface TriggerSyncResponse {
  success: boolean;
  message: string;
  jobName: string;
}
