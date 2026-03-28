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

export interface AIInvestigationSubmitResponse {
  status: string;
  vulnerabilityId: string;
}

export interface AIBatchInvestigationSubmitResponse {
  status: string;
  vulnerabilityIds: string[];
}

export interface AIAssessment {
  summary?: string;
  provider?: string;
  language?: string;
  generatedAt?: string;
  tokenUsage?: { inputTokens: number; outputTokens: number } | null;
  [key: string]: unknown;
}

export interface AIBatchInvestigationRequest {
  vulnerabilityIds: string[];
  provider: AIProviderId;
  language?: string | null;
  additionalContext?: string | null;
}

export interface AIBatchInvestigationResponse {
  provider: AIProviderId;
  language: string;
  summary: string;
  individualSummaries: Record<string, string>;
  generatedAt: string;
  vulnerabilityCount: number;
  tokenUsage?: { inputTokens: number; outputTokens: number } | null;
}

export interface BatchAnalysisItem {
  batchId: string;
  vulnerabilityIds: string[];
  provider: string;
  language: string;
  summary: string;
  individualSummaries: Record<string, string>;
  additionalContext?: string | null;
  vulnerabilityCount: number;
  generatedAt: string;
  tokenUsage?: { inputTokens: number; outputTokens: number } | null;
}

export interface BatchAnalysisListResponse {
  items: BatchAnalysisItem[];
  total: number;
  limit: number;
  offset: number;
}

export interface BatchAnalysisReference {
  batchId: string;
  timestamp: string;
  provider: string;
  summaryExcerpt: string;
  summary?: string;
  language?: string;
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
  aiAssessments?: AIAssessment[];
  cvssMetrics?: CvssMetrics | null;
  impactedProducts?: ImpactedProduct[];
  sourceIds?: string[];
  batchAnalyses?: BatchAnalysisReference[];
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

export type RefreshSourceType = "NVD" | "EUVD" | "CIRCL" | "GHSA";

export interface VulnerabilityRefreshRequest {
  vulnIds?: string[];
  sourceIds?: string[];
  source?: RefreshSourceType;
}

export type VulnerabilityRefreshStatus = {
  identifier: string;
  provider?: string | null;
  status: "inserted" | "updated" | "skipped" | "error";
  message?: string | null;
  changedFields?: number | null;
  resolvedId?: string | null;
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
  dataset: "vulnerabilities" | "saved_searches";
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

export interface ResyncResponse {
  deleted: boolean;
  refresh: VulnerabilityRefreshResponse | null;
  message: string;
}

// --- SCA Scanning ---

export interface ScanSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  negligible: number;
  unknown: number;
  total: number;
}

export interface ScanTarget {
  id: string;
  type: "container_image" | "source_repo";
  name: string;
  registry?: string | null;
  repositoryUrl?: string | null;
  description?: string | null;
  tags?: string[];
  createdAt: string;
  updatedAt: string;
  lastScanAt?: string | null;
  scanCount: number;
  latestSummary?: ScanSummary | null;
  latestScanId?: string | null;
  hasRunningScan?: boolean;
  autoScan?: boolean;
  scanners?: string[];
}

export interface ScanTargetListResponse {
  total: number;
  items: ScanTarget[];
}

export interface Scan {
  id: string;
  targetId: string;
  targetName?: string | null;
  scanners: string[];
  status: "pending" | "running" | "completed" | "failed";
  source: "ci_cd" | "manual";
  imageRef?: string | null;
  commitSha?: string | null;
  branch?: string | null;
  pipelineUrl?: string | null;
  startedAt: string;
  finishedAt?: string | null;
  durationSeconds?: number | null;
  summary: ScanSummary;
  sbomComponentCount?: number | null;
  error?: string | null;
  complianceSummary?: Record<string, number> | null;
  layerAnalysisAvailable?: boolean;
}

export interface ScanListResponse {
  total: number;
  items: Scan[];
}

export interface ScanFinding {
  id: string;
  scanId: string;
  targetId: string;
  vulnerabilityId?: string | null;
  matchedFrom?: string | null;
  scanner: string;
  packageName: string;
  packageVersion: string;
  packageType: string;
  packagePath?: string | null;
  severity: string;
  title?: string | null;
  description?: string | null;
  fixVersion?: string | null;
  fixState: string;
  dataSource?: string | null;
  urls?: string[];
  cvssScore?: number | null;
  cvssVector?: string | null;
}

export interface ScanFindingListResponse {
  total: number;
  items: ScanFinding[];
}

export interface SbomComponent {
  id: string;
  scanId: string;
  targetId: string;
  name: string;
  version: string;
  type: string;
  purl?: string | null;
  cpe?: string | null;
  licenses: string[];
  supplier?: string | null;
  filePath?: string | null;
  provenanceVerified?: boolean | null;
  provenanceSourceRepo?: string | null;
  provenanceBuildSystem?: string | null;
  provenanceAttestationType?: string | null;
}

export interface SbomComponentListResponse {
  total: number;
  items: SbomComponent[];
}

export interface ScanLayerDetail {
  index: number;
  digest: string;
  sizeBytes: number;
  command: string;
}

export interface ScanLayerAnalysis {
  scanId: string;
  efficiency: number;
  wastedBytes: number;
  userWastedPercent: number;
  totalImageSize: number;
  layers: ScanLayerDetail[];
  passThreshold: boolean;
}

export interface ScanHistoryEntry {
  scanId: string;
  startedAt: string;
  status: string;
  summary: ScanSummary;
  durationSeconds?: number | null;
}

export interface ScanHistoryResponse {
  targetId: string;
  items: ScanHistoryEntry[];
}

export interface ScanComparisonFinding {
  vulnerabilityId?: string | null;
  packageName: string;
  packageVersion: string;
  severity: string;
  fixVersion?: string | null;
}

export interface ScanComparisonChanged {
  before: ScanComparisonFinding;
  after: ScanComparisonFinding;
}

export interface ScanComparisonResponse {
  scanIdA: string;
  scanIdB: string;
  summaryA: ScanSummary;
  summaryB: ScanSummary;
  added: ScanComparisonFinding[];
  removed: ScanComparisonFinding[];
  changed?: ScanComparisonChanged[];
  unchangedCount: number;
}

export interface SubmitScanRequest {
  target: string;
  type: "container_image" | "source_repo";
  scanners?: string[];
  commitSha?: string;
  branch?: string;
  pipelineUrl?: string;
  source?: string;
  sourceArchiveBase64?: string;
  oneTime?: boolean;
}

// --- Notifications ---

export interface NotificationStatusResponse {
  enabled: boolean;
  reachable: boolean;
  url: string;
  tags?: string | null;
}

export interface NotificationTestResponse {
  success: boolean;
  message: string;
}

export type NotificationRuleType = "event" | "saved_search" | "vendor" | "product" | "dql";

export interface NotificationRule {
  id: string;
  name: string;
  enabled: boolean;
  ruleType: NotificationRuleType;
  appriseTag: string;
  eventTypes: string[];
  savedSearchId?: string | null;
  vendorSlug?: string | null;
  productSlug?: string | null;
  dqlQuery?: string | null;
  createdAt: string;
  updatedAt: string;
  lastEvaluatedAt?: string | null;
  lastTriggeredAt?: string | null;
}

export interface NotificationRuleListResponse {
  total: number;
  items: NotificationRule[];
}

export interface NotificationRuleCreate {
  name: string;
  enabled: boolean;
  ruleType: NotificationRuleType;
  appriseTag: string;
  eventTypes?: string[];
  savedSearchId?: string | null;
  vendorSlug?: string | null;
  productSlug?: string | null;
  dqlQuery?: string | null;
}

export interface NotificationChannel {
  id: string;
  url: string;
  tag: string;
  createdAt: string;
}

export interface NotificationChannelListResponse {
  items: NotificationChannel[];
}

export type NotificationEventKey = "new_vulnerabilities" | "scan_completed" | "scan_failed" | "sync_failed" | "watch_rule_match";

export interface NotificationTemplate {
  id: string;
  eventKey: NotificationEventKey;
  tag: string;
  titleTemplate: string;
  bodyTemplate: string;
  createdAt: string;
  updatedAt: string;
}

export interface NotificationTemplateCreate {
  eventKey: NotificationEventKey;
  tag: string;
  titleTemplate: string;
  bodyTemplate: string;
}

export interface NotificationTemplateListResponse {
  items: NotificationTemplate[];
}

export interface SubmitScanResponse {
  scanId: string;
  targetId: string;
  status: string;
  findingsCount: number;
  sbomComponentCount: number;
  summary: ScanSummary;
  error?: string | null;
}
