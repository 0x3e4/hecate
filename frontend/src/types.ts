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

export type AIProviderId = "openai" | "anthropic" | "gemini" | "openai-compatible";

export interface AIProviderInfo {
  id: AIProviderId;
  label: string;
}

export interface AIInvestigationResponse {
  provider: AIProviderId;
  language: string;
  summary: string;
  generatedAt: string;
  triggeredBy?: string | null;
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
  triggeredBy?: string | null;
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
  triggeredBy?: string | null;
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
  triggeredBy?: string | null;
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
  triggeredBy?: string | null;
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
  // Advanced filters
  epssScoreMin?: number;
  epssScoreMax?: number;
  assigner?: string[];
  cwes?: string[];
  sources?: string[];
  cvssVersion?: string;
  cvssScoreMin?: number;
  cvssScoreMax?: number;
  attackVector?: string[];
  attackComplexity?: string[];
  attackRequirements?: string[];
  privilegesRequired?: string[];
  userInteraction?: string[];
  scope?: string[];
  confidentialityImpact?: string[];
  integrityImpact?: string[];
  availabilityImpact?: string[];
  publishedFrom?: string;
  publishedTo?: string;
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
  affectedInventory?: AffectedInventoryItem[];
  attackPath?: AttackPathNarrative | null;
}

export type AttackPathNodeType =
  | "entry"
  | "asset"
  | "package"
  | "cve"
  | "cwe"
  | "capec"
  | "exploit"
  | "impact"
  | "fix";

export type AttackPathLikelihood =
  | "very_low"
  | "low"
  | "medium"
  | "high"
  | "very_high"
  | "unknown";

export type AttackPathExploitMaturity =
  | "theoretical"
  | "poc"
  | "functional"
  | "high"
  | "unknown";

export type AttackPathReachability = "confirmed" | "likely" | "unknown" | "not_reachable";

export interface AttackPathNode {
  id: string;
  type: AttackPathNodeType;
  label: string;
  description?: string | null;
  severity?: string | null;
  metadata?: Record<string, unknown> | null;
}

export interface AttackPathEdge {
  source: string;
  target: string;
  label?: string | null;
}

export interface AttackPathLabels {
  likelihood: AttackPathLikelihood;
  exploitMaturity: AttackPathExploitMaturity;
  reachability: AttackPathReachability;
  privilegesRequired?: string | null;
  userInteraction?: string | null;
  businessImpact?: string | null;
}

export interface AttackPathGraph {
  nodes: AttackPathNode[];
  edges: AttackPathEdge[];
  labels: AttackPathLabels;
  disclaimer: string;
  generatedAt: string;
}

export interface AttackPathNarrative {
  provider: string;
  language: string;
  summary: string;
  generatedAt: string;
  tokenUsage?: Record<string, number> | null;
  triggeredBy?: string | null;
}

export interface AttackPathResponse {
  vulnerabilityId: string;
  graph: AttackPathGraph;
  narrative?: AttackPathNarrative | null;
}

export type AttackStage =
  | "foothold"
  | "credential_access"
  | "priv_escalation"
  | "lateral_movement"
  | "impact";

export interface ChainFindingRef {
  vulnerabilityId: string;
  packageName: string;
  packageVersion?: string | null;
  severity?: string | null;
  cvssScore?: number | null;
  primaryCwe?: string | null;
  title?: string | null;
}

export interface ScanAttackChainStage {
  stage: AttackStage;
  label: string;
  findings: ChainFindingRef[];
  capecTechniques: string[];
}

export interface ScanAttackChainNarrative {
  provider: string;
  language: string;
  summary: string;
  generatedAt: string;
  tokenUsage?: Record<string, number> | null;
  triggeredBy?: string | null;
}

export interface ScanAttackChainResponse {
  scanId: string;
  graph: AttackPathGraph;
  stages: ScanAttackChainStage[];
  narrative?: ScanAttackChainNarrative | null;
}

export type InventoryDeployment = "onprem" | "cloud" | "hybrid";
/** Free-form environment label. Common values: prod, staging, dev, test, dr. */
export type InventoryEnvironment = string;

export interface InventoryItem {
  id: string;
  name: string;
  vendorSlug: string;
  productSlug: string;
  vendorName?: string | null;
  productName?: string | null;
  version: string;
  deployment: InventoryDeployment;
  environment: InventoryEnvironment;
  instanceCount: number;
  owner?: string | null;
  notes?: string | null;
  createdAt: string;
  updatedAt: string;
  affectedVulnCount?: number | null;
}

export interface InventoryItemListResponse {
  items: InventoryItem[];
  total: number;
}

export interface AffectedInventoryItem {
  id: string;
  name: string;
  vendorName?: string | null;
  productName?: string | null;
  version: string;
  deployment: InventoryDeployment;
  environment: InventoryEnvironment;
  instanceCount: number;
  owner?: string | null;
}

export interface AffectedVulnerabilityItem {
  vulnId: string;
  title?: string | null;
  severity?: string | null;
  cvssScore?: number | null;
  epssScore?: number | null;
  exploited?: boolean | null;
  published?: string | null;
}

export interface AffectedVulnerabilitiesResponse {
  itemId: string;
  total: number;
  vulnerabilities: AffectedVulnerabilityItem[];
}

export type RefreshSourceType = "NVD" | "EUVD" | "CIRCL" | "GHSA" | "OSV";

export interface VulnerabilityRefreshRequest {
  vulnIds?: string[];
  sourceIds?: string[];
  source?: RefreshSourceType;
}

export type VulnerabilityRefreshStatus = {
  identifier: string;
  provider?: string | null;
  status: "inserted" | "updated" | "skipped" | "error" | "accepted";
  message?: string | null;
  changedFields?: number | null;
  resolvedId?: string | null;
};

export interface VulnerabilityRefreshResponse {
  requested: string[];
  results: VulnerabilityRefreshStatus[];
  // Backend dispatches refresh asynchronously (HTTP 202) to stay under the
  // Cloudflare 100s edge timeout. Clients subscribe to SSE `job_completed` /
  // `job_failed` events with `jobName === "vulnerability_refresh_" + jobId`
  // to pick up the final per-ID results.
  jobId?: string | null;
}

export interface PagedVulnerabilityResponse {
  total: number;
  items: VulnerabilityPreview[];
  maxOffset?: number;
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
  dataset: "vulnerabilities" | "saved_searches" | "inventory";
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
  deleted: number;
  refreshed: number;
  resolvedIds: string[];
  errors: string[];
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
  type: "container_image" | "source_repo" | "sbom-import";
  name: string;
  registry?: string | null;
  repositoryUrl?: string | null;
  description?: string | null;
  tags?: string[];
  group?: string | null;
  createdAt: string;
  updatedAt: string;
  lastScanAt?: string | null;
  scanCount: number;
  latestSummary?: ScanSummary | null;
  latestScanId?: string | null;
  hasRunningScan?: boolean;
  runningScanId?: string | null;
  runningScanStatus?: string | null;
  autoScan?: boolean;
  scanners?: string[];
  // Last auto-scan /check probe (powers the Scanner-tab diagnostics table).
  lastCheckAt?: string | null;
  lastCheckVerdict?:
    | "changed"
    | "unchanged"
    | "first_scan"
    | "check_failed_skipped"
    | "check_failed_scanned"
    | null;
  lastCheckCurrentFingerprint?: string | null;
  lastCheckError?: string | null;
  lastImageDigest?: string | null;
  lastCommitSha?: string | null;
}

export interface ScanTargetListResponse {
  total: number;
  items: ScanTarget[];
}

export interface ScanTargetGroup {
  group: string | null;
  targetCount: number;
  latestSummary: ScanSummary;
}

export interface ScanTargetGroupListResponse {
  items: ScanTargetGroup[];
}

export interface ScanAiAnalysis {
  scanId?: string;
  provider?: string;
  language?: string;
  summary: string;
  generatedAt: string;
  tokenUsage?: Record<string, number> | null;
  triggeredBy?: string | null;
}

export interface Scan {
  id: string;
  targetId: string;
  targetName?: string | null;
  scanners: string[];
  status: "pending" | "running" | "completed" | "failed" | "cancelled";
  source: "ci_cd" | "manual" | "scheduled" | "sbom-import";
  imageRef?: string | null;
  commitSha?: string | null;
  branch?: string | null;
  repositoryUrl?: string | null;
  pipelineUrl?: string | null;
  startedAt: string;
  finishedAt?: string | null;
  durationSeconds?: number | null;
  summary: ScanSummary;
  sbomComponentCount?: number | null;
  error?: string | null;
  complianceSummary?: Record<string, number> | null;
  licenseComplianceSummary?: Record<string, number> | null;
  layerAnalysisAvailable?: boolean;
  aiAnalysis?: ScanAiAnalysis | null;
  aiAnalyses?: ScanAiAnalysis[] | null;
  attackChain?: ScanAttackChainNarrative | null;
  attackChains?: ScanAttackChainNarrative[] | null;
}

export interface ScanListResponse {
  total: number;
  items: Scan[];
}

export interface ScannerStats {
  memoryUsedBytes: number;
  memoryLimitBytes: number;
  tmpDiskTotalBytes: number;
  tmpDiskUsedBytes: number;
  tmpDiskFreeBytes: number;
  activeScans: number;
  error?: string;
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
  vexStatus?: "not_affected" | "affected" | "fixed" | "under_investigation" | null;
  vexJustification?: string | null;
  vexDetail?: string | null;
  vexUpdatedAt?: string | null;
  dismissed?: boolean;
  dismissedReason?: string | null;
  dismissedAt?: string | null;
  dismissedBy?: string | null;
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

export interface ConsolidatedTarget {
  targetId: string;
  scanId: string;
}

export interface ConsolidatedFinding {
  vulnerabilityId?: string | null;
  packageName: string;
  packageVersion: string;
  severity: string;
  fixVersion?: string | null;
  fixState: string;
  title?: string | null;
  scanners: string[];
  targets: ConsolidatedTarget[];
  cvssScore?: number | null;
  urls?: string[];
  packageType?: string | null;
  packagePath?: string | null;
}

export interface ConsolidatedFindingListResponse {
  total: number;
  items: ConsolidatedFinding[];
}

export interface ConsolidatedSbom {
  name: string;
  version: string;
  type: string;
  purl?: string | null;
  licenses: string[];
  provenanceVerified?: boolean | null;
  targets: ConsolidatedTarget[];
}

export interface ConsolidatedSbomListResponse {
  total: number;
  items: ConsolidatedSbom[];
}

export interface ConsolidatedAlert {
  title?: string | null;
  packageName: string;
  packageVersion: string;
  severity: string;
  description?: string | null;
  category?: string | null;
  packagePath?: string | null;
  targets: ConsolidatedTarget[];
}

export interface ConsolidatedAlertListResponse {
  total: number;
  items: ConsolidatedAlert[];
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
  commitSha?: string | null;
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

export type NotificationRuleType = "event" | "saved_search" | "vendor" | "product" | "dql" | "scan" | "inventory";

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
  scanSeverityThreshold?: string | null;
  scanTargetFilter?: string | null;
  inventoryItemIds?: string[] | null;
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
  scanSeverityThreshold?: string | null;
  scanTargetFilter?: string | null;
  inventoryItemIds?: string[] | null;
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

export type NotificationEventKey = "new_vulnerabilities" | "scan_completed" | "scan_failed" | "sync_failed" | "watch_rule_match" | "inventory_match";

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

// --- License Compliance ---

export interface LicensePolicy {
  id: string;
  name: string;
  description?: string | null;
  allowed: string[];
  denied: string[];
  reviewed: string[];
  defaultAction: "allow" | "warn" | "deny";
  isDefault: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface LicensePolicyListResponse {
  items: LicensePolicy[];
  total: number;
}

export interface LicenseGroups {
  permissive: string[];
  weakCopyleft: string[];
  copyleft: string[];
}

export interface EvaluatedLicense {
  licenseId: string;
  status: "allowed" | "denied" | "warned" | "unknown";
}

export interface LicenseViolation {
  name: string;
  version: string;
  type: string;
  purl?: string | null;
  licenses: string[];
  status: "denied" | "warned" | "unknown";
  evaluatedLicenses: EvaluatedLicense[];
}

export interface LicenseComplianceSummary {
  allowed: number;
  denied: number;
  warned: number;
  unknown: number;
}

export interface LicenseComplianceResult {
  policyId: string | null;
  policyName: string | null;
  summary: LicenseComplianceSummary;
  violations: LicenseViolation[];
}

export interface LicenseOverviewComponent {
  name: string;
  version: string;
}

export interface LicenseOverviewItem {
  licenseId: string;
  componentCount: number;
  components: LicenseOverviewComponent[];
}

export interface LicenseOverviewResponse {
  items: LicenseOverviewItem[];
  total: number;
}

export interface MalwareFeedEntry {
  source: "dynamic";
  ecosystem: string;
  name: string;
  versions: string[];
  allVersions: boolean;
  description: string;
  origin?: string | null;
  staticIndex?: number | null;
  updatedAt?: string | null;
  ingestedAt?: string | null;
  severity?: string | null;
  references?: string[];
  alsoSeenIn?: string[];
  relatedOrigins?: string[];
}

export interface MalwareFeedResponse {
  generatedAt: string;
  total: number;
  malTotal: number;
  offset: number;
  limit: number;
  entries: MalwareFeedEntry[];
}
