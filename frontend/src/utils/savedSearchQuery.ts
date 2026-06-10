// Shared vulnerability-query helpers, extracted from VulnerabilityListPage so the
// AI-Analyse page can turn a SavedSearch into the exact same request the list page
// issues (single source of truth — no divergence between the two call sites).

import type { AssetFiltersSelection } from "../components/AssetFilters";
import type { AdvancedFiltersState } from "../components/AdvancedFilters";
import type { SavedSearch, VulnerabilityQuery } from "../types";

export type QueryMode = "keyword" | "dql" | "regex";

export const QUERY_MODE_PARAM = "mode";

export type FilterState = AssetFiltersSelection;

export const sanitizeList = (values: string[]): string[] =>
  values
    .map((value) => value.trim())
    .filter((value, index, array) => value.length > 0 && array.indexOf(value) === index);

export const readFiltersFromParams = (params: URLSearchParams): FilterState => ({
  vendorSlugs: sanitizeList(params.getAll("vendor")),
  productSlugs: sanitizeList(params.getAll("product")),
  versionIds: sanitizeList(params.getAll("version")),
});

export const readAdvancedFiltersFromParams = (params: URLSearchParams): AdvancedFiltersState => ({
  includeRejected: params.get("includeRejected") === "true",
  includeReserved: params.get("includeReserved") === "true",
  exploitedOnly: params.get("exploitedOnly") === "true",
  aiAnalysedOnly: params.get("aiAnalysedOnly") === "true",
  severity: sanitizeList(params.getAll("severity")),
  sources: sanitizeList(params.getAll("sources")),
  epssScoreMin: params.get("epssScoreMin") ?? "",
  epssScoreMax: params.get("epssScoreMax") ?? "",
  cvssVersion: params.get("cvssVersion") ?? "",
  cvssScoreMin: params.get("cvssScoreMin") ?? "",
  cvssScoreMax: params.get("cvssScoreMax") ?? "",
  cwes: params.get("cwes") ?? "",
  assigner: params.get("assigner") ?? "",
  publishedFrom: params.get("publishedFrom") ?? "",
  publishedTo: params.get("publishedTo") ?? "",
  attackVector: sanitizeList(params.getAll("attackVector")),
  attackComplexity: sanitizeList(params.getAll("attackComplexity")),
  attackRequirements: sanitizeList(params.getAll("attackRequirements")),
  privilegesRequired: sanitizeList(params.getAll("privilegesRequired")),
  userInteraction: sanitizeList(params.getAll("userInteraction")),
  scope: sanitizeList(params.getAll("scope")),
  confidentialityImpact: sanitizeList(params.getAll("confidentialityImpact")),
  integrityImpact: sanitizeList(params.getAll("integrityImpact")),
  availabilityImpact: sanitizeList(params.getAll("availabilityImpact")),
});

export const readQueryModeFromParams = (params: URLSearchParams): QueryMode => {
  const value = params.get(QUERY_MODE_PARAM);
  if (value === "dql") return "dql";
  if (value === "regex") return "regex";
  return "keyword";
};

export interface BuildVulnerabilityRequestArgs {
  searchTerm: string;
  filters: FilterState;
  advancedFilters: AdvancedFiltersState;
  queryMode: QueryMode;
  limit: number;
  offset: number;
}

export type VulnerabilityRequestParams = Partial<VulnerabilityQuery> & {
  limit: number;
  offset: number;
};

/**
 * Map a resolved search state onto the API request body for GET /v1/vulnerabilities.
 * Mirrors the request-building block in VulnerabilityListPage's fetch effect — keep
 * the two in lockstep when adding a new advanced filter.
 */
export const buildVulnerabilityRequestParams = (
  args: BuildVulnerabilityRequestArgs
): VulnerabilityRequestParams => {
  const { filters, advancedFilters: af, queryMode, limit, offset } = args;
  const normalizedSearch = args.searchTerm.trim();
  const requestParams: VulnerabilityRequestParams = { limit, offset };

  if (queryMode === "dql") {
    requestParams.searchTerm = null;
    requestParams.dqlQuery = normalizedSearch || null;
    requestParams.includeRejected = true;
  } else if (queryMode === "regex") {
    requestParams.searchTerm = null;
    requestParams.regexQuery = normalizedSearch || null;
    requestParams.includeRejected = true;
  } else {
    requestParams.searchTerm = normalizedSearch || null;
    requestParams.vendorSlugs = filters.vendorSlugs;
    requestParams.productSlugs = filters.productSlugs;
    requestParams.versionFilters = filters.versionIds;
    if (af.includeRejected) requestParams.includeRejected = true;
    if (af.includeReserved) requestParams.includeReserved = true;
    if (af.exploitedOnly) requestParams.exploitedOnly = true;
    if (af.aiAnalysedOnly) requestParams.aiAnalysedOnly = true;
    if (af.severity.length) requestParams.severity = af.severity;
    if (af.epssScoreMin) requestParams.epssScoreMin = parseFloat(af.epssScoreMin) / 100;
    if (af.epssScoreMax) requestParams.epssScoreMax = parseFloat(af.epssScoreMax) / 100;
    if (af.assigner.trim())
      requestParams.assigner = af.assigner.split(",").map((s) => s.trim()).filter(Boolean);
    if (af.cwes.trim())
      requestParams.cwes = af.cwes
        .split(",")
        .map((s) => s.trim().replace(/^CWE-/i, ""))
        .filter(Boolean);
    if (af.sources.length) requestParams.sources = af.sources;
    if (af.cvssVersion) requestParams.cvssVersion = af.cvssVersion;
    if (af.cvssScoreMin) requestParams.cvssScoreMin = parseFloat(af.cvssScoreMin);
    if (af.cvssScoreMax) requestParams.cvssScoreMax = parseFloat(af.cvssScoreMax);
    if (af.attackVector.length) requestParams.attackVector = af.attackVector;
    if (af.attackComplexity.length) requestParams.attackComplexity = af.attackComplexity;
    if (af.attackRequirements.length) requestParams.attackRequirements = af.attackRequirements;
    if (af.privilegesRequired.length) requestParams.privilegesRequired = af.privilegesRequired;
    if (af.userInteraction.length) requestParams.userInteraction = af.userInteraction;
    if (af.scope.length) requestParams.scope = af.scope;
    if (af.confidentialityImpact.length) requestParams.confidentialityImpact = af.confidentialityImpact;
    if (af.integrityImpact.length) requestParams.integrityImpact = af.integrityImpact;
    if (af.availabilityImpact.length) requestParams.availabilityImpact = af.availabilityImpact;
    if (af.publishedFrom) requestParams.publishedFrom = af.publishedFrom;
    if (af.publishedTo) requestParams.publishedTo = af.publishedTo;
  }

  return requestParams;
};

/**
 * Turn a SavedSearch into a GET /v1/vulnerabilities request capped at `limit`.
 * Honours the saved keyword/dql/regex mode, falling back to the `mode` param in
 * `queryParams` when `queryMode` is absent (legacy saved searches).
 */
export const buildQueryFromSavedSearch = (
  saved: SavedSearch,
  limit: number
): VulnerabilityRequestParams => {
  const params = new URLSearchParams(saved.queryParams || "");
  const mode: QueryMode = (saved.queryMode as QueryMode | undefined) ?? readQueryModeFromParams(params);
  const searchParam = params.get("search") ?? "";

  let searchTerm = searchParam;
  if (mode === "dql") {
    searchTerm = (saved.dqlQuery ?? searchParam) || "";
  } else if (mode === "regex") {
    searchTerm = (saved.regexQuery ?? searchParam) || "";
  }

  return buildVulnerabilityRequestParams({
    searchTerm,
    filters: readFiltersFromParams(params),
    advancedFilters: readAdvancedFiltersFromParams(params),
    queryMode: mode,
    limit,
    offset: 0,
  });
};
