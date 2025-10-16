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
  aiAssessment?: Record<string, unknown> | null;
}

export interface VulnerabilityQuery {
  searchTerm: string | null;
  cpeFilters?: string[];
  severity?: string[];
  limit?: number;
}
