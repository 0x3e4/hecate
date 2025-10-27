import { CvssMetric, CvssMetrics, CvssVectorData } from "../types";

const VERSION_PRIORITIES: Array<{ key: string; label: string }> = [
  { key: "cvssMetricV40", label: "CVSS 4.0" },
  { key: "cvssMetricV31", label: "CVSS 3.1" },
  { key: "cvssMetricV30", label: "CVSS 3.0" },
  { key: "cvssMetricV2", label: "CVSS 2.0" },
];

export interface ParsedCvssMetric {
  key: string;
  label: string;
  version?: string | null;
  baseScore?: number | null;
  baseSeverity?: string | null;
  vectorString?: string | null;
  exploitabilityScore?: number | null;
  impactScore?: number | null;
  attackVector?: string | null;
  attackComplexity?: string | null;
  privilegesRequired?: string | null;
  userInteraction?: string | null;
  scope?: string | null;
  confidentialityImpact?: string | null;
  integrityImpact?: string | null;
  availabilityImpact?: string | null;
  source?: string | null;
  type?: string | null;
  raw: CvssMetric;
}

const toNumber = (value: unknown): number | null => {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (!trimmed) {
      return null;
    }
    const parsed = Number(trimmed);
    if (!Number.isNaN(parsed) && Number.isFinite(parsed)) {
      return parsed;
    }
  }
  return null;
};

const normalizeSeverity = (value: unknown): string | null => {
  if (typeof value === "string") {
    return value.trim().toUpperCase() || null;
  }
  return null;
};

const pickPrimaryMetric = (entries: CvssMetric[]): CvssMetric | undefined => {
  if (!entries.length) {
    return undefined;
  }
  const primary = entries.find((entry) => typeof entry.type === "string" && entry.type.toLowerCase() === "primary");
  if (primary) {
    return primary;
  }
  const nvdMetric = entries.find(
    (entry) => typeof entry.source === "string" && entry.source.toLowerCase() === "nvd@nist.gov"
  );
  if (nvdMetric) {
    return nvdMetric;
  }
  return entries[0];
};

const resolveMetricsForKey = (key: string, entries: CvssMetric[] | undefined): ParsedCvssMetric | null => {
  if (!entries || !entries.length) {
    return null;
  }
  const selected = pickPrimaryMetric(entries);
  if (!selected) {
    return null;
  }

  const data: CvssVectorData | undefined =
    selected.cvssData && typeof selected.cvssData === "object" ? selected.cvssData : undefined;
  const baseScore = toNumber(data?.baseScore ?? selected.baseScore);
  const exploitabilityScore = toNumber(selected.exploitabilityScore);
  const impactScore = toNumber(selected.impactScore);

  return {
    key,
    label: VERSION_PRIORITIES.find((candidate) => candidate.key === key)?.label ?? key,
    version: data?.version ?? selected.vectorString?.split("/")[0]?.replace("CVSS:", "") ?? null,
    baseScore,
    baseSeverity: normalizeSeverity(data?.baseSeverity ?? selected.baseSeverity),
    vectorString: typeof data?.vectorString === "string" ? data.vectorString : selected.vectorString ?? null,
    exploitabilityScore,
    impactScore,
    attackVector: (data?.attackVector as string | undefined) ?? null,
    attackComplexity: (data?.attackComplexity as string | undefined) ?? null,
    privilegesRequired: (data?.privilegesRequired as string | undefined) ?? null,
    userInteraction: (data?.userInteraction as string | undefined) ?? null,
    scope: (data?.scope as string | undefined) ?? null,
    confidentialityImpact: (data?.confidentialityImpact as string | undefined) ?? null,
    integrityImpact: (data?.integrityImpact as string | undefined) ?? null,
    availabilityImpact: (data?.availabilityImpact as string | undefined) ?? null,
    source: typeof selected.source === "string" ? selected.source : null,
    type: typeof selected.type === "string" ? selected.type : null,
    raw: selected,
  };
};

export const getOrderedCvssMetrics = (metrics: CvssMetrics | null | undefined): ParsedCvssMetric[] => {
  if (!metrics) {
    return [];
  }

  const ordered: ParsedCvssMetric[] = [];
  const seenKeys = new Set<string>();

  VERSION_PRIORITIES.forEach(({ key }) => {
    const parsed = resolveMetricsForKey(key, metrics[key]);
    if (parsed) {
      ordered.push(parsed);
      seenKeys.add(key);
    }
  });

  Object.entries(metrics).forEach(([key, entries]) => {
    if (seenKeys.has(key)) {
      return;
    }
    const parsed = resolveMetricsForKey(key, entries);
    if (parsed) {
      ordered.push(parsed);
    }
  });

  return ordered;
};

export const getPreferredCvssMetric = (metrics: CvssMetrics | null | undefined): ParsedCvssMetric | null => {
  const ordered = getOrderedCvssMetrics(metrics);
  return ordered.length ? ordered[0] : null;
};
