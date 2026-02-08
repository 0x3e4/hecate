import { CvssMetric, CvssMetrics, CvssVectorData } from "../types";

interface VersionGroup {
  id: string;
  label: string;
  keys: string[];
}

interface MetricAttribute {
  label: string;
  key: string;
}

const VERSION_GROUPS: VersionGroup[] = [
  { id: "v40", label: "CVSS 4.0", keys: ["v40", "cvssMetricV40"] },
  { id: "v31", label: "CVSS 3.1", keys: ["v31", "cvssMetricV31", "cvssMetricV3"] },
  { id: "v30", label: "CVSS 3.0", keys: ["v30", "cvssMetricV30"] },
  { id: "v20", label: "CVSS 2.0", keys: ["v20", "cvssMetricV2"] },
  { id: "other", label: "CVSS (Other)", keys: ["other", "cvssMetricOther"] },
];

// Attack Requirements and Sub* impacts are now main fields for v4.0
const V40_ADDITIONAL_FIELDS: MetricAttribute[] = [
  { label: "Exploit Maturity", key: "exploitMaturity" },
  { label: "Modified Attack Vector", key: "modifiedAttackVector" },
  { label: "Modified Attack Complexity", key: "modifiedAttackComplexity" },
  { label: "Modified Attack Requirements", key: "modifiedAttackRequirements" },
  { label: "Modified Privileges Required", key: "modifiedPrivilegesRequired" },
  { label: "Modified User Interaction", key: "modifiedUserInteraction" },
  { label: "Modified Vuln Confidentiality", key: "modifiedVulnConfidentialityImpact" },
  { label: "Modified Vuln Integrity", key: "modifiedVulnIntegrityImpact" },
  { label: "Modified Vuln Availability", key: "modifiedVulnAvailabilityImpact" },
  { label: "Modified Sub Confidentiality", key: "modifiedSubConfidentialityImpact" },
  { label: "Modified Sub Integrity", key: "modifiedSubIntegrityImpact" },
  { label: "Modified Sub Availability", key: "modifiedSubAvailabilityImpact" },
  { label: "Safety", key: "safety" },
  { label: "Automatable", key: "automatable" },
  { label: "Recovery", key: "recovery" },
  { label: "Value Density", key: "valueDensity" },
  { label: "Response Effort", key: "vulnerabilityResponseEffort" },
  { label: "Provider Urgency", key: "providerUrgency" },
  { label: "Confidentiality Requirement", key: "confidentialityRequirement" },
  { label: "Integrity Requirement", key: "integrityRequirement" },
  { label: "Availability Requirement", key: "availabilityRequirement" },
];

// Scope is now displayed in the main attributes list for v3.x
const V31_ADDITIONAL_FIELDS: MetricAttribute[] = [];

// Authentication is now displayed in the main attributes list for v2.0
const V20_ADDITIONAL_FIELDS: MetricAttribute[] = [];

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
  attackRequirements?: string | null; // CVSS 4.0
  privilegesRequired?: string | null;
  userInteraction?: string | null;
  scope?: string | null; // CVSS 3.x
  confidentialityImpact?: string | null;
  integrityImpact?: string | null;
  availabilityImpact?: string | null;
  // CVSS 4.0 Subsequent System impact metrics
  subConfidentialityImpact?: string | null;
  subIntegrityImpact?: string | null;
  subAvailabilityImpact?: string | null;
  additionalAttributes?: Array<{ label: string; value: string | null }>;
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

const dedupeMetrics = (entries: CvssMetric[]): CvssMetric[] => {
  const seen = new Set<string>();
  const unique: CvssMetric[] = [];
  entries.forEach((entry) => {
    if (!entry || typeof entry !== "object") {
      return;
    }
    const serialized = JSON.stringify(entry);
    if (seen.has(serialized)) {
      return;
    }
    seen.add(serialized);
    unique.push(entry);
  });
  return unique;
};

const collectEntries = (metrics: CvssMetrics | null | undefined, keys: string[]): CvssMetric[] => {
  if (!metrics) {
    return [];
  }
  const collected: CvssMetric[] = [];
  keys.forEach((key) => {
    const list = metrics[key];
    if (Array.isArray(list)) {
      list.forEach((entry) => {
        if (entry && typeof entry === "object") {
          collected.push(entry);
        }
      });
    }
  });
  return dedupeMetrics(collected);
};

const extractString = (source: unknown, key: string): string | null => {
  if (!source || typeof source !== "object") {
    return null;
  }
  const lowerKey = key.toLowerCase();
  for (const [candidateKey, candidateValue] of Object.entries(source as Record<string, unknown>)) {
    if (candidateKey.toLowerCase() !== lowerKey) {
      continue;
    }
    if (candidateValue === null || candidateValue === undefined) {
      return null;
    }
    if (typeof candidateValue === "string") {
      const trimmed = candidateValue.trim();
      if (trimmed.length > 0) {
        return trimmed;
      }
      return null;
    }
    if (typeof candidateValue === "number") {
      if (Number.isFinite(candidateValue)) {
        return candidateValue.toString();
      }
      return null;
    }
    if (typeof candidateValue === "boolean") {
      return candidateValue ? "TRUE" : "FALSE";
    }
  }
  return null;
};

const pickField = (
  vectorData: CvssVectorData | undefined,
  selected: CvssMetric | undefined,
  fallbackEntries: CvssMetric[],
  ...keys: string[]
): string | null => {
  const candidates: unknown[] = [
    vectorData,
    selected?.data,
    selected?.cvssData,
    selected,
  ];

  fallbackEntries.forEach((entry) => {
    if (!entry || typeof entry !== "object") {
      return;
    }
    candidates.push(entry.data);
    candidates.push(entry.cvssData);
    candidates.push(entry);
  });

  for (const key of keys) {
    for (const candidate of candidates) {
      const value = extractString(candidate, key);
      if (value) {
        return value;
      }
    }
  }
  return null;
};

const resolveGroup = (group: VersionGroup, metrics: CvssMetrics | null | undefined): ParsedCvssMetric | null => {
  const entries = collectEntries(metrics, group.keys);
  if (!entries.length) {
    return null;
  }
  const selected = pickPrimaryMetric(entries);
  if (!selected) {
    return null;
  }

  const fallbackEntries = entries.filter((entry) => entry !== selected);

  const vectorData: CvssVectorData | undefined =
    (selected.data && typeof selected.data === "object" ? selected.data : undefined) ??
    (selected.cvssData && typeof selected.cvssData === "object" ? selected.cvssData : undefined);

  const baseScore = toNumber(pickField(vectorData, selected, fallbackEntries, "baseScore"));
  const exploitabilityScore = toNumber(
    pickField(vectorData, selected, fallbackEntries, "exploitabilityScore")
  );
  const impactScore = toNumber(pickField(vectorData, selected, fallbackEntries, "impactScore"));
  const attackVector = pickField(vectorData, selected, fallbackEntries, "attackVector", "accessVector");
  const attackComplexity = pickField(
    vectorData,
    selected,
    fallbackEntries,
    "attackComplexity",
    "accessComplexity"
  );
  const attackRequirements = pickField(
    vectorData,
    selected,
    fallbackEntries,
    "attackRequirements"
  );
  const privilegesRequired = pickField(
    vectorData,
    selected,
    fallbackEntries,
    "privilegesRequired",
    "authentication"
  );
  const userInteraction = pickField(
    vectorData,
    selected,
    fallbackEntries,
    "userInteraction",
    "userInteractionRequired"
  );
  const scope = pickField(vectorData, selected, fallbackEntries, "scope");
  const confidentialityImpact = pickField(
    vectorData,
    selected,
    fallbackEntries,
    "confidentialityImpact",
    "vulnConfidentialityImpact"
  );
  const integrityImpact = pickField(
    vectorData,
    selected,
    fallbackEntries,
    "integrityImpact",
    "vulnIntegrityImpact"
  );
  const availabilityImpact = pickField(
    vectorData,
    selected,
    fallbackEntries,
    "availabilityImpact",
    "vulnAvailabilityImpact"
  );
  // CVSS 4.0 Subsequent System impact metrics
  const subConfidentialityImpact = pickField(
    vectorData,
    selected,
    fallbackEntries,
    "subConfidentialityImpact",
    "subsequentConfidentialityImpact",
    "subSequentSystemConfidentiality"
  );
  const subIntegrityImpact = pickField(
    vectorData,
    selected,
    fallbackEntries,
    "subIntegrityImpact",
    "subsequentIntegrityImpact",
    "subSequentSystemIntegrity"
  );
  const subAvailabilityImpact = pickField(
    vectorData,
    selected,
    fallbackEntries,
    "subAvailabilityImpact",
    "subsequentAvailabilityImpact",
    "subSequentSystemAvailability"
  );

  const additionalAttributes: Array<{ label: string; value: string | null }> = [];
  const attachAdditionalAttributes = (fields: MetricAttribute[]) => {
    fields.forEach(({ label, key }) => {
      const value = pickField(vectorData, selected, fallbackEntries, key);
      if (value) {
        additionalAttributes.push({ label, value });
      }
    });
  };

  if (group.id === "v40") {
    attachAdditionalAttributes(V40_ADDITIONAL_FIELDS);
  } else if (group.id === "v31") {
    attachAdditionalAttributes(V31_ADDITIONAL_FIELDS);
  } else if (group.id === "v20") {
    attachAdditionalAttributes(V20_ADDITIONAL_FIELDS);
  }

  if (scope && group.id !== "v31") {
    additionalAttributes.unshift({ label: "Scope", value: scope });
  }

  return {
    key: group.id,
    label: group.label,
    version:
      pickField(vectorData, selected, fallbackEntries, "version") ??
      selected.vectorString?.split("/")[0]?.replace("CVSS:", "") ??
      null,
    baseScore,
    baseSeverity: normalizeSeverity(
      pickField(vectorData, selected, fallbackEntries, "baseSeverity", "severity")
    ),
    vectorString: pickField(vectorData, selected, fallbackEntries, "vectorString"),
    exploitabilityScore,
    impactScore,
    attackVector,
    attackComplexity,
    attackRequirements,
    privilegesRequired,
    userInteraction,
    scope,
    confidentialityImpact,
    integrityImpact,
    availabilityImpact,
    subConfidentialityImpact,
    subIntegrityImpact,
    subAvailabilityImpact,
    additionalAttributes: additionalAttributes.length ? additionalAttributes : undefined,
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
  const consumedKeys = new Set<string>();

  VERSION_GROUPS.forEach((group) => {
    const parsed = resolveGroup(group, metrics);
    group.keys.forEach((key) => consumedKeys.add(key));
    if (parsed) {
      ordered.push(parsed);
    }
  });

  // collect remaining keys not covered above to keep full dataset available
  Object.entries(metrics).forEach(([key, entries]) => {
    if (consumedKeys.has(key)) {
      return;
    }
    if (!Array.isArray(entries) || entries.length === 0) {
      return;
    }
    const fallbackGroup: VersionGroup = { id: key, label: key.toUpperCase(), keys: [key] };
    const parsed = resolveGroup(fallbackGroup, metrics);
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
