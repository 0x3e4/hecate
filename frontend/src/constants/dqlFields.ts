export type FieldType = "string" | "number" | "boolean" | "date" | "array";

export interface DQLFieldHint {
  field: string;
  description: string;
  type: FieldType;
  aggregatable: boolean;
}

export const DQL_FIELD_HINTS: DQLFieldHint[] = [
  { field: "vuln_id", description: "ID (z.B. CVE oder EUVD ID)", type: "string", aggregatable: true },
  { field: "source", description: "Name der Quelle (z.B. NVD oder EUVD)", type: "string", aggregatable: true },
  { field: "title", description: "Titel des Eintrags", type: "string", aggregatable: false },
  { field: "summary", description: "Beschreibungstext", type: "string", aggregatable: false },
  { field: "vendors", description: "Liste der betroffenen Hersteller", type: "array", aggregatable: true },
  { field: "products", description: "Liste der Produkte", type: "array", aggregatable: true },
  { field: "product_versions", description: "Produktversionen (Text)", type: "array", aggregatable: true },
  { field: "product_version_ids", description: "Produktversions-IDs aus dem Katalog", type: "array", aggregatable: true },
  { field: "aliases", description: "Weitere Identifier / Aliasse", type: "array", aggregatable: true },
  { field: "cwes", description: "CWE Klassifizierung", type: "array", aggregatable: true },
  { field: "cpes", description: "CPE Einträge", type: "array", aggregatable: true },
  { field: "cvss.severity", description: "CVSS Severity (z.B. critical, high, medium, low)", type: "string", aggregatable: true },
  { field: "cvss.base_score", description: "CVSS Basisscore", type: "number", aggregatable: false },
  { field: "cvssMetrics.v40.data.baseScore", description: "CVSS 4.0 Basisscore", type: "number", aggregatable: false },
  { field: "cvssMetrics.v40.data.baseSeverity", description: "CVSS 4.0 Severity", type: "string", aggregatable: true },
  { field: "cvssMetrics.v40.data.vectorString", description: "CVSS 4.0 Vektor", type: "string", aggregatable: false },
  { field: "cvssMetrics.v40.data.attackVector", description: "CVSS 4.0 Angriffsvektor", type: "string", aggregatable: true },
  { field: "cvssMetrics.v31.data.baseScore", description: "CVSS 3.x Basisscore", type: "number", aggregatable: false },
  { field: "cvssMetrics.v31.data.attackVector", description: "CVSS 3.x Angriffsvektor", type: "string", aggregatable: true },
  { field: "cvssMetrics.v31.data.privilegesRequired", description: "CVSS 3.x benötigte Privilegien", type: "string", aggregatable: true },
  { field: "cvssMetrics.v31.exploitabilityScore", description: "CVSS 3.x Exploitability Score", type: "number", aggregatable: false },
  { field: "cvssMetrics.v20.data.baseScore", description: "CVSS 2.0 Basisscore", type: "number", aggregatable: false },
  { field: "cvssMetrics.v20.data.accessVector", description: "CVSS 2.0 Angriffsvektor", type: "string", aggregatable: true },
  { field: "cvssMetrics.v20.data.authentication", description: "CVSS 2.0 Authentifizierung", type: "string", aggregatable: true },
  { field: "epss_score", description: "EPSS Score", type: "number", aggregatable: false },
  { field: "published", description: "Datum der Veröffentlichung (z.B. 2025-11-03)", type: "date", aggregatable: false },
  { field: "ingested_at", description: "Datum des Imports (z.B. 2025-11-03)", type: "date", aggregatable: false },
  { field: "assigner", description: "Schwachstellen Auftraggeber", type: "string", aggregatable: true },
  { field: "exploited", description: "True/False für aktive Exploitation (KEV)", type: "boolean", aggregatable: true },
  { field: "rejected", description: "True/False für abgehlente Schwachstellen", type: "boolean", aggregatable: true },
];

export interface FieldCategory {
  name: string;
  fields: string[];
}

export const FIELD_CATEGORIES: FieldCategory[] = [
  {
    name: "Identification",
    fields: ["vuln_id", "source", "aliases", "assigner"]
  },
  {
    name: "Description",
    fields: ["title", "summary", "cwes"]
  },
  {
    name: "Impact & Scoring",
    fields: ["cvss.severity", "cvss.base_score", "epss_score", "exploited", "rejected"]
  },
  {
    name: "CVSS 4.0 Metrics",
    fields: [
      "cvssMetrics.v40.data.baseScore",
      "cvssMetrics.v40.data.baseSeverity",
      "cvssMetrics.v40.data.vectorString",
      "cvssMetrics.v40.data.attackVector"
    ]
  },
  {
    name: "CVSS 3.x Metrics",
    fields: [
      "cvssMetrics.v31.data.baseScore",
      "cvssMetrics.v31.data.attackVector",
      "cvssMetrics.v31.data.privilegesRequired",
      "cvssMetrics.v31.exploitabilityScore"
    ]
  },
  {
    name: "CVSS 2.0 Metrics",
    fields: [
      "cvssMetrics.v20.data.baseScore",
      "cvssMetrics.v20.data.accessVector",
      "cvssMetrics.v20.data.authentication"
    ]
  },
  {
    name: "Assets & Products",
    fields: ["vendors", "products", "product_versions", "product_version_ids", "cpes"]
  },
  {
    name: "Dates",
    fields: ["published", "ingested_at"]
  }
];
