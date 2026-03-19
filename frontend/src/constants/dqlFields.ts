export type FieldType = "string" | "number" | "boolean" | "date" | "array";

export interface DQLFieldHint {
  field: string;
  description: string;
  type: FieldType;
  aggregatable: boolean;
}

export const DQL_FIELD_HINTS: DQLFieldHint[] = [
  // Identification
  { field: "vuln_id", description: "ID (z.B. CVE oder EUVD ID)", type: "string", aggregatable: true },
  { field: "source", description: "Name der Quelle (z.B. NVD oder EUVD)", type: "string", aggregatable: true },
  { field: "aliases", description: "Weitere Identifier / Aliasse", type: "array", aggregatable: true },
  { field: "assigner", description: "Schwachstellen Auftraggeber", type: "string", aggregatable: true },

  // Description
  { field: "title", description: "Titel des Eintrags", type: "string", aggregatable: false },
  { field: "summary", description: "Beschreibungstext", type: "string", aggregatable: false },
  { field: "cwes", description: "CWE Klassifizierung", type: "array", aggregatable: true },
  { field: "cpes", description: "CPE Einträge", type: "array", aggregatable: true },

  // Impact & Scoring
  { field: "cvss.severity", description: "CVSS Severity (z.B. critical, high, medium, low)", type: "string", aggregatable: true },
  { field: "cvss.base_score", description: "CVSS Basisscore", type: "number", aggregatable: false },
  { field: "epss_score", description: "EPSS Score (0.00 - 100.00)", type: "number", aggregatable: false },
  { field: "exploited", description: "True/False für aktive Exploitation (KEV)", type: "boolean", aggregatable: true },
  { field: "rejected", description: "True/False für abgelehnte Schwachstellen", type: "boolean", aggregatable: true },

  // CVSS 4.0
  { field: "cvssMetrics.v40.data.baseScore", description: "CVSS 4.0 Basisscore", type: "number", aggregatable: false },
  { field: "cvssMetrics.v40.data.baseSeverity", description: "CVSS 4.0 Severity", type: "string", aggregatable: true },
  { field: "cvssMetrics.v40.data.vectorString", description: "CVSS 4.0 Vektor", type: "string", aggregatable: false },
  { field: "cvssMetrics.v40.data.attackVector", description: "CVSS 4.0 Angriffsvektor", type: "string", aggregatable: true },
  { field: "cvssMetrics.v40.data.attackComplexity", description: "CVSS 4.0 Angriffskomplexität", type: "string", aggregatable: true },
  { field: "cvssMetrics.v40.data.attackRequirements", description: "CVSS 4.0 Angriffsvoraussetzungen", type: "string", aggregatable: true },
  { field: "cvssMetrics.v40.data.privilegesRequired", description: "CVSS 4.0 benötigte Privilegien", type: "string", aggregatable: true },
  { field: "cvssMetrics.v40.data.userInteraction", description: "CVSS 4.0 Benutzerinteraktion", type: "string", aggregatable: true },
  { field: "cvssMetrics.v40.data.confidentialityImpact", description: "CVSS 4.0 Vertraulichkeit", type: "string", aggregatable: true },
  { field: "cvssMetrics.v40.data.integrityImpact", description: "CVSS 4.0 Integrität", type: "string", aggregatable: true },
  { field: "cvssMetrics.v40.data.availabilityImpact", description: "CVSS 4.0 Verfügbarkeit", type: "string", aggregatable: true },
  { field: "cvssMetrics.v40.exploitabilityScore", description: "CVSS 4.0 Exploitability Score", type: "number", aggregatable: false },
  { field: "cvssMetrics.v40.impactScore", description: "CVSS 4.0 Impact Score", type: "number", aggregatable: false },
  { field: "cvssMetrics.v40.source", description: "CVSS 4.0 Quelle", type: "string", aggregatable: true },
  { field: "cvssMetrics.v40.type", description: "CVSS 4.0 Typ (Primary/Secondary)", type: "string", aggregatable: true },

  // CVSS 3.x
  { field: "cvssMetrics.v31.data.baseScore", description: "CVSS 3.x Basisscore", type: "number", aggregatable: false },
  { field: "cvssMetrics.v31.data.baseSeverity", description: "CVSS 3.x Severity", type: "string", aggregatable: true },
  { field: "cvssMetrics.v31.data.vectorString", description: "CVSS 3.x Vektor", type: "string", aggregatable: false },
  { field: "cvssMetrics.v31.data.attackVector", description: "CVSS 3.x Angriffsvektor", type: "string", aggregatable: true },
  { field: "cvssMetrics.v31.data.attackComplexity", description: "CVSS 3.x Angriffskomplexität", type: "string", aggregatable: true },
  { field: "cvssMetrics.v31.data.privilegesRequired", description: "CVSS 3.x benötigte Privilegien", type: "string", aggregatable: true },
  { field: "cvssMetrics.v31.data.userInteraction", description: "CVSS 3.x Benutzerinteraktion", type: "string", aggregatable: true },
  { field: "cvssMetrics.v31.data.scope", description: "CVSS 3.x Scope (UNCHANGED/CHANGED)", type: "string", aggregatable: true },
  { field: "cvssMetrics.v31.data.confidentialityImpact", description: "CVSS 3.x Vertraulichkeit", type: "string", aggregatable: true },
  { field: "cvssMetrics.v31.data.integrityImpact", description: "CVSS 3.x Integrität", type: "string", aggregatable: true },
  { field: "cvssMetrics.v31.data.availabilityImpact", description: "CVSS 3.x Verfügbarkeit", type: "string", aggregatable: true },
  { field: "cvssMetrics.v31.exploitabilityScore", description: "CVSS 3.x Exploitability Score", type: "number", aggregatable: false },
  { field: "cvssMetrics.v31.impactScore", description: "CVSS 3.x Impact Score", type: "number", aggregatable: false },
  { field: "cvssMetrics.v31.source", description: "CVSS 3.x Quelle", type: "string", aggregatable: true },
  { field: "cvssMetrics.v31.type", description: "CVSS 3.x Typ (Primary/Secondary)", type: "string", aggregatable: true },

  // CVSS 2.0
  { field: "cvssMetrics.v20.data.baseScore", description: "CVSS 2.0 Basisscore", type: "number", aggregatable: false },
  { field: "cvssMetrics.v20.data.baseSeverity", description: "CVSS 2.0 Severity", type: "string", aggregatable: true },
  { field: "cvssMetrics.v20.data.vectorString", description: "CVSS 2.0 Vektor", type: "string", aggregatable: false },
  { field: "cvssMetrics.v20.data.accessVector", description: "CVSS 2.0 Angriffsvektor", type: "string", aggregatable: true },
  { field: "cvssMetrics.v20.data.accessComplexity", description: "CVSS 2.0 Zugriffskomplexität", type: "string", aggregatable: true },
  { field: "cvssMetrics.v20.data.authentication", description: "CVSS 2.0 Authentifizierung", type: "string", aggregatable: true },
  { field: "cvssMetrics.v20.data.confidentialityImpact", description: "CVSS 2.0 Vertraulichkeit", type: "string", aggregatable: true },
  { field: "cvssMetrics.v20.data.integrityImpact", description: "CVSS 2.0 Integrität", type: "string", aggregatable: true },
  { field: "cvssMetrics.v20.data.availabilityImpact", description: "CVSS 2.0 Verfügbarkeit", type: "string", aggregatable: true },
  { field: "cvssMetrics.v20.exploitabilityScore", description: "CVSS 2.0 Exploitability Score", type: "number", aggregatable: false },
  { field: "cvssMetrics.v20.impactScore", description: "CVSS 2.0 Impact Score", type: "number", aggregatable: false },
  { field: "cvssMetrics.v20.source", description: "CVSS 2.0 Quelle", type: "string", aggregatable: true },
  { field: "cvssMetrics.v20.type", description: "CVSS 2.0 Typ (Primary/Secondary)", type: "string", aggregatable: true },

  // Impacted Products (nested)
  { field: "impactedProducts.vendor.name", description: "Betroffener Hersteller (Name)", type: "string", aggregatable: false },
  { field: "impactedProducts.vendor.slug", description: "Betroffener Hersteller (Slug)", type: "string", aggregatable: false },
  { field: "impactedProducts.product.name", description: "Betroffenes Produkt (Name)", type: "string", aggregatable: false },
  { field: "impactedProducts.product.slug", description: "Betroffenes Produkt (Slug)", type: "string", aggregatable: false },
  { field: "impactedProducts.versions", description: "Betroffene Versionen", type: "array", aggregatable: false },
  { field: "impactedProducts.environments", description: "Betroffene Umgebungen", type: "array", aggregatable: false },
  { field: "impactedProducts.vulnerable", description: "Verwundbar (true/false)", type: "boolean", aggregatable: false },

  // Assets & Products
  { field: "vendors", description: "Liste der betroffenen Hersteller", type: "array", aggregatable: true },
  { field: "vendorSlugs", description: "Hersteller-Slugs (normalisiert, z.B. fortinet)", type: "array", aggregatable: true },
  { field: "products", description: "Liste der Produkte", type: "array", aggregatable: true },
  { field: "productSlugs", description: "Produkt-Slugs (normalisiert, z.B. fortiswitch)", type: "array", aggregatable: true },
  { field: "product_versions", description: "Produktversionen (Text)", type: "array", aggregatable: true },
  { field: "product_version_ids", description: "Produktversions-IDs aus dem Katalog", type: "array", aggregatable: true },

  // Dates
  { field: "published", description: "Datum der Veröffentlichung (z.B. 2025-11-03)", type: "date", aggregatable: false },
  { field: "ingested_at", description: "Datum des Imports (z.B. 2025-11-03)", type: "date", aggregatable: false },
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
    fields: ["title", "summary", "cwes", "cpes"]
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
      "cvssMetrics.v40.data.attackVector",
      "cvssMetrics.v40.data.attackComplexity",
      "cvssMetrics.v40.data.attackRequirements",
      "cvssMetrics.v40.data.privilegesRequired",
      "cvssMetrics.v40.data.userInteraction",
      "cvssMetrics.v40.data.confidentialityImpact",
      "cvssMetrics.v40.data.integrityImpact",
      "cvssMetrics.v40.data.availabilityImpact",
      "cvssMetrics.v40.exploitabilityScore",
      "cvssMetrics.v40.impactScore",
      "cvssMetrics.v40.source",
      "cvssMetrics.v40.type"
    ]
  },
  {
    name: "CVSS 3.x Metrics",
    fields: [
      "cvssMetrics.v31.data.baseScore",
      "cvssMetrics.v31.data.baseSeverity",
      "cvssMetrics.v31.data.vectorString",
      "cvssMetrics.v31.data.attackVector",
      "cvssMetrics.v31.data.attackComplexity",
      "cvssMetrics.v31.data.privilegesRequired",
      "cvssMetrics.v31.data.userInteraction",
      "cvssMetrics.v31.data.scope",
      "cvssMetrics.v31.data.confidentialityImpact",
      "cvssMetrics.v31.data.integrityImpact",
      "cvssMetrics.v31.data.availabilityImpact",
      "cvssMetrics.v31.exploitabilityScore",
      "cvssMetrics.v31.impactScore",
      "cvssMetrics.v31.source",
      "cvssMetrics.v31.type"
    ]
  },
  {
    name: "CVSS 2.0 Metrics",
    fields: [
      "cvssMetrics.v20.data.baseScore",
      "cvssMetrics.v20.data.baseSeverity",
      "cvssMetrics.v20.data.vectorString",
      "cvssMetrics.v20.data.accessVector",
      "cvssMetrics.v20.data.accessComplexity",
      "cvssMetrics.v20.data.authentication",
      "cvssMetrics.v20.data.confidentialityImpact",
      "cvssMetrics.v20.data.integrityImpact",
      "cvssMetrics.v20.data.availabilityImpact",
      "cvssMetrics.v20.exploitabilityScore",
      "cvssMetrics.v20.impactScore",
      "cvssMetrics.v20.source",
      "cvssMetrics.v20.type"
    ]
  },
  {
    name: "Impacted Products",
    fields: [
      "impactedProducts.vendor.name",
      "impactedProducts.vendor.slug",
      "impactedProducts.product.name",
      "impactedProducts.product.slug",
      "impactedProducts.versions",
      "impactedProducts.environments",
      "impactedProducts.vulnerable"
    ]
  },
  {
    name: "Assets & Products",
    fields: ["vendors", "vendorSlugs", "products", "productSlugs", "product_versions", "product_version_ids"]
  },
  {
    name: "Dates",
    fields: ["published", "ingested_at"]
  }
];
