export type FieldType = "string" | "number" | "boolean" | "date" | "array";

export interface DQLFieldHint {
  field: string;
  /** English description (default UI language). */
  description: string;
  /** German description, shown when the UI language is `de`. */
  descriptionDe: string;
  type: FieldType;
  aggregatable: boolean;
}

export const DQL_FIELD_HINTS: DQLFieldHint[] = [
  // Identification
  {
    field: "vuln_id",
    description: "ID (e.g. CVE or EUVD ID)",
    descriptionDe: "ID (z.B. CVE oder EUVD ID)",
    type: "string",
    aggregatable: true,
  },
  {
    field: "source",
    description: "Source name incl. all data sources (e.g. NVD, EUVD, CIRCL, GHSA)",
    descriptionDe: "Name der Quelle inkl. aller Datenquellen (z.B. NVD, EUVD, CIRCL, GHSA)",
    type: "string",
    aggregatable: true,
  },
  {
    field: "aliases",
    description: "Additional identifiers / aliases",
    descriptionDe: "Weitere Identifier / Aliasse",
    type: "array",
    aggregatable: true,
  },
  {
    field: "assigner",
    description: "Vulnerability assigner",
    descriptionDe: "Schwachstellen Auftraggeber",
    type: "string",
    aggregatable: true,
  },

  // Description
  {
    field: "title",
    description: "Entry title",
    descriptionDe: "Titel des Eintrags",
    type: "string",
    aggregatable: false,
  },
  {
    field: "summary",
    description: "Description text",
    descriptionDe: "Beschreibungstext",
    type: "string",
    aggregatable: false,
  },
  {
    field: "cwes",
    description: "CWE classification",
    descriptionDe: "CWE Klassifizierung",
    type: "array",
    aggregatable: true,
  },
  {
    field: "cpes",
    description: "CPE entries",
    descriptionDe: "CPE Einträge",
    type: "array",
    aggregatable: true,
  },

  // Impact & Scoring
  {
    field: "cvss.severity",
    description: "CVSS severity (e.g. critical, high, medium, low)",
    descriptionDe: "CVSS Severity (z.B. critical, high, medium, low)",
    type: "string",
    aggregatable: true,
  },
  {
    field: "cvss.base_score",
    description: "CVSS base score",
    descriptionDe: "CVSS Basisscore",
    type: "number",
    aggregatable: false,
  },
  {
    field: "epss_score",
    description: "EPSS score (0.00 - 100.00)",
    descriptionDe: "EPSS Score (0.00 - 100.00)",
    type: "number",
    aggregatable: false,
  },
  {
    field: "exploited",
    description: "True/false for active exploitation (KEV)",
    descriptionDe: "True/False für aktive Exploitation (KEV)",
    type: "boolean",
    aggregatable: true,
  },
  {
    field: "rejected",
    description: "True/false for rejected vulnerabilities",
    descriptionDe: "True/False für abgelehnte Schwachstellen",
    type: "boolean",
    aggregatable: true,
  },

  // CVSS 4.0
  {
    field: "cvssMetrics.v40.data.baseScore",
    description: "CVSS 4.0 base score",
    descriptionDe: "CVSS 4.0 Basisscore",
    type: "number",
    aggregatable: false,
  },
  {
    field: "cvssMetrics.v40.data.baseSeverity",
    description: "CVSS 4.0 severity",
    descriptionDe: "CVSS 4.0 Severity",
    type: "string",
    aggregatable: true,
  },
  {
    field: "cvssMetrics.v40.data.vectorString",
    description: "CVSS 4.0 vector",
    descriptionDe: "CVSS 4.0 Vektor",
    type: "string",
    aggregatable: false,
  },
  {
    field: "cvssMetrics.v40.data.attackVector",
    description: "CVSS 4.0 attack vector",
    descriptionDe: "CVSS 4.0 Angriffsvektor",
    type: "string",
    aggregatable: true,
  },
  {
    field: "cvssMetrics.v40.data.attackComplexity",
    description: "CVSS 4.0 attack complexity",
    descriptionDe: "CVSS 4.0 Angriffskomplexität",
    type: "string",
    aggregatable: true,
  },
  {
    field: "cvssMetrics.v40.data.attackRequirements",
    description: "CVSS 4.0 attack requirements",
    descriptionDe: "CVSS 4.0 Angriffsvoraussetzungen",
    type: "string",
    aggregatable: true,
  },
  {
    field: "cvssMetrics.v40.data.privilegesRequired",
    description: "CVSS 4.0 privileges required",
    descriptionDe: "CVSS 4.0 benötigte Privilegien",
    type: "string",
    aggregatable: true,
  },
  {
    field: "cvssMetrics.v40.data.userInteraction",
    description: "CVSS 4.0 user interaction",
    descriptionDe: "CVSS 4.0 Benutzerinteraktion",
    type: "string",
    aggregatable: true,
  },
  {
    field: "cvssMetrics.v40.data.confidentialityImpact",
    description: "CVSS 4.0 confidentiality",
    descriptionDe: "CVSS 4.0 Vertraulichkeit",
    type: "string",
    aggregatable: true,
  },
  {
    field: "cvssMetrics.v40.data.integrityImpact",
    description: "CVSS 4.0 integrity",
    descriptionDe: "CVSS 4.0 Integrität",
    type: "string",
    aggregatable: true,
  },
  {
    field: "cvssMetrics.v40.data.availabilityImpact",
    description: "CVSS 4.0 availability",
    descriptionDe: "CVSS 4.0 Verfügbarkeit",
    type: "string",
    aggregatable: true,
  },
  {
    field: "cvssMetrics.v40.exploitabilityScore",
    description: "CVSS 4.0 exploitability score",
    descriptionDe: "CVSS 4.0 Exploitability Score",
    type: "number",
    aggregatable: false,
  },
  {
    field: "cvssMetrics.v40.impactScore",
    description: "CVSS 4.0 impact score",
    descriptionDe: "CVSS 4.0 Impact Score",
    type: "number",
    aggregatable: false,
  },
  {
    field: "cvssMetrics.v40.source",
    description: "CVSS 4.0 source",
    descriptionDe: "CVSS 4.0 Quelle",
    type: "string",
    aggregatable: true,
  },
  {
    field: "cvssMetrics.v40.type",
    description: "CVSS 4.0 type (Primary/Secondary)",
    descriptionDe: "CVSS 4.0 Typ (Primary/Secondary)",
    type: "string",
    aggregatable: true,
  },

  // CVSS 3.x
  {
    field: "cvssMetrics.v31.data.baseScore",
    description: "CVSS 3.x base score",
    descriptionDe: "CVSS 3.x Basisscore",
    type: "number",
    aggregatable: false,
  },
  {
    field: "cvssMetrics.v31.data.baseSeverity",
    description: "CVSS 3.x severity",
    descriptionDe: "CVSS 3.x Severity",
    type: "string",
    aggregatable: true,
  },
  {
    field: "cvssMetrics.v31.data.vectorString",
    description: "CVSS 3.x vector",
    descriptionDe: "CVSS 3.x Vektor",
    type: "string",
    aggregatable: false,
  },
  {
    field: "cvssMetrics.v31.data.attackVector",
    description: "CVSS 3.x attack vector",
    descriptionDe: "CVSS 3.x Angriffsvektor",
    type: "string",
    aggregatable: true,
  },
  {
    field: "cvssMetrics.v31.data.attackComplexity",
    description: "CVSS 3.x attack complexity",
    descriptionDe: "CVSS 3.x Angriffskomplexität",
    type: "string",
    aggregatable: true,
  },
  {
    field: "cvssMetrics.v31.data.privilegesRequired",
    description: "CVSS 3.x privileges required",
    descriptionDe: "CVSS 3.x benötigte Privilegien",
    type: "string",
    aggregatable: true,
  },
  {
    field: "cvssMetrics.v31.data.userInteraction",
    description: "CVSS 3.x user interaction",
    descriptionDe: "CVSS 3.x Benutzerinteraktion",
    type: "string",
    aggregatable: true,
  },
  {
    field: "cvssMetrics.v31.data.scope",
    description: "CVSS 3.x scope (UNCHANGED/CHANGED)",
    descriptionDe: "CVSS 3.x Scope (UNCHANGED/CHANGED)",
    type: "string",
    aggregatable: true,
  },
  {
    field: "cvssMetrics.v31.data.confidentialityImpact",
    description: "CVSS 3.x confidentiality",
    descriptionDe: "CVSS 3.x Vertraulichkeit",
    type: "string",
    aggregatable: true,
  },
  {
    field: "cvssMetrics.v31.data.integrityImpact",
    description: "CVSS 3.x integrity",
    descriptionDe: "CVSS 3.x Integrität",
    type: "string",
    aggregatable: true,
  },
  {
    field: "cvssMetrics.v31.data.availabilityImpact",
    description: "CVSS 3.x availability",
    descriptionDe: "CVSS 3.x Verfügbarkeit",
    type: "string",
    aggregatable: true,
  },
  {
    field: "cvssMetrics.v31.exploitabilityScore",
    description: "CVSS 3.x exploitability score",
    descriptionDe: "CVSS 3.x Exploitability Score",
    type: "number",
    aggregatable: false,
  },
  {
    field: "cvssMetrics.v31.impactScore",
    description: "CVSS 3.x impact score",
    descriptionDe: "CVSS 3.x Impact Score",
    type: "number",
    aggregatable: false,
  },
  {
    field: "cvssMetrics.v31.source",
    description: "CVSS 3.x source",
    descriptionDe: "CVSS 3.x Quelle",
    type: "string",
    aggregatable: true,
  },
  {
    field: "cvssMetrics.v31.type",
    description: "CVSS 3.x type (Primary/Secondary)",
    descriptionDe: "CVSS 3.x Typ (Primary/Secondary)",
    type: "string",
    aggregatable: true,
  },

  // CVSS 2.0
  {
    field: "cvssMetrics.v20.data.baseScore",
    description: "CVSS 2.0 base score",
    descriptionDe: "CVSS 2.0 Basisscore",
    type: "number",
    aggregatable: false,
  },
  {
    field: "cvssMetrics.v20.data.baseSeverity",
    description: "CVSS 2.0 severity",
    descriptionDe: "CVSS 2.0 Severity",
    type: "string",
    aggregatable: true,
  },
  {
    field: "cvssMetrics.v20.data.vectorString",
    description: "CVSS 2.0 vector",
    descriptionDe: "CVSS 2.0 Vektor",
    type: "string",
    aggregatable: false,
  },
  {
    field: "cvssMetrics.v20.data.accessVector",
    description: "CVSS 2.0 access vector",
    descriptionDe: "CVSS 2.0 Angriffsvektor",
    type: "string",
    aggregatable: true,
  },
  {
    field: "cvssMetrics.v20.data.accessComplexity",
    description: "CVSS 2.0 access complexity",
    descriptionDe: "CVSS 2.0 Zugriffskomplexität",
    type: "string",
    aggregatable: true,
  },
  {
    field: "cvssMetrics.v20.data.authentication",
    description: "CVSS 2.0 authentication",
    descriptionDe: "CVSS 2.0 Authentifizierung",
    type: "string",
    aggregatable: true,
  },
  {
    field: "cvssMetrics.v20.data.confidentialityImpact",
    description: "CVSS 2.0 confidentiality",
    descriptionDe: "CVSS 2.0 Vertraulichkeit",
    type: "string",
    aggregatable: true,
  },
  {
    field: "cvssMetrics.v20.data.integrityImpact",
    description: "CVSS 2.0 integrity",
    descriptionDe: "CVSS 2.0 Integrität",
    type: "string",
    aggregatable: true,
  },
  {
    field: "cvssMetrics.v20.data.availabilityImpact",
    description: "CVSS 2.0 availability",
    descriptionDe: "CVSS 2.0 Verfügbarkeit",
    type: "string",
    aggregatable: true,
  },
  {
    field: "cvssMetrics.v20.exploitabilityScore",
    description: "CVSS 2.0 exploitability score",
    descriptionDe: "CVSS 2.0 Exploitability Score",
    type: "number",
    aggregatable: false,
  },
  {
    field: "cvssMetrics.v20.impactScore",
    description: "CVSS 2.0 impact score",
    descriptionDe: "CVSS 2.0 Impact Score",
    type: "number",
    aggregatable: false,
  },
  {
    field: "cvssMetrics.v20.source",
    description: "CVSS 2.0 source",
    descriptionDe: "CVSS 2.0 Quelle",
    type: "string",
    aggregatable: true,
  },
  {
    field: "cvssMetrics.v20.type",
    description: "CVSS 2.0 type (Primary/Secondary)",
    descriptionDe: "CVSS 2.0 Typ (Primary/Secondary)",
    type: "string",
    aggregatable: true,
  },

  // Impacted Products (nested)
  {
    field: "impactedProducts.vendor.name",
    description: "Affected vendor (name)",
    descriptionDe: "Betroffener Hersteller (Name)",
    type: "string",
    aggregatable: false,
  },
  {
    field: "impactedProducts.vendor.slug",
    description: "Affected vendor (slug)",
    descriptionDe: "Betroffener Hersteller (Slug)",
    type: "string",
    aggregatable: false,
  },
  {
    field: "impactedProducts.product.name",
    description: "Affected product (name)",
    descriptionDe: "Betroffenes Produkt (Name)",
    type: "string",
    aggregatable: false,
  },
  {
    field: "impactedProducts.product.slug",
    description: "Affected product (slug)",
    descriptionDe: "Betroffenes Produkt (Slug)",
    type: "string",
    aggregatable: false,
  },
  {
    field: "impactedProducts.versions",
    description: "Affected versions",
    descriptionDe: "Betroffene Versionen",
    type: "array",
    aggregatable: false,
  },
  {
    field: "impactedProducts.environments",
    description: "Affected environments",
    descriptionDe: "Betroffene Umgebungen",
    type: "array",
    aggregatable: false,
  },
  {
    field: "impactedProducts.vulnerable",
    description: "Vulnerable (true/false)",
    descriptionDe: "Verwundbar (true/false)",
    type: "boolean",
    aggregatable: false,
  },

  // Assets & Products
  {
    field: "vendors",
    description: "List of affected vendors",
    descriptionDe: "Liste der betroffenen Hersteller",
    type: "array",
    aggregatable: true,
  },
  {
    field: "vendorSlugs",
    description: "Vendor slugs (normalised, e.g. fortinet)",
    descriptionDe: "Hersteller-Slugs (normalisiert, z.B. fortinet)",
    type: "array",
    aggregatable: true,
  },
  {
    field: "products",
    description: "List of products",
    descriptionDe: "Liste der Produkte",
    type: "array",
    aggregatable: true,
  },
  {
    field: "productSlugs",
    description: "Product slugs (normalised, e.g. fortiswitch)",
    descriptionDe: "Produkt-Slugs (normalisiert, z.B. fortiswitch)",
    type: "array",
    aggregatable: true,
  },
  {
    field: "product_versions",
    description: "Product versions (text, exact match on the given string)",
    descriptionDe: "Produktversionen (Text, exakter Treffer auf die genannte Zeichenkette)",
    type: "array",
    aggregatable: true,
  },
  {
    field: "product_version_ids",
    description: "Product version IDs from the catalog",
    descriptionDe: "Produktversions-IDs aus dem Katalog",
    type: "array",
    aggregatable: true,
  },
  {
    field: "affectedVersion",
    description:
      "Version you run (e.g. 7.0.1) – also matches advisories that only cover the version as a range",
    descriptionDe:
      "Version, die du einsetzt (z.B. 7.0.1) – trifft auch Advisories, die die Version nur als Bereich abdecken",
    type: "string",
    aggregatable: false,
  },

  // Dates
  {
    field: "published",
    description: "Publication date (e.g. 2025-11-03)",
    descriptionDe: "Datum der Veröffentlichung (z.B. 2025-11-03)",
    type: "date",
    aggregatable: false,
  },
  {
    field: "ingested_at",
    description: "Ingestion date (e.g. 2025-11-03)",
    descriptionDe: "Datum des Imports (z.B. 2025-11-03)",
    type: "date",
    aggregatable: false,
  },
];

export interface FieldCategory {
  /** Stable identifier (also the English display label). */
  name: string;
  /** German display label, shown when the UI language is `de`. */
  nameDe: string;
  fields: string[];
}

export const FIELD_CATEGORIES: FieldCategory[] = [
  {
    name: "Identification",
    nameDe: "Identifikation",
    fields: ["vuln_id", "source", "aliases", "assigner"]
  },
  {
    name: "Description",
    nameDe: "Beschreibung",
    fields: ["title", "summary", "cwes", "cpes"]
  },
  {
    name: "Impact & Scoring",
    nameDe: "Auswirkung & Bewertung",
    fields: ["cvss.severity", "cvss.base_score", "epss_score", "exploited", "rejected"]
  },
  {
    name: "CVSS 4.0 Metrics",
    nameDe: "CVSS 4.0 Metriken",
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
    nameDe: "CVSS 3.x Metriken",
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
    nameDe: "CVSS 2.0 Metriken",
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
    nameDe: "Betroffene Produkte",
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
    nameDe: "Assets & Produkte",
    fields: [
      "vendors",
      "vendorSlugs",
      "products",
      "productSlugs",
      "product_versions",
      "product_version_ids",
      "affectedVersion"
    ]
  },
  {
    name: "Dates",
    nameDe: "Daten",
    fields: ["published", "ingested_at"]
  }
];
