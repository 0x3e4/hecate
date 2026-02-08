import { useState } from "react";
import { ParsedCvssMetric } from "../utils/cvss";
import { getCvssExplanation } from "../utils/cvssExplanations";

interface CvssMetricDisplayProps {
  metric: ParsedCvssMetric | null;
  compact?: boolean;
  showVector?: boolean;
  showScores?: boolean;
}

const HIDDEN_VALUES = new Set(["NOT DEFINED", "NOT_DEFINED", "X"]);

const CVSS_CALCULATOR_PATHS: Record<string, string> = {
  v40: "4-0",
  v31: "3.1",
  v30: "3.0",
  v20: "2.0",
};

const formatEnumValue = (value: string | null | undefined): string => {
  if (!value) {
    return "";
  }
  const normalized = value.toString().replace(/_/g, " ").trim();
  if (!normalized) {
    return "";
  }
  const upper = normalized.replace(/\s+/g, " ").toUpperCase();
  if (HIDDEN_VALUES.has(upper)) {
    return "";
  }
  return upper;
};

const formatScore = (value: number | null | undefined): string => {
  if (typeof value !== "number" || Number.isNaN(value)) {
    return "—";
  }
  return value.toFixed(1);
};

const normalizeVersion = (value: string | null | undefined): string | null => {
  if (!value) {
    return null;
  }
  const trimmed = value.trim();
  if (!trimmed) {
    return null;
  }
  const withoutPrefix = trimmed.startsWith("CVSS:") ? trimmed.slice(5) : trimmed;
  return withoutPrefix;
};

const buildCvssCalculatorUrl = (metric: ParsedCvssMetric): string | null => {
  const vector = metric.vectorString?.trim();
  if (!vector) {
    return null;
  }
  const directPath = CVSS_CALCULATOR_PATHS[metric.key];
  if (directPath) {
    return `https://www.first.org/cvss/calculator/${directPath}#${vector}`;
  }
  const normalizedVersion = normalizeVersion(metric.version);
  if (!normalizedVersion) {
    return null;
  }
  if (normalizedVersion === "4.0" || normalizedVersion === "4") {
    return `https://www.first.org/cvss/calculator/4-0#${vector}`;
  }
  if (normalizedVersion === "3.1") {
    return `https://www.first.org/cvss/calculator/3.1#${vector}`;
  }
  if (normalizedVersion === "3.0" || normalizedVersion === "3") {
    return `https://www.first.org/cvss/calculator/3.0#${vector}`;
  }
  if (normalizedVersion === "2.0" || normalizedVersion === "2") {
    return `https://www.first.org/cvss/calculator/2.0#${vector}`;
  }
  return null;
};

export const CvssMetricDisplay = ({
  metric,
  compact = false,
  showVector = true,
  showScores = true,
}: CvssMetricDisplayProps) => {
  const [selectedLabel, setSelectedLabel] = useState<string | null>(null);

  if (!metric) {
    return (
      <div className={`cvss-card ${compact ? "compact" : ""}`}>
        <div className="cvss-details">
          <div className="cvss-empty">Keine CVSS-Daten verfügbar.</div>
        </div>
        <div className="cvss-score-ring severity-unknown">
          <span className="cvss-score-value">—</span>
          <span className="cvss-score-label">Keine Daten</span>
          <span className="cvss-score-version">CVSS</span>
        </div>
      </div>
    );
  }

  const severity = metric.baseSeverity ?? "UNKNOWN";
  const severityClass = severity ? severity.toLowerCase() : "unknown";
  const severityLabel = formatEnumValue(severity);

  // Build version-aware attribute list
  const isV4 = metric.key === "v40" || metric.version?.startsWith("4");
  const isV3 = metric.key === "v31" || metric.key === "v30" || metric.version?.startsWith("3");
  const isV2 = metric.key === "v20" || metric.version?.startsWith("2");

  const attributes: Array<{ label: string; value: string | null | undefined }> = [];

  // Common base metrics for all versions
  attributes.push({ label: "Attack Vector", value: metric.attackVector });
  attributes.push({ label: "Attack Complexity", value: metric.attackComplexity });

  if (isV2) {
    // CVSS 2.0 uses Authentication instead of Privileges Required
    attributes.push({ label: "Authentication", value: metric.privilegesRequired });
  } else {
    // CVSS 4.0 has Attack Requirements as a base metric
    if (isV4) {
      attributes.push({ label: "Attack Requirements", value: metric.attackRequirements });
    }
    attributes.push({ label: "Privileges Required", value: metric.privilegesRequired });
    attributes.push({ label: "User Interaction", value: metric.userInteraction });
  }

  // Scope for CVSS 3.x
  if (isV3) {
    attributes.push({ label: "Scope", value: metric.scope });
  }

  // Impact metrics - label appropriately for each version
  if (isV4) {
    // CVSS 4.0: Vulnerable System impacts
    attributes.push({ label: "Vuln. Confidentiality", value: metric.confidentialityImpact });
    attributes.push({ label: "Vuln. Integrity", value: metric.integrityImpact });
    attributes.push({ label: "Vuln. Availability", value: metric.availabilityImpact });
    // CVSS 4.0: Subsequent System impacts
    attributes.push({ label: "Sub. Confidentiality", value: metric.subConfidentialityImpact });
    attributes.push({ label: "Sub. Integrity", value: metric.subIntegrityImpact });
    attributes.push({ label: "Sub. Availability", value: metric.subAvailabilityImpact });
  } else {
    attributes.push({ label: "Confidentiality Impact", value: metric.confidentialityImpact });
    attributes.push({ label: "Integrity Impact", value: metric.integrityImpact });
    attributes.push({ label: "Availability Impact", value: metric.availabilityImpact });
  }

  // Add version-specific additional attributes
  if (metric.additionalAttributes) {
    attributes.push(...metric.additionalAttributes);
  }

  const visibleAttributes = attributes
    .map((attribute) => {
      const displayValue = formatEnumValue(attribute.value ?? null);
      return displayValue
        ? {
            label: attribute.label,
            value: attribute.value,
            displayValue,
          }
        : null;
    })
    .filter((entry): entry is { label: string; value: string | null | undefined; displayValue: string } => entry !== null);

  const visibleItems = compact ? visibleAttributes.slice(0, 4) : visibleAttributes;
  const showVectorInfo = showVector && Boolean(metric.vectorString);
  const showSubscores = showScores && (metric.exploitabilityScore != null || metric.impactScore != null);
  const hasAnyDetails = visibleAttributes.length > 0 || showSubscores || showVectorInfo;
  const vectorLink = metric ? buildCvssCalculatorUrl(metric) : null;

  return (
    <div className={`cvss-card ${compact ? "compact" : ""}`}>
      <div className="cvss-details">
        {hasAnyDetails ? (
          <>
            {visibleItems.length > 0 && (
              <div className="cvss-badge-grid">
                {visibleItems.map((attribute) => {
                  const normalizedValue =
                    attribute.displayValue.toLowerCase().replace(/\s+/g, "_") || "unknown";
                  const isSelected = selectedLabel === attribute.label;
                  const explanation = isSelected
                    ? getCvssExplanation(attribute.label, attribute.displayValue)
                    : null;
                  return (
                    <div key={attribute.label}>
                      <div
                        className={`cvss-badge-row cvss-badge-row--clickable${isSelected ? " cvss-badge-row--active" : ""}`}
                        onClick={() => setSelectedLabel(isSelected ? null : attribute.label)}
                      >
                        <span className="cvss-badge-label">{attribute.label}</span>
                        <span className="cvss-badge-value" data-level={normalizedValue}>
                          {attribute.displayValue}
                        </span>
                      </div>
                      {isSelected && explanation && (
                        <div className="cvss-explanation">
                          <div className="cvss-explanation__metric">{explanation.metric}</div>
                          {explanation.value && (
                            <div className="cvss-explanation__value">
                              <strong>{attribute.displayValue}:</strong> {explanation.value}
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}

            {showSubscores && (
              <div className="cvss-subscores">
                {metric.exploitabilityScore != null && (
                  <span className="cvss-subscore">
                    Exploitability: {formatScore(metric.exploitabilityScore)}
                  </span>
                )}
                {metric.impactScore != null && (
                  <span className="cvss-subscore">Impact: {formatScore(metric.impactScore)}</span>
                )}
              </div>
            )}

            {showVectorInfo && (
              <div className="cvss-vector">
                <span className="cvss-badge-label">Vector</span>
                {vectorLink ? (
                  <a href={vectorLink} target="_blank" rel="noreferrer">
                    <code>{metric.vectorString}</code>
                  </a>
                ) : (
                  <code>{metric.vectorString}</code>
                )}
              </div>
            )}
          </>
        ) : (
          <div className="cvss-empty">{compact ? "Keine CVSS-Details" : "Keine Detaildaten vorhanden."}</div>
        )}
      </div>

      <div className={`cvss-score-ring severity-${severityClass}`}>
        <span className="cvss-score-value">{formatScore(metric.baseScore)}</span>
        <span className="cvss-score-label">{severityLabel}</span>
        <span className="cvss-score-version">{metric.label}</span>
      </div>
    </div>
  );
};
