import { ParsedCvssMetric } from "../utils/cvss";

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
  const attributes: Array<{ label: string; value: string | null | undefined }> = [
    { label: "Attack Vector", value: metric.attackVector },
    { label: "Attack Complexity", value: metric.attackComplexity },
    { label: "Privileges Required", value: metric.privilegesRequired },
    { label: "User Interaction", value: metric.userInteraction },
    { label: "Confidentiality Impact", value: metric.confidentialityImpact },
    { label: "Integrity Impact", value: metric.integrityImpact },
    { label: "Availability Impact", value: metric.availabilityImpact },
  ];
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
                  return (
                    <div key={attribute.label} className="cvss-badge-row">
                      <span className="cvss-badge-label">{attribute.label}</span>
                      <span className="cvss-badge-value" data-level={normalizedValue}>
                        {attribute.displayValue}
                      </span>
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
