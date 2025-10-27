import { ParsedCvssMetric } from "../utils/cvss";

interface CvssMetricDisplayProps {
  metric: ParsedCvssMetric | null;
  compact?: boolean;
  showVector?: boolean;
  showScores?: boolean;
}

const formatEnumValue = (value: string | null | undefined): string => {
  if (!value) {
    return "";
  }
  return value
    .toString()
    .toLowerCase()
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
};

const formatScore = (value: number | null | undefined): string => {
  if (typeof value !== "number" || Number.isNaN(value)) {
    return "—";
  }
  return value.toFixed(1);
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
        <div className="cvss-score-ring">
          <span className="cvss-score-value">—</span>
          <span className="cvss-score-label">Keine Daten</span>
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
  const visibleAttributes = attributes.filter((attribute) => !!formatEnumValue(attribute.value));
  const showVectorInfo = showVector && Boolean(metric.vectorString);
  const showSubscores = showScores && (metric.exploitabilityScore != null || metric.impactScore != null);

  return (
    <div className={`cvss-card ${compact ? "compact" : ""}`}>
      <div className={`cvss-score-ring severity-${severityClass}`}>
        <span className="cvss-score-value">{formatScore(metric.baseScore)}</span>
        <span className="cvss-score-label">{severityLabel}</span>
        <span className="cvss-score-version">{metric.label}</span>
      </div>

      <div className="cvss-details">
        {visibleAttributes.length > 0 && (
          <div className="cvss-badge-grid">
            {visibleAttributes.map((attribute) => {
              const normalizedValue = (attribute.value ?? "")
                .toString()
                .trim()
                .toLowerCase()
                .replace(/\s+/g, "_");
              return (
                <div key={attribute.label} className="cvss-badge-row">
                  <span className="cvss-badge-label">{attribute.label}</span>
                  <span className="cvss-badge-value" data-level={normalizedValue}>
                    {formatEnumValue(attribute.value)}
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
            <code>{metric.vectorString}</code>
          </div>
        )}
      </div>
    </div>
  );
};
