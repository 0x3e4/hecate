import { useState } from "react";
import { AIBatchInvestigationResponse, VulnerabilityPreview } from "../../types";
import { useI18n } from "../../i18n/context";
import { AILoadingIndicator } from "../AILoadingIndicator";
import { formatDateTime } from "../../utils/dateFormat";
import { ReportMarkdown, ReportMeta } from "./ReportParts";

interface BatchAnalysisDisplayProps {
  response: AIBatchInvestigationResponse | null;
  vulnerabilities: VulnerabilityPreview[];
  loading: boolean;
  loadingStartedAt?: number;
  typing: boolean;
  displayText: string;
}

type TabKey = "combined" | string; // "combined" or vulnerability ID

export const BatchAnalysisDisplay = ({
  response,
  vulnerabilities,
  loading,
  loadingStartedAt,
  typing,
  displayText,
}: BatchAnalysisDisplayProps) => {
  const { t, locale } = useI18n();
  const [activeTab, setActiveTab] = useState<TabKey>("combined");
  const normalizeId = (value: string) => value.trim().toUpperCase();
  const resolveIndividualSummary = (id: string) => {
    if (!response) {
      return null;
    }
    const direct = response.individualSummaries[id];
    if (typeof direct === "string" && direct.trim()) {
      return direct;
    }
    const normalized = normalizeId(id);
    const match = Object.entries(response.individualSummaries).find(
      ([key, value]) => normalizeId(key) === normalized && typeof value === "string" && value.trim()
    );
    return match?.[1] ?? null;
  };
  const combinedIncludesIndividuals = response
    ? /##\s+Individual Vulnerability Notes/i.test(response.summary) ||
      vulnerabilities.some((vuln) => response.summary.includes(`### ${vuln.vulnId}`))
    : false;

  if (loading) {
    return (
      <div className="ai-analyse-result">
        <AILoadingIndicator startedAt={loadingStartedAt} />
      </div>
    );
  }

  if (!response) {
    return (
      <p className="ai-analyse-result-idle">
        {t(
          "Select vulnerabilities and start the analysis to display results here.",
          "Wählen Sie Schwachstellen aus und starten Sie die Analyse, um die Ergebnisse hier anzuzeigen."
        )}
      </p>
    );
  }

  // Determine what content to show
  let contentToDisplay = "";
  if (typing) {
    // During typing animation, show displayText
    contentToDisplay = displayText;
  } else {
    // After typing is done, show the appropriate content based on active tab
    if (activeTab === "combined") {
      contentToDisplay = response.summary;
      if (response && !combinedIncludesIndividuals) {
        const individualNotes = vulnerabilities
          .map((vuln) => {
            const note = resolveIndividualSummary(vuln.vulnId);
            if (!note) {
              return null;
            }
            return `### ${vuln.vulnId}\n${note}`;
          })
          .filter(Boolean)
          .join("\n\n");
        if (individualNotes) {
          contentToDisplay += `\n\n---\n\n## Individual Vulnerability Notes\n\n${individualNotes}`;
        }
      }
    } else {
      contentToDisplay = resolveIndividualSummary(activeTab) || t("No analysis available", "Keine Analyse verfügbar");
    }
  }

  const metaRows = [
    { label: t("Provider", "Provider"), value: response.provider },
    { label: t("Language", "Sprache"), value: response.language },
    { label: t("Vulnerabilities", "Schwachstellen"), value: response.vulnerabilityCount.toLocaleString(locale) },
    { label: t("Generated", "Erstellt"), value: formatDateTime(response.generatedAt) },
    ...(response.tokenUsage
      ? [
          {
            label: t("Tokens", "Tokens"),
            value: `${response.tokenUsage.inputTokens.toLocaleString(locale)} in / ${response.tokenUsage.outputTokens.toLocaleString(locale)} out`,
          },
        ]
      : []),
  ];

  return (
    <div className="ai-analyse-result">
      <h3 className="visually-hidden">
        {activeTab === "combined" ? t("Combined analysis", "Kombinierte Analyse") : activeTab}
      </h3>

      {/* Tab navigation */}
      <div className="ai-analyse-tabs">
        <button
          type="button"
          className={`ai-analyse-tab${activeTab === "combined" ? " ai-analyse-tab--active" : ""}`}
          aria-pressed={activeTab === "combined"}
          onClick={() => setActiveTab("combined")}
        >
          {t("Combined analysis", "Kombinierte Analyse")}
        </button>
        {vulnerabilities.map((vuln) => (
          <button
            type="button"
            key={vuln.vulnId}
            className={`ai-analyse-tab mono${activeTab === vuln.vulnId ? " ai-analyse-tab--active" : ""}`}
            aria-pressed={activeTab === vuln.vulnId}
            onClick={() => setActiveTab(vuln.vulnId)}
          >
            {vuln.vulnId}
          </button>
        ))}
      </div>

      {/* Content area */}
      <ReportMarkdown>{contentToDisplay}</ReportMarkdown>

      {/* Metadata footer */}
      {!typing && (
        <div className="ai-analyse-result-meta">
          <ReportMeta rows={metaRows} />
        </div>
      )}
    </div>
  );
};
