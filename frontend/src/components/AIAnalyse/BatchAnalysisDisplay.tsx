import { useState } from "react";
import Markdown from "react-markdown";
import { AIBatchInvestigationResponse, VulnerabilityPreview } from "../../types";
import { useI18n } from "../../i18n/context";
import { AILoadingIndicator } from "../AILoadingIndicator";
import { formatDateTime } from "../../utils/dateFormat";

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
      <div className="batch-analysis-display">
        <AILoadingIndicator startedAt={loadingStartedAt} />
      </div>
    );
  }

  if (!response) {
    return (
      <div className="batch-analysis-display">
        <p className="muted">
          {t(
            "Select vulnerabilities and start the analysis to display results here.",
            "Wählen Sie Schwachstellen aus und starten Sie die Analyse, um die Ergebnisse hier anzuzeigen."
          )}
        </p>
      </div>
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

  return (
    <div className="batch-analysis-display">
      {/* Tab navigation */}
      <div className="batch-analysis-tabs">
        <button
          className={`batch-analysis-tab ${activeTab === "combined" ? "active" : ""}`}
          onClick={() => setActiveTab("combined")}
        >
          {t("Combined Analysis", "Kombinierte Analyse")}
        </button>
        {vulnerabilities.map((vuln) => (
          <button
            key={vuln.vulnId}
            className={`batch-analysis-tab ${activeTab === vuln.vulnId ? "active" : ""}`}
            onClick={() => setActiveTab(vuln.vulnId)}
          >
            {vuln.vulnId}
          </button>
        ))}
      </div>

      {/* Content area */}
      <div className="batch-analysis-content">
        <div className="ai-summary-text">
          <Markdown>{contentToDisplay}</Markdown>
          {typing && <span className="typing-cursor">▋</span>}
        </div>

        {/* Metadata footer */}
        {!typing && (
          <div className="ai-summary-meta">
            <span className="muted">
              Provider: <strong>{response.provider}</strong>
            </span>
            {" · "}
            <span className="muted">
              {t("Language", "Sprache")}: <strong>{response.language}</strong>
            </span>
            {" · "}
            <span className="muted">
              {t("Vulnerabilities", "Schwachstellen")}: <strong>{response.vulnerabilityCount.toLocaleString(locale)}</strong>
            </span>
            {" · "}
            <span className="muted">
              {t("Generated", "Erstellt")}: <strong>{formatDateTime(response.generatedAt)}</strong>
            </span>
            {response.tokenUsage && (
              <>
                {" · "}
                <span className="muted">
                  {t("Tokens", "Tokens")}: <strong>{response.tokenUsage.inputTokens.toLocaleString(locale)} in / {response.tokenUsage.outputTokens.toLocaleString(locale)} out</strong>
                </span>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
