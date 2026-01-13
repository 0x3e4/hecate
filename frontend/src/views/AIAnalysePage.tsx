import { useState, useEffect, useRef, useCallback } from "react";
import { getAiProviders, listBatchAnalyses, requestBatchAiInvestigation } from "../api/vulnerabilities";
import {
  AIBatchInvestigationResponse,
  AIProviderId,
  AIProviderInfo,
  BatchAnalysisItem,
  VulnerabilityPreview,
} from "../types";
import { VulnerabilitySelector } from "../components/AIAnalyse/VulnerabilitySelector";
import { BatchAnalysisDisplay } from "../components/AIAnalyse/BatchAnalysisDisplay";

export const AIAnalysePage = () => {
  const [selectedVulnIds, setSelectedVulnIds] = useState<string[]>([]);
  const [selectedProvider, setSelectedProvider] = useState<AIProviderId | null>(null);
  const [additionalContext, setAdditionalContext] = useState<string>("");
  const [aiProviders, setAiProviders] = useState<AIProviderInfo[]>([]);
  const [loading, setLoading] = useState<boolean>(false);
  const [response, setResponse] = useState<AIBatchInvestigationResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [typing, setTyping] = useState<boolean>(false);
  const [displayText, setDisplayText] = useState<string>("");
  const [batchHistory, setBatchHistory] = useState<BatchAnalysisItem[]>([]);
  const [batchHistoryLoading, setBatchHistoryLoading] = useState<boolean>(false);
  const [batchHistoryError, setBatchHistoryError] = useState<string | null>(null);

  const shouldAnimateSummaryRef = useRef(false);
  const typingIntervalRef = useRef<number | null>(null);

  // Set document title
  useEffect(() => {
    document.title = "Hecate Cyber Defense - AI-Analyse";
    return () => {
      document.title = "Hecate Cyber Defense";
    };
  }, []);

  // Load AI providers on mount
  useEffect(() => {
    const loadProviders = async () => {
      try {
        const providers = await getAiProviders();
        setAiProviders(providers);
        if (providers.length > 0 && !selectedProvider) {
          setSelectedProvider(providers[0].id);
        }
      } catch (err) {
        console.error("Failed to load AI providers:", err);
      }
    };
    loadProviders();
  }, []);

  const loadBatchHistory = useCallback(async () => {
    setBatchHistoryLoading(true);
    setBatchHistoryError(null);
    try {
      const data = await listBatchAnalyses({ limit: 10, offset: 0 });
      setBatchHistory(data.items || []);
    } catch (err) {
      console.error("Failed to load batch analyses:", err);
      setBatchHistoryError("Batch-Analysen konnten nicht geladen werden.");
    } finally {
      setBatchHistoryLoading(false);
    }
  }, []);

  useEffect(() => {
    loadBatchHistory();
  }, [loadBatchHistory]);

  // Typing animation effect
  useEffect(() => {
    if (!response || !shouldAnimateSummaryRef.current) {
      return;
    }

    setTyping(true);
    setDisplayText("");

    const fullText = response.summary;
    let currentIndex = 0;

    const typeNextChar = () => {
      if (currentIndex < fullText.length) {
        currentIndex += 1;
        setDisplayText(fullText.slice(0, currentIndex));
      } else {
        // Animation complete
        setTyping(false);
        shouldAnimateSummaryRef.current = false;
        if (typingIntervalRef.current !== null) {
          clearInterval(typingIntervalRef.current);
          typingIntervalRef.current = null;
        }
      }
    };

    // Call immediately to show first character without delay
    typeNextChar();
    typingIntervalRef.current = window.setInterval(typeNextChar, 3);

    return () => {
      if (typingIntervalRef.current !== null) {
        clearInterval(typingIntervalRef.current);
        typingIntervalRef.current = null;
      }
    };
  }, [response]);

  const handleRunAnalysis = async () => {
    if (!selectedProvider) {
      setError("Bitte wählen Sie einen AI-Provider aus.");
      return;
    }

    if (selectedVulnIds.length === 0) {
      setError("Bitte wählen Sie mindestens eine Schwachstelle aus.");
      return;
    }

    setError(null);
    setLoading(true);
    setResponse(null);
    shouldAnimateSummaryRef.current = true;

    try {
      const result = await requestBatchAiInvestigation({
        vulnerabilityIds: selectedVulnIds,
        provider: selectedProvider,
        language: "de",
        additionalContext: additionalContext.trim() || null,
      });

      setResponse(result);
      await loadBatchHistory();
    } catch (err: any) {
      console.error("AI analysis failed:", err);

      // Handle specific error cases
      if (err.response?.status === 429) {
        setError(
          "API-Kontingent erschöpft. Bitte versuchen Sie es später erneut oder wenden Sie sich an Ihren Administrator."
        );
      } else if (err.response?.status === 404) {
        setError("Eine oder mehrere Schwachstellen wurden nicht gefunden.");
      } else if (err.response?.data?.detail) {
        setError(err.response.data.detail);
      } else {
        setError("Fehler bei der AI-Analyse. Bitte versuchen Sie es erneut.");
      }
      shouldAnimateSummaryRef.current = false;
    } finally {
      setLoading(false);
    }
  };

  // Get vulnerability preview objects for display
  // Note: We only have IDs, so we create minimal preview objects
  const selectedVulnerabilities: VulnerabilityPreview[] = selectedVulnIds.map((id) => ({
    vulnId: id,
    title: "",
    summary: "",
    severity: null,
    cvssScore: null,
    epssScore: null,
    published: null,
  }));

  const hasAiProviders = aiProviders.length > 0;
  const providerLabelMap = new Map(aiProviders.map((provider) => [provider.id, provider.label]));

  return (
    <div className="page ai-analyse-page">
      <section className="card">
        <h2>AI-Analyse</h2>
        <p className="muted">
          Wählen Sie mehrere Schwachstellen für eine kombinierte KI-Analyse aus.
          Die KI identifiziert Zusammenhänge, gemeinsame Angriffsvektoren und priorisiert Ihre Maßnahmen.
        </p>

        {!hasAiProviders ? (
          <div className="alert alert-warning" style={{ marginTop: "1.5rem" }}>
            Keine AI-Provider konfiguriert. Bitte konfigurieren Sie mindestens einen AI-Provider in den Systemeinstellungen.
          </div>
        ) : (
          <div className="ai-analyse-layout">
            {/* Left column: Vulnerability selector */}
            <div className="ai-analyse-left">
              <VulnerabilitySelector
                selectedIds={selectedVulnIds}
                onSelectionChange={setSelectedVulnIds}
                maxSelection={10}
              />
            </div>

            {/* Right column: Controls and display */}
            <div className="ai-analyse-right">
              {/* Controls */}
              <div className="ai-analyse-controls">
                <div className="form-group">
                  <label htmlFor="ai-provider">AI-Provider</label>
                  <select
                    id="ai-provider"
                    value={selectedProvider || ""}
                    onChange={(e) => setSelectedProvider(e.target.value as AIProviderId)}
                    disabled={loading}
                  >
                    {aiProviders.map((provider) => (
                      <option key={provider.id} value={provider.id}>
                        {provider.label}
                      </option>
                    ))}
                  </select>
                </div>

                <div className="form-group">
                  <label htmlFor="additional-context">
                    Zusätzlicher Kontext (optional)
                  </label>
                  <textarea
                    id="additional-context"
                    rows={3}
                    value={additionalContext}
                    onChange={(e) => setAdditionalContext(e.target.value)}
                    placeholder="z.B. spezifische Versionen, Umgebungsdetails, besondere Anforderungen..."
                    disabled={loading}
                  />
                </div>

                <button
                  className="btn btn-primary"
                  onClick={handleRunAnalysis}
                  disabled={loading || selectedVulnIds.length === 0}
                  style={{ width: "100%" }}
                >
                  {loading ? "Analyse läuft..." : "Analyse starten"}
                </button>

                {error && (
                  <div className="alert alert-error" style={{ marginTop: "1rem" }}>
                    {error}
                  </div>
                )}
              </div>

              {/* Analysis display */}
              <BatchAnalysisDisplay
                response={response}
                vulnerabilities={selectedVulnerabilities}
                loading={loading}
                typing={typing}
                displayText={displayText}
              />
            </div>
          </div>
        )}
      </section>

      <section className="card">
        <h2>Batch-Analyse Verlauf</h2>
        <p className="muted">
          Übersicht der letzten kombinierten AI-Analysen.
        </p>

        {batchHistoryLoading && (
          <div className="muted">Batch-Analysen werden geladen...</div>
        )}
        {batchHistoryError && (
          <div className="alert alert-error" style={{ marginTop: "1rem" }}>
            {batchHistoryError}
          </div>
        )}
        {!batchHistoryLoading && !batchHistoryError && batchHistory.length === 0 && (
          <div className="muted">Keine Batch-Analysen vorhanden.</div>
        )}
        {!batchHistoryLoading && !batchHistoryError && batchHistory.length > 0 && (
          <div className="ai-analysis__batch-list">
            {batchHistory.map((batch) => {
              const providerLabel = providerLabelMap.get(batch.provider) ?? batch.provider;
              const summary = (batch.summary || "").trim();
              const summaryPreview = summary.length > 320 ? `${summary.slice(0, 320)}...` : summary;
              return (
                <div key={batch.batch_id} className="ai-analysis__batch-card">
                  <div className="ai-analysis__batch-header">
                    <span className="ai-analysis__batch-id">{batch.batch_id}</span>
                    <span className="muted" style={{ fontSize: "0.85rem" }}>
                      {batch.vulnerability_count} Schwachstellen
                    </span>
                  </div>
                  {summaryPreview ? (
                    <div className="ai-analysis__text">
                      {summaryPreview}
                    </div>
                  ) : (
                    <div className="muted">Keine Zusammenfassung verfügbar.</div>
                  )}
                  {batch.vulnerability_ids?.length > 0 && (
                    <div className="vuln-aliases" style={{ marginTop: "0.75rem" }}>
                      {batch.vulnerability_ids.map((id) => (
                        <span key={`${batch.batch_id}-${id}`} className="chip">
                          {id}
                        </span>
                      ))}
                    </div>
                  )}
                  {(providerLabel || batch.language || batch.timestamp) && (
                    <div className="ai-analysis__meta">
                      {providerLabel && <span>{providerLabel}</span>}
                      {batch.language && <span> · Sprache: {batch.language.toUpperCase()}</span>}
                      {batch.timestamp && <span> · {new Date(batch.timestamp).toLocaleString()}</span>}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </section>
    </div>
  );
};
