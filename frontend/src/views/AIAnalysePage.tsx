import { useState, useEffect, useRef, useCallback } from "react";
import { Link } from "react-router-dom";
import Markdown from "react-markdown";
import {
  getAiProviders,
  listBatchAnalyses,
  listSingleAiAnalyses,
  requestBatchAiInvestigation,
  triggerVulnerabilityRefresh,
  type SingleAnalysisItem,
} from "../api/vulnerabilities";
import { api } from "../api/client";
import {
  AIBatchInvestigationResponse,
  AIProviderId,
  AIProviderInfo,
  BatchAnalysisItem,
  VulnerabilityPreview,
} from "../types";
import { VulnerabilitySelector } from "../components/AIAnalyse/VulnerabilitySelector";
import { BatchAnalysisDisplay } from "../components/AIAnalyse/BatchAnalysisDisplay";
import { useI18n } from "../i18n/context";
import { usePersistentState } from "../hooks/usePersistentState";

export const AIAnalysePage = () => {
  const { t, locale } = useI18n();

  // --- Page-level auth gate ---
  const [authRequired, setAuthRequired] = useState<boolean | null>(null);
  const [authOk, setAuthOk] = useState(false);
  const [authPassword, setAuthPassword] = useState("");
  const [authError, setAuthError] = useState("");
  const [authChecking, setAuthChecking] = useState(false);

  useEffect(() => {
    api.get<{ required: boolean }>("/v1/status/ai-auth").then((r) => {
      setAuthRequired(r.data.required);
      if (!r.data.required) setAuthOk(true);
    }).catch(() => {
      setAuthRequired(false);
      setAuthOk(true);
    });
  }, []);

  const handleAuthSubmit = async () => {
    setAuthChecking(true);
    setAuthError("");
    try {
      const r = await api.post<{ authenticated: boolean }>("/v1/status/ai-auth", { password: authPassword });
      if (r.data.authenticated) {
        setAuthOk(true);
        setAiAnalysisPassword(authPassword);
      }
    } catch {
      setAuthError(t("Invalid password.", "Falsches Passwort."));
    } finally {
      setAuthChecking(false);
    }
  };

  const [selectedVulnIds, setSelectedVulnIds] = useState<string[]>([]);
  const [selectedProvider, setSelectedProvider] = useState<AIProviderId | null>(null);
  const [aiAnalysisPassword, setAiAnalysisPassword] = usePersistentState<string>("ai_analysis_password", "");
  const [additionalContext, setAdditionalContext] = useState<string>("");
  const [aiProviders, setAiProviders] = useState<AIProviderInfo[]>([]);
  const [loading, setLoading] = useState<boolean>(false);
  const [response, setResponse] = useState<AIBatchInvestigationResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [typing, setTyping] = useState<boolean>(false);
  const [displayText, setDisplayText] = useState<string>("");
  const [batchHistory, setBatchHistory] = useState<BatchAnalysisItem[]>([]);
  const [singleHistory, setSingleHistory] = useState<SingleAnalysisItem[]>([]);
  const [historyLoading, setHistoryLoading] = useState<boolean>(false);
  const [historyError, setHistoryError] = useState<string | null>(null);
  const [historyPage, setHistoryPage] = useState<number>(0);
  const [batchTotal, setBatchTotal] = useState<number>(0);
  const [singleTotal, setSingleTotal] = useState<number>(0);

  const HISTORY_PAGE_SIZE = 20;

  const shouldAnimateSummaryRef = useRef(false);
  const typingIntervalRef = useRef<number | null>(null);

  // Set document title
  useEffect(() => {
    document.title = t("Hecate Cyber Defense - AI Analysis", "Hecate Cyber Defense - AI-Analyse");
    return () => {
      document.title = "Hecate Cyber Defense";
    };
  }, [t]);

  // Load AI providers on mount
  useEffect(() => {
    const loadProviders = async () => {
      try {
        const providers = await getAiProviders(aiAnalysisPassword);
        setAiProviders(providers);
        setSelectedProvider((current) => current ?? (providers.length > 0 ? providers[0].id : null));
      } catch (err) {
        console.error("Failed to load AI providers:", err);
        const status = (err as any)?.response?.status;
        if (status === 401) {
          setError(t("AI password is missing or invalid.", "AI-Passwort fehlt oder ist ungültig."));
        }
      }
    };
    loadProviders();
  }, [aiAnalysisPassword, t]);

  const loadHistory = useCallback(async (page: number) => {
    setHistoryLoading(true);
    setHistoryError(null);
    try {
      const offset = page * HISTORY_PAGE_SIZE;
      const [batchData, singleData] = await Promise.all([
        listBatchAnalyses({ limit: HISTORY_PAGE_SIZE, offset }, aiAnalysisPassword),
        listSingleAiAnalyses({ limit: HISTORY_PAGE_SIZE, offset }, aiAnalysisPassword),
      ]);
      setBatchHistory(batchData.items || []);
      setSingleHistory(singleData.items || []);
      setBatchTotal(batchData.total);
      setSingleTotal(singleData.total);
    } catch (err) {
      console.error("Failed to load AI analyses history:", err);
      const status = (err as any)?.response?.status;
      if (status === 401) {
        setHistoryError(t("AI password is missing or invalid.", "AI-Passwort fehlt oder ist ungültig."));
      } else {
        setHistoryError(t("Could not load AI analyses.", "AI-Analysen konnten nicht geladen werden."));
      }
    } finally {
      setHistoryLoading(false);
    }
  }, [HISTORY_PAGE_SIZE, aiAnalysisPassword, t]);

  useEffect(() => {
    loadHistory(historyPage);
  }, [loadHistory, historyPage]);

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

  const handleRunAnalysis = async (passwordOverride?: string) => {
    if (!selectedProvider) {
      setError(t("Please select an AI provider.", "Bitte wählen Sie einen AI-Provider aus."));
      return;
    }

    if (selectedVulnIds.length === 0) {
      setError(t("Please select at least one vulnerability.", "Bitte wählen Sie mindestens eine Schwachstelle aus."));
      return;
    }

    setError(null);
    setLoading(true);
    setResponse(null);
    shouldAnimateSummaryRef.current = true;

    try {
      // Sync vulnerability data first to ensure up-to-date information
      await triggerVulnerabilityRefresh({ vulnIds: selectedVulnIds });

      const result = await requestBatchAiInvestigation({
        vulnerabilityIds: selectedVulnIds,
        provider: selectedProvider,
        language: "de",
        additionalContext: additionalContext.trim() || null,
      }, passwordOverride ?? aiAnalysisPassword);

      setResponse(result);
      setHistoryPage(0);
      await loadHistory(0);
    } catch (err: any) {
      console.error("AI analysis failed:", err);

      // Handle specific error cases
      if (err.response?.status === 429) {
        setError(
          t(
            "API quota exhausted. Please try again later or contact your administrator.",
            "API-Kontingent erschöpft. Bitte versuchen Sie es später erneut oder wenden Sie sich an Ihren Administrator."
          )
        );
      } else if (err.response?.status === 401) {
        setError(t("AI password is missing or invalid.", "AI-Passwort fehlt oder ist ungültig."));
      } else if (err.response?.status === 404) {
        setError(t("One or more vulnerabilities were not found.", "Eine oder mehrere Schwachstellen wurden nicht gefunden."));
      } else if (err.response?.data?.detail) {
        setError(err.response.data.detail);
      } else {
        setError(t("Error during AI analysis. Please try again.", "Fehler bei der AI-Analyse. Bitte versuchen Sie es erneut."));
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

  // Pagination calculations for history (batch + single combined)
  const historyTotalCombined = batchTotal + singleTotal;
  const historyMaxTotal = Math.max(batchTotal, singleTotal);
  const hasPreviousHistoryPage = historyPage > 0;
  const hasNextHistoryPage = (historyPage + 1) * HISTORY_PAGE_SIZE < historyMaxTotal;

  if (authRequired && !authOk) {
    return (
      <div className="page" style={{ display: "flex", alignItems: "center", justifyContent: "center", minHeight: "60vh" }}>
        <div className="card" style={{ maxWidth: "400px", width: "100%", textAlign: "center" }}>
          <h3>{t("AI Analysis Password", "AI-Analyse-Passwort")}</h3>
          <p className="muted">{t("Enter the password to access this page.", "Passwort eingeben, um auf diese Seite zuzugreifen.")}</p>
          <input
            type="password"
            value={authPassword}
            onChange={(e) => setAuthPassword(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter") void handleAuthSubmit(); }}
            placeholder={t("Password", "Passwort")}
            autoFocus
            style={{ width: "100%", marginTop: "1rem", boxSizing: "border-box" }}
          />
          {authError && <p style={{ color: "#ffa3a3", fontSize: "0.85rem", margin: "0.5rem 0 0" }}>{authError}</p>}
          <div style={{ marginTop: "1rem" }}>
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => void handleAuthSubmit()}
              disabled={authChecking || !authPassword}
              style={{ width: "100%", boxSizing: "border-box" }}
            >
              {authChecking ? t("Checking...", "Prüfe…") : t("Unlock", "Entsperren")}
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (authRequired === null) {
    return (
      <div className="page" style={{ display: "flex", alignItems: "center", justifyContent: "center", minHeight: "60vh" }}>
        <p className="muted">{t("Loading...", "Laden…")}</p>
      </div>
    );
  }

  return (
    <div className="page ai-analyse-page">
      <section className="card">
        <h2>{t("AI Analysis", "AI-Analyse")}</h2>
        <p className="muted">
          {t(
            "Select multiple vulnerabilities for a combined AI analysis. The AI identifies relationships, common attack vectors, and helps prioritize actions.",
            "Wählen Sie mehrere Schwachstellen für eine kombinierte KI-Analyse aus. Die KI identifiziert Zusammenhänge, gemeinsame Angriffsvektoren und priorisiert Ihre Maßnahmen."
          )}
        </p>

        {!hasAiProviders ? (
          error ? (
            <div className="alert alert-error" style={{ marginTop: "1.5rem" }}>
              {error}
            </div>
          ) : (
            <div className="alert alert-warning" style={{ marginTop: "1.5rem" }}>
              {t(
                "No AI providers configured. Please configure at least one provider in system settings.",
                "Keine AI-Provider konfiguriert. Bitte konfigurieren Sie mindestens einen AI-Provider in den Systemeinstellungen."
              )}
            </div>
          )
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
                  <label htmlFor="ai-provider">{t("AI Provider", "AI-Provider")}</label>
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
                    {t("Additional context (optional)", "Zusätzlicher Kontext (optional)")}
                  </label>
                  <textarea
                    id="additional-context"
                    rows={3}
                    value={additionalContext}
                    onChange={(e) => setAdditionalContext(e.target.value)}
                    placeholder={t(
                      "e.g. specific versions, environment details, special requirements...",
                      "z.B. spezifische Versionen, Umgebungsdetails, besondere Anforderungen..."
                    )}
                    disabled={loading}
                  />
                </div>

                <button
                  className="btn btn-primary"
                  onClick={() => void handleRunAnalysis()}
                  disabled={loading || selectedVulnIds.length === 0}
                  style={{ width: "100%" }}
                >
                  {loading ? t("Analysis running...", "Analyse läuft...") : t("Start analysis", "Analyse starten")}
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
        <h2>{t("History", "Historie")}</h2>
        <p className="muted">
          {t("Overview of all AI analyses.", "Übersicht aller AI-Analysen.")}
        </p>

        {historyTotalCombined > 0 && (
          <div style={{ margin: "1rem 0", display: "flex", alignItems: "center", justifyContent: "flex-end", gap: "0.75rem", flexWrap: "wrap" }}>
            <span className="muted" style={{ fontSize: "0.85rem" }}>
              {t("Page", "Seite")} {historyPage + 1} · {t("Total", "Gesamt")}: {historyTotalCombined.toLocaleString(locale)} {t("entries", "Einträge")}
            </span>
            <div style={{ display: "flex", gap: "0.5rem" }}>
              <button
                type="button"
                onClick={() => setHistoryPage((current) => Math.max(0, current - 1))}
                disabled={!hasPreviousHistoryPage || historyLoading}
              >
                {t("Previous", "Zurück")}
              </button>
              <button
                type="button"
                onClick={() => setHistoryPage((current) => current + 1)}
                disabled={!hasNextHistoryPage || historyLoading}
              >
                {t("Next", "Weiter")}
              </button>
            </div>
          </div>
        )}

        {historyLoading && (
          <div className="muted">{t("Loading AI analyses...", "AI-Analysen werden geladen...")}</div>
        )}
        {historyError && (
          <div className="alert alert-error" style={{ marginTop: "1rem" }}>
            {historyError}
          </div>
        )}
        {!historyLoading && !historyError && batchHistory.length === 0 && singleHistory.length === 0 && (
          <div className="muted">{t("No AI analyses available.", "Keine AI-Analysen vorhanden.")}</div>
        )}
        {!historyLoading && !historyError && (batchHistory.length > 0 || singleHistory.length > 0) && (
          <div className="ai-analysis__batch-list">
            {/* Combine and sort by timestamp */}
            {[
              ...batchHistory.map((b) => ({ ...b, type: "batch" as const })),
              ...singleHistory,
            ]
              .sort((a, b) => {
                const timeA = new Date(a.timestamp || 0).getTime();
                const timeB = new Date(b.timestamp || 0).getTime();
                return timeB - timeA;
              })
              .map((item) => {
                const providerLabel = providerLabelMap.get(item.provider) ?? item.provider;

                if (item.type === "batch") {
                  const batch = item as BatchAnalysisItem & { type: "batch" };
                  const summary = (batch.summary || "").trim();
                  return (
                    <div key={batch.batch_id} className="ai-analysis__batch-card">
                      <div className="ai-analysis__batch-header">
                        <span className="ai-analysis__batch-id">{batch.batch_id}</span>
                        <span className="chip chip-batch">Batch</span>
                      </div>
                      {batch.vulnerability_ids?.length > 0 && (
                        <div className="vuln-aliases" style={{ marginTop: "0.5rem", marginBottom: "0.5rem" }}>
                          {batch.vulnerability_ids.map((id) => (
                            <Link
                              key={`${batch.batch_id}-${id}`}
                              to={`/vulnerability/${encodeURIComponent(id)}`}
                              className="chip chip-link"
                            >
                              {id}
                            </Link>
                          ))}
                        </div>
                      )}
                      {summary ? (
                        <div className="ai-analysis__text markdown-content">
                          <Markdown>{summary}</Markdown>
                        </div>
                      ) : (
                        <div className="muted">{t("No summary available.", "Keine Zusammenfassung verfügbar.")}</div>
                      )}
                      {(providerLabel || batch.language || batch.timestamp || batch.token_usage) && (
                        <div className="ai-analysis__meta">
                          {providerLabel && <span>{providerLabel}</span>}
                          {batch.language && <span> · {t("Language", "Sprache")}: {batch.language.toUpperCase()}</span>}
                          {batch.timestamp && <span> · {new Date(batch.timestamp).toLocaleString(locale)}</span>}
                          {batch.token_usage && (
                            <span> · {t("Tokens", "Tokens")}: {batch.token_usage.inputTokens.toLocaleString(locale)} in / {batch.token_usage.outputTokens.toLocaleString(locale)} out</span>
                          )}
                        </div>
                      )}
                    </div>
                  );
                } else {
                  const single = item as SingleAnalysisItem;
                  const summary = (single.summary || "").trim();
                  return (
                    <div key={`single-${single.vulnerability_id}`} className="ai-analysis__batch-card">
                      <div className="ai-analysis__batch-header">
                        <Link
                          to={`/vulnerability/${encodeURIComponent(single.vulnerability_id)}`}
                          className="ai-analysis__batch-id"
                          style={{ textDecoration: "none" }}
                        >
                          {single.vulnerability_id}
                        </Link>
                        <span className="chip chip-single">{t("Single", "Einzel")}</span>
                      </div>
                      <div style={{ marginTop: "0.5rem", marginBottom: "0.5rem" }}>
                        <Link
                          to={`/vulnerability/${encodeURIComponent(single.vulnerability_id)}`}
                          className="chip chip-link"
                          style={{ textDecoration: "none" }}
                        >
                          {single.vulnerability_id}
                        </Link>
                      </div>
                      {single.title && (
                        <div className="muted" style={{ fontSize: "0.9rem", marginBottom: "0.5rem" }}>
                          {single.title}
                        </div>
                      )}
                      {summary ? (
                        <div className="ai-analysis__text markdown-content">
                          <Markdown>{summary}</Markdown>
                        </div>
                      ) : (
                        <div className="muted">{t("No summary available.", "Keine Zusammenfassung verfügbar.")}</div>
                      )}
                      {(providerLabel || single.language || single.timestamp || single.token_usage) && (
                        <div className="ai-analysis__meta">
                          {providerLabel && <span>{providerLabel}</span>}
                          {single.language && <span> · {t("Language", "Sprache")}: {single.language.toUpperCase()}</span>}
                          {single.timestamp && <span> · {new Date(single.timestamp).toLocaleString(locale)}</span>}
                          {single.token_usage && (
                            <span> · {t("Tokens", "Tokens")}: {single.token_usage.inputTokens.toLocaleString(locale)} in / {single.token_usage.outputTokens.toLocaleString(locale)} out</span>
                          )}
                        </div>
                      )}
                    </div>
                  );
                }
              })}
          </div>
        )}
      </section>

    </div>
  );
};
