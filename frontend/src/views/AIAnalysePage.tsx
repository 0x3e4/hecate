import { useState, useEffect, useRef, useCallback } from "react";
import { Link, useNavigate } from "react-router-dom";
import "../screens/ai-analyse.css";
import { stripAiSummaryFooter } from "../utils/aiSummary";
import {
  getAiProviders,
  getBatchAnalysis,
  listBatchAnalyses,
  listSingleAiAnalyses,
  requestBatchAiInvestigation,
  triggerVulnerabilityRefresh,
  type SingleAnalysisItem,
} from "../api/vulnerabilities";
import { listScanAiAnalyses, type ScanAiAnalysisHistoryItem } from "../api/scans";
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
import { TimelineReport } from "../components/AIAnalyse/TimelineReport";
import { SkeletonBlock } from "../components/Skeleton";
import { useI18n } from "../i18n/context";
import { usePersistentState } from "../hooks/usePersistentState";
import { useSSE } from "../hooks/useSSE";
import { eventForRun } from "../utils/aiRun";
import { useServerConfig } from "../server-config/context";
import { useSavedSearches } from "../hooks/useSavedSearches";
import { useToastContext } from "../components/ToastProvider";
import { EmptyState, PageHeader, Section } from "../ui/primitives";

export const AIAnalysePage = () => {
  const { t, locale } = useI18n();
  const navigate = useNavigate();
  const { aiBatchMaxVulns } = useServerConfig();
  const { savedSearches } = useSavedSearches();
  const { showToast } = useToastContext();

  // --- Page-level auth gate ---
  const [authRequired, setAuthRequired] = useState<boolean | null>(null);
  const [authOk, setAuthOk] = useState(false);
  const [authPassword, setAuthPassword] = useState("");
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
    try {
      const r = await api.post<{ authenticated: boolean }>("/v1/status/ai-auth", { password: authPassword });
      if (r.data.authenticated) {
        setAuthOk(true);
        setAiAnalysisPassword(authPassword);
      }
    } catch {
      showToast(t("Invalid password.", "Falsches Passwort."), "error");
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
  // The batch run this page waits for; events of any other run are ignored
  const [batchRunId, setBatchRunId] = useState<string | null>(null);
  // The ids that run analysed: the result belongs to them, not to a later selection
  const [analysedVulnIds, setAnalysedVulnIds] = useState<string[]>([]);
  const [loadingStartedAt, setLoadingStartedAt] = useState<number>(0);
  const [response, setResponse] = useState<AIBatchInvestigationResponse | null>(null);
  const { jobs: sseJobs } = useSSE();
  const [typing, setTyping] = useState<boolean>(false);
  const [displayText, setDisplayText] = useState<string>("");
  const [batchHistory, setBatchHistory] = useState<BatchAnalysisItem[]>([]);
  const [singleHistory, setSingleHistory] = useState<SingleAnalysisItem[]>([]);
  const [scanHistory, setScanHistory] = useState<ScanAiAnalysisHistoryItem[]>([]);
  const [historyLoading, setHistoryLoading] = useState<boolean>(false);
  const [historyPage, setHistoryPage] = useState<number>(0);
  const [batchTotal, setBatchTotal] = useState<number>(0);
  const [singleTotal, setSingleTotal] = useState<number>(0);
  const [scanTotal, setScanTotal] = useState<number>(0);

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
          showToast(t("AI password is missing or invalid.", "AI-Passwort fehlt oder ist ungültig."), "error");
        }
      }
    };
    loadProviders();
  }, [aiAnalysisPassword, t, showToast]);

  const loadHistory = useCallback(async (page: number) => {
    setHistoryLoading(true);
    try {
      const offset = page * HISTORY_PAGE_SIZE;
      const [batchData, singleData, scanData] = await Promise.all([
        listBatchAnalyses({ limit: HISTORY_PAGE_SIZE, offset }, aiAnalysisPassword),
        listSingleAiAnalyses({ limit: HISTORY_PAGE_SIZE, offset }, aiAnalysisPassword),
        listScanAiAnalyses({ limit: HISTORY_PAGE_SIZE, offset }).catch(() => ({ items: [], total: 0, limit: HISTORY_PAGE_SIZE, offset })),
      ]);
      setBatchHistory(batchData.items || []);
      setSingleHistory(singleData.items || []);
      setScanHistory(scanData.items || []);
      setBatchTotal(batchData.total);
      setSingleTotal(singleData.total);
      setScanTotal(scanData.total);
    } catch (err) {
      console.error("Failed to load AI analyses history:", err);
      const status = (err as any)?.response?.status;
      if (status === 401) {
        showToast(t("AI password is missing or invalid.", "AI-Passwort fehlt oder ist ungültig."), "error");
      } else {
        showToast(t("Could not load AI analyses.", "AI-Analysen konnten nicht geladen werden."), "error");
      }
    } finally {
      setHistoryLoading(false);
    }
  }, [HISTORY_PAGE_SIZE, aiAnalysisPassword, t, showToast]);

  useEffect(() => {
    loadHistory(historyPage);
  }, [loadHistory, historyPage]);

  // Watch for batch AI investigation completion via SSE
  useEffect(() => {
    if (!loading) return;
    const job = eventForRun(sseJobs, "ai_batch_investigation", batchRunId);
    if (!job) return;

    if (job.status === "completed") {
      setBatchRunId(null);
      const batchId = job.metadata?.batchId as string | undefined;
      if (batchId) {
        getBatchAnalysis(batchId, aiAnalysisPassword)
          .then((result) => {
            shouldAnimateSummaryRef.current = true;
            setResponse(result);
            setHistoryPage(0);
            loadHistory(0);
          })
          .catch((err) => {
            console.error("Failed to fetch batch result", err);
            showToast(t("Error loading analysis result.", "Fehler beim Laden des Analyseergebnisses."), "error");
          })
          .finally(() => setLoading(false));
      } else {
        setLoading(false);
      }
    } else if (job.status === "failed") {
      setBatchRunId(null);
      showToast(job.error ?? t("AI analysis failed.", "AI-Analyse fehlgeschlagen."), "error");
      setLoading(false);
    }
  }, [sseJobs, loading, batchRunId, aiAnalysisPassword, loadHistory, t, showToast]);

  // Typing animation effect
  useEffect(() => {
    if (!response || !shouldAnimateSummaryRef.current) {
      return;
    }

    // No reveal under reduced motion: the full report renders at once.
    if (window.matchMedia?.("(prefers-reduced-motion: reduce)").matches) {
      shouldAnimateSummaryRef.current = false;
      return;
    }

    setTyping(true);
    setDisplayText("");

    const fullText = response.summary;
    let currentIndex = 0;
    const charsPerTick = Math.max(4, Math.ceil(fullText.length / 600));

    const typeNextChunk = () => {
      if (currentIndex < fullText.length) {
        currentIndex = Math.min(currentIndex + charsPerTick, fullText.length);
        setDisplayText(fullText.slice(0, currentIndex));
      } else {
        setTyping(false);
        shouldAnimateSummaryRef.current = false;
        if (typingIntervalRef.current !== null) {
          clearInterval(typingIntervalRef.current);
          typingIntervalRef.current = null;
        }
      }
    };

    typeNextChunk();
    typingIntervalRef.current = window.setInterval(typeNextChunk, 8);

    return () => {
      if (typingIntervalRef.current !== null) {
        clearInterval(typingIntervalRef.current);
        typingIntervalRef.current = null;
      }
    };
  }, [response]);

  const handleRunAnalysis = async (passwordOverride?: string) => {
    if (!selectedProvider) {
      showToast(t("Please select an AI provider.", "Bitte wählen Sie einen AI-Provider aus."), "error");
      return;
    }

    if (selectedVulnIds.length === 0) {
      showToast(t("Please select at least one vulnerability.", "Bitte wählen Sie mindestens eine Schwachstelle aus."), "error");
      return;
    }

    setLoading(true);
    setBatchRunId(null);
    setAnalysedVulnIds(selectedVulnIds);
    setLoadingStartedAt(Date.now());
    setResponse(null);
    shouldAnimateSummaryRef.current = true;

    try {
      // Sync vulnerability data first to ensure up-to-date information
      await triggerVulnerabilityRefresh({ vulnIds: selectedVulnIds });

      // Submit batch analysis — returns immediately, SSE handles completion
      const submitted = await requestBatchAiInvestigation({
        vulnerabilityIds: selectedVulnIds,
        provider: selectedProvider,
        language: "de",
        additionalContext: additionalContext.trim() || null,
      }, passwordOverride ?? aiAnalysisPassword);
      setBatchRunId(submitted.runId ?? null);
      // loading stays true — SSE effect will set it to false on completion/failure
    } catch (err: any) {
      console.error("AI analysis failed:", err);

      // Handle specific error cases — surfaced as a transient toast.
      if (err.response?.status === 429) {
        showToast(
          t(
            "API quota exhausted. Please try again later or contact your administrator.",
            "API-Kontingent erschöpft. Bitte versuchen Sie es später erneut oder wenden Sie sich an Ihren Administrator."
          ),
          "error"
        );
      } else if (err.response?.status === 401) {
        showToast(t("AI password is missing or invalid.", "AI-Passwort fehlt oder ist ungültig."), "error");
      } else if (err.response?.status === 404) {
        showToast(t("One or more vulnerabilities were not found.", "Eine oder mehrere Schwachstellen wurden nicht gefunden."), "error");
      } else if (err.response?.data?.detail) {
        showToast(String(err.response.data.detail), "error");
      } else {
        showToast(t("Error during AI analysis. Please try again.", "Fehler bei der AI-Analyse. Bitte versuchen Sie es erneut."), "error");
      }
      shouldAnimateSummaryRef.current = false;
      setLoading(false);
    }
  };


  // Get vulnerability preview objects for display
  // Note: We only have IDs, so we create minimal preview objects
  const displayedVulnIds = loading || response ? analysedVulnIds : selectedVulnIds;
  const selectedVulnerabilities: VulnerabilityPreview[] = displayedVulnIds.map((id) => ({
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
  const historyTotalCombined = batchTotal + singleTotal + scanTotal;
  const historyMaxTotal = Math.max(batchTotal, singleTotal, scanTotal);
  const hasPreviousHistoryPage = historyPage > 0;
  const hasNextHistoryPage = (historyPage + 1) * HISTORY_PAGE_SIZE < historyMaxTotal;

  if (authRequired && !authOk) {
    return (
      <div className="dialog-overlay ai-analyse-gate" onClick={() => navigate(-1)}>
        <div
          className="dialog"
          role="dialog"
          aria-modal="true"
          aria-labelledby="ai-analyse-gate-title"
          onClick={(e) => e.stopPropagation()}
        >
          <h1 id="ai-analyse-gate-title" className="ai-analyse-gate-title">
            {t("AI analysis password", "AI-Analyse-Passwort")}
          </h1>
          <p>{t("Enter the password to access this page.", "Passwort eingeben, um auf diese Seite zuzugreifen.")}</p>
          <input
            type="password"
            value={authPassword}
            onChange={(e) => setAuthPassword(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter") void handleAuthSubmit(); else if (e.key === "Escape") navigate(-1); }}
            aria-label={t("Password", "Passwort")}
            placeholder={t("Password", "Passwort")}
            autoFocus
          />
          <div className="dialog-actions">
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => navigate(-1)}
            >
              {t("Cancel", "Abbrechen")}
            </button>
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => void handleAuthSubmit()}
              disabled={authChecking || !authPassword}
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
      <div className="dialog-overlay ai-analyse-gate">
        <div className="dialog">
          <p className="muted">{t("Loading...", "Laden…")}</p>
        </div>
      </div>
    );
  }

  const historyPager = historyTotalCombined > 0 && (
    <div className="ai-analyse-pager">
      <span>{t("Page", "Seite")} {historyPage + 1}</span>
      <span>{t("Total", "Gesamt")}: {historyTotalCombined.toLocaleString(locale)} {t("entries", "Einträge")}</span>
      <button
        type="button"
        className="btn btn-secondary"
        onClick={() => setHistoryPage((current) => Math.max(0, current - 1))}
        disabled={!hasPreviousHistoryPage || historyLoading}
      >
        {t("Previous", "Zurück")}
      </button>
      <button
        type="button"
        className="btn btn-secondary"
        onClick={() => setHistoryPage((current) => current + 1)}
        disabled={!hasNextHistoryPage || historyLoading}
      >
        {t("Next", "Weiter")}
      </button>
    </div>
  );

  return (
    <div className="page ai-analyse">
      <PageHeader
        title={t("AI analysis", "AI-Analyse")}
        description={t(
          "Select multiple vulnerabilities for a combined AI analysis. The AI identifies relationships, common attack vectors, and helps prioritize actions.",
          "Wählen Sie mehrere Schwachstellen für eine kombinierte KI-Analyse aus. Die KI identifiziert Zusammenhänge, gemeinsame Angriffsvektoren und priorisiert Ihre Maßnahmen."
        )}
      />

      {!hasAiProviders ? (
        <section>
          <EmptyState title={t("No AI providers configured.", "Keine AI-Provider konfiguriert.")}>
            {t(
              "Please configure at least one provider in system settings.",
              "Bitte konfigurieren Sie mindestens einen AI-Provider in den Systemeinstellungen."
            )}
          </EmptyState>
        </section>
      ) : (
        <section className="ai-analyse-compose">
          <VulnerabilitySelector
            selectedIds={selectedVulnIds}
            onSelectionChange={setSelectedVulnIds}
            maxSelection={aiBatchMaxVulns}
            savedSearches={savedSearches}
          />

          {/* Controls */}
          <div className="ai-analyse-form well">
            <div className="ai-analyse-field">
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

            <div className="ai-analyse-field">
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
              type="button"
              className="btn btn-primary ai-analyse-start"
              onClick={() => void handleRunAnalysis()}
              disabled={loading || selectedVulnIds.length === 0}
            >
              {loading ? t("Analysis running...", "Analyse läuft...") : t("Start analysis", "Analyse starten")}
            </button>
          </div>

          {/* Analysis display */}
          <BatchAnalysisDisplay
            response={response}
            vulnerabilities={selectedVulnerabilities}
            loading={loading}
            loadingStartedAt={loadingStartedAt}
            typing={typing}
            displayText={displayText}
          />
        </section>
      )}

      <Section title={t("History", "Historie")} actions={historyPager} className="ai-analyse-history">
        <p className="ai-analyse-history-note">
          {t("Overview of all AI analyses.", "Übersicht aller AI-Analysen.")}
        </p>

        {historyLoading && (
          <div role="status">
            <span className="visually-hidden">{t("Loading AI analyses...", "AI-Analysen werden geladen...")}</span>
            <div className="ai-analyse-timeline" aria-hidden="true">
              {["45%", "60%", "35%"].map((width) => (
                <div key={width} className="ai-analyse-report">
                  <div className="ai-analyse-report-rail">
                    <SkeletonBlock height={16} width="75%" />
                    <SkeletonBlock height={14} width="30%" />
                    <SkeletonBlock height={12} width="90%" />
                  </div>
                  <div className="ai-analyse-report-main">
                    <SkeletonBlock height={20} width={width} />
                    <SkeletonBlock height={14} />
                    <SkeletonBlock height={14} />
                    <SkeletonBlock height={14} width="70%" />
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
        {!historyLoading && batchHistory.length === 0 && singleHistory.length === 0 && scanHistory.length === 0 && (
          <EmptyState title={t("No AI analyses available.", "Keine AI-Analysen vorhanden.")} />
        )}
        {!historyLoading && (batchHistory.length > 0 || singleHistory.length > 0 || scanHistory.length > 0) && (
          <ol className="ai-analyse-timeline">
            {/* Combine and sort by timestamp */}
            {[
              ...batchHistory.map((b) => ({ ...b, type: "batch" as const })),
              ...singleHistory,
              ...scanHistory,
            ]
              .sort((a, b) => {
                const timeA = new Date(("generatedAt" in a ? a.generatedAt : a.timestamp) || 0).getTime();
                const timeB = new Date(("generatedAt" in b ? b.generatedAt : b.timestamp) || 0).getTime();
                return timeB - timeA;
              })
              .map((item) => {
                const providerLabel = providerLabelMap.get(item.provider as AIProviderId) ?? item.provider;

                if (item.type === "scan") {
                  const scan = item as ScanAiAnalysisHistoryItem;
                  const ref = scan.commit_sha
                    ? { label: t("Commit", "Commit"), value: scan.commit_sha.slice(0, 12) }
                    : scan.image_ref
                    ? { label: t("Image", "Image"), value: scan.image_ref }
                    : null;
                  return (
                    <TimelineReport
                      key={`scan-${scan.scan_id}-${scan.timestamp ?? ""}`}
                      date={scan.timestamp}
                      kind={t("Scan", "Scan")}
                      provider={providerLabel}
                      triggeredBy={scan.triggeredBy}
                      language={scan.language}
                      tokenUsage={scan.tokenUsage}
                      heading={
                        <Link to={`/scans/${encodeURIComponent(scan.scan_id)}`} className="row-link">
                          {scan.target_name || scan.target_id || scan.scan_id}
                        </Link>
                      }
                      details={ref && (
                        <p className="ai-analyse-report-detail">
                          {ref.label}: <code className="mono">{ref.value}</code>
                        </p>
                      )}
                      summary={stripAiSummaryFooter((scan.summary || "").trim())}
                    />
                  );
                }

                if (item.type === "batch") {
                  const batch = item as BatchAnalysisItem & { type: "batch" };
                  return (
                    <TimelineReport
                      key={batch.batchId}
                      date={batch.generatedAt}
                      kind={t("Batch", "Batch")}
                      provider={providerLabel}
                      triggeredBy={batch.triggeredBy}
                      language={batch.language}
                      tokenUsage={batch.tokenUsage}
                      heading={<span className="mono">{batch.batchId}</span>}
                      details={batch.vulnerabilityIds?.length > 0 && (
                        <div className="link-list mono ai-analyse-report-ids">
                          {batch.vulnerabilityIds.map((id) => (
                            <Link key={`${batch.batchId}-${id}`} to={`/vulnerability/${encodeURIComponent(id)}`}>
                              {id}
                            </Link>
                          ))}
                        </div>
                      )}
                      summary={stripAiSummaryFooter((batch.summary || "").trim())}
                    />
                  );
                } else {
                  const single = item as SingleAnalysisItem;
                  return (
                    <TimelineReport
                      key={`single-${single.vulnerability_id}`}
                      date={single.timestamp}
                      kind={t("Single", "Einzeln")}
                      provider={providerLabel}
                      triggeredBy={single.triggeredBy}
                      language={single.language}
                      tokenUsage={single.token_usage}
                      heading={
                        <Link to={`/vulnerability/${encodeURIComponent(single.vulnerability_id)}`} className="row-link mono">
                          {single.vulnerability_id}
                        </Link>
                      }
                      details={single.title && <p className="ai-analyse-report-detail">{single.title}</p>}
                      summary={stripAiSummaryFooter((single.summary || "").trim())}
                    />
                  );
                }
              })}
          </ol>
        )}
        {!historyLoading && historyPager}
      </Section>
    </div>
  );
};
