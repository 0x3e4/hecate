import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { fetchScanAttackChain, triggerScanAttackChainNarrative, fetchScan } from "../api/scans";
import { getAiProviders } from "../api/vulnerabilities";
import { useI18n } from "../i18n/context";
import { usePersistentState } from "../hooks/usePersistentState";
import { useSSE } from "../hooks/useSSE";
import { eventForRun, runIdOf } from "../utils/aiRun";
import type {
  AIProviderInfo,
  ScanAttackChainResponse,
  ScanAttackChainStage,
} from "../types";
import { EmptyState, ErrorState } from "../ui/primitives";
import { AttackPathGraphView } from "./AttackPathGraph";
import { LoadingRegion, SkeletonBlock } from "./Skeleton";

interface ScanAttackChainViewProps {
  scanId: string;
  aiEnabled: boolean;
  onPersistedNarrativeChange?: () => void;
}

/** A kill-chain stage is a position in the attack, not a severity, so it stays neutral. */
function StageChip({
  stage,
  active,
  onClick,
}: {
  stage: ScanAttackChainStage;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button type="button" className="scan-detail-stage" aria-pressed={active} onClick={onClick}>
      <span>{stage.label}</span>
      <span className="scan-detail-stage-count">{stage.findings.length}</span>
    </button>
  );
}

export function ScanAttackChainView({
  scanId,
  aiEnabled,
  onPersistedNarrativeChange,
}: ScanAttackChainViewProps) {
  const { t, locale } = useI18n();
  const [aiAnalysisPassword] = usePersistentState<string>("ai_analysis_password", "");
  const [response, setResponse] = useState<ScanAttackChainResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [activeStage, setActiveStage] = useState<string | null>(null);
  const [narrativeLoading, setNarrativeLoading] = useState<boolean>(false);
  const [narrativeStartedAt, setNarrativeStartedAt] = useState<number | null>(null);
  const [aiProviders, setAiProviders] = useState<AIProviderInfo[]>([]);
  // The narrative run this view waits for; its SSE events say when it ends or fails.
  const [narrativeRunId, setNarrativeRunId] = useState<string | null>(null);
  // Stored narratives when the run started: the polling fallback waits for one more.
  const chainsAtStartRef = useRef(0);
  const { jobs: sseJobs } = useSSE();
  const jobName = `scan_attack_chain_${scanId}`;

  useEffect(() => {
    if (!aiEnabled) return;
    let cancelled = false;
    getAiProviders()
      .then((list) => {
        if (!cancelled) setAiProviders(list);
      })
      .catch(() => {
        if (!cancelled) setAiProviders([]);
      });
    return () => {
      cancelled = true;
    };
  }, [aiEnabled]);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    fetchScanAttackChain(scanId, { language: locale })
      .then((data) => {
        if (!cancelled) setResponse(data);
      })
      .catch((err) => {
        console.error("Failed to fetch attack chain", err);
        if (!cancelled) {
          setError(t("Failed to load the attack chain.", "Angriffskette konnte nicht geladen werden."));
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [scanId, locale, t]);

  const stages = response?.stages ?? [];
  const totalCves = useMemo(
    () => stages.reduce((acc, s) => acc + s.findings.length, 0),
    [stages],
  );

  // Wrapped in useCallback so the prop reference stays stable across pill
  // clicks / activeStage changes. Otherwise AttackPathGraphView re-renders
  // and (in some browsers) the synthetic-event reconciliation interrupted
  // panzoom's drag-tracking, manifesting as "graph resets and freezes".
  const finishNarrative = useCallback(async () => {
    setNarrativeLoading(false);
    setNarrativeStartedAt(null);
    setNarrativeRunId(null);
    try {
      setResponse(await fetchScanAttackChain(scanId, { language: locale }));
    } catch {
      // the graph stays; the next visit loads the narrative
    }
    onPersistedNarrativeChange?.();
  }, [scanId, locale, onPersistedNarrativeChange]);

  // Follow the run over SSE, and pick up one already running when the tab opens.
  useEffect(() => {
    const latest = sseJobs.get(jobName);
    if (!narrativeLoading) {
      if (latest?.status === "running") {
        setNarrativeLoading(true);
        setNarrativeRunId(runIdOf(latest));
        setNarrativeStartedAt(latest.startedAt ? new Date(latest.startedAt).getTime() : Date.now());
      }
      return;
    }
    const job = eventForRun(sseJobs, jobName, narrativeRunId);
    if (job?.status === "completed") {
      void finishNarrative();
    } else if (job?.status === "failed") {
      setError(job.error ?? t("Narrative generation failed.", "Beschreibungserzeugung fehlgeschlagen."));
      setNarrativeLoading(false);
      setNarrativeStartedAt(null);
      setNarrativeRunId(null);
    }
  }, [sseJobs, jobName, narrativeLoading, narrativeRunId, finishNarrative, t]);

  // Fallback when the stream is down: wait for one more stored narrative. (The old
  // poll also accepted an existing one, so a second run "finished" at once.)
  useEffect(() => {
    if (!narrativeLoading) return;
    let cancelled = false;
    const timer = window.setInterval(async () => {
      try {
        const fresh = await fetchScan(scanId);
        if (!cancelled && (fresh.attackChains?.length ?? 0) > chainsAtStartRef.current) void finishNarrative();
      } catch { /* the next tick tries again */ }
    }, 8000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [narrativeLoading, scanId, finishNarrative]);

  const handleTriggerNarrative = useCallback(
    async (provider: string, additionalContext: string) => {
      setError(null);
      setNarrativeLoading(true);
      setNarrativeStartedAt(Date.now());
      try {
        chainsAtStartRef.current = (await fetchScan(scanId)).attackChains?.length ?? 0;
        const submitted = await triggerScanAttackChainNarrative(
          scanId,
          {
            provider,
            language: locale,
            additionalContext: additionalContext || undefined,
          },
          aiAnalysisPassword || undefined,
        );
        setNarrativeRunId(submitted.runId ?? null);
      } catch (err: unknown) {
        const status = (err as { response?: { status?: number } } | undefined)?.response?.status;
        const detail = (err as { response?: { data?: { detail?: string } } } | undefined)?.response?.data?.detail;
        let message =
          detail ?? t("Failed to start narrative generation.", "Beschreibungserzeugung konnte nicht gestartet werden.");
        if (status === 401) {
          message = t("AI password is missing or invalid.", "AI-Passwort fehlt oder ist ungültig.");
        }
        setError(message);
        setNarrativeLoading(false);
        setNarrativeStartedAt(null);
      }
    },
    [scanId, locale, aiAnalysisPassword, t],
  );

  if (loading && !response) {
    return (
      <LoadingRegion label={t("Loading attack chain", "Angriffskette wird geladen")} className="scan-detail-skeleton">
        <SkeletonBlock height="1.25rem" width="240px" />
        <SkeletonBlock height={36} width="60%" />
        <SkeletonBlock height={240} />
      </LoadingRegion>
    );
  }
  if (!response) {
    return error
      ? <ErrorState title={error} />
      : <EmptyState title={t("No attack chain available.", "Keine Angriffskette verfügbar.")} />;
  }
  if (totalCves === 0) {
    return (
      <EmptyState
        title={t(
          "This scan has no CVE-typed findings: nothing to chain yet.",
          "Dieser Scan hat keine CVE-Findings: noch keine Kette aufbauen.",
        )}
      />
    );
  }

  return (
    <div className={`attack-chain${loading ? " is-refreshing" : ""}`} aria-busy={loading || undefined}>
      <div className="scan-detail-chain-head">
        <div>
          <h2>{t("Cross-CVE Attack Chain", "Angriffskette über mehrere CVEs")}</h2>
          <p className="scan-detail-chain-text">
            {t(
              `${stages.length} stages, ${totalCves} CVEs chained from this scan's findings.`,
              `${stages.length} Stufen, ${totalCves} CVEs aus den Findings dieses Scans verkettet.`,
            )}
          </p>
        </div>
        <div className="scan-detail-chips">
          {stages.map((stage) => (
            <StageChip
              key={stage.stage}
              stage={stage}
              active={activeStage === stage.stage}
              onClick={() =>
                setActiveStage((prev) => (prev === stage.stage ? null : stage.stage))
              }
            />
          ))}
        </div>
      </div>

      <AttackPathGraphView
        graph={response.graph}
        narrative={response.narrative ?? null}
        aiEnabled={aiEnabled}
        aiProviders={aiProviders}
        onTriggerNarrative={handleTriggerNarrative}
        loading={narrativeLoading}
        loadingStartedAt={narrativeStartedAt}
        error={error}
      />
    </div>
  );
}

export default ScanAttackChainView;
