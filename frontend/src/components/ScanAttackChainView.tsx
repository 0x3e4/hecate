import { useCallback, useEffect, useMemo, useState } from "react";

import { fetchScanAttackChain, triggerScanAttackChainNarrative, fetchScan } from "../api/scans";
import { getAiProviders } from "../api/vulnerabilities";
import { useI18n } from "../i18n/context";
import { usePersistentState } from "../hooks/usePersistentState";
import type {
  AIProviderInfo,
  ScanAttackChainResponse,
  ScanAttackChainStage,
} from "../types";
import { EmptyState, ErrorState } from "../ui/primitives";
import { AttackPathGraphView } from "./AttackPathGraph";
import { AILoadingIndicator } from "./AILoadingIndicator";
import { SkeletonBlock } from "./Skeleton";

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
  const handleTriggerNarrative = useCallback(
    async (provider: string, additionalContext: string) => {
      setError(null);
      setNarrativeLoading(true);
      setNarrativeStartedAt(Date.now());
      try {
        await triggerScanAttackChainNarrative(
          scanId,
          {
            provider,
            language: locale,
            additionalContext: additionalContext || undefined,
          },
          aiAnalysisPassword || undefined,
        );
        // Poll the scan a few times to surface the narrative.
        let attempts = 0;
        const baseLength = response?.narrative ? 1 : 0;
        const pollHandle: { id: number | null } = { id: null };
        const tick = async () => {
          attempts += 1;
          if (attempts > 30) {
            setNarrativeLoading(false);
            setNarrativeStartedAt(null);
            return;
          }
          try {
            const fresh = await fetchScan(scanId);
            const freshLen = (fresh.attackChains?.length ?? 0);
            if (freshLen > baseLength || fresh.attackChain) {
              const updated = await fetchScanAttackChain(scanId, { language: locale });
              setResponse(updated);
              setNarrativeLoading(false);
              setNarrativeStartedAt(null);
              onPersistedNarrativeChange?.();
              return;
            }
          } catch {
            // fall through to retry
          }
          pollHandle.id = window.setTimeout(tick, 4000);
        };
        pollHandle.id = window.setTimeout(tick, 4000);
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
    [scanId, locale, aiAnalysisPassword, response?.narrative, onPersistedNarrativeChange, t],
  );

  if (loading && !response) {
    return (
      <div className="scan-detail-skeleton" role="status" aria-label={t("Loading attack chain…", "Angriffskette wird geladen…")}>
        <SkeletonBlock height="1.25rem" width="240px" radius={4} />
        <SkeletonBlock height={36} width="60%" radius={4} />
        <SkeletonBlock height={240} radius={4} />
      </div>
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
    <div className="attack-chain">
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

      {narrativeLoading && !error ? (
        <div className="scan-detail-chain-loading">
          <AILoadingIndicator compact startedAt={narrativeStartedAt ?? undefined} />
        </div>
      ) : null}
    </div>
  );
}

export default ScanAttackChainView;
