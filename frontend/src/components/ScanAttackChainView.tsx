import { useEffect, useMemo, useState } from "react";

import { fetchScanAttackChain, triggerScanAttackChainNarrative, fetchScan } from "../api/scans";
import { getAiProviders } from "../api/vulnerabilities";
import { useI18n } from "../i18n/context";
import { usePersistentState } from "../hooks/usePersistentState";
import type {
  AIProviderInfo,
  ScanAttackChainResponse,
  ScanAttackChainStage,
} from "../types";
import { AttackPathGraphView } from "./AttackPathGraph";
import { AILoadingIndicator } from "./AILoadingIndicator";

interface ScanAttackChainViewProps {
  scanId: string;
  aiEnabled: boolean;
  onPersistedNarrativeChange?: () => void;
}

const STAGE_TONE: Record<string, "danger" | "warning" | "info" | "muted"> = {
  foothold: "warning",
  credential_access: "info",
  priv_escalation: "warning",
  lateral_movement: "info",
  impact: "danger",
};

function StageChip({
  stage,
  active,
  onClick,
}: {
  stage: ScanAttackChainStage;
  active: boolean;
  onClick: () => void;
}) {
  const tone = STAGE_TONE[stage.stage] ?? "muted";
  const palette = {
    danger: { bg: "rgba(255,107,107,0.15)", border: "rgba(255,107,107,0.45)", text: "#ffd6d6" },
    warning: { bg: "rgba(240,166,71,0.16)", border: "rgba(240,166,71,0.45)", text: "#ffe4bd" },
    info: { bg: "rgba(92,132,255,0.15)", border: "rgba(92,132,255,0.45)", text: "#d8e3ff" },
    muted: { bg: "rgba(255,255,255,0.06)", border: "rgba(255,255,255,0.18)", text: "rgba(220,224,235,0.9)" },
  }[tone];
  return (
    <button
      type="button"
      onClick={onClick}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: "0.4rem",
        padding: "0.4rem 0.75rem",
        background: palette.bg,
        border: `1px solid ${palette.border}`,
        borderRadius: "999px",
        color: palette.text,
        fontSize: "0.8rem",
        fontWeight: 500,
        cursor: "pointer",
        outline: active ? "2px solid rgba(255,255,255,0.45)" : "none",
        outlineOffset: "1px",
      }}
    >
      <span>{stage.label}</span>
      <span
        style={{
          background: "rgba(0,0,0,0.25)",
          padding: "0.05rem 0.45rem",
          borderRadius: "999px",
          fontSize: "0.7rem",
          fontWeight: 700,
        }}
      >
        {stage.findings.length}
      </span>
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

  const handleTriggerNarrative = async (provider: string, additionalContext: string) => {
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
  };

  if (loading && !response) {
    return (
      <div className="muted" style={{ padding: "1.5rem", textAlign: "center" }}>
        {t("Loading attack chain…", "Angriffskette wird geladen…")}
      </div>
    );
  }
  if (!response) {
    return (
      <div className="muted" style={{ padding: "1.5rem", textAlign: "center" }}>
        {error ?? t("No attack chain available.", "Keine Angriffskette verfügbar.")}
      </div>
    );
  }
  if (totalCves === 0) {
    return (
      <div className="muted" style={{ padding: "1.5rem", textAlign: "center" }}>
        {t(
          "This scan has no CVE-typed findings — nothing to chain yet.",
          "Dieser Scan hat keine CVE-Findings — noch keine Kette aufbauen.",
        )}
      </div>
    );
  }

  return (
    <div className="attack-chain">
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          gap: "0.75rem",
          padding: "0.85rem 1rem",
          marginBottom: "1rem",
          background: "rgba(151,117,250,0.08)",
          border: "1px solid rgba(151,117,250,0.3)",
          borderRadius: "0.65rem",
          color: "rgba(228,220,255,0.95)",
        }}
      >
        <div>
          <strong style={{ display: "block", marginBottom: "0.25rem" }}>
            {t("Cross-CVE Attack Chain", "Angriffskette über mehrere CVEs")}
          </strong>
          <span style={{ fontSize: "0.85rem", opacity: 0.85 }}>
            {t(
              `${stages.length} stages · ${totalCves} CVEs chained from this scan's findings.`,
              `${stages.length} Stufen · ${totalCves} CVEs aus den Findings dieses Scans verkettet.`,
            )}
          </span>
        </div>
        <div style={{ display: "flex", flexWrap: "wrap", gap: "0.5rem" }}>
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
        <div style={{ marginTop: "0.75rem" }}>
          <AILoadingIndicator compact startedAt={narrativeStartedAt ?? undefined} />
        </div>
      ) : null}
    </div>
  );
}

export default ScanAttackChainView;
