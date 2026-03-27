import { useState, useEffect } from "react";
import { useI18n } from "../i18n/context";

interface AILoadingIndicatorProps {
  /** Compact mode for inline use (e.g., within vulnerability detail) */
  compact?: boolean;
  /** Stable start timestamp (ms) so the timer survives remounts */
  startedAt?: number;
}

const STEPS_EN = [
  "Reasoning about vulnerability context",
  "Searching security advisories",
  "Analyzing attack vectors",
  "Compiling recommendations",
];

const STEPS_DE = [
  "Schwachstellenkontext analysieren",
  "Sicherheitshinweise durchsuchen",
  "Angriffsvektoren bewerten",
  "Empfehlungen zusammenstellen",
];

export const AILoadingIndicator = ({ compact = false, startedAt }: AILoadingIndicatorProps) => {
  const { t } = useI18n();
  const origin = startedAt ?? Date.now();
  const [elapsed, setElapsed] = useState(() => Math.floor((Date.now() - origin) / 1000));

  const steps = t(STEPS_EN, STEPS_DE) as unknown as string[];

  // Derive active step from elapsed time (8s per step)
  const activeStep = Math.min(Math.floor(elapsed / 8), steps.length - 1);

  useEffect(() => {
    const timer = setInterval(() => {
      setElapsed(Math.floor((Date.now() - origin) / 1000));
    }, 1000);
    return () => clearInterval(timer);
  }, [origin]);

  const formatElapsed = (secs: number) => {
    const m = Math.floor(secs / 60);
    const s = secs % 60;
    return m > 0 ? `${m}:${String(s).padStart(2, "0")}` : `${s}s`;
  };

  return (
    <div className="ai-loading-indicator" style={compact ? { padding: "1.5rem 1rem" } : undefined}>
      <div className="ai-loading-indicator__brain">
        <div className="ai-loading-indicator__ring" />
        <div className="ai-loading-indicator__ring ai-loading-indicator__ring--inner" />
        <div className="ai-loading-indicator__icon">🧠</div>
      </div>

      <div className="ai-loading-indicator__status">
        {t("AI analysis in progress...", "AI-Analyse wird durchgeführt...")}
      </div>

      {!compact && (
        <div className="ai-loading-indicator__steps">
          {steps.map((step, i) => (
            <div
              key={i}
              className={`ai-loading-indicator__step${
                i < activeStep ? " ai-loading-indicator__step--done" :
                i === activeStep ? " ai-loading-indicator__step--active" : ""
              }`}
            >
              <span>{i < activeStep ? "✓" : i === activeStep ? "›" : "·"}</span>
              <span>{step}</span>
            </div>
          ))}
        </div>
      )}

      <div className="ai-loading-indicator__elapsed">{formatElapsed(elapsed)}</div>
    </div>
  );
};
