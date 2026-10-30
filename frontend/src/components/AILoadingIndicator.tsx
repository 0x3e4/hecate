import { useState, useEffect } from "react";
import { LuCheck } from "react-icons/lu";
import { useI18n } from "../i18n/context";
import "../screens/ai-analyse.css";

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
  const { t, language } = useI18n();
  const origin = startedAt ?? Date.now();
  const [elapsed, setElapsed] = useState(() => Math.floor((Date.now() - origin) / 1000));

  const steps = language === "de" ? STEPS_DE : STEPS_EN;

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
    <div className={`ai-analyse-loader${compact ? " ai-analyse-loader--compact" : ""}`}>
      <div className="ai-analyse-loader-head">
        <p className="ai-analyse-loader-status" role="status">
          {t("AI analysis in progress...", "AI-Analyse wird durchgeführt...")}
        </p>
        <span className="ai-analyse-loader-elapsed">{formatElapsed(elapsed)}</span>
      </div>

      {!compact && (
        <ol className="ai-analyse-loader-steps">
          {steps.map((step, i) => (
            <li
              key={i}
              className={`ai-analyse-loader-step${
                i < activeStep ? " ai-analyse-loader-step--done" :
                i === activeStep ? " ai-analyse-loader-step--active" : ""
              }`}
              aria-current={i === activeStep ? "step" : undefined}
            >
              <span className="ai-analyse-loader-mark">
                {i < activeStep ? <LuCheck size={14} aria-hidden="true" /> : null}
              </span>
              <span>{step}</span>
            </li>
          ))}
        </ol>
      )}
    </div>
  );
};
