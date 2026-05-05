import { useEffect, useMemo, useState } from "react";
import Markdown from "react-markdown";
import { Link } from "react-router-dom";

import { useI18n, type TranslateFn } from "../i18n/context";
import { stripAiSummaryFooter } from "../utils/aiSummary";
import type {
  AttackPathExploitMaturity,
  AttackPathGraph,
  AttackPathLikelihood,
  AttackPathNarrative,
  AttackPathNode,
  AttackPathNodeType,
  AttackPathReachability,
  AIProviderInfo,
} from "../types";
import { AILoadingIndicator } from "./AILoadingIndicator";

interface AttackPathGraphProps {
  graph: AttackPathGraph;
  narrative?: AttackPathNarrative | null;
  aiEnabled: boolean;
  aiProviders?: AIProviderInfo[];
  onTriggerNarrative?: (provider: string, additionalContext: string) => void | Promise<void>;
  loading?: boolean;
  loadingStartedAt?: number | null;
  error?: string | null;
}

interface MermaidModule {
  default: {
    initialize: (config: Record<string, unknown>) => void;
    render: (id: string, code: string) => Promise<{ svg: string }>;
  };
}

let _mermaidPromise: Promise<MermaidModule | null> | null = null;
let _mermaidInitialized = false;

const SEVERITY_COLORS: Record<string, { fill: string; stroke: string; color: string }> = {
  critical: { fill: "#7a1f2b", stroke: "#ff6b6b", color: "#ffe7e7" },
  high: { fill: "#7a3a1f", stroke: "#ff9b5a", color: "#ffe7d6" },
  medium: { fill: "#7a6a1f", stroke: "#f0c247", color: "#fff5d6" },
  low: { fill: "#1f4d7a", stroke: "#5c8aff", color: "#dde7ff" },
  none: { fill: "#2a3349", stroke: "#5c637a", color: "#cfd6e4" },
  negligible: { fill: "#2a3349", stroke: "#5c637a", color: "#cfd6e4" },
};

const NODE_TYPE_COLORS: Record<AttackPathNodeType, { fill: string; stroke: string; color: string }> = {
  entry: { fill: "#1f3556", stroke: "#5c84ff", color: "#dde7ff" },
  asset: { fill: "#1f4842", stroke: "#5cc8b1", color: "#cdf3eb" },
  package: { fill: "#2c3a52", stroke: "#7388ad", color: "#dfe5f1" },
  cve: { fill: "#5a1d28", stroke: "#ff6b6b", color: "#ffe1e1" },
  cwe: { fill: "#5a3d1d", stroke: "#f0a647", color: "#fbe4c4" },
  capec: { fill: "#4a235a", stroke: "#c065ff", color: "#ecd6ff" },
  exploit: { fill: "#7a1f2b", stroke: "#ff8a8a", color: "#ffe7e7" },
  impact: { fill: "#5a1f4a", stroke: "#ff7ad9", color: "#ffd8f1" },
  fix: { fill: "#1f5a30", stroke: "#5acf80", color: "#d6f5df" },
};

const LIKELIHOOD_LABEL_KEYS: Record<AttackPathLikelihood, [string, string]> = {
  very_high: ["Very high", "Sehr hoch"],
  high: ["High", "Hoch"],
  medium: ["Medium", "Mittel"],
  low: ["Low", "Niedrig"],
  very_low: ["Very low", "Sehr niedrig"],
  unknown: ["Unknown", "Unbekannt"],
};

const EXPLOIT_MATURITY_LABEL_KEYS: Record<AttackPathExploitMaturity, [string, string]> = {
  high: ["Active exploitation", "Aktive Ausnutzung"],
  functional: ["Functional exploit", "Funktionierender Exploit"],
  poc: ["Proof of concept", "Proof-of-Concept"],
  theoretical: ["Theoretical", "Theoretisch"],
  unknown: ["Unknown", "Unbekannt"],
};

const REACHABILITY_LABEL_KEYS: Record<AttackPathReachability, [string, string]> = {
  confirmed: ["Confirmed", "Bestätigt"],
  likely: ["Likely", "Wahrscheinlich"],
  unknown: ["Unknown", "Unbekannt"],
  not_reachable: ["Not reachable", "Nicht erreichbar"],
};

const LIKELIHOOD_TONES: Record<AttackPathLikelihood, "danger" | "warning" | "info" | "muted"> = {
  very_high: "danger",
  high: "danger",
  medium: "warning",
  low: "info",
  very_low: "info",
  unknown: "muted",
};

const MATURITY_TONES: Record<AttackPathExploitMaturity, "danger" | "warning" | "info" | "muted"> = {
  high: "danger",
  functional: "danger",
  poc: "warning",
  theoretical: "info",
  unknown: "muted",
};

const REACHABILITY_TONES: Record<AttackPathReachability, "danger" | "warning" | "info" | "muted"> = {
  confirmed: "danger",
  likely: "warning",
  unknown: "muted",
  not_reachable: "info",
};

async function loadMermaid(): Promise<MermaidModule | null> {
  if (_mermaidPromise) return _mermaidPromise;
  _mermaidPromise = import("mermaid")
    .then((mod) => {
      if (!_mermaidInitialized) {
        try {
          mod.default.initialize({
            startOnLoad: false,
            theme: "dark",
            securityLevel: "strict",
            flowchart: { htmlLabels: false, useMaxWidth: true, curve: "basis" },
          });
          _mermaidInitialized = true;
        } catch {
          // ignore — fallback renderer will kick in
        }
      }
      return mod as unknown as MermaidModule;
    })
    .catch(() => null);
  return _mermaidPromise;
}

function escapeForMermaid(text: string): string {
  return text.replace(/"/g, "&quot;").replace(/\n/g, "<br/>");
}

function pickNodeColor(node: AttackPathNode): { fill: string; stroke: string; color: string } {
  if (node.severity) {
    const sev = node.severity.toLowerCase();
    if (SEVERITY_COLORS[sev]) return SEVERITY_COLORS[sev];
  }
  return NODE_TYPE_COLORS[node.type] ?? NODE_TYPE_COLORS.entry;
}

function buildMermaidSource(graph: AttackPathGraph): string {
  const lines: string[] = ["flowchart TD"];
  const classNames = new Map<string, { fill: string; stroke: string; color: string }>();

  for (const node of graph.nodes) {
    const colors = pickNodeColor(node);
    const className = `cls_${node.id.replace(/[^a-zA-Z0-9]/g, "_")}`;
    classNames.set(className, colors);
    const label = escapeForMermaid(node.label);
    lines.push(`  ${node.id}["${label}"]:::${className}`);
  }

  for (const edge of graph.edges) {
    if (edge.label) {
      lines.push(`  ${edge.source} -- "${escapeForMermaid(edge.label)}" --> ${edge.target}`);
    } else {
      lines.push(`  ${edge.source} --> ${edge.target}`);
    }
  }

  for (const [name, colors] of classNames.entries()) {
    lines.push(
      `  classDef ${name} fill:${colors.fill},stroke:${colors.stroke},color:${colors.color},stroke-width:1.5px`,
    );
  }
  return lines.join("\n");
}

function chipBackground(tone: "danger" | "warning" | "info" | "muted"): React.CSSProperties {
  switch (tone) {
    case "danger":
      return {
        background: "rgba(255, 107, 107, 0.16)",
        border: "1px solid rgba(255, 107, 107, 0.45)",
        color: "rgba(255, 220, 220, 0.96)",
      };
    case "warning":
      return {
        background: "rgba(240, 166, 71, 0.18)",
        border: "1px solid rgba(240, 166, 71, 0.45)",
        color: "rgba(255, 232, 200, 0.96)",
      };
    case "info":
      return {
        background: "rgba(92, 132, 255, 0.18)",
        border: "1px solid rgba(92, 132, 255, 0.45)",
        color: "rgba(220, 232, 255, 0.96)",
      };
    case "muted":
    default:
      return {
        background: "rgba(255, 255, 255, 0.06)",
        border: "1px solid rgba(255, 255, 255, 0.16)",
        color: "rgba(220, 224, 235, 0.85)",
      };
  }
}

function LabelChip({
  label,
  value,
  tone,
}: {
  label: string;
  value: string;
  tone: "danger" | "warning" | "info" | "muted";
}) {
  const style = {
    ...chipBackground(tone),
    display: "inline-flex",
    alignItems: "center",
    gap: "0.4rem",
    padding: "0.25rem 0.6rem",
    borderRadius: "999px",
    fontSize: "0.78rem",
    fontWeight: 500,
    whiteSpace: "nowrap" as const,
  };
  return (
    <span style={style}>
      <span style={{ opacity: 0.7 }}>{label}:</span>
      <span>{value}</span>
    </span>
  );
}

function FallbackChain({ graph }: { graph: AttackPathGraph }) {
  const orderedNodes = useMemo(() => {
    const order: AttackPathNodeType[] = [
      "entry",
      "asset",
      "package",
      "cve",
      "cwe",
      "capec",
      "exploit",
      "impact",
      "fix",
    ];
    const indexOf = (t: AttackPathNodeType) => {
      const idx = order.indexOf(t);
      return idx === -1 ? order.length : idx;
    };
    return [...graph.nodes].sort((a, b) => indexOf(a.type) - indexOf(b.type));
  }, [graph.nodes]);

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        gap: "0.5rem",
        padding: "0.75rem 0",
      }}
    >
      {orderedNodes.map((node, idx) => {
        const colors = pickNodeColor(node);
        return (
          <div key={node.id} style={{ display: "flex", flexDirection: "column", alignItems: "stretch" }}>
            <div
              style={{
                background: colors.fill,
                border: `1px solid ${colors.stroke}`,
                color: colors.color,
                borderRadius: "0.5rem",
                padding: "0.5rem 0.75rem",
                fontSize: "0.9rem",
                lineHeight: 1.35,
              }}
            >
              <div style={{ fontWeight: 600 }}>{node.label}</div>
              {node.description ? (
                <div style={{ fontSize: "0.78rem", opacity: 0.85, marginTop: "0.25rem" }}>
                  {node.description}
                </div>
              ) : null}
            </div>
            {idx < orderedNodes.length - 1 ? (
              <div style={{ textAlign: "center", opacity: 0.55, padding: "0.15rem 0" }}>↓</div>
            ) : null}
          </div>
        );
      })}
    </div>
  );
}

function CrossReferences({ nodes, t }: { nodes: AttackPathNode[]; t: TranslateFn }) {
  const refs: { kind: string; id: string; label: string; href: string }[] = [];
  for (const node of nodes) {
    const meta = node.metadata as Record<string, unknown> | null | undefined;
    if (!meta) continue;
    if (node.type === "cwe" && typeof meta.cweId === "string") {
      refs.push({
        kind: "CWE",
        id: meta.cweId,
        label: node.label,
        href: `https://cwe.mitre.org/data/definitions/${meta.cweId.replace(/^CWE-/i, "")}.html`,
      });
    }
    if (node.type === "capec" && typeof meta.capecId === "string") {
      refs.push({
        kind: "CAPEC",
        id: meta.capecId,
        label: node.label,
        href: `https://capec.mitre.org/data/definitions/${meta.capecId.replace(/^CAPEC-/i, "")}.html`,
      });
    }
  }
  if (!refs.length) return null;
  return (
    <div style={{ marginTop: "1rem" }}>
      <div className="muted" style={{ fontSize: "0.8rem", marginBottom: "0.4rem" }}>
        {t("Standards reference", "Standards-Referenz")}
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: "0.35rem" }}>
        {refs.map((ref) => (
          <a
            key={`${ref.kind}-${ref.id}`}
            href={ref.href}
            target="_blank"
            rel="noopener noreferrer"
            className="chip"
            style={{
              fontSize: "0.78rem",
              textDecoration: "none",
              color: "rgba(220, 224, 235, 0.88)",
              border: "1px solid rgba(255, 255, 255, 0.18)",
            }}
          >
            {ref.id}
          </a>
        ))}
      </div>
    </div>
  );
}

export function AttackPathGraphView({
  graph,
  narrative,
  aiEnabled,
  aiProviders = [],
  onTriggerNarrative,
  loading = false,
  loadingStartedAt = null,
  error = null,
}: AttackPathGraphProps) {
  const { t, language } = useI18n();
  const [renderState, setRenderState] = useState<"idle" | "loading" | "ready" | "fallback">("idle");
  const [svgMarkup, setSvgMarkup] = useState<string | null>(null);
  const [renderId] = useState(() => `attack-path-${Math.random().toString(36).slice(2, 10)}`);
  const [selectedProvider, setSelectedProvider] = useState<string>(aiProviders[0]?.id ?? "");
  const [additionalContext, setAdditionalContext] = useState<string>("");

  useEffect(() => {
    if (!selectedProvider && aiProviders[0]?.id) {
      setSelectedProvider(aiProviders[0].id);
    }
  }, [aiProviders, selectedProvider]);

  const mermaidSource = useMemo(() => buildMermaidSource(graph), [graph]);

  useEffect(() => {
    let cancelled = false;
    setRenderState("loading");
    setSvgMarkup(null);
    loadMermaid().then(async (mod) => {
      if (cancelled) return;
      if (!mod) {
        setRenderState("fallback");
        return;
      }
      try {
        const result = await mod.default.render(`${renderId}-svg`, mermaidSource);
        if (cancelled) return;
        setSvgMarkup(result.svg);
        setRenderState("ready");
      } catch {
        if (cancelled) return;
        setRenderState("fallback");
      }
    });
    return () => {
      cancelled = true;
    };
  }, [mermaidSource, renderId]);

  const labels = graph.labels;
  const likelihoodLabelPair = LIKELIHOOD_LABEL_KEYS[labels.likelihood] ?? LIKELIHOOD_LABEL_KEYS.unknown;
  const maturityLabelPair =
    EXPLOIT_MATURITY_LABEL_KEYS[labels.exploitMaturity] ?? EXPLOIT_MATURITY_LABEL_KEYS.unknown;
  const reachabilityLabelPair =
    REACHABILITY_LABEL_KEYS[labels.reachability] ?? REACHABILITY_LABEL_KEYS.unknown;

  const narrativeText = useMemo(
    () => stripAiSummaryFooter(narrative?.summary ?? ""),
    [narrative?.summary],
  );

  const canTriggerNarrative = aiEnabled && !!onTriggerNarrative && aiProviders.length > 0;

  return (
    <div className="attack-path">
      <div
        style={{
          padding: "0.75rem 1rem",
          borderRadius: "0.65rem",
          background: "rgba(92, 132, 255, 0.08)",
          border: "1px solid rgba(92, 132, 255, 0.3)",
          color: "rgba(220, 232, 255, 0.92)",
          fontSize: "0.85rem",
          lineHeight: 1.45,
          marginBottom: "1rem",
        }}
      >
        <strong style={{ display: "block", marginBottom: "0.25rem" }}>
          {t("Plausible attack path — not proof of exploitability", "Plausibler Angriffspfad — kein Beweis der Ausnutzbarkeit")}
        </strong>
        <span>{graph.disclaimer}</span>
      </div>

      <div style={{ display: "flex", flexWrap: "wrap", gap: "0.5rem", marginBottom: "1rem" }}>
        <LabelChip
          label={t("Likelihood", "Wahrscheinlichkeit")}
          value={t(likelihoodLabelPair[0], likelihoodLabelPair[1])}
          tone={LIKELIHOOD_TONES[labels.likelihood]}
        />
        <LabelChip
          label={t("Exploit maturity", "Exploit-Reifegrad")}
          value={t(maturityLabelPair[0], maturityLabelPair[1])}
          tone={MATURITY_TONES[labels.exploitMaturity]}
        />
        <LabelChip
          label={t("Reachability", "Erreichbarkeit")}
          value={t(reachabilityLabelPair[0], reachabilityLabelPair[1])}
          tone={REACHABILITY_TONES[labels.reachability]}
        />
        {labels.privilegesRequired ? (
          <LabelChip
            label={t("Privileges required", "Erforderliche Rechte")}
            value={labels.privilegesRequired}
            tone="muted"
          />
        ) : null}
        {labels.userInteraction ? (
          <LabelChip
            label={t("User interaction", "Benutzerinteraktion")}
            value={labels.userInteraction}
            tone="muted"
          />
        ) : null}
        {labels.businessImpact ? (
          <LabelChip
            label={t("Business impact", "Geschäftliche Auswirkung")}
            value={labels.businessImpact}
            tone={labels.businessImpact === "high" ? "danger" : "muted"}
          />
        ) : null}
      </div>

      <div
        style={{
          padding: "1rem",
          borderRadius: "0.65rem",
          background: "rgba(15, 18, 30, 0.55)",
          border: "1px solid rgba(255, 255, 255, 0.08)",
          overflowX: "auto",
        }}
      >
        {renderState === "ready" && svgMarkup ? (
          <div
            // eslint-disable-next-line react/no-danger -- mermaid output rendered in strict securityLevel
            dangerouslySetInnerHTML={{ __html: svgMarkup }}
          />
        ) : renderState === "fallback" ? (
          <FallbackChain graph={graph} />
        ) : (
          <div className="muted" style={{ padding: "1.5rem", textAlign: "center" }}>
            {t("Rendering attack path…", "Angriffspfad wird gezeichnet…")}
          </div>
        )}
      </div>

      <CrossReferences nodes={graph.nodes} t={t} />

      <div style={{ marginTop: "1.5rem" }}>
        <h4 style={{ fontSize: "0.95rem", margin: "0 0 0.5rem 0" }}>
          {t("Scenario narrative", "Szenario-Beschreibung")}
        </h4>

        {!aiEnabled ? (
          <div className="muted" style={{ fontSize: "0.85rem" }}>
            {t(
              "Configure an AI provider in System settings to generate prose attack scenarios.",
              "Konfiguriere einen AI-Provider in den Systemeinstellungen, um eine Prosa-Angriffsbeschreibung zu erzeugen.",
            )}
          </div>
        ) : null}

        {aiEnabled && !narrative && !loading ? (
          <div
            style={{
              display: "flex",
              flexDirection: "column",
              gap: "0.6rem",
              padding: "0.85rem 1rem",
              background: "rgba(255, 255, 255, 0.03)",
              border: "1px solid rgba(255, 255, 255, 0.1)",
              borderRadius: "0.55rem",
            }}
          >
            <div className="muted" style={{ fontSize: "0.85rem" }}>
              {t(
                "Use an AI provider to generate a 4-6 step prose scenario aligned with the graph above.",
                "Erzeuge mit einem AI-Provider eine 4-6-Schritte-Beschreibung passend zum Graph oben.",
              )}
            </div>
            {canTriggerNarrative ? (
              <div style={{ display: "flex", flexWrap: "wrap", gap: "0.5rem", alignItems: "center" }}>
                <select
                  value={selectedProvider}
                  onChange={(event) => setSelectedProvider(event.target.value)}
                  disabled={loading}
                >
                  {aiProviders.map((provider) => (
                    <option key={provider.id} value={provider.id}>
                      {provider.label}
                    </option>
                  ))}
                </select>
                <input
                  type="text"
                  value={additionalContext}
                  onChange={(event) => setAdditionalContext(event.target.value)}
                  disabled={loading}
                  placeholder={t(
                    "Optional context (e.g., we run this on Kubernetes)",
                    "Optionaler Kontext (z. B. wir betreiben dies auf Kubernetes)",
                  )}
                  style={{
                    flex: "1 1 220px",
                    padding: "0.4rem 0.6rem",
                    background: "rgba(15, 18, 30, 0.85)",
                    border: "1px solid rgba(255,255,255,0.18)",
                    borderRadius: "6px",
                    color: "#f5f7fa",
                    fontSize: "0.9rem",
                  }}
                />
                <button
                  type="button"
                  onClick={() =>
                    void onTriggerNarrative?.(selectedProvider, additionalContext.trim())
                  }
                  disabled={loading || !selectedProvider}
                >
                  {t("Generate scenario narrative", "Szenario-Beschreibung erzeugen")}
                </button>
              </div>
            ) : null}
          </div>
        ) : null}

        {loading ? (
          <AILoadingIndicator compact startedAt={loadingStartedAt ?? undefined} />
        ) : null}

        {error ? (
          <div className="ai-analysis__error" style={{ marginTop: "0.5rem" }}>
            {error}
          </div>
        ) : null}

        {narrative ? (
          <div
            style={{
              padding: "0.85rem 1rem",
              borderRadius: "0.55rem",
              background: "rgba(255, 255, 255, 0.03)",
              border: "1px solid rgba(255, 255, 255, 0.1)",
              marginTop: "0.5rem",
            }}
          >
            <div
              className="muted"
              style={{
                fontSize: "0.78rem",
                marginBottom: "0.5rem",
                display: "flex",
                gap: "0.5rem",
                flexWrap: "wrap",
              }}
            >
              <span>
                {t("Provider", "Anbieter")}: {narrative.provider}
              </span>
              {narrative.triggeredBy ? <span>· {narrative.triggeredBy}</span> : null}
              <span>· {new Date(narrative.generatedAt).toLocaleString(language === "de" ? "de-DE" : "en-US")}</span>
            </div>
            <Markdown>{narrativeText}</Markdown>
          </div>
        ) : null}
      </div>
    </div>
  );
}

// Re-export under a friendlier name for callers
export default AttackPathGraphView;

// Convenience component for cross-linking inline (used by Scan Detail expansions if needed)
export function AttackPathSummaryLink({
  vulnId,
  t,
}: {
  vulnId: string;
  t: TranslateFn;
}) {
  return (
    <Link to={`/vulnerability/${encodeURIComponent(vulnId)}`} className="muted" style={{ textDecoration: "underline" }}>
      {t("Open full attack path", "Vollständigen Angriffspfad öffnen")}
    </Link>
  );
}
