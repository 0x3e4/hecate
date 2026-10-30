import { useEffect, useMemo, useRef, useState } from "react";
import Markdown from "react-markdown";
import { Link, useNavigate } from "react-router-dom";
import { LuArrowDown, LuMinus, LuPlus, LuMaximize2 } from "react-icons/lu";

import "../screens/vulnerability-detail.css";
import { useI18n, type TranslateFn } from "../i18n/context";
import { IconButton, severityLevel } from "../ui/primitives";
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
import { SkeletonBlock } from "./Skeleton";

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

interface PanzoomController {
  dispose: () => void;
  zoomTo: (clientX: number, clientY: number, scaleMultiplier: number) => void;
  zoomAbs: (clientX: number, clientY: number, zoomLevel: number) => void;
  smoothZoom: (clientX: number, clientY: number, scaleMultiplier: number) => void;
  moveTo: (x: number, y: number) => void;
  getTransform: () => { x: number; y: number; scale: number };
}

interface PanzoomModule {
  default: (
    target: SVGElement | HTMLElement,
    options?: Record<string, unknown>,
  ) => PanzoomController;
}

let _mermaidPromise: Promise<MermaidModule | null> | null = null;
let _mermaidInitialized = false;
let _panzoomPromise: Promise<PanzoomModule | null> | null = null;

interface NodeColors {
  fill: string;
  stroke: string;
  color: string;
}

const readToken = (name: string): string =>
  getComputedStyle(document.documentElement).getPropertyValue(name).trim();

/**
 * Flattens painted layers on a 1x1 canvas and reads the result back as sRGB hex.
 * The design tokens are oklch, which Mermaid's theme code cannot parse, and a
 * comma in `rgb()` would split a classDef. Tokens stay the single source of colour.
 */
const paintToHex = (layers: Array<{ color: string; alpha?: number }>): string => {
  const context = document.createElement("canvas").getContext("2d", { willReadFrequently: true });
  if (!context) return layers[layers.length - 1].color;
  context.canvas.width = 1;
  context.canvas.height = 1;
  for (const { color, alpha = 1 } of layers) {
    context.globalAlpha = alpha;
    context.fillStyle = color;
    context.fillRect(0, 0, 1, 1);
  }
  const [red, green, blue] = context.getImageData(0, 0, 1, 1).data;
  return `#${[red, green, blue].map((channel) => channel.toString(16).padStart(2, "0")).join("")}`;
};

const tokenHex = (name: string): string => paintToHex([{ color: readToken(name) }]);

/** Severity is the one colour on the graph, and only on the nodes that carry it. */
const SEVERITY_NODE_TYPES: ReadonlySet<AttackPathNodeType> = new Set<AttackPathNodeType>(["cve", "impact"]);
const SEVERITY_TINT = 0.2;

/** Matches the canvas `max-height` in vulnerability-detail.css. */
const GRAPH_MAX_VIEWPORT_SHARE = 0.85;

function escapeForMermaid(text: string): string {
  return text.replace(/"/g, "&quot;").replace(/\n/g, "<br/>");
}

function pickNodeColor(node: AttackPathNode): NodeColors {
  const ink = tokenHex("--color-ink");
  const level = severityLevel(node.severity);
  if (level !== "none" && SEVERITY_NODE_TYPES.has(node.type)) {
    const severity = readToken(`--sev-${level}`);
    return {
      fill: paintToHex([{ color: readToken("--color-paper-2") }, { color: severity, alpha: SEVERITY_TINT }]),
      stroke: paintToHex([{ color: severity }]),
      color: ink,
    };
  }
  return { fill: tokenHex("--color-paper-3"), stroke: tokenHex("--color-rule-strong"), color: ink };
}

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
            theme: "base",
            themeVariables: {
              darkMode: true,
              background: tokenHex("--color-paper-2"),
              primaryColor: tokenHex("--color-paper-3"),
              primaryTextColor: tokenHex("--color-ink"),
              primaryBorderColor: tokenHex("--color-rule-strong"),
              secondaryColor: tokenHex("--color-paper-3"),
              tertiaryColor: tokenHex("--color-paper-2"),
              lineColor: tokenHex("--color-muted"),
              textColor: tokenHex("--color-ink-2"),
              edgeLabelBackground: tokenHex("--color-paper-2"),
              fontFamily: readToken("--font-body"),
            },
            themeCSS: `.edgeLabel rect { opacity: 1; } .edgeLabel text { fill: ${tokenHex("--color-muted")}; font-size: 13px; }`,
            securityLevel: "strict",
            flowchart: { htmlLabels: false, useMaxWidth: true, curve: "basis", rankSpacing: 36, nodeSpacing: 36 },
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

async function loadPanzoom(): Promise<PanzoomModule | null> {
  if (_panzoomPromise) return _panzoomPromise;
  _panzoomPromise = import("panzoom")
    .then((mod) => mod as unknown as PanzoomModule)
    .catch(() => null);
  return _panzoomPromise;
}

function buildMermaidSource(graph: AttackPathGraph): string {
  const lines: string[] = ["flowchart TD"];
  const classNames = new Map<string, NodeColors>();

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

// CVSS vector letters and impact bands as words; analyst-supplied assumptions pass through as typed.
const METRIC_VALUE_LABELS: Record<string, [string, string]> = {
  N: ["None", "Keine"],
  L: ["Low", "Niedrig"],
  H: ["High", "Hoch"],
  R: ["Required", "Erforderlich"],
  P: ["Passive", "Passiv"],
  A: ["Active", "Aktiv"],
  low: ["Low", "Niedrig"],
  medium: ["Medium", "Mittel"],
  high: ["High", "Hoch"],
  critical: ["Critical", "Kritisch"],
  unknown: ["Unknown", "Unbekannt"],
};

function LabelChip({
  label,
  value,
  tone,
}: {
  label: string;
  value: string;
  tone: "danger" | "warning" | "info" | "muted";
}) {
  return (
    <div className="vulnerability-detail-path-label" data-tone={tone}>
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
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
    <ol className="vulnerability-detail-path-chain">
      {orderedNodes.map((node, idx) => {
        const colors = pickNodeColor(node);
        return (
          <li key={node.id}>
            <div
              className="vulnerability-detail-path-chain-node"
              style={{ background: colors.fill, borderColor: colors.stroke, color: colors.color }}
            >
              <div className="vulnerability-detail-path-chain-label">{node.label}</div>
              {node.description ? (
                <div className="vulnerability-detail-path-chain-text">{node.description}</div>
              ) : null}
            </div>
            {idx < orderedNodes.length - 1 ? (
              <LuArrowDown className="vulnerability-detail-path-chain-arrow" size={14} aria-hidden="true" />
            ) : null}
          </li>
        );
      })}
    </ol>
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
    <div className="vulnerability-detail-path-references">
      <div className="vulnerability-detail-path-subhead">
        {t("Standards reference", "Standards-Referenz")}
      </div>
      <div className="link-list">
        {refs.map((ref) => (
          <a
            key={`${ref.kind}-${ref.id}`}
            href={ref.href}
            target="_blank"
            rel="noopener noreferrer"
            className="vulnerability-detail-path-reference"
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
  const navigate = useNavigate();
  const [renderState, setRenderState] = useState<"idle" | "loading" | "ready" | "fallback">("idle");
  const [svgMarkup, setSvgMarkup] = useState<string | null>(null);
  const [renderId] = useState(() => `attack-path-${Math.random().toString(36).slice(2, 10)}`);
  const [selectedProvider, setSelectedProvider] = useState<string>(aiProviders[0]?.id ?? "");
  const [additionalContext, setAdditionalContext] = useState<string>("");
  const svgContainerRef = useRef<HTMLDivElement | null>(null);
  const panzoomRef = useRef<PanzoomController | null>(null);
  const attachedSvgRef = useRef<SVGElement | null>(null);

  // Stable nodes-by-id lookup so click handlers can navigate without
  // triggering the panzoom-attach effect to re-run.
  const nodesById = useMemo(() => {
    const out = new Map<string, (typeof graph.nodes)[number]>();
    for (const n of graph.nodes) out.set(n.id, n);
    return out;
  }, [graph.nodes]);

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

  // Attach pan/zoom to the freshly rendered Mermaid SVG. The handler is
  // idempotent — it only (re)attaches when the SVG DOM element identity has
  // actually changed. A naive "dispose + attach" on every re-run was wiping
  // the user's pan/zoom transform whenever an unrelated prop further up the
  // tree changed (e.g. the AI providers list arriving ~1s after mount, or
  // any state change in the parent), which manifested as "zoom resets and
  // freezes after ~1s".
  useEffect(() => {
    if (renderState !== "ready" || !svgMarkup) return;
    const container = svgContainerRef.current;
    if (!container) return;
    const svgEl = container.querySelector("svg") as SVGElement | null;
    if (!svgEl) return;

    // Already attached to this exact SVG node — keep the existing controller
    // (and the user's zoom state) intact.
    if (attachedSvgRef.current === svgEl && panzoomRef.current) return;

    // Mermaid replaced the SVG (or this is the first attach) — tear down the
    // previous controller and double-click listener if any, then attach fresh.
    if (panzoomRef.current) {
      panzoomRef.current.dispose();
      panzoomRef.current = null;
    }
    const previousContainer = container;
    const previousDblClick = (previousContainer as HTMLDivElement & { __apDbl?: () => void }).__apDbl;
    if (previousDblClick) {
      previousContainer.removeEventListener("dblclick", previousDblClick);
    }

    // Mermaid sets `max-width: 100%` inline which fights panzoom's transforms.
    // Clear it so the SVG can grow when the user zooms in.
    svgEl.style.maxWidth = "none";
    svgEl.style.height = "auto";
    // Open with the whole path in frame, never scaled above its native size.
    const { width: nativeWidth, height: nativeHeight } = (svgEl as SVGSVGElement).viewBox.baseVal;
    if (nativeWidth > 0 && nativeHeight > 0) {
      const fit = Math.min(1, container.clientWidth / nativeWidth, (window.innerHeight * GRAPH_MAX_VIEWPORT_SHARE) / nativeHeight);
      svgEl.style.width = `${nativeWidth * fit}px`;
    }
    svgEl.setAttribute("aria-label", t("Attack path graph", "Angriffspfad-Graph"));
    attachedSvgRef.current = svgEl;

    let disposed = false;
    loadPanzoom().then((mod) => {
      if (disposed || !mod) return;
      // Make sure the SVG we captured is still the current one — a fast
      // re-render between effect-run and promise-resolve could have replaced it.
      if (attachedSvgRef.current !== svgEl) return;
      const controller = mod.default(svgEl, {
        maxZoom: 8,
        minZoom: 0.2,
        bounds: false,
        zoomDoubleClickSpeed: 1, // we own dblclick → reset below
        smoothScroll: false,
      });
      panzoomRef.current = controller;
    });

    const handleDoubleClick = () => {
      const ctrl = panzoomRef.current;
      if (!ctrl) return;
      const rect = svgEl.getBoundingClientRect();
      ctrl.zoomAbs(rect.left + rect.width / 2, rect.top + rect.height / 2, 1);
      ctrl.moveTo(0, 0);
    };
    container.addEventListener("dblclick", handleDoubleClick);
    (container as HTMLDivElement & { __apDbl?: () => void }).__apDbl = handleDoubleClick;

    return () => {
      disposed = true;
      // Note: deliberately NOT disposing the controller here — that's done by
      // the unmount effect below, OR by the next attach when the SVG element
      // genuinely changes. Disposing on every effect re-run is what caused
      // the original "freeze after 1s" bug.
    };
    // `t` only labels the SVG; a language switch must not re-attach panzoom.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [renderState, svgMarkup]);

  // Final cleanup on unmount — safe because attachedSvgRef + panzoomRef are
  // module-scope across re-renders.
  useEffect(() => {
    return () => {
      if (panzoomRef.current) {
        panzoomRef.current.dispose();
        panzoomRef.current = null;
      }
      const container = svgContainerRef.current;
      const dbl = container && (container as HTMLDivElement & { __apDbl?: () => void }).__apDbl;
      if (container && dbl) {
        container.removeEventListener("dblclick", dbl);
      }
      attachedSvgRef.current = null;
    };
  }, []);

  // Bind click handlers to CVE / CWE / CAPEC node groups so they navigate to
  // the relevant detail page or external taxonomy page. Mermaid emits each
  // node as a `<g class="node" id="flowchart-{nodeId}-..."`. We walk the
  // rendered SVG once, look up the source node by id, and attach a listener.
  // The handlers run on `click` (not mousedown) so they don't fight the
  // panzoom drag-detection logic.
  useEffect(() => {
    if (renderState !== "ready") return;
    const container = svgContainerRef.current;
    if (!container) return;
    const svgEl = container.querySelector("svg");
    if (!svgEl) return;

    const handlers: Array<{ el: Element; fn: (e: Event) => void }> = [];
    const nodeEls = svgEl.querySelectorAll<SVGGElement>("g.node");
    nodeEls.forEach((el) => {
      // Mermaid id format: "flowchart-{nodeId}-{counter}". Strip the prefix
      // and the trailing counter to recover the original node id.
      const rawId = el.id || "";
      const match = rawId.match(/^flowchart-(.+)-\d+$/);
      const nodeId = match?.[1];
      if (!nodeId) return;
      const node = nodesById.get(nodeId);
      if (!node) return;

      let target: { kind: "internal" | "external"; href: string } | null = null;
      const meta = (node.metadata ?? {}) as Record<string, unknown>;
      if (node.type === "cve") {
        const vid = (meta.vulnerabilityId as string | undefined) ?? node.label.split("\\n")[0].trim();
        if (vid) target = { kind: "internal", href: `/vulnerability/${encodeURIComponent(vid)}` };
      } else if (node.type === "cwe" && typeof meta.cweId === "string") {
        target = {
          kind: "external",
          href: `https://cwe.mitre.org/data/definitions/${meta.cweId.replace(/^CWE-/i, "")}.html`,
        };
      } else if (node.type === "capec" && typeof meta.capecId === "string") {
        target = {
          kind: "external",
          href: `https://capec.mitre.org/data/definitions/${meta.capecId.replace(/^CAPEC-/i, "")}.html`,
        };
      }

      if (!target) return;
      // Visual affordance: pointer cursor + on-hover outline.
      el.style.cursor = "pointer";

      const fn = (e: Event) => {
        // Defensive: panzoom emits mouseup → click sequence after drag. If
        // the user panned more than a few px the click will still fire here,
        // but Mermaid's nodes are small enough that this is acceptable. We
        // could thresholding this with a mousedown coordinate but the simpler
        // contract — "click navigates" — is what users expect.
        e.stopPropagation();
        if (target!.kind === "internal") {
          navigate(target!.href);
        } else {
          window.open(target!.href, "_blank", "noopener,noreferrer");
        }
      };
      el.addEventListener("click", fn);
      handlers.push({ el, fn });
    });

    return () => {
      for (const { el, fn } of handlers) {
        el.removeEventListener("click", fn);
      }
    };
  }, [renderState, svgMarkup, nodesById, navigate]);

  const zoomBy = (factor: number) => {
    const controller = panzoomRef.current;
    const container = svgContainerRef.current;
    if (!controller || !container) return;
    const rect = container.getBoundingClientRect();
    controller.smoothZoom(rect.left + rect.width / 2, rect.top + rect.height / 2, factor);
  };

  const resetZoom = () => {
    const controller = panzoomRef.current;
    const container = svgContainerRef.current;
    if (!controller || !container) return;
    const rect = container.getBoundingClientRect();
    controller.zoomAbs(rect.left + rect.width / 2, rect.top + rect.height / 2, 1);
    controller.moveTo(0, 0);
  };

  const labels = graph.labels;
  const metricWord = (value: string) => {
    const pair = METRIC_VALUE_LABELS[value];
    return pair ? t(pair[0], pair[1]) : value;
  };
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
    <div className="vulnerability-detail-path">
      <div className="well vulnerability-detail-path-disclaimer">
        <strong>
          {t("Plausible attack path, not proof of exploitability", "Plausibler Angriffspfad, kein Beweis der Ausnutzbarkeit")}
        </strong>
        <span>{graph.disclaimer}</span>
      </div>

      <dl className="vulnerability-detail-path-labels">
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
            value={metricWord(labels.privilegesRequired)}
            tone="muted"
          />
        ) : null}
        {labels.userInteraction ? (
          <LabelChip
            label={t("User interaction", "Benutzerinteraktion")}
            value={metricWord(labels.userInteraction)}
            tone="muted"
          />
        ) : null}
        {labels.businessImpact ? (
          <LabelChip
            label={t("Business impact", "Geschäftliche Auswirkung")}
            value={metricWord(labels.businessImpact)}
            tone={labels.businessImpact === "high" ? "danger" : "muted"}
          />
        ) : null}
      </dl>

      <div className="vulnerability-detail-path-stage">
        {renderState === "ready" && svgMarkup ? (
          <>
            <div
              ref={svgContainerRef}
              className="vulnerability-detail-path-canvas"
              onMouseDown={(e) => {
                (e.currentTarget as HTMLDivElement).style.cursor = "grabbing";
              }}
              onMouseUp={(e) => {
                (e.currentTarget as HTMLDivElement).style.cursor = "grab";
              }}
              onMouseLeave={(e) => {
                (e.currentTarget as HTMLDivElement).style.cursor = "grab";
              }}
              // mermaid output rendered in strict securityLevel
              dangerouslySetInnerHTML={{ __html: svgMarkup }}
            />
            <div
              className="vulnerability-detail-path-zoom"
              // Stop pointer events from being swallowed by the panzoom drag handler
              onMouseDown={(e) => e.stopPropagation()}
              onWheel={(e) => e.stopPropagation()}
            >
              <IconButton label={t("Zoom out", "Verkleinern")} onClick={() => zoomBy(0.8)}>
                <LuMinus size={14} aria-hidden="true" />
              </IconButton>
              <IconButton label={t("Reset zoom", "Zoom zurücksetzen")} onClick={() => resetZoom()}>
                <LuMaximize2 size={14} aria-hidden="true" />
              </IconButton>
              <IconButton label={t("Zoom in", "Vergrößern")} onClick={() => zoomBy(1.25)}>
                <LuPlus size={14} aria-hidden="true" />
              </IconButton>
            </div>
            <div className="vulnerability-detail-path-hint">
              {t(
                "Drag to pan, scroll to zoom, double-click to reset",
                "Ziehen zum Verschieben, Scrollen zum Zoomen, Doppelklick zum Zurücksetzen",
              )}
            </div>
          </>
        ) : renderState === "fallback" ? (
          <FallbackChain graph={graph} />
        ) : (
          <div role="status">
            <span className="visually-hidden">{t("Rendering attack path…", "Angriffspfad wird gezeichnet…")}</span>
            <SkeletonBlock height={320} radius={4} />
          </div>
        )}
      </div>

      <CrossReferences nodes={graph.nodes} t={t} />

      <div className="vulnerability-detail-path-narrative">
        <h3>{t("Scenario narrative", "Szenario-Beschreibung")}</h3>

        {!aiEnabled ? (
          <p className="vulnerability-detail-path-note">
            {t(
              "Configure an AI provider in System settings to generate prose attack scenarios.",
              "Konfiguriere einen AI-Provider in den Systemeinstellungen, um eine Prosa-Angriffsbeschreibung zu erzeugen.",
            )}
          </p>
        ) : null}

        {aiEnabled && canTriggerNarrative ? (
          <>
            <div className="vulnerability-detail-ai-controls">
              <label htmlFor="attack-path-provider">
                {t("Provider", "Anbieter")}
              </label>
              <select
                id="attack-path-provider"
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
              <button
                type="button"
                className="btn btn-primary"
                onClick={() =>
                  void onTriggerNarrative?.(selectedProvider, additionalContext.trim())
                }
                disabled={loading || !selectedProvider}
              >
                {loading
                  ? t("Generating...", "Erzeuge...")
                  : t("Generate scenario narrative", "Szenario-Beschreibung erzeugen")}
              </button>
            </div>
            <div className="vulnerability-detail-ai-context">
              <label htmlFor="attack-path-context">
                {t("Additional information (optional)", "Zusätzliche Informationen (optional)")}
              </label>
              <textarea
                id="attack-path-context"
                value={additionalContext}
                onChange={(event) => setAdditionalContext(event.target.value)}
                disabled={loading}
                placeholder={t(
                  "Enter additional context (e.g., we run this on Kubernetes)...",
                  "Geben Sie zusätzlichen Kontext ein (z. B. wir betreiben dies auf Kubernetes)...",
                )}
              />
            </div>
          </>
        ) : null}

        {error ? (
          <p className="vulnerability-detail-error" role="alert">
            {error}
          </p>
        ) : null}

        {loading ? (
          <AILoadingIndicator compact startedAt={loadingStartedAt ?? undefined} />
        ) : null}

        {narrative ? (
          <div className="well vulnerability-detail-path-narrative-body">
            <div className="vulnerability-detail-meta-line">
              <span>
                {t("Provider", "Anbieter")}: {narrative.provider}
              </span>
              {narrative.triggeredBy ? <span>{narrative.triggeredBy}</span> : null}
              <span>{new Date(narrative.generatedAt).toLocaleString(language === "de" ? "de-DE" : "en-US")}</span>
            </div>
            <div className="vulnerability-detail-prose">
              <Markdown>{narrativeText}</Markdown>
            </div>
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
    <Link to={`/vulnerability/${encodeURIComponent(vulnId)}`} className="vulnerability-detail-path-open">
      {t("Open full attack path", "Vollständigen Angriffspfad öffnen")}
    </Link>
  );
}
