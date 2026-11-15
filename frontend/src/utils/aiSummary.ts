/**
 * Strip the legacy attribution footer that older backends appended to stored
 * AI summaries (`\n\n---\n_Added via ..._`). Newer backends no longer append
 * this footer — the attribution is rendered as structured metadata instead —
 * but existing records in OpenSearch / MongoDB may still contain it, so strip
 * it here before rendering markdown.
 */
export function stripAiSummaryFooter(summary: string | null | undefined): string {
  if (!summary) return "";
  return summary.replace(/\n{1,2}---\n_Added via [^\n]*_\s*$/u, "").trimEnd();
}

const PROVIDER_NAMES: Record<string, string> = {
  openai: "OpenAI",
  anthropic: "Anthropic",
  gemini: "Gemini",
  "openai-compatible": "OpenAI-compatible",
  "mcp-client": "MCP client",
};

/** The provider's display name ("openai" → "OpenAI"); unknown ids pass through. */
export function aiProviderName(provider: string | null | undefined): string {
  return provider ? PROVIDER_NAMES[provider] ?? provider : "";
}

/**
 * Who wrote an analysis: "OpenAI · gpt-5". The model is stored on analyses made
 * since it was recorded (and on MCP saves that pass one); for the others pass
 * `unknownModel` (e.g. "model not recorded") so the gap is visible instead of silent.
 */
export function aiMadeBy(
  provider: string | null | undefined,
  model: string | null | undefined,
  unknownModel?: string,
): string {
  return [aiProviderName(provider), model?.trim() || unknownModel].filter(Boolean).join(" · ");
}
