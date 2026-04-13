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
