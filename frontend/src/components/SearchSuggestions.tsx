import { useEffect, useState } from "react";

import { fetchVulnerabilitySuggestions, type VulnerabilitySuggestion } from "../api/vulnerabilities";
import type { TranslateFn } from "../i18n/context";
import { LoadingState, SeverityTag } from "../ui/primitives";
import { severityLabel } from "../utils/cveGroups";
import { suggestionScanId } from "../utils/searchSuggestions";

export const SUGGESTION_MIN_LENGTH = 2;
const DEBOUNCE_MS = 200;

/**
 * Candidates for what is typed, fetched 200 ms after the last keystroke. A newer
 * query aborts the older request, so a slow answer never replaces a fresher one.
 */
export const useVulnerabilitySuggestions = (query: string, enabled: boolean) => {
  const [items, setItems] = useState<VulnerabilitySuggestion[]>([]);
  const [loading, setLoading] = useState(false);
  const trimmed = query.trim();

  useEffect(() => {
    if (!enabled || trimmed.length < SUGGESTION_MIN_LENGTH) {
      setItems([]);
      setLoading(false);
      return;
    }
    const controller = new AbortController();
    setLoading(true);
    const timer = window.setTimeout(() => {
      fetchVulnerabilitySuggestions(trimmed, controller.signal)
        .then((result) => {
          if (!controller.signal.aborted) setItems(result);
        })
        .catch(() => {
          if (!controller.signal.aborted) setItems([]);
        })
        .finally(() => {
          if (!controller.signal.aborted) setLoading(false);
        });
    }, DEBOUNCE_MS);
    return () => {
      window.clearTimeout(timer);
      controller.abort();
    };
  }, [trimmed, enabled]);

  return { items, loading };
};

interface SuggestionListProps {
  t: TranslateFn;
  listId: string;
  items: VulnerabilitySuggestion[];
  loading: boolean;
  activeIndex: number;
  attentionIds: ReadonlySet<string>;
  cveScan: Record<string, string>;
  scanTargets: Record<string, string>;
  onPick: (vulnId: string) => void;
  onHover: (index: number) => void;
}

const formatEpss = (score: number) => `${(score * 100).toFixed(score >= 0.1 ? 0 : 1)}%`;

/** The list under the dashboard search: what each match is, and why it ranks where it does. */
export const SuggestionList = ({
  t,
  listId,
  items,
  loading,
  activeIndex,
  attentionIds,
  cveScan,
  scanTargets,
  onPick,
  onHover,
}: SuggestionListProps) => (
  <div className="dashboard-suggest" onMouseDown={(event) => event.preventDefault()}>
    {items.length === 0 ? (
      loading ? (
        <LoadingState inline label={t("Looking for matches…", "Suche Treffer…")} />
      ) : (
        <p className="dashboard-suggest-empty">
          {t("No matches. Press Enter to look the ID up.", "Keine Treffer. Enter sucht genau diese ID.")}
        </p>
      )
    ) : (
      <ul
        id={listId}
        role="listbox"
        aria-label={t("Matching vulnerabilities", "Passende Schwachstellen")}
        className={`dashboard-suggest-list${loading ? " is-refreshing" : ""}`}
        aria-busy={loading || undefined}
      >
        {items.map((item, index) => {
          const scanId = suggestionScanId(item, cveScan);
          const what = [item.products.join(", "), item.info].filter(Boolean).join(" — ");
          return (
            <li
              key={item.vulnId}
              id={`${listId}-${index}`}
              role="option"
              aria-selected={index === activeIndex}
              className="dashboard-suggest-option"
              onClick={() => onPick(item.vulnId)}
              onMouseEnter={() => onHover(index)}
            >
              <span className="dashboard-suggest-head">
                <span className="mono dashboard-suggest-id">{item.vulnId}</span>
                <SeverityTag severity={item.severity}>{severityLabel(item.severity, t)}</SeverityTag>
                {attentionIds.has(item.vulnId) && <span className="chip">{t("Needs attention", "Braucht Aufmerksamkeit")}</span>}
                {item.inventoryMatchIds.length > 0 && <span className="chip">{t("In inventory", "Im Inventar")}</span>}
                {scanId && <span className="chip">{scanTargets[scanId] ?? t("In scans", "In Scans")}</span>}
                {item.kevListed && <span className="chip">KEV</span>}
                {item.epssScore != null && <span className="dashboard-suggest-epss">EPSS {formatEpss(item.epssScore)}</span>}
              </span>
              {what && <span className="dashboard-suggest-info">{what}</span>}
            </li>
          );
        })}
      </ul>
    )}
  </div>
);
