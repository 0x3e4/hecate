/**
 * Sorting and filtering of the inventory list. Pure, so the page and the tests
 * share one rule. The signals come from data the page already loads per item:
 * the affecting CVEs and the endoflife.date status.
 */
import type { AffectedVulnerabilityItem, EolStatus, InventoryItem } from "../types";

export type InventorySortKey = "activity" | "severity" | "cves" | "support" | "edited" | "name";

export const INVENTORY_SORT_KEYS: InventorySortKey[] = ["activity", "severity", "cves", "support", "edited", "name"];

export interface InventoryFilters {
  environment: string; // "" = all
  deployment: string; // "" = all
  owner: string; // "" = all
  affectedOnly: boolean;
  exploitedOnly: boolean;
  endOfLifeOnly: boolean;
  updateOnly: boolean;
}

export const DEFAULT_INVENTORY_FILTERS: InventoryFilters = {
  environment: "",
  deployment: "",
  owner: "",
  affectedOnly: false,
  exploitedOnly: false,
  endOfLifeOnly: false,
  updateOnly: false,
};

/** What the list knows about one item. `known` is false while its CVEs still load. */
export interface ItemSignals {
  known: boolean;
  count: number;
  /** 0 critical … 4 low, 5 = no rated CVE. */
  worst: number;
  exploited: boolean;
  /** Newest change of any affecting CVE (ms), else its publication. */
  lastActivity: number | null;
  endOfLife: boolean;
  updateAvailable: boolean;
  /** End of support (ms) when endoflife.date knows it. */
  supportEnds: number | null;
}

const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, moderate: 2, low: 3 };

const toTime = (value?: string | null): number | null => {
  if (!value) return null;
  const time = Date.parse(value);
  return Number.isNaN(time) ? null : time;
};

/** When a CVE last moved: Hecate's last change, else its publication. */
export const cveActivity = (cve: AffectedVulnerabilityItem): number | null =>
  toTime(cve.lastChangeAt) ?? toTime(cve.published);

export const itemSignals = (
  cves: AffectedVulnerabilityItem[] | null,
  eol: EolStatus | null,
): ItemSignals => {
  const list = cves ?? [];
  let worst = 5;
  let lastActivity: number | null = null;
  for (const cve of list) {
    const rank = SEVERITY_RANK[(cve.severity || "").toLowerCase()];
    if (rank !== undefined && rank < worst) worst = rank;
    const activity = cveActivity(cve);
    if (activity !== null && (lastActivity === null || activity > lastActivity)) lastActivity = activity;
  }
  return {
    known: cves !== null,
    count: list.length,
    worst,
    exploited: list.some((cve) => cve.exploited === true),
    lastActivity,
    endOfLife: eol?.status === "eol",
    updateAvailable: eol?.isOutdated === true,
    supportEnds: toTime(eol?.eolDate),
  };
};

export const matchesInventoryFilters = (
  item: InventoryItem,
  signals: ItemSignals,
  filters: InventoryFilters,
): boolean => {
  if (filters.environment && item.environment.toLowerCase() !== filters.environment.toLowerCase()) return false;
  if (filters.deployment && item.deployment !== filters.deployment) return false;
  if (filters.owner && (item.owner || "") !== filters.owner) return false;
  // A flag filter hides an item only once its data is in: a row that is still
  // loading stays, so the list does not jump while the CVEs arrive.
  if (filters.affectedOnly && signals.known && signals.count === 0) return false;
  if (filters.exploitedOnly && signals.known && !signals.exploited) return false;
  if (filters.endOfLifeOnly && !signals.endOfLife) return false;
  if (filters.updateOnly && !signals.updateAvailable) return false;
  return true;
};

/** Larger first, unknown last. */
const desc = (a: number | null, b: number | null) => (a === b ? 0 : a === null ? 1 : b === null ? -1 : b - a);
/** Smaller first, unknown last. */
const asc = (a: number | null, b: number | null) => (a === b ? 0 : a === null ? 1 : b === null ? -1 : a - b);

export const sortInventoryItems = (
  items: InventoryItem[],
  signalsOf: (item: InventoryItem) => ItemSignals,
  key: InventorySortKey,
): InventoryItem[] => {
  const byName = (a: InventoryItem, b: InventoryItem) =>
    a.name.localeCompare(b.name, undefined, { sensitivity: "base" }) || a.version.localeCompare(b.version);
  const compare = (a: InventoryItem, b: InventoryItem): number => {
    const sa = signalsOf(a);
    const sb = signalsOf(b);
    switch (key) {
      case "activity":
        return desc(sa.lastActivity, sb.lastActivity);
      case "severity":
        return (
          asc(sa.known && sa.count ? sa.worst : null, sb.known && sb.count ? sb.worst : null) ||
          Number(sb.exploited) - Number(sa.exploited) ||
          desc(sa.known ? sa.count : null, sb.known ? sb.count : null)
        );
      case "cves":
        return desc(sa.known ? sa.count : null, sb.known ? sb.count : null);
      case "support":
        return asc(sa.supportEnds, sb.supportEnds);
      case "edited":
        return desc(toTime(a.updatedAt), toTime(b.updatedAt));
      default:
        return 0;
    }
  };
  return [...items].sort((a, b) => compare(a, b) || byName(a, b));
};

/** A CVE affecting the item changed after the previous visit to the page. */
export const hasNewActivity = (signals: ItemSignals, previousVisit: number | null): boolean =>
  previousVisit !== null && signals.lastActivity !== null && signals.lastActivity > previousVisit;

export const LAST_VISIT_KEY = "hecate.inventory.lastVisit";

/** The previous visit to the page (ms). Storage may be missing or blocked: then nothing counts as new. */
export const readLastVisit = (): number | null => {
  try {
    const previous = Number(window.localStorage.getItem(LAST_VISIT_KEY));
    return Number.isFinite(previous) && previous > 0 ? previous : null;
  } catch {
    return null;
  }
};

/** Records a visit; called when the page is left, so "new" holds while the page is open. */
export const stampLastVisit = (now: number = Date.now()): void => {
  try {
    window.localStorage.setItem(LAST_VISIT_KEY, String(now));
  } catch {
    // Blocked storage: the marker simply never shows.
  }
};
