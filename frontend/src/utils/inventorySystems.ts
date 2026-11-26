import type { InventorySystem, InventorySystemReportStatus } from "../types";

type Translate = (en: string, de: string) => string;

const DAY_MS = 24 * 60 * 60 * 1000;

/** Whole days since the last report, counted in calendar days of the viewer; null without one. */
export const reportAgeDays = (lastReportAt: string | null | undefined, now: Date = new Date()): number | null => {
  if (!lastReportAt) return null;
  const then = new Date(lastReportAt);
  if (Number.isNaN(then.getTime())) return null;
  const startOf = (d: Date) => new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime();
  return Math.max(0, Math.round((startOf(now) - startOf(then)) / DAY_MS));
};

/** "today", "yesterday", "5 days ago", "never". */
export const reportAgeLabel = (lastReportAt: string | null | undefined, t: Translate, now: Date = new Date()): string => {
  const days = reportAgeDays(lastReportAt, now);
  if (days === null) return t("never", "nie");
  if (days === 0) return t("today", "heute");
  if (days === 1) return t("yesterday", "gestern");
  return t(`${days} days ago`, `vor ${days} Tagen`);
};

export const reportStatusLabel = (status: InventorySystemReportStatus, t: Translate): string => {
  switch (status) {
    case "reporting":
      return t("Reporting", "Meldet");
    case "stale":
      return t("No recent report", "Keine aktuelle Meldung");
    default:
      return t("Never reported", "Nie gemeldet");
  }
};

export const isRetired = (system: InventorySystem): boolean => Boolean(system.retiredAt);

export interface SystemStats {
  total: number;
  reporting: number;
  stale: number;
  never: number;
  internet: number;
  retired: number;
}

/** Counts of the systems in use; retired ones only in ``retired``. */
export const systemStats = (systems: InventorySystem[]): SystemStats => {
  const active = systems.filter((s) => !isRetired(s));
  return {
    total: active.length,
    reporting: active.filter((s) => s.reportStatus === "reporting").length,
    stale: active.filter((s) => s.reportStatus === "stale").length,
    never: active.filter((s) => s.reportStatus === "never").length,
    internet: active.filter((s) => s.exposure === "internet").length,
    retired: systems.length - active.length,
  };
};

export interface SystemFilters {
  query: string;
  status: InventorySystemReportStatus | "";
  kind: string;
  /** Retired systems (dropped by every list that named them) are hidden unless set. */
  showRetired?: boolean;
}

export const matchesSystemFilters = (system: InventorySystem, filters: SystemFilters): boolean => {
  if (isRetired(system) && !filters.showRetired) return false;
  if (filters.status && system.reportStatus !== filters.status) return false;
  if (filters.kind && (system.kind ?? "") !== filters.kind) return false;
  const query = filters.query.trim().toLocaleLowerCase();
  if (!query) return true;
  const haystack = [
    system.name, system.environment, system.owner, system.notes,
    ...system.groups, ...(system.listSources ?? []), ...system.products.map((p) => p.name),
  ]
    .filter(Boolean)
    .join(" ")
    .toLocaleLowerCase();
  return haystack.includes(query);
};

// Gaps first: a system that stopped reporting, then one that never did.
const STATUS_RANK: Record<InventorySystemReportStatus, number> = { stale: 0, never: 1, reporting: 2 };

/**
 * What needs a look first: systems without a recent report, then internet-facing
 * ones, then the most critical / high findings, then by name. Retired ones last.
 */
export const sortSystems = (systems: InventorySystem[]): InventorySystem[] =>
  [...systems].sort((a, b) => {
    const retired = Number(isRetired(a)) - Number(isRetired(b));
    if (retired) return retired;
    const status = STATUS_RANK[a.reportStatus] - STATUS_RANK[b.reportStatus];
    if (status) return status;
    const exposed = Number(b.exposure === "internet") - Number(a.exposure === "internet");
    if (exposed) return exposed;
    const critical = (b.latestSummary?.critical ?? 0) - (a.latestSummary?.critical ?? 0);
    if (critical) return critical;
    const high = (b.latestSummary?.high ?? 0) - (a.latestSummary?.high ?? 0);
    if (high) return high;
    return a.name.localeCompare(b.name, undefined, { sensitivity: "base", numeric: true });
  });

/** "dmz, web,  ,DMZ" -> ["dmz", "web"]: trimmed, case-insensitively unique. */
export const parseGroups = (text: string): string[] => {
  const out: string[] = [];
  for (const part of text.split(",")) {
    const value = part.trim();
    if (value && !out.some((g) => g.toLocaleLowerCase() === value.toLocaleLowerCase())) out.push(value);
  }
  return out;
};
