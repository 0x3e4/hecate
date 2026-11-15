/**
 * Findings-tab filters and the VEX sort order (pure, tested).
 *
 * Dependency scope: runtime / dev / optional come from the lockfile or
 * manifest; "unknown" is a finding whose source said nothing. VEX "set by"
 * groups the raw `vexUpdatedBy` actor into who is behind a status.
 */

export type ScopeFilterValue = "runtime" | "dev" | "optional" | "unknown";
export const SCOPE_FILTER_VALUES: ScopeFilterValue[] = ["runtime", "optional", "dev", "unknown"];

export type VexFilterValue = "none" | "affected" | "under_investigation" | "fixed" | "not_affected";
export const VEX_FILTER_VALUES: VexFilterValue[] = ["none", "affected", "under_investigation", "fixed", "not_affected"];

export type VexSetBy = "manual" | "imported" | "source" | "rule" | "reachability";
export const VEX_SET_BY_VALUES: VexSetBy[] = ["manual", "imported", "source", "rule", "reachability"];

/** Most urgent first: affected, under investigation, no status, fixed, not affected. */
const VEX_SORT_RANK: Record<VexFilterValue, number> = {
  affected: 0,
  under_investigation: 1,
  none: 2,
  fixed: 3,
  not_affected: 4,
};

const SCOPE_RANK: Record<string, number> = { runtime: 3, optional: 2, dev: 1 };

export const VEX_RULE_ACTOR_PREFIX = "vex-rule:";

export function scopeOf(scope: string | null | undefined): ScopeFilterValue {
  return scope === "runtime" || scope === "dev" || scope === "optional" ? scope : "unknown";
}

/** Runtime wins over optional, optional over dev; unknown never overrides. */
export function mergeScope(current: string | null | undefined, incoming: string | null | undefined): string | null {
  const a = SCOPE_RANK[current ?? ""] ?? 0;
  const b = SCOPE_RANK[incoming ?? ""] ?? 0;
  if (!b) return a ? (current as string) : null;
  return b > a ? (incoming as string) : (current as string);
}

export function vexKey(status: string | null | undefined): VexFilterValue {
  return status && status in VEX_SORT_RANK ? (status as VexFilterValue) : "none";
}

export function compareVex(a: string | null | undefined, b: string | null | undefined): number {
  return VEX_SORT_RANK[vexKey(a)] - VEX_SORT_RANK[vexKey(b)];
}

/** Who is behind a status; null when there is none. Carried-forward statuses count as manual. */
export function vexSetBy(actor: string | null | undefined, status?: string | null): VexSetBy | null {
  if (status === null || (!actor && !status)) return null;
  if (!actor) return "manual";
  if (actor === "vex-import") return "imported";
  if (actor === "vex-source") return "source";
  if (actor.startsWith(VEX_RULE_ACTOR_PREFIX)) return "rule";
  if (actor.startsWith("reachability:")) return "reachability";
  return "manual";
}

export function vexRuleId(actor: string | null | undefined): string | null {
  return actor && actor.startsWith(VEX_RULE_ACTOR_PREFIX) ? actor.slice(VEX_RULE_ACTOR_PREFIX.length) : null;
}

export interface FilterableFinding {
  dependencyScope?: string | null;
  vexStatus?: string | null;
  vexUpdatedBy?: string | null;
  vexNeedsReview?: boolean;
}

export interface FindingFilterState {
  /** Empty = every scope. */
  scopes: ScopeFilterValue[];
  /** Empty = every VEX status. */
  vex: VexFilterValue[];
  /** Empty = any writer. */
  setBy: VexSetBy[];
  needsReview: boolean;
}

export const EMPTY_FINDING_FILTERS: FindingFilterState = { scopes: [], vex: [], setBy: [], needsReview: false };

export function matchesFindingFilters(row: FilterableFinding, filters: FindingFilterState): boolean {
  if (filters.scopes.length && !filters.scopes.includes(scopeOf(row.dependencyScope))) return false;
  if (filters.vex.length && !filters.vex.includes(vexKey(row.vexStatus))) return false;
  if (filters.setBy.length) {
    const who = vexSetBy(row.vexUpdatedBy, row.vexStatus ?? null);
    if (!who || !filters.setBy.includes(who)) return false;
  }
  if (filters.needsReview && !(row.vexStatus && row.vexNeedsReview)) return false;
  return true;
}

export function hasActiveFindingFilters(filters: FindingFilterState): boolean {
  return filters.scopes.length > 0 || filters.vex.length > 0 || filters.setBy.length > 0 || filters.needsReview;
}

/** Toggle a value in a multi-select filter list (keeps the canonical order). */
export function toggleValue<T extends string>(list: T[], value: T, order: T[]): T[] {
  const next = list.includes(value) ? list.filter(v => v !== value) : [...list, value];
  return order.filter(v => next.includes(v));
}
