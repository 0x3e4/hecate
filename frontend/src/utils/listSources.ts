import type { InventoryListSource, InventoryListSourceInput, InventorySystemListFormat } from "../types";

/** Intervals offered for a fetched server list, in minutes (the backend takes 15 to 10080). */
export const INTERVAL_CHOICES = [15, 30, 60, 360, 720, 1440, 10080] as const;

export type IntervalUnit = "minutes" | "hours" | "days" | "weeks";

/** 60 → 1 hours, 1440 → 1 days: the largest whole unit. */
export const intervalParts = (minutes: number): { value: number; unit: IntervalUnit } => {
  if (minutes % 10080 === 0) return { value: minutes / 10080, unit: "weeks" };
  if (minutes % 1440 === 0) return { value: minutes / 1440, unit: "days" };
  if (minutes % 60 === 0) return { value: minutes / 60, unit: "hours" };
  return { value: minutes, unit: "minutes" };
};

export interface ListSourceForm {
  source: string;
  url: string;
  format: InventorySystemListFormat | "";
  mode: "merge" | "replace";
  intervalMinutes: number;
  authHeaderName: string;
  /** Typed credential; empty keeps the stored one. */
  authHeaderValue: string;
  removeCredential: boolean;
}

export const EMPTY_LIST_SOURCE_FORM: ListSourceForm = {
  source: "",
  url: "",
  format: "",
  mode: "merge",
  intervalMinutes: 60,
  authHeaderName: "Authorization",
  authHeaderValue: "",
  removeCredential: false,
};

export const formFromSource = (source: InventoryListSource): ListSourceForm => ({
  source: source.source,
  url: source.url,
  format: source.format ?? "",
  mode: source.mode,
  intervalMinutes: source.intervalMinutes,
  authHeaderName: source.authHeaderName ?? "Authorization",
  authHeaderValue: "",
  removeCredential: false,
});

/**
 * What to send for the form. On an edit the URL goes only when it changed (the
 * server masks tokens in it, so sending it back would store the mask) and the
 * credential only when one was typed or removed.
 */
export const listSourcePayload = (form: ListSourceForm, existing?: InventoryListSource): InventoryListSourceInput => {
  const payload: InventoryListSourceInput = {
    source: form.source.trim(),
    format: form.format || null,
    mode: form.mode,
    intervalMinutes: form.intervalMinutes,
  };
  const url = form.url.trim();
  if (!existing || url !== existing.url) payload.url = url;
  const credential = form.authHeaderValue.trim();
  if (form.removeCredential) {
    payload.authHeaderValue = "";
  } else if (credential) {
    payload.authHeaderValue = credential;
    payload.authHeaderName = form.authHeaderName.trim() || "Authorization";
  } else if (existing?.authSet && form.authHeaderName.trim() && form.authHeaderName.trim() !== existing.authHeaderName) {
    payload.authHeaderName = form.authHeaderName.trim();
  }
  return payload;
};

export type ChangeKind = "created" | "updated" | "retired" | "restored";

/** The non-zero changes of a fetch, in reading order. */
export const resultChanges = (result: {
  createdCount: number;
  updatedCount: number;
  retiredCount: number;
  restoredCount: number;
}): { kind: ChangeKind; count: number }[] =>
  (
    [
      { kind: "created", count: result.createdCount },
      { kind: "updated", count: result.updatedCount },
      { kind: "restored", count: result.restoredCount },
      { kind: "retired", count: result.retiredCount },
    ] as const
  ).filter((change) => change.count > 0);
