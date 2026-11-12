/**
 * What a running sync's progress report can show. Pipelines report
 * `processed` (and per-source counters); NVD and EUVD add `remote_total`, the
 * size of the whole source. That total only bounds a full sync, so an
 * incremental run gets a count, not a bar that would sit near 0 % and jump.
 */
export interface SyncProgressView {
  processed: number;
  /** Set when a bar makes sense: the run covers the whole source. */
  total: number | null;
  /** 0–100, rounded down; null without a total. */
  percent: number | null;
}

const asCount = (value: unknown): number | null =>
  typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : null;

export const syncProgressView = (
  jobName: string,
  progress: Record<string, unknown> | null | undefined,
): SyncProgressView | null => {
  if (!progress) return null;
  const processed = asCount(progress.processed);
  if (processed === null) return null;
  const fullRun = jobName.includes("initial");
  const limit = asCount(progress.limit);
  const remote = asCount(progress.remote_total);
  // A limit bounds any run; the source total only a full one.
  const total = limit && limit > 0 ? limit : fullRun && remote && remote > 0 ? remote : null;
  const percent = total ? Math.min(100, Math.floor((processed / total) * 100)) : null;
  return { processed, total, percent };
};
