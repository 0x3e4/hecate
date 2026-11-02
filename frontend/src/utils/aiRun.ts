import type { JobEvent } from "../hooks/useSSE";

/** The runId an AI job event carries, or null for events without one. */
export const runIdOf = (job: JobEvent | undefined): string | null => {
  const value = job?.metadata?.runId;
  return typeof value === "string" && value ? value : null;
};

/**
 * The latest event of one AI run, or undefined while it has not arrived.
 *
 * SSE keeps only the newest event per job name, so the previous run's
 * "completed" is still there when the next run starts. Matching the runId from
 * the submit response keeps a page from taking that one for its own and
 * loading the old result.
 */
export const eventForRun = (
  jobs: Map<string, JobEvent>,
  jobName: string,
  runId: string | null,
): JobEvent | undefined => {
  if (!runId) return undefined;
  const job = jobs.get(jobName);
  return runIdOf(job) === runId ? job : undefined;
};
