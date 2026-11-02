import { describe, expect, it } from "vitest";

import type { JobEvent } from "../hooks/useSSE";
import { eventForRun, runIdOf } from "./aiRun";

const event = (status: JobEvent["status"], runId?: string): JobEvent => ({
  eventType: status === "running" ? "job_started" : status === "completed" ? "job_completed" : "job_failed",
  jobName: "ai_batch_investigation",
  status,
  startedAt: null,
  finishedAt: null,
  durationSeconds: null,
  progress: null,
  metadata: runId ? { runId } : {},
  error: null,
});

describe("eventForRun", () => {
  it("ignores the previous run's result while the new run is pending", () => {
    const jobs = new Map([["ai_batch_investigation", event("completed", "old")]]);

    expect(eventForRun(jobs, "ai_batch_investigation", "new")).toBeUndefined();
  });

  it("ignores every event before the submit response named the run", () => {
    const jobs = new Map([["ai_batch_investigation", event("completed", "old")]]);

    expect(eventForRun(jobs, "ai_batch_investigation", null)).toBeUndefined();
  });

  it("returns the event of the run it waits for", () => {
    const done = event("completed", "new");
    const jobs = new Map([["ai_batch_investigation", done]]);

    expect(eventForRun(jobs, "ai_batch_investigation", "new")).toBe(done);
  });

  it("does not take an event without a runId for any run", () => {
    const jobs = new Map([["ai_batch_investigation", event("completed")]]);

    expect(eventForRun(jobs, "ai_batch_investigation", "new")).toBeUndefined();
    expect(runIdOf(jobs.get("ai_batch_investigation"))).toBeNull();
  });
});
