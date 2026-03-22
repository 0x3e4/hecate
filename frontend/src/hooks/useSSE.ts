import { useEffect, useState } from "react";

export interface JobEvent {
  eventType: "job_started" | "job_completed" | "job_failed" | "job_progress" | "new_vulnerabilities";
  jobName: string;
  status: "running" | "completed" | "failed";
  startedAt: string | null;
  finishedAt: string | null;
  durationSeconds: number | null;
  progress: Record<string, unknown> | null;
  metadata: Record<string, unknown>;
  error: string | null;
}

// ---------------------------------------------------------------------------
// Module-level singleton: one EventSource connection shared by all components
// ---------------------------------------------------------------------------

const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "/api";

type Listener = (jobs: Map<string, JobEvent>, connected: boolean) => void;

let _es: EventSource | null = null;
let _jobs: Map<string, JobEvent> = new Map();
let _connected = false;
let _listeners: Set<Listener> = new Set();
let _retryDelay = 1000;
let _retryTimer: ReturnType<typeof setTimeout> | null = null;

function _notify() {
  for (const fn of _listeners) fn(_jobs, _connected);
}

function _connect() {
  if (_es) _es.close();

  const es = new EventSource(`${BASE_URL}/v1/events`);
  _es = es;

  es.onopen = () => {
    _connected = true;
    _retryDelay = 1000;
    _notify();
  };

  const handleEvent = (e: MessageEvent) => {
    try {
      const event: JobEvent = JSON.parse(e.data);
      _jobs = new Map(_jobs);
      _jobs.set(
        event.eventType === "new_vulnerabilities"
          ? `new_vulnerabilities:${event.jobName}:${Date.now()}`
          : event.jobName,
        event,
      );
      _notify();
    } catch {
      // ignore parse errors
    }
  };

  es.addEventListener("job_started", handleEvent);
  es.addEventListener("job_completed", handleEvent);
  es.addEventListener("job_failed", handleEvent);
  es.addEventListener("job_progress", handleEvent);
  es.addEventListener("new_vulnerabilities", handleEvent);

  es.onerror = () => {
    _connected = false;
    es.close();
    _notify();
    const delay = _retryDelay;
    _retryDelay = Math.min(delay * 2, 30000);
    _retryTimer = setTimeout(_connect, delay);
  };
}

function _ensureConnection() {
  if (!_es || _es.readyState === EventSource.CLOSED) {
    _connect();
  }
}

function _maybeDisconnect() {
  if (_listeners.size === 0 && _es) {
    _es.close();
    _es = null;
    _connected = false;
    if (_retryTimer) {
      clearTimeout(_retryTimer);
      _retryTimer = null;
    }
  }
}

// ---------------------------------------------------------------------------
// Public hook – multiple callers share one EventSource
// ---------------------------------------------------------------------------

export function useSSE() {
  const [state, setState] = useState<{ jobs: Map<string, JobEvent>; connected: boolean }>({
    jobs: _jobs,
    connected: _connected,
  });

  useEffect(() => {
    const listener: Listener = (jobs, connected) => setState({ jobs, connected });
    _listeners.add(listener);
    _ensureConnection();

    // Push current state immediately in case events arrived before mount
    listener(_jobs, _connected);

    return () => {
      _listeners.delete(listener);
      _maybeDisconnect();
    };
  }, []);

  return state;
}
