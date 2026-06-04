import axios from "axios";

import {
  extractTargetIdFromUrl,
  getAdminPassword,
  getTargetPassword,
  requestWritePassword,
  setAdminPassword,
  setTargetPassword,
} from "./writeAuth";

// Callers can declare the owning target of a write so the per-target password
// is attached even when the target id isn't in the URL (e.g. scan delete, VEX).
declare module "axios" {
  export interface AxiosRequestConfig {
    meta?: { targetId?: string };
    _writeRetried?: boolean;
  }
}

const baseURL = import.meta.env.VITE_API_BASE_URL ?? "/api";

export const api = axios.create({
  baseURL,
  timeout: 60000  // Increased to 60s to handle long-running operations like stats
});

const MUTATING = new Set(["post", "put", "patch", "delete"]);

const resolveTargetId = (config: {
  url?: string;
  meta?: { targetId?: string };
}): string | null => config.meta?.targetId ?? extractTargetIdFromUrl(config.url);

// Request: attach write credentials to mutating requests only (reads stay open).
api.interceptors.request.use((config) => {
  const method = (config.method ?? "get").toLowerCase();
  if (!MUTATING.has(method)) return config;
  const admin = getAdminPassword();
  if (admin) {
    config.headers = config.headers ?? {};
    (config.headers as Record<string, string>)["X-System-Password"] = admin;
  }
  const targetId = resolveTargetId(config);
  if (targetId) {
    const targetPw = getTargetPassword(targetId);
    if (targetPw) {
      config.headers = config.headers ?? {};
      (config.headers as Record<string, string>)["X-Target-Password"] = targetPw;
    }
  }
  return config;
});

// Response: on a 401 from a write, prompt for the password, then retry once.
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const config = error?.config;
    const status = error?.response?.status;
    const method = (config?.method ?? "get").toLowerCase();
    if (!config || status !== 401 || !MUTATING.has(method) || config._writeRetried) {
      return Promise.reject(error);
    }
    const targetId = resolveTargetId(config);
    const password = await requestWritePassword({ targetId });
    if (!password) {
      return Promise.reject(error);
    }
    // Persist into the matching slot for future requests, and send both headers
    // on the retry so it works whether this is the admin or the target secret.
    if (targetId) {
      setTargetPassword(targetId, password);
    } else {
      setAdminPassword(password);
    }
    config._writeRetried = true;
    config.headers = config.headers ?? {};
    (config.headers as Record<string, string>)["X-System-Password"] = password;
    (config.headers as Record<string, string>)["X-Target-Password"] = password;
    return api(config);
  }
);
