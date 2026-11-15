import axios from "axios";

import { currentReturnPath, loginUrl } from "../auth/returnTo";
import { readStoredLanguage } from "../i18n/language";
import { emitToast } from "./toastBridge";
import {
  extractTargetIdFromUrl,
  getAdminPassword,
  getTargetPassword,
  requestWritePassword,
  setAdminPassword,
  setTargetPassword,
  writePromptTarget,
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
export const apiBaseURL: string = baseURL;

export const api = axios.create({
  baseURL,
  timeout: 60000,  // Increased to 60s to handle long-running operations like stats
  // Proves to the backend that a cookie-authenticated write comes from these
  // pages: a cross-site form or script cannot add a custom header.
  headers: { "X-Hecate-Request": "1" },
});

const roleDeniedMessage = (role: string): string => {
  const german = readStoredLanguage() === "de";
  if (role === "admin") {
    return german ? "Dafür ist die Admin-Rolle nötig." : "This action requires the admin role.";
  }
  return german ? "Dafür ist mindestens die Editor-Rolle nötig." : "This action requires the editor role.";
};

let loginRedirectStarted = false;

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

// Response: on a 401 that the backend marked as a write-gate rejection, prompt
// for the password, then retry once. We gate on the `X-Write-Auth-Required`
// marker (not just any 401 on a mutating request) so that wrong AI/system
// passwords typed into a page's own unlock dialog — e.g. POST /status/ai-auth —
// are handled by that page, not hijacked by the global write-password prompt.
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const config = error?.config;
    const status = error?.response?.status;
    const headers = error?.response?.headers ?? {};
    // A signed-in user whose role is too low: say so, never ask for a password.
    if (status === 403 && headers["x-auth-role-required"]) {
      emitToast(roleDeniedMessage(String(headers["x-auth-role-required"])), "error");
      return Promise.reject(error);
    }
    // Only a sign-in helps (session expired, or a write without one): go to the
    // identity provider and come back here. A 401 that also offers a password
    // goes to the password prompt below, which has its own sign-in button.
    if (status === 401 && headers["x-auth-required"] === "login" && !headers["x-write-auth-required"]) {
      if (!loginRedirectStarted && typeof window !== "undefined") {
        loginRedirectStarted = true;
        window.location.assign(loginUrl(baseURL, currentReturnPath()));
      }
      return Promise.reject(error);
    }
    const targetId = config
      ? writePromptTarget(error?.response?.headers?.["x-write-auth-required"], resolveTargetId(config))
      : undefined;
    if (!config || status !== 401 || targetId === undefined || config._writeRetried) {
      return Promise.reject(error);
    }
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
