import axios, { AxiosHeaders } from "axios";

import { currentReturnPath, loginUrl } from "../auth/returnTo";
import { readStoredLanguage } from "../i18n/language";
import { emitToast } from "./toastBridge";
import {
  accessPromptFor,
  extractTargetIdFromUrl,
  getAdminPassword,
  getTargetPassword,
  hasAccessPrompt,
  isAdminReadUrl,
  requestAccess,
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

// Request: attach write credentials to mutating requests, and the system
// password to the few reads behind the admin gate (the System page settings).
api.interceptors.request.use((config) => {
  const method = (config.method ?? "get").toLowerCase();
  if (!MUTATING.has(method)) {
    const admin = isAdminReadUrl(config.url) ? getAdminPassword() : null;
    if (admin) {
      config.headers = config.headers ?? {};
      (config.headers as Record<string, string>)["X-System-Password"] = admin;
    }
    return config;
  }
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

const PASSWORD_HEADERS = ["X-System-Password", "X-Target-Password"];

// Response: on a 401 that a sign-in or a password would open (the backend marks
// those with `X-Auth-Required: login` / `X-Write-Auth-Required`), ask through the
// access prompt, then retry once, so the action the user started still runs.
// Only marked 401s: a wrong AI / system password typed into a page's own unlock
// dialog (POST /status/ai-auth) stays with that page.
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
    const prompt = config ? accessPromptFor(status, headers, resolveTargetId(config)) : undefined;
    if (!config || prompt === undefined || config._writeRetried) {
      return Promise.reject(error);
    }
    // No prompt mounted (outside the app shell): the old full-page sign-in.
    if (!hasAccessPrompt()) {
      if (prompt.signIn && !loginRedirectStarted && typeof window !== "undefined") {
        loginRedirectStarted = true;
        window.location.assign(loginUrl(baseURL, currentReturnPath()));
      }
      return Promise.reject(error);
    }
    const answer = await requestAccess(prompt);
    if (!answer) {
      return Promise.reject(error);
    }
    config._writeRetried = true;
    config.headers = config.headers ?? new AxiosHeaders();
    const requestHeaders = config.headers as AxiosHeaders | Record<string, string>;
    if (answer.kind === "signed-in") {
      // The session authorizes the retry; a password left on the first attempt
      // belonged to whoever used this browser before the sign-in.
      for (const name of PASSWORD_HEADERS) {
        if (requestHeaders instanceof AxiosHeaders) requestHeaders.delete(name);
        else delete requestHeaders[name];
      }
      return api(config);
    }
    // Persist into the matching slot for future requests, and send both headers
    // on the retry so it works whether this is the admin or the target secret.
    if (prompt.targetId) {
      setTargetPassword(prompt.targetId, answer.password);
    } else {
      setAdminPassword(answer.password);
    }
    for (const name of PASSWORD_HEADERS) {
      if (requestHeaders instanceof AxiosHeaders) requestHeaders.set(name, answer.password);
      else requestHeaders[name] = answer.password;
    }
    return api(config);
  }
);
