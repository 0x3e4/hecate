// Client-side credential store for the write-protection gate (see backend
// app/core/write_auth.py). Two secrets:
//   - admin password  -> X-System-Password  (unlocks all writes; set on System unlock)
//   - per-target pw    -> X-Target-Password  (unlocks one target's writes)
// Reads never carry a password. Stored in localStorage so writes from any page
// work after a single unlock.

const ADMIN_KEY = "hecate.system_password";
const TARGET_KEY = "hecate.target_pw";

export const getAdminPassword = (): string | null => {
  try {
    return localStorage.getItem(ADMIN_KEY) || null;
  } catch {
    return null;
  }
};

export const setAdminPassword = (password: string): void => {
  try {
    localStorage.setItem(ADMIN_KEY, password);
  } catch {
    /* ignore quota / private-mode errors */
  }
};

export const clearAdminPassword = (): void => {
  try {
    localStorage.removeItem(ADMIN_KEY);
  } catch {
    /* ignore */
  }
};

const readTargetMap = (): Record<string, string> => {
  try {
    const raw = localStorage.getItem(TARGET_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
};

const writeTargetMap = (map: Record<string, string>): void => {
  try {
    localStorage.setItem(TARGET_KEY, JSON.stringify(map));
  } catch {
    /* ignore */
  }
};

export const getTargetPassword = (targetId: string): string | null => {
  if (!targetId) return null;
  return readTargetMap()[targetId] || null;
};

export const setTargetPassword = (targetId: string, password: string): void => {
  if (!targetId) return;
  const map = readTargetMap();
  map[targetId] = password;
  writeTargetMap(map);
};

export const clearTargetPassword = (targetId: string): void => {
  const map = readTargetMap();
  if (targetId in map) {
    delete map[targetId];
    writeTargetMap(map);
  }
};

// Reads behind the admin gate (backend require_admin_read / require_token_admin):
// the System page's settings. The interceptor sends the system password on
// these GETs too; every other read goes without it.
const ADMIN_READ_PREFIXES = [
  "/v1/notifications",
  "/v1/backup",
  "/v1/sync",
  "/v1/advisory-feeds",
  "/v1/inventory/systems/sources",
  "/v1/api-tokens",
  "/v1/audit",
];

export const isAdminReadUrl = (url: string | undefined): boolean => {
  if (!url) return false;
  const path = url.split(/[?#]/, 1)[0].replace(/^https?:\/\/[^/]+/, "").replace(/^\/api(?=\/v1\/)/, "");
  return ADMIN_READ_PREFIXES.some((prefix) => path === prefix || path.startsWith(`${prefix}/`));
};

// Storage key of the AI analysis password (usePersistentState in the AI views).
export const AI_PASSWORD_KEY = "ai_analysis_password";

// Every write secret this browser holds: the system password, all target
// passwords and the AI password. Called on sign-in and sign-out, because the
// interceptor attaches them to whoever is signed in next, and the backend
// honours a matching system password even for a viewer session.
export const clearWriteSecrets = (): void => {
  for (const key of [ADMIN_KEY, TARGET_KEY, AI_PASSWORD_KEY]) {
    try {
      localStorage.removeItem(key);
    } catch {
      /* ignore */
    }
  }
};

// Best-effort extraction of a target id from a request URL. The target id is a
// single URL-encoded segment after /scans/targets/ (any /check or
// /write-password suffix is a literal slash that follows it).
export const extractTargetIdFromUrl = (url: string | undefined): string | null => {
  if (!url) return null;
  const match = url.match(/\/scans\/targets\/([^/?#]+)/);
  if (!match) return null;
  try {
    return decodeURIComponent(match[1]);
  } catch {
    return match[1];
  }
};

// --- 401 access prompt bridge (axios <-> React) -------------------------------
// The WriteAuthProvider registers a prompt here; the response interceptor calls
// it on a refused request and retries the request with the answer, so the
// action the user started runs once they signed in or entered the password.

/**
 * Which password a write-gate rejection asks for, from its `X-Write-Auth-Required`
 * marker: the target's (or the admin's) for "1", only the admin's for "admin".
 * `undefined` means the 401 did not come from a write gate.
 */
export const writePromptTarget = (marker: unknown, targetId: string | null): string | null | undefined => {
  const value = String(marker ?? "");
  if (value === "admin") return null;
  if (value === "1") return targetId;
  return undefined;
};
/** What would let a refused request through. */
export type AccessPrompt = {
  /** Sign-in is configured and would open it (`X-Auth-Required: login`). */
  signIn: boolean;
  /** A password would open it too (`X-Write-Auth-Required`). */
  password: boolean;
  /** The target whose password is accepted; null = the system password. */
  targetId: string | null;
};

export type AccessAnswer = { kind: "password"; password: string } | { kind: "signed-in" } | null;

/**
 * The prompt a refused request calls for, from the backend's markers, or
 * `undefined` when neither a sign-in nor a password helps (a role denial,
 * a wrong password typed into a page's own unlock dialog, any other error).
 */
export const accessPromptFor = (
  status: number | undefined,
  headers: Record<string, unknown>,
  targetId: string | null,
): AccessPrompt | undefined => {
  if (status !== 401) return undefined;
  const passwordTarget = writePromptTarget(headers["x-write-auth-required"], targetId);
  const signIn = String(headers["x-auth-required"] ?? "") === "login";
  if (!signIn && passwordTarget === undefined) return undefined;
  return { signIn, password: passwordTarget !== undefined, targetId: passwordTarget ?? null };
};

type AccessPromptFn = (prompt: AccessPrompt) => Promise<AccessAnswer>;

let _prompt: AccessPromptFn | null = null;
let _inflight: { key: string; promise: Promise<AccessAnswer> } | null = null;

export const registerWritePrompt = (fn: AccessPromptFn | null): void => {
  _prompt = fn;
};

export const hasAccessPrompt = (): boolean => _prompt !== null;

const promptKey = (p: AccessPrompt): string => `${p.signIn}|${p.password}|${p.targetId ?? ""}`;

/**
 * Asks once for several refused requests: a page often fires a few writes or
 * reads together, and each would otherwise open (and overwrite) its own dialog.
 * Requests waiting on the same prompt share its answer; a sign-in answers every
 * waiting request, since the session now covers them all.
 */
export const requestAccess = async (prompt: AccessPrompt): Promise<AccessAnswer> => {
  const key = promptKey(prompt);
  while (_inflight) {
    const current = _inflight;
    const answer = await current.promise;
    if (_inflight === current) _inflight = null;
    if (current.key === key || answer?.kind === "signed-in") return answer;
  }
  if (!_prompt) return null;
  const promise = _prompt(prompt);
  _inflight = { key, promise };
  try {
    return await promise;
  } finally {
    if (_inflight?.promise === promise) _inflight = null;
  }
};
