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

// --- 401 password prompt bridge (axios <-> React) -----------------------------
// The WriteAuthProvider registers a resolver here; the response interceptor
// calls it to obtain a password (or null if the user cancels).

export type WritePromptContext = { targetId: string | null };
type WritePrompt = (ctx: WritePromptContext) => Promise<string | null>;

let _prompt: WritePrompt | null = null;

export const registerWritePrompt = (fn: WritePrompt | null): void => {
  _prompt = fn;
};

export const requestWritePassword = async (
  ctx: WritePromptContext
): Promise<string | null> => {
  if (!_prompt) return null;
  return _prompt(ctx);
};
