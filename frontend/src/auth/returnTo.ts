// Where to land after signing in. Mirrors safe_return_to in backend/app/api/v1/auth.py:
// only plain same-site paths, so a crafted link cannot bounce the browser elsewhere.

const MAX_LENGTH = 2000;

export const safeReturnTo = (value: string | null | undefined): string => {
  if (!value || value.length > MAX_LENGTH) return "/";
  if (!value.startsWith("/") || value.startsWith("//") || value.startsWith("/\\")) return "/";
  for (const ch of value) {
    if (ch.charCodeAt(0) < 32 || ch === "\\") return "/";
  }
  if (value === "/api" || value.startsWith("/api/")) return "/";
  return value;
};

/** The backend route that starts the OIDC sign-in, coming back to `path`. */
export const loginUrl = (apiBase: string, path: string): string => {
  const base = apiBase.replace(/\/+$/, "");
  return `${base}/v1/auth/login?returnTo=${encodeURIComponent(safeReturnTo(path))}`;
};

/** The page the browser is on, as a return path (minus the `authError` marker). */
export const currentReturnPath = (): string => {
  if (typeof window === "undefined") return "/";
  const url = new URL(window.location.href);
  url.searchParams.delete("authError");
  const search = url.searchParams.toString();
  return `${url.pathname}${search ? `?${search}` : ""}${url.hash}`;
};

export type AuthRole = "admin" | "editor" | "viewer";

const RANK: Record<AuthRole, number> = { viewer: 1, editor: 2, admin: 3 };

/** Whether `role` reaches `needed`. An unknown role reaches nothing. */
export const roleAtLeast = (role: string | null | undefined, needed: AuthRole): boolean => {
  if (!role || !(role in RANK)) return false;
  return RANK[role as AuthRole] >= RANK[needed];
};
