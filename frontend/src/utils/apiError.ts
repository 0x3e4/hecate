import { isAxiosError } from "axios";

/** What kind of failure an error is, as far as the user is concerned. */
export type ErrorKind =
  | "offline"
  | "timeout"
  | "not_found"
  | "forbidden"
  | "rate_limited"
  | "server"
  | "unknown";

export interface DescribedError {
  kind: ErrorKind;
  /** HTTP status, when the server answered at all. */
  status: number | null;
  /** The server's `detail` message, when it sent one. */
  detail: string | null;
  /** Method and path of the failed request, for the technical details. */
  request: string | null;
  /** The raw message, for the technical details. */
  message: string | null;
}

const asText = (value: unknown): string | null => (typeof value === "string" && value.trim() ? value.trim() : null);

/** Sorts any thrown value into a kind the UI can explain. Never throws. */
export const describeError = (err: unknown): DescribedError => {
  if (isAxiosError(err)) {
    const status = err.response?.status ?? null;
    const data = err.response?.data as { detail?: unknown } | undefined;
    const method = err.config?.method?.toUpperCase();
    const url = err.config?.url;
    const base: Omit<DescribedError, "kind"> = {
      status,
      detail: asText(data?.detail),
      request: method && url ? `${method} ${url}` : url ?? null,
      message: asText(err.message),
    };
    if (status === null) {
      if (err.code === "ECONNABORTED" || err.code === "ETIMEDOUT") return { kind: "timeout", ...base };
      return { kind: "offline", ...base };
    }
    if (status === 404) return { kind: "not_found", ...base };
    if (status === 401 || status === 403) return { kind: "forbidden", ...base };
    if (status === 429) return { kind: "rate_limited", ...base };
    if (status === 408 || status === 504) return { kind: "timeout", ...base };
    if (status >= 500) return { kind: "server", ...base };
    return { kind: "unknown", ...base };
  }
  const message = err instanceof Error ? asText(err.message) : asText(err);
  return { kind: "unknown", status: null, detail: null, request: null, message };
};

/**
 * Why the backend refused a request, from the markers its gates set
 * (backend app/core/write_auth.py):
 * - `login`: a sign-in would open it (`X-Auth-Required: login`, no password offered)
 * - `login_or_password`: a sign-in or the system / target password would
 * - `password`: only a password would (no sign-in configured)
 * - `role`: signed in, but the role is too low (`X-Auth-Role-Required`)
 * `null` for anything else, a 404 or a server error included.
 */
export type AuthDenial =
  | { kind: "login" }
  | { kind: "login_or_password" }
  | { kind: "password" }
  | { kind: "role"; role: string };

export const authDenial = (err: unknown): AuthDenial | null => {
  if (!isAxiosError(err) || !err.response) return null;
  const { status } = err.response;
  const headers = (err.response.headers ?? {}) as Record<string, unknown>;
  const login = String(headers["x-auth-required"] ?? "") === "login";
  const password = Boolean(headers["x-write-auth-required"]);
  if (status === 403 && headers["x-auth-role-required"]) {
    return { kind: "role", role: String(headers["x-auth-role-required"]) };
  }
  if (status !== 401) return null;
  if (login && password) return { kind: "login_or_password" };
  if (login) return { kind: "login" };
  if (password) return { kind: "password" };
  return null;
};

type Translate = (english: string, german: string) => string;

/** One sentence naming what the refused action needs, e.g. for a toast. */
export const authDenialMessage = (denial: AuthDenial, action: string, t: Translate): string => {
  switch (denial.kind) {
    // With sign-in configured that is the way in; the password stays an
    // alternative in the prompt, not in the message.
    case "login":
    case "login_or_password":
      return t(`${action}: sign in first.`, `${action}: bitte zuerst anmelden.`);
    case "password":
      return t(`${action}: the system password is needed.`, `${action}: dafür ist das System-Passwort nötig.`);
    case "role":
      return denial.role === "admin"
        ? t(`${action}: this needs the admin role.`, `${action}: dafür ist die Admin-Rolle nötig.`)
        : t(`${action}: this needs at least the editor role.`, `${action}: dafür ist mindestens die Editor-Rolle nötig.`);
  }
};

/** One sentence on what happened and what helps, per kind. */
export const errorHint = (described: DescribedError, t: Translate): string => {
  const status = described.status ? ` (HTTP ${described.status})` : "";
  switch (described.kind) {
    case "offline":
      return t(
        "Hecate's backend did not answer. It may be restarting, or the network is down.",
        "Das Hecate-Backend hat nicht geantwortet. Es startet vielleicht gerade neu, oder das Netzwerk ist weg.",
      );
    case "timeout":
      return t(
        `The request took too long${status}. The server may be busy; try again in a moment.`,
        `Die Anfrage hat zu lange gedauert${status}. Der Server ist vielleicht ausgelastet; versuch es gleich noch einmal.`,
      );
    case "not_found":
      return t("This does not exist (any more).", "Das gibt es nicht (mehr).");
    case "forbidden":
      return t(
        `Access was refused${status}. A password may be missing or wrong.`,
        `Der Zugriff wurde verweigert${status}. Vielleicht fehlt ein Passwort oder es ist falsch.`,
      );
    case "rate_limited":
      return t(
        "Too many attempts in a short time. Wait a few minutes and try again.",
        "Zu viele Versuche in kurzer Zeit. Warte ein paar Minuten und versuch es dann erneut.",
      );
    case "server":
      return t(
        `The server ran into an error${status}. Trying again often helps; if not, the backend log says why.`,
        `Der Server hatte einen Fehler${status}. Ein neuer Versuch hilft oft; sonst steht der Grund im Backend-Log.`,
      );
    default:
      return t("Something unexpected went wrong.", "Etwas Unerwartetes ist schiefgelaufen.");
  }
};
